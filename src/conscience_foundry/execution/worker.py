"""Bounded remote worker: reads pinned inputs, writes verified outputs, manifest last.

Trust model:

* The worker holds no ledger, database credential, model client or environment
  lookup. Its whole input is the immutable plan and attempt bytes, the transient
  grants minted by the control side, an already scoped object store and a clock.
  PostgreSQL alone owns reservations, claims and acceptance; whatever this
  function returns is a *claim* the control side verifies before it counts.
* The absolute deadline (grant expiry, plan expiry, budget validity and the
  approved wall ceiling from first entry) is checked at entry and immediately
  before every bounded external step, so an expired envelope has no application
  effects. That bounds what the worker does; it does not bound provider billing
  before the worker is entered, which is the capability record's job.
* Input and output byte ceilings come from the approved plan and pinned limits.
  Working memory is bounded by checking the source against the approved memory
  ceiling before it is read. Nothing is written before every output fits.
* The result manifest is written strictly last and only after every output it
  names is verified in the store. A deterministic content failure becomes a
  ``failed`` manifest; an unavailable input, an exceeded bound or an expired
  envelope raises without a manifest, since none of those proves anything about
  the content.
* Failures surface only as stable ``ContractError`` codes: no text, path,
  credential or provider payload is formatted anywhere.
"""

from __future__ import annotations

import hashlib
import io
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Protocol

from pydantic import TypeAdapter

from conscience_foundry.contracts.accounting import ResourceUsage
from conscience_foundry.contracts.admission import AdmissionReport, SourceAsset
from conscience_foundry.contracts.canonical import DocumentRevision, ExtractionSpec
from conscience_foundry.contracts.common import (
    ContractError,
    ContractLimits,
    Instant,
    Reason,
    Ref,
    WireModel,
)
from conscience_foundry.contracts.execution import ExecutionPlan, ResultManifest, StageAttempt
from conscience_foundry.core.identity import RevisionInputs, revision_id, structure_digest
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.processing.text_utf8 import process_text
from conscience_foundry.storage.local import ObjectStore, VerifiedBytes

if TYPE_CHECKING:
    from conscience_foundry.execution.ports import TransportGrants

_INSTANT = TypeAdapter(Instant)
_ARTIFACT_MEDIA = "application/json"
_WORKING_COPIES = 4
"""Source bytes, decoded text, canonical text and serialized outputs held at the peak."""
_CONTENT_FAILURES = frozenset({"empty_text", "bom_rejected", "nul_rejected", "invalid_encoding"})
"""Deterministic verdicts about the source bytes; everything else is not a content failure."""
_WORKER_SCOPES = frozenset({"read", "remoteTransfer", "extract"})


class Clock(Protocol):
    def now(self) -> Instant: ...


def _parse(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def _format(value: datetime) -> Instant:
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _bootstrap(size: int) -> ContractLimits:
    """Syntax-only limits for pinned bytes whose real limits are not yet known.

    Every property of ``size`` bytes is at most ``size``, so this admits exactly
    well-formed documents of that length and invents no tunable ceiling; the
    pinned limits artifact then replaces it before any content is processed.
    """
    bound = max(size, 1)
    return ContractLimits.model_validate(
        {
            "schemaVersion": "kf.contract-limits.v1",
            "version": "worker.bootstrap.v1",
            "maxJsonBytes": bound,
            "maxStringScalars": bound,
            "maxArrayItems": bound,
            "maxDepth": bound,
            "maxManifestItems": bound,
            "maxSourceBytes": bound,
            "maxOutputBytes": bound,
            "maxErrorMessageScalars": bound,
        }
    )


def _wire[Model: WireModel](model: type[Model], data: bytes, limits: ContractLimits) -> Model:
    try:
        return model.from_wire(data, limits)
    except ContractError:
        raise
    except Exception:
        raise ContractError("invalid_schema") from None


def _encode(record: WireModel, limits: ContractLimits) -> bytes:
    raw = record.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8")
    _wire(type(record), raw, limits)  # bounded, strict, round-trippable
    return raw


def _ref(project_id: str, data: bytes, schema: str, media_type: str) -> Ref:
    return Ref(
        schema_version="kf.artifact-ref.v1",
        project_id=project_id,
        digest=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        media_type=media_type,
        artifact_schema=schema,
        locations=(),
    )


def _identity(ref: Ref) -> tuple[object, ...]:
    return ref.project_id, ref.artifact_schema, ref.digest, ref.size_bytes, ref.media_type


class _Deadline:
    """One absolute deadline, re-read from the clock before every bounded step."""

    def __init__(self, clock: Clock, deadline: Instant) -> None:
        self._clock = clock
        self.deadline = deadline

    def check(self) -> Instant:
        try:
            now = self._clock.now()
            _INSTANT.validate_python(now)
        except Exception:
            raise ContractError("unavailable") from None
        if now >= self.deadline:
            raise ContractError("authorization_expired")
        return now

    def tighten(self, deadline: Instant) -> None:
        self.deadline = min(self.deadline, deadline)


def _checked_grants(
    grants: TransportGrants, plan: ExecutionPlan, attempt: StageAttempt, plan_bytes: bytes
) -> Instant:
    """Bind the transient grants to this exact plan and attempt without reading secrets."""
    try:
        project_id, plan_digest = grants.project_id, grants.plan_digest
        attempt_id, expires_at = grants.attempt_id, grants.expires_at
        _INSTANT.validate_python(expires_at)
    except Exception:
        raise ContractError("forbidden") from None
    if (
        project_id != plan.project_id
        or attempt_id != attempt.attempt_id
        or plan_digest != hashlib.sha256(plan_bytes).hexdigest()
    ):
        raise ContractError("forbidden")
    return expires_at


def _quantity(delta: timedelta) -> str:
    return f"{max(delta.total_seconds(), 0):.3f}"


def run_worker(
    plan_bytes: bytes,
    attempt_bytes: bytes,
    grants: TransportGrants,
    store: ObjectStore,
    clock: Clock,
) -> Ref:
    """Process the one planned input and return the reference of the result manifest."""
    if type(plan_bytes) is not bytes or type(attempt_bytes) is not bytes:
        raise ContractError("invalid_schema")
    if not callable(getattr(clock, "now", None)) or not (
        callable(getattr(store, "read_verified", None))
        and callable(getattr(store, "put_verified", None))
    ):
        raise ContractError("invalid_schema")
    plan = _wire(ExecutionPlan, plan_bytes, _bootstrap(len(plan_bytes)))
    attempt = _wire(StageAttempt, attempt_bytes, _bootstrap(len(attempt_bytes)))
    if (
        attempt.project_id != plan.project_id
        or attempt.plan_id != plan.plan_id
        or attempt.operation_key != plan.operation_key
        or attempt.state not in {"dispatching", "running"}
    ):
        raise ContractError("forbidden")
    grant_expiry = _checked_grants(grants, plan, attempt, plan_bytes)

    bounds = _Deadline(clock, min(grant_expiry, plan.expires_at, plan.budget.valid_until))
    started = bounds.check()  # entry: an expired envelope stops here, before any store access
    bounds.tighten(_format(_parse(started) + timedelta(seconds=plan.resources.max_wall_seconds)))
    context = AccessContext(plan.project_id, attempt.attempt_id, _WORKER_SCOPES)
    memory_bytes = plan.resources.memory_mib * 1024 * 1024
    transferred = 0

    def read(ref: Ref, schema: str, ceiling: int) -> bytes:
        nonlocal transferred
        if ref.project_id != plan.project_id or ref.artifact_schema != schema:
            raise ContractError("forbidden")
        if ref.size_bytes > ceiling:
            raise ContractError("limit_exceeded")
        bounds.check()
        try:
            value = store.read_verified(ref, context, ceiling)
        except ContractError:
            raise
        except Exception:
            raise ContractError("unavailable") from None
        raw = value.data if type(value) is VerifiedBytes else None
        if (
            type(raw) is not bytes
            or len(raw) != ref.size_bytes
            or hashlib.sha256(raw).hexdigest() != ref.digest
        ):
            raise ContractError("hash_mismatch")
        transferred += len(raw)
        return raw

    def write(ref: Ref, raw: bytes, *, checked: bool = False) -> None:
        nonlocal transferred
        if not checked:
            bounds.check()
        try:
            written = store.put_verified(io.BytesIO(raw), ref, context)
        except ContractError:
            raise
        except Exception:
            raise ContractError("unavailable") from None
        if written != ref:
            raise ContractError("hash_mismatch")
        transferred += len(raw)

    # Pinned inputs. The limits are known only after the recipe names them, so the
    # first two reads are bounded by the approved output ceiling of the plan.
    pinned = plan.resources.max_output_bytes
    spec_raw = read(plan.extraction_spec_ref, "kf.extraction-spec.v1", pinned)
    spec = _wire(ExtractionSpec, spec_raw, _bootstrap(len(spec_raw)))
    if spec.limits_ref.digest not in {ref.digest for ref in plan.limits_refs}:
        raise ContractError("forbidden")
    limits_raw = read(spec.limits_ref, "kf.contract-limits.v1", pinned)
    limits = _wire(ContractLimits, limits_raw, _bootstrap(len(limits_raw)))
    if _wire(ExecutionPlan, plan_bytes, limits) != plan:
        raise ContractError("hash_mismatch")
    if _wire(StageAttempt, attempt_bytes, limits) != attempt:
        raise ContractError("hash_mismatch")

    report_raw = read(plan.admission_report_ref, "kf.admission-report.v1", limits.max_json_bytes)
    report = _wire(AdmissionReport, report_raw, limits)
    (source_ref,) = plan.input_refs
    rows = [
        entry
        for entry in report.entries
        if entry.status == "admitted"
        and entry.snapshot_ref is not None
        and _identity(entry.snapshot_ref) == _identity(source_ref)
    ]
    if len(rows) != 1:
        raise ContractError("forbidden")
    row = rows[0]

    ceiling = min(plan.resources.max_output_bytes, limits.max_output_bytes)
    if source_ref.size_bytes * _WORKING_COPIES > memory_bytes:
        raise ContractError("limit_exceeded")
    source = read(source_ref, "kf.raw-original.v1", limits.max_source_bytes)
    asset = SourceAsset(
        schema_version="kf.source-asset.v1",
        project_id=plan.project_id,
        asset_id=row.asset_id,
        source_id=row.source_id,
        original_ref=source_ref,
        admission_report_ref=plan.admission_report_ref,
        metadata={},
    )

    def manifest_for(
        outputs: tuple[Ref, ...],
        errors: tuple[Reason, ...],
        revision_ref: Ref | None,
        quality_ref: Ref | None,
        completed_at: Instant,
        wall: str,
        moved: int,
    ) -> ResultManifest:
        return ResultManifest(
            schema_version="kf.result.v1",
            project_id=plan.project_id,
            plan_id=plan.plan_id,
            operation_key=plan.operation_key,
            attempt_id=attempt.attempt_id,
            input_digests=(source_ref.digest,),
            status="failed" if errors else "succeeded",
            outputs=outputs,
            errors=errors,
            usage=ResourceUsage(
                wall_seconds=wall,
                transfer_bytes=moved,
                provider_request_ids=(),
                cost_status="unknown",
                tariff_ref=plan.budget.tariff_ref,
            ),
            completed_at=completed_at,
            **({"document_revision_ref": revision_ref} if revision_ref is not None else {}),
            **({"quality_report_ref": quality_ref} if quality_ref is not None else {}),
        )

    # The widest wall string the deadline allows, so the ceiling check is an upper bound.
    widest_wall = f"{plan.resources.max_wall_seconds}.999"

    def projected(
        outputs: tuple[Ref, ...],
        errors: tuple[Reason, ...],
        revision_ref: Ref | None,
        quality_ref: Ref | None,
        written: int,
    ) -> None:
        """Refuse before the first write if outputs plus the manifest cannot fit.

        The manifest reports the bytes moved by the time it is written, so it is projected with
        the bytes about to be written already counted: the count may gain a digit by then.
        """
        size = len(
            _encode(
                manifest_for(
                    outputs,
                    errors,
                    revision_ref,
                    quality_ref,
                    started,
                    widest_wall,
                    transferred + written,
                ),
                limits,
            )
        )
        if written + size > ceiling:
            raise ContractError("limit_exceeded")

    def conclude(
        outputs: tuple[Ref, ...],
        errors: tuple[Reason, ...],
        revision_ref: Ref | None,
        quality_ref: Ref | None,
    ) -> Ref:
        completed = bounds.check()
        manifest = manifest_for(
            outputs,
            errors,
            revision_ref,
            quality_ref,
            completed,
            _quantity(_parse(completed) - _parse(started)),
            transferred,
        )
        raw = _encode(manifest, limits)
        manifest_ref = _ref(plan.project_id, raw, "kf.result.v1", _ARTIFACT_MEDIA)
        write(manifest_ref, raw, checked=True)  # strictly last: it names only verified outputs
        return manifest_ref

    try:
        output = process_text(
            asset,
            VerifiedBytes(source, hashlib.sha256(source).hexdigest()),
            spec,
            limits=limits,
            limits_bytes=limits_raw,
        )
    except ContractError as error:
        if error.code not in _CONTENT_FAILURES:
            raise
        verdict = (Reason.model_validate({"code": error.code, "message": error.code}),)
        projected((), verdict, None, None, 0)
        return conclude((), verdict, None, None)

    text_ref = _ref(plan.project_id, output.text, "kf.canonical-text.v1", "text/plain")
    origin_raw = _encode(output.origin_map, limits)
    origin_ref = _ref(plan.project_id, origin_raw, "kf.origin-map.v1", _ARTIFACT_MEDIA)
    quality_raw = _encode(output.quality, limits)
    quality_ref = _ref(plan.project_id, quality_raw, "kf.quality-report.v1", _ARTIFACT_MEDIA)
    revision = DocumentRevision(
        schema_version="kf.document-revision.v1",
        project_id=plan.project_id,
        source_id=row.source_id,
        asset_id=row.asset_id,
        revision_id=revision_id(
            RevisionInputs(
                plan.project_id,
                row.source_id,
                source_ref.digest,
                text_ref.digest,
                plan.extraction_spec_ref.digest,
                structure_digest(output.sections, limits=limits),
                origin_ref.digest,
            ),
            limits=limits,
        ),
        original_ref=source_ref,
        text_ref=text_ref,
        extraction_spec_ref=plan.extraction_spec_ref,
        text_encoding="utf-8",
        offset_unit="unicode_scalar",
        sections=output.sections,
        origin_map_ref=origin_ref,
        quality_report_ref=quality_ref,
    )
    revision_raw = _encode(revision, limits)
    revision_ref = _ref(plan.project_id, revision_raw, "kf.document-revision.v1", _ARTIFACT_MEDIA)
    parts = (
        (text_ref, output.text),
        (origin_ref, origin_raw),
        (quality_ref, quality_raw),
        (revision_ref, revision_raw),
    )
    outputs = tuple(ref for ref, _ in parts)
    projected(outputs, (), revision_ref, quality_ref, sum(len(raw) for _, raw in parts))
    for ref, raw in parts:
        write(ref, raw)
    return conclude(outputs, (), revision_ref, quality_ref)
