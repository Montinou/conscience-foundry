"""Test-only deterministic enrichment transport, editorial verdicts and ledger seeding.

The fakes supply scripted responses, scripted faults and deterministic editorial verdicts only.
They own no counters and no acceptance policy: the allowance mechanism, D05 accounting, the T1
codec, the T9 exact-anchor checker and the C08 validators enforce every outcome under test.
Nothing here loads a model, provider, Graph or Laya package, and nothing opens a network socket.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import uuid4

from psycopg import sql
from psycopg.types.json import Jsonb
from pydantic import BeforeValidator, Field
from pydantic.json_schema import SkipJsonSchema

from conscience_foundry.contracts.canonical import DocumentRevision, DocumentSpan
from conscience_foundry.contracts.codec import hash_jcs
from conscience_foundry.contracts.common import (
    ContractError,
    ContractLimits,
    Digest,
    Id,
    Reason,
    Ref,
    SafeInteger,
    ScalarString,
    WireModel,
)
from conscience_foundry.contracts.extensions import (
    EnrichmentRequest,
    EnrichmentResult,
    EnrichmentSpec,
    EnrichmentValidationContext,
    correlate_enrichment,
)
from conscience_foundry.core.spans import check_exact_quote
from conscience_foundry.execution.allowance import (
    AllowanceContext,
    CallEvent,
    CallState,
    advance_allowance,
)
from conscience_foundry.ledger.db import Ledger, register_admission
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.local import VerifiedBytes

# Reuse the reviewed synthetic admission builder of the ledger integration tests.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
from test_ledger_db import (  # noqa: E402
    ACTOR,
    ASSET,
    PROJECT,
    SOURCE,
    TIME,
    admission,
)

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "public" / "extension_cases.json"
CASES = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
NOW = "2026-10-26T00:00:00.000Z"
TEST_OPERATION_DOMAIN = "test.enrichment-operation.v1"
ENRICH_ACCESS = AccessContext(PROJECT, ACTOR, frozenset({"enrich"}))


def operation_key_for(label: str = "synthetic.enrichment") -> Digest:
    """Synthetic generic key: deliberately not an F1Operation projection."""
    return hash_jcs(
        TEST_OPERATION_DOMAIN, {"projectId": PROJECT, "assetId": ASSET, "task": label}
    )


def contract_limits() -> ContractLimits:
    return ContractLimits.model_validate(
        {
            "schemaVersion": "kf.contract-limits.v1",
            "version": "synthetic.acceptance.v1",
            "maxJsonBytes": 65536,
            "maxStringScalars": 1024,
            "maxArrayItems": 64,
            "maxDepth": 16,
            "maxManifestItems": 8,
            "maxSourceBytes": 65536,
            "maxOutputBytes": 65536,
            "maxErrorMessageScalars": 120,
        }
    )


# --------------------------------------------------------------------------- scripted transport


class TransportRefused(Exception):
    """Scripted fault: the connection was refused before any request left the process."""


class TransportLost(Exception):
    """Scripted fault: the request may have been accepted but no response ever arrived."""


@dataclass(frozen=True)
class ScriptedResponse:
    raw: bytes
    provider_request_id: str | None


class FakeEnrichmentTransport:
    """Pops one scripted step per send; it never counts, limits or judges anything."""

    def __init__(
        self,
        script: Sequence[Mapping[str, Any]],
        on_send: Callable[[str], None] | None = None,
    ) -> None:
        self._script = list(script)
        self._on_send = on_send
        self.sent: list[tuple[str, str]] = []

    def send(self, call_id: str, request_digest: str) -> ScriptedResponse:
        self.sent.append((call_id, request_digest))
        if self._on_send is not None:
            self._on_send(call_id)
        step = self._script.pop(0)
        if step["kind"] == "lost":
            raise TransportLost
        if step["kind"] == "fault":
            raise TransportRefused
        if "raw" in step:
            body = step["raw"].encode("utf-8")
        else:
            body = json.dumps(step["json"], ensure_ascii=False).encode("utf-8")
        return ScriptedResponse(body, step.get("providerRequestId"))


class DeterministicEditorialReview:
    """Injected editorial verdicts keyed by claim; unknown claims stay insufficient."""

    def __init__(self, verdicts: Mapping[str, str]) -> None:
        self._verdicts = dict(verdicts)

    def judge(
        self, quote: str, claim: str
    ) -> Literal["supported", "disputed", "insufficient_context"]:
        verdict = self._verdicts.get(claim)
        if verdict == "supported":
            return "supported"
        if verdict == "disputed":
            return "disputed"
        return "insufficient_context"


# --------------------------------------------------------------------------- candidate payload


def _array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class AnnotationRange(WireModel):
    revision_id: Digest
    start: SafeInteger
    end: SafeInteger


class CandidateAnnotation(WireModel):
    quote: Annotated[ScalarString, Field(min_length=1)]
    claim: Annotated[ScalarString, Field(min_length=1)]
    range: AnnotationRange | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )


class CandidateAnnotations(WireModel):
    schema_version: Literal["synthetic.candidate-annotations.v1"]
    annotations: Annotated[
        tuple[CandidateAnnotation, ...], BeforeValidator(_array), Field(min_length=1)
    ]


# --------------------------------------------------------------------------- evaluation harness


def _ref(schema: str, data: bytes | None = None, media: str = "application/json") -> Ref:
    body = data if data is not None else schema.encode()
    return Ref.model_validate(
        {
            "schemaVersion": "kf.artifact-ref.v1",
            "projectId": PROJECT,
            "digest": hashlib.sha256(body).hexdigest(),
            "sizeBytes": len(body),
            "mediaType": media,
            "artifactSchema": schema,
            "locations": [],
        }
    )


@dataclass(frozen=True)
class Evaluation:
    result: EnrichmentResult
    context: EnrichmentValidationContext
    outcome: Literal["known", "unknown"]
    reason_code: str | None


class EnrichmentHarness:
    """Binds one synthetic request to real production validators.

    The statuses below are produced by the T1 codec, the T9 exact-anchor checker and the injected
    editorial verdict, then re-checked by the real C08 correlation validators. No status is read
    from the scripted response.
    """

    def __init__(
        self,
        *,
        operation_key: Digest,
        attempt_id: Id,
        reservation_id: Id,
        review: DeterministicEditorialReview | None = None,
    ) -> None:
        self.limits = contract_limits()
        self.text: str = CASES["text"]
        self.text_bytes = self.text.encode("utf-8")
        self.revision_id: str = CASES["revisionId"]
        self.review = review or DeterministicEditorialReview(CASES["verdicts"])
        text_ref = _ref("kf.canonical-text.v1", self.text_bytes, "text/plain")
        self.revision = DocumentRevision.model_validate(
            {
                "schemaVersion": "kf.document-revision.v1",
                "projectId": PROJECT,
                "sourceId": SOURCE,
                "assetId": ASSET,
                "revisionId": self.revision_id,
                "originalRef": _ref("kf.raw-original.v1", self.text_bytes, "text/plain"),
                "textRef": text_ref,
                "extractionSpecRef": _ref("kf.extraction-spec.v1"),
                "textEncoding": "utf-8",
                "offsetUnit": "unicode_scalar",
                "sections": [{"sectionId": "body", "start": 0, "end": len(self.text)}],
                "originMapRef": _ref("kf.origin-map.v1"),
                "qualityReportRef": _ref("kf.quality-report.v1"),
            }
        )
        self.spec = EnrichmentSpec.model_validate(
            {
                "schemaVersion": "kf.enrichment-spec.v1",
                "specId": "synthetic.v1",
                "taskId": "synthetic.annotation",
                "profileId": "technical_minimal",
                "profileVersion": "v1",
                "inputSchemaRef": _ref("json-schema.2020-12"),
                "outputSchemaRef": _ref("json-schema.2020-12"),
                "promptRef": _ref("synthetic.prompt.v1"),
                "contextPolicyRef": _ref("synthetic.context-policy.v1"),
                "modelRouteRef": _ref("synthetic.route.v1"),
                "generationSettingsRef": _ref("synthetic.generation.v1"),
                "validationPolicyRef": _ref("synthetic.validation-policy.v1"),
                "reviewPolicyRef": _ref("synthetic.review-policy.v1"),
                "executionLimitsRef": _ref("synthetic.execution-limits.v1"),
                "runtimeRef": _ref("synthetic.runtime.v1"),
            }
        )
        self.operation_key = operation_key
        self.attempt_id = attempt_id
        self.reservation_id = reservation_id
        self.request = EnrichmentRequest.model_validate(
            {
                "schemaVersion": "kf.enrichment-request.v1",
                "projectId": PROJECT,
                "operationKey": operation_key,
                "attemptId": attempt_id,
                "specRef": _ref("kf.enrichment-spec.v1"),
                "policyRef": _ref("kf.policy.v1"),
                "canonicalRevisionRefs": [_ref("kf.document-revision.v1")],
                "contextSpans": [],
                "omittedContextRefs": [],
                "inputRef": _ref("synthetic.payload.v1"),
                "reservationId": reservation_id,
                "deadline": "2026-10-26T01:00:00.000Z",
            }
        )
        self.request_bytes = self.request.model_dump_json(by_alias=True).encode("utf-8")
        self.request_digest = hashlib.sha256(self.request_bytes).hexdigest()

    def span_for(self, start: int, end: int, revision_id: str) -> DocumentSpan:
        return DocumentSpan.model_validate(
            {
                "schemaVersion": "kf.document-span.v1",
                "projectId": PROJECT,
                "sourceId": SOURCE,
                "revisionId": revision_id,
                "sectionId": "body",
                "start": start,
                "end": end,
                "offsetUnit": "unicode_scalar",
            }
        )

    def _occurrences(self, quote: str) -> list[int]:
        found: list[int] = []
        position = self.text.find(quote)
        while position != -1:
            found.append(position)
            position = self.text.find(quote, position + 1)
        return found

    def _anchor(self, annotation: CandidateAnnotation) -> None:
        """Exact evidence through the production checker; a bare repeated quote is ambiguous."""
        if annotation.range is None:
            occurrences = self._occurrences(annotation.quote)
            if len(occurrences) != 1:
                raise ContractError("invalid_span")
            start = occurrences[0]
            span = self.span_for(start, start + len(annotation.quote), self.revision_id)
        else:
            if annotation.range.start >= annotation.range.end:
                raise ContractError("invalid_span")
            span = self.span_for(
                annotation.range.start, annotation.range.end, annotation.range.revision_id
            )
        check_exact_quote(
            VerifiedBytes(self.text_bytes, hashlib.sha256(self.text_bytes).hexdigest()),
            span,
            annotation.quote,
            revision=self.revision,
            limits=self.limits,
        )

    def evaluate(self, response: ScriptedResponse | None) -> Evaluation:
        reason: Reason | None = None
        raw_ref: Ref | None = None
        candidate_ref: Ref | None = None
        outcome: Literal["known", "unknown"] = "known"
        if response is None:
            outcome = "unknown"
            schema, anchor, semantic, disposition = "not_run", "not_run", "pending", "needs_review"
            reason = Reason(code="result_incomplete", message="No response was received")
        else:
            raw_ref = _ref("synthetic.raw-response.v1", response.raw)
            try:
                parsed = CandidateAnnotations.from_wire(response.raw, self.limits)
            except ContractError as error:
                schema, anchor, semantic, disposition = "invalid", "not_run", "pending", "rejected"
                reason = Reason(code=error.code, message="Response failed the schema check")  # type: ignore[arg-type]
            else:
                schema = "valid"
                candidate_ref = _ref("kf.annotation-set.v1", response.raw)
                try:
                    for annotation in parsed.annotations:
                        self._anchor(annotation)
                except ContractError as error:
                    anchor, semantic, disposition = "invalid", "pending", "rejected"
                    reason = Reason(code=error.code, message="Exact evidence check failed")  # type: ignore[arg-type]
                else:
                    anchor = "valid"
                    verdicts = [
                        self.review.judge(item.quote, item.claim) for item in parsed.annotations
                    ]
                    if all(item == "supported" for item in verdicts):
                        semantic, disposition = "supported", "accepted"
                    elif "disputed" in verdicts:
                        semantic, disposition = "disputed", "needs_review"
                    else:
                        semantic, disposition = "insufficient_context", "needs_review"
        result = EnrichmentResult.model_validate(
            {
                "schemaVersion": "kf.enrichment-result.v1",
                "projectId": PROJECT,
                "operationKey": self.operation_key,
                "attemptId": self.attempt_id,
                "specRef": self.request.spec_ref,
                **({"rawResponseRef": raw_ref} if raw_ref is not None else {}),
                **({"candidateAnnotationsRef": candidate_ref} if candidate_ref is not None else {}),
                "schemaStatus": schema,
                "anchorStatus": anchor,
                "semanticStatus": semantic,
                "disposition": disposition,
                "validationReportRef": _ref("synthetic.validation-report.v1"),
                "attemptReportRef": _ref("synthetic.attempt-report.v1"),
                "reasons": [reason] if reason is not None else [],
            }
        )
        context = EnrichmentValidationContext(
            request_digest=self.request_digest,
            project_id=PROJECT,
            operation_key=self.operation_key,
            attempt_id=self.attempt_id,
            spec_ref=self.request.spec_ref,
            validation_policy_ref=self.spec.validation_policy_ref,
            review_policy_ref=self.spec.review_policy_ref,
            anchors_applicable=True,
            attributed_claims=True,
            inference_allowed=False,
            expected_schema_status=schema,  # type: ignore[arg-type]
            expected_anchor_status=anchor,  # type: ignore[arg-type]
            expected_semantic_status=semantic,  # type: ignore[arg-type]
            expected_disposition=disposition,  # type: ignore[arg-type]
        )
        return Evaluation(result, context, outcome, reason.code if reason is not None else None)

    def correlate(self, result: EnrichmentResult, context: EnrichmentValidationContext) -> None:
        correlate_enrichment(
            self.request,
            result,
            request_bytes=self.request_bytes,
            limits=self.limits,
            spec=self.spec,
            context=context,
        )


# --------------------------------------------------------------------------- ledger seeding


@dataclass(frozen=True)
class SeededScope:
    project_id: str
    run_id: str
    operation_key: str
    attempt_id: str
    reservation_id: str


def seed_admitted_scope(
    ledger: Ledger, *, run_id: str, operation_key: str, reserved_usd: str = "4"
) -> SeededScope:
    """Trusted test setup: production admission registration, then generic ledger rows.

    The operation key is a synthetic `test.enrichment-operation.v1` digest, never an F1Operation;
    the reservation/attempt rows model one already-funded D05 attempt. No public CLI can do this.
    """
    data = admission()
    authorization_id, plan_id, reservation_id, attempt_id = (str(uuid4()) for _ in range(4))
    with ledger.transaction() as tx:
        register_admission(
            data.manifest_ref, data.report, data.report_ref, tx, evidence=data.evidence
        )
        tx.create_run(PROJECT, run_id, data.report_ref.digest)
        tx.lock(PROJECT, run_id)
        connection = tx.connection
        connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,operation_key,asset_id) VALUES (%s,%s,%s) "
                "ON CONFLICT DO NOTHING"
            ).format(tx.table("operations")),
            (PROJECT, operation_key, ASSET),
        )
        connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,authorization_id,run_id,authorization_ref,"
                "allowed_plan_digests,max_run_cost,max_concurrent_attempts,actor_id,"
                "authorized_at,expires_at) VALUES (%s,%s,%s,%s,%s,10,3,%s,%s,%s)"
            ).format(tx.table("authorizations")),
            (
                PROJECT,
                authorization_id,
                run_id,
                Jsonb({}),
                [],
                ACTOR,
                TIME,
                "2026-10-27T00:00:00.000Z",
            ),
        )
        connection.execute(
            sql.SQL(
                "UPDATE {} SET current_authorization_id=%s,max_run_cost=10,"
                "max_concurrent_attempts=3 WHERE project_id=%s AND run_id=%s"
            ).format(tx.table("runs")),
            (authorization_id, PROJECT, run_id),
        )
        connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,plan_id,run_id,plan_digest,plan_ref,"
                "authorization_id,operation_key) VALUES (%s,%s,%s,%s,%s,%s,%s)"
            ).format(tx.table("plans")),
            (
                PROJECT,
                plan_id,
                run_id,
                hashlib.sha256(plan_id.encode()).hexdigest(),
                Jsonb({}),
                authorization_id,
                operation_key,
            ),
        )
        connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,reservation_id,run_id,authorization_id,operation_key,"
                "scope,reserved_usd,outstanding_usd,settled_usd,evidence_ref) "
                "VALUES (%s,%s,%s,%s,%s,'attempt',%s,%s,0,%s)"
            ).format(tx.table("reservations")),
            (
                PROJECT,
                reservation_id,
                run_id,
                authorization_id,
                operation_key,
                reserved_usd,
                reserved_usd,
                Jsonb({}),
            ),
        )
        number = connection.execute(
            sql.SQL(
                "SELECT coalesce(max(attempt_number),0)+1 FROM {} "
                "WHERE project_id=%s AND operation_key=%s"
            ).format(tx.table("attempts")),
            (PROJECT, operation_key),
        ).fetchone()
        assert number is not None
        connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,attempt_id,run_id,plan_id,operation_key,"
                "attempt_number,reservation_id,state,created_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,'running',%s)"
            ).format(tx.table("attempts")),
            (PROJECT, attempt_id, run_id, plan_id, operation_key, number[0], reservation_id, TIME),
        )
    return SeededScope(PROJECT, run_id, operation_key, attempt_id, reservation_id)


def allowance_context(seeded: SeededScope, request_digest: str) -> AllowanceContext:
    return AllowanceContext(
        seeded.project_id,
        seeded.run_id,
        seeded.operation_key,
        seeded.attempt_id,
        seeded.reservation_id,
        request_digest,
    )


# --------------------------------------------------------------------------- test coordinator


@dataclass(frozen=True)
class Submission:
    call_id: str
    response: ScriptedResponse | None
    outcome: Literal["known", "unknown"]
    reserved: CallState
    settled: CallState


def submit(
    ledger: Ledger,
    transport: FakeEnrichmentTransport,
    scope: AllowanceContext,
    kind: Literal["request", "repair", "transport"],
    *,
    now: str = NOW,
    input_tokens: int = 10,
    output_tokens: int = 10,
    context_scalars: int = 5,
    access: AccessContext = ENRICH_ACCESS,
) -> Submission:
    """Reserve through the production allowance, then perform the scripted effect, then settle.

    The ordering is the property under test: the effect is only attempted after the production
    reservation committed, and the outcome (including a lost one) is recorded under the same
    local call identity.
    """
    call_id = str(uuid4())
    reserved = advance_allowance(
        CallEvent(
            event_id=str(uuid4()),
            call_id=call_id,
            context=scope,
            kind=kind,
            external_request_id=None,
            reserved_input_tokens=input_tokens,
            reserved_output_tokens=output_tokens,
            context_scalars=context_scalars,
            outcome="pending",
        ),
        access,
        ledger,
        now,
    )
    response: ScriptedResponse | None = None
    outcome: Literal["known", "unknown"] = "known"
    try:
        response = transport.send(call_id, scope.request_digest)
    except TransportRefused:
        outcome = "known"
    except TransportLost:
        outcome = "unknown"
    settled = advance_allowance(
        CallEvent(
            event_id=str(uuid4()),
            call_id=call_id,
            context=scope,
            kind="outcome",
            external_request_id=response.provider_request_id if response is not None else None,
            reserved_input_tokens=0,
            reserved_output_tokens=0,
            context_scalars=0,
            outcome=outcome,
        ),
        access,
        ledger,
        now,
    )
    return Submission(call_id, response, outcome, reserved, settled)
