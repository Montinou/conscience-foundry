"""Bounded durable evidence resolution, separate from provider authenticity."""

from __future__ import annotations

import hashlib
import io
from dataclasses import replace
from decimal import Decimal, localcontext
from typing import Any

from psycopg import sql
from pydantic import TypeAdapter, ValidationError

from conscience_foundry.contracts.accounting import BillingAdjustment, BudgetEvent
from conscience_foundry.contracts.admission import AdmissionReport, IntakeManifest, SourceAsset
from conscience_foundry.contracts.canonical import ExtractionSpec
from conscience_foundry.contracts.codec import load_json
from conscience_foundry.contracts.common import (
    ArtifactLocation,
    ContractError,
    ContractLimits,
    Id,
    Instant,
    Money,
    Reason,
    Ref,
    WireModel,
)
from conscience_foundry.contracts.execution import ExecutionConfig, ExecutionPlan, RunAuthorization
from conscience_foundry.contracts.project import PolicyArtifact
from conscience_foundry.contracts.registry import registered_schema_ids, validate_artifact
from conscience_foundry.core.identity import F1Operation, operation_key
from conscience_foundry.execution.ports import (
    BillingFacts,
    BudgetProof,
    CapabilityFacts,
    ControlContext,
    ControlFacts,
    ControlProof,
    CostAllocation,
    EstimateFacts,
    EvidenceBinding,
    GrantFacts,
    VerifiedPlan,
)
from conscience_foundry.ledger.budget import BudgetContext, BudgetEvidenceClaim
from conscience_foundry.ledger.db import AdmissionRegistrationEvidence, LedgerTxn
from conscience_foundry.policy.access import AccessContext, require_permission


def limits_for(control: ControlContext, schema: str) -> ContractLimits:
    value = control.limits_by_schema.get(schema)
    if type(value) is not ContractLimits:
        raise ContractError("limits_missing")
    try:
        return ContractLimits.model_validate(value.model_dump())
    except ValidationError:
        raise ContractError("limits_missing") from None


def clock(control: ControlContext) -> Instant:
    if type(control) is not ControlContext or type(control.access) is not AccessContext:
        raise ContractError("forbidden")
    try:
        value = control.clock()
        if type(value) is not str:
            raise ValueError
        return TypeAdapter(Instant).validate_python(value)
    except Exception:
        raise ContractError("unavailable") from None


def authorize(control: ControlContext, action: str, project: Id, run: Id | None) -> None:
    clock(control)
    if project != control.access.project_id:
        raise ContractError("forbidden")
    try:
        allowed = control.authorize(action, project, run, control.access.actor_id)
    except Exception:
        raise ContractError("forbidden") from None
    if allowed is not True:
        raise ContractError("forbidden")


def current_policy(control: ControlContext, project: Id) -> PolicyArtifact:
    if project != control.access.project_id:
        raise ContractError("forbidden")
    try:
        value = control.current_policy(project)
        if type(value) is not PolicyArtifact:
            raise ValueError
        value = PolicyArtifact.from_wire(encoded(value), limits_for(control, "kf.policy.v1"))
    except ContractError:
        raise
    except Exception:
        raise ContractError("permission_unknown") from None
    if value.project_id != project or value.effective_at > clock(control):
        raise ContractError("permission_unknown")
    return value


def identity(ref: Ref) -> tuple[object, ...]:
    return ref.project_id, ref.artifact_schema, ref.digest, ref.size_bytes, ref.media_type


def encoded(value: WireModel) -> bytes:
    return value.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8")


def bounded_request(value: object, control: ControlContext) -> bytes:
    """Bound internal decisions with the installed finite control-record limits."""
    import json

    bound = limits_for(control, "kf.stage-attempt.v1")
    size, pieces = 0, []
    try:
        for piece in json.JSONEncoder(
            ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False
        ).iterencode(value):
            raw = piece.encode("utf-8")
            size += len(raw)
            if size > min(bound.max_json_bytes, bound.max_output_bytes):
                raise ContractError("limit_exceeded")
            pieces.append(raw)
        data = b"".join(pieces)
        load_json(data, bound)
        return data
    except ContractError:
        raise
    except (ValueError, TypeError, UnicodeError):
        raise ContractError("invalid_schema") from None


def read_artifact(
    ref: Ref, control: ControlContext, *, evidence: bool = False
) -> tuple[bytes, Any]:
    if type(ref) is not Ref or ref.project_id != control.access.project_id:
        raise ContractError("forbidden")
    try:
        Ref.model_validate(ref.model_dump())
    except ValidationError:
        raise ContractError("invalid_schema") from None
    known = ref.artifact_schema in registered_schema_ids()
    if not known and (
        not evidence or ref.artifact_schema not in control.evidence_authority.decoders
    ):
        raise ContractError("unsupported_schema")
    bound = limits_for(control, ref.artifact_schema)
    ceiling = (
        bound.max_source_bytes
        if ref.artifact_schema == "kf.raw-original.v1"
        else min(bound.max_output_bytes, bound.max_json_bytes)
    )
    if ref.size_bytes > ceiling:
        raise ContractError("limit_exceeded")
    value = control.store.read_verified(ref, control.access, ceiling)
    raw = value.data
    if (
        type(raw) is not bytes
        or len(raw) != ref.size_bytes
        or hashlib.sha256(raw).hexdigest() != ref.digest
        or value.digest != ref.digest
    ):
        raise ContractError("hash_mismatch")
    if known:
        return raw, validate_artifact(ref, raw, limits_by_schema=control.limits_by_schema)
    try:
        decoded = control.evidence_authority.decoders[ref.artifact_schema](raw, bound)
    except Exception:
        raise ContractError("unsupported_schema") from None
    if decoded is None or type(decoded) is bool:
        raise ContractError("unsupported_schema")
    return raw, decoded


def read_model[Model: WireModel](
    ref: Ref, model: type[Model], control: ControlContext
) -> tuple[bytes, Model]:
    raw, value = read_artifact(ref, control)
    if type(value) is not model:
        raise ContractError("unsupported_schema")
    return raw, value


def put_record(record: WireModel, control: ControlContext) -> Ref:
    raw = encoded(record)
    schema = record.model_dump(by_alias=True).get("schemaVersion")
    if type(schema) is not str:
        raise ContractError("unsupported_schema")
    ref = Ref(
        schema_version="kf.artifact-ref.v1",
        project_id=control.access.project_id,
        digest=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        media_type="application/json",
        artifact_schema=schema,
        locations=(
            ArtifactLocation(
                store_id=control.output_store_id,
                object_key="sha256/"
                + hashlib.sha256(raw).hexdigest()[:2]
                + "/"
                + hashlib.sha256(raw).hexdigest(),
            ),
        ),
    )
    validate_artifact(ref, raw, limits_by_schema=control.limits_by_schema)
    control.store.put_verified(io.BytesIO(raw), ref, control.access)
    return ref


def checked_reason(reason: Reason, control: ControlContext) -> Reason:
    if type(reason) is not Reason:
        raise ContractError("invalid_schema")
    raw = encoded(reason)
    return Reason.from_wire(raw, limits_for(control, "kf.stage-attempt.v1"))


def money(value: object, control: ControlContext) -> Decimal:
    if type(value) is not str:
        raise ContractError("invalid_schema")
    if len(value) > limits_for(control, "kf.budget-event.v1").max_string_scalars:
        raise ContractError("limit_exceeded")
    try:
        return Decimal(TypeAdapter(Money).validate_python(value))
    except (ValueError, ValidationError):
        raise ContractError("invalid_schema") from None


def check_binding(actual: EvidenceBinding, expected: EvidenceBinding) -> None:
    if type(actual) is not EvidenceBinding or actual != expected:
        raise ContractError("forbidden")
    for value in (
        actual.evidence_digest,
        actual.request_digest,
        actual.project_id,
        actual.run_id,
        actual.reservation_id,
        actual.attempt_id,
        actual.authorization_digest,
        actual.plan_digest,
    ):
        if value is not None and type(value) is not str:
            raise ContractError("forbidden")


def control_facts(
    control: ControlContext,
    action: str,
    run: Id | None,
    evidence_ref: Ref,
    request_bytes: bytes,
    *,
    reservation: Id | None = None,
    attempt: Id | None = None,
    authorization_ref: Ref | None = None,
    plan_ref: Ref | None = None,
    snapshot: str | None = None,
) -> ControlFacts:
    authorize(control, action, control.access.project_id, run)
    raw, _ = read_artifact(evidence_ref, control, evidence=True)
    binding = EvidenceBinding(
        evidence_ref.digest,
        hashlib.sha256(request_bytes).hexdigest(),
        control.access.project_id,
        run,
        reservation,
        attempt,
        authorization_ref.digest if authorization_ref else None,
        plan_ref.digest if plan_ref else None,
    )
    proof = ControlProof(
        binding,
        evidence_ref,
        raw,
        request_bytes,
        control.access.actor_id,
        action,
        snapshot,
        clock(control),
    )
    try:
        facts = control.evidence_authority.control(proof)
    except Exception:
        raise ContractError("forbidden") from None
    if type(facts) is not ControlFacts:
        raise ContractError("forbidden")
    check_binding(facts.binding, binding)
    if (
        facts.actor_id != control.access.actor_id
        or facts.action != action
        or facts.snapshot_digest != snapshot
    ):
        raise ContractError("forbidden")
    return facts


def admission_evidence(
    plan: ExecutionPlan,
    tx: LedgerTxn,
    control: ControlContext,
) -> tuple[AdmissionRegistrationEvidence, IntakeManifest, AdmissionReport]:
    """Resolve exact historical refs from current transaction metadata, not guesses."""
    tx.lock(plan.project_id, plan.run_id)
    row = tx.connection.execute(
        sql.SQL(
            "SELECT r.report_ref,b.manifest_ref,r.policy_ref FROM {} r JOIN {} b ON "
            "(r.project_id,r.batch_id,r.manifest_digest)="
            "(b.project_id,b.batch_id,b.manifest_digest) "
            "WHERE r.project_id=%s AND r.report_digest=%s"
        ).format(tx.table("admission_reports"), tx.table("batches")),
        (plan.project_id, plan.admission_report_ref.digest),
    ).fetchone()
    if row is None:
        raise ContractError("forbidden")
    report_ref, manifest_ref, policy_ref = (Ref.model_validate(value) for value in row)
    if identity(report_ref) != identity(plan.admission_report_ref) or identity(
        policy_ref
    ) != identity(plan.policy_ref):
        raise ContractError("hash_mismatch")
    manifest_bytes, manifest = read_model(manifest_ref, IntakeManifest, control)
    # Full-report metadata permission must hold before any selected source IO.
    policy = current_policy(control, plan.project_id)
    for item in manifest.items:
        require_permission(control.access, policy, item.source_id, "auditMetadataRead")
    report_bytes, report = read_model(report_ref, AdmissionReport, control)
    policy_bytes, pinned = read_model(policy_ref, PolicyArtifact, control)
    report.validate_manifest(manifest, pinned)
    if report.manifest_digest != manifest_ref.digest or identity(manifest.policy_ref) != identity(
        policy_ref
    ):
        raise ContractError("hash_mismatch")
    return (
        AdmissionRegistrationEvidence(
            manifest_bytes, report_bytes, policy_bytes, pinned, control.limits_by_schema
        ),
        manifest,
        report,
    )


def source_asset(
    plan: ExecutionPlan,
    manifest: IntakeManifest,
    report: AdmissionReport,
    control: ControlContext,
    *,
    asset_id: Id | None = None,
) -> SourceAsset:
    candidates: list[SourceAsset] = []
    for item in manifest.items:
        entry = next((entry for entry in report.entries if entry.asset_id == item.asset_id), None)
        if (
            entry is None
            or entry.status != "admitted"
            or entry.snapshot_ref is None
            or (asset_id is not None and item.asset_id != asset_id)
        ):
            continue
        key = operation_key(
            F1Operation(
                plan.project_id,
                item.asset_id,
                item.source_id,
                (item.original_digest,),
                plan.extraction_spec_ref.digest,
                manifest.profile_id,
                manifest.profile_version,
                manifest.policy_ref.digest,
                plan.contract_set_ref.digest,
                tuple(ref.digest for ref in plan.limits_refs),
            ),
            limits=limits_for(control, "kf.execution-plan.v1"),
        )
        if key == plan.operation_key and identity(entry.snapshot_ref) == identity(
            plan.input_refs[0]
        ):
            candidates.append(
                SourceAsset(
                    schema_version="kf.source-asset.v1",
                    project_id=plan.project_id,
                    asset_id=item.asset_id,
                    source_id=item.source_id,
                    original_ref=entry.snapshot_ref,
                    admission_report_ref=plan.admission_report_ref,
                    metadata=item.metadata,
                )
            )
    if len(candidates) != 1:
        raise ContractError("forbidden")
    return candidates[0]


def verified_plan(
    plan_ref: Ref,
    authorization_ref: Ref,
    tx: LedgerTxn,
    control: ControlContext,
    *,
    spending: bool,
) -> VerifiedPlan:
    data, plan = read_model(plan_ref, ExecutionPlan, control)
    _, auth = read_model(authorization_ref, RunAuthorization, control)
    if (
        plan.project_id != auth.project_id
        or plan.run_id != auth.run_id
        or plan.budget.authorization_id != auth.authorization_id
        or plan_ref.digest not in auth.allowed_plan_digests
        or plan.admission_report_ref.digest != auth.admission_report_digest
    ):
        raise ContractError("forbidden")
    _, manifest, report = admission_evidence(plan, tx, control)
    asset = source_asset(plan, manifest, report, control)
    config_bytes, config = read_model(plan.execution_config_ref, ExecutionConfig, control)
    if identity(config.tariff_ref) != identity(plan.budget.tariff_ref):
        raise ContractError("forbidden")
    read_artifact(plan.contract_set_ref, control)
    _, spec = read_model(plan.extraction_spec_ref, ExtractionSpec, control)
    if spec.image_digest != config.image_digest:
        raise ContractError("unsupported_capability")
    if not any(identity(ref) == identity(spec.limits_ref) for ref in plan.limits_refs):
        raise ContractError("limits_missing")
    for ref in plan.limits_refs:
        read_model(ref, ContractLimits, control)
    tariff_bytes, _ = read_artifact(config.tariff_ref, control, evidence=True)
    resource_bytes, _ = read_artifact(config.resource_policy_ref, control, evidence=True)
    if spending:
        policy = current_policy(control, plan.project_id)
        for effect in ("read", "extract", "remoteTransfer"):
            require_permission(control.access, policy, asset.source_id, effect)
        if config.remote_destination_id not in policy.allowed_remote_destinations:
            raise ContractError("forbidden")
    return VerifiedPlan(
        plan_ref,
        data,
        plan,
        authorization_ref,
        auth,
        config,
        config_bytes,
        tariff_bytes,
        resource_bytes,
        asset,
    )


def _capabilities(
    facts: EstimateFacts,
    plans: tuple[VerifiedPlan, ...],
    control: ControlContext,
    *,
    at: str | None = None,
) -> None:
    if type(facts.capabilities) is not tuple or len(facts.capabilities) != len(plans):
        raise ContractError("forbidden")
    for plan, capability in zip(plans, facts.capabilities, strict=True):
        if type(capability) is not CapabilityFacts or (
            identity(capability.execution_config_ref) != identity(plan.model.execution_config_ref)
            or identity(capability.tariff_ref) != identity(plan.config.tariff_ref)
            or identity(capability.resource_policy_ref) != identity(plan.config.resource_policy_ref)
            or capability.image_digest != plan.config.image_digest
            or capability.destination_id != plan.config.remote_destination_id
            or capability.resources != plan.model.resources
        ):
            raise ContractError("unsupported_capability")
    for instant in (facts.funded_from, facts.funded_until, facts.first_upload_at):
        if instant is not None:
            TypeAdapter(Instant).validate_python(instant)
    if not facts.funded_from <= (at or clock(control)) < facts.funded_until:
        raise ContractError("authorization_expired")
    if facts.first_upload_at is not None and not (
        facts.funded_from <= facts.first_upload_at <= clock(control)
    ):
        raise ContractError("forbidden")


class BudgetVerifier:
    """A transaction-scoped resolver; use only while that transaction is active."""

    def __init__(self, control: ControlContext, tx: LedgerTxn) -> None:
        self.control, self.tx = control, tx

    def _storage_funding(
        self, claim: BudgetEvidenceClaim
    ) -> tuple[tuple[VerifiedPlan, ...], Ref, bytes]:
        c, tx = self.control, self.tx
        count = tx.connection.execute(
            sql.SQL(
                "SELECT count(*) FROM {} WHERE project_id=%s AND run_id=%s AND reservation_id=%s"
            ).format(tx.table("budget_events")),
            (claim.project_id, claim.run_id, claim.reservation_id),
        ).fetchone()
        bound = limits_for(c, "kf.budget-event.v1")
        if count is None or count[0] > bound.max_array_items:
            raise ContractError("limit_exceeded")
        entries = tx.connection.execute(
            sql.SQL(
                "SELECT record_bytes FROM {} WHERE project_id=%s AND run_id=%s "
                "AND reservation_id=%s LIMIT %s"
            ).format(tx.table("budget_events")),
            (claim.project_id, claim.run_id, claim.reservation_id, bound.max_array_items + 1),
        ).fetchall()
        reserves = [BudgetEvent.from_wire(bytes(row[0]), bound) for row in entries]
        reserves = [event for event in reserves if event.event_type == "reserve"]
        if len(reserves) != 1 or reserves[0].scope != "run_storage":
            raise ContractError("forbidden")
        reserve = reserves[0]
        request = bounded_request(
            {
                "projectId": claim.project_id,
                "runId": claim.run_id,
                "authorizationDigest": claim.authorization_ref.digest,
                "currency": "USD",
                "amountUsd": reserve.amount_usd,
            },
            c,
        )
        funding = BudgetEvidenceClaim(
            "reserve_storage",
            reserve.evidence_ref,
            claim.project_id,
            claim.run_id,
            claim.reservation_id,
            None,
            reserve.created_at,
            claim.authorization_ref,
            None,
            None,
            request,
            hashlib.sha256(request).hexdigest(),
        )
        raw, _ = read_artifact(reserve.evidence_ref, c, evidence=True)
        _, auth = read_model(claim.authorization_ref, RunAuthorization, c)
        proof = BudgetProof(funding, EvidenceBinding.from_budget(funding), raw, auth, ())
        facts = c.evidence_authority.budget(proof)
        if type(facts) is not EstimateFacts:
            raise ContractError("forbidden")
        check_binding(facts.binding, proof.binding)
        if (
            type(facts.plan_refs) is not tuple
            or not facts.plan_refs
            or len(facts.plan_refs) > bound.max_array_items
        ):
            raise ContractError("limit_exceeded")
        if len({ref.digest for ref in facts.plan_refs}) != len(facts.plan_refs) or {
            ref.digest for ref in facts.plan_refs
        } != set(auth.allowed_plan_digests):
            raise ContractError("forbidden")
        plans = tuple(
            verified_plan(ref, claim.authorization_ref, tx, c, spending=False)
            for ref in facts.plan_refs
        )
        confirmed = c.evidence_authority.budget(replace(proof, plans=plans))
        if type(confirmed) is not EstimateFacts or confirmed != facts:
            raise ContractError("forbidden")
        _capabilities(facts, plans, c, at=reserve.created_at)
        if facts.currency != "USD" or money(facts.amount_ceiling_usd, c) > money(
            reserve.amount_usd, c
        ):
            raise ContractError("forbidden")
        categories = tuple(value.category for value in facts.allocations)
        if (
            type(facts.allocations) is not tuple
            or len(categories) > 6
            or "storage" not in categories
            or len(set(categories)) != len(categories)
            or any(type(value) is not CostAllocation for value in facts.allocations)
        ):
            raise ContractError("forbidden")
        with localcontext() as arithmetic:
            arithmetic.prec = (
                sum(len(value.amount_usd) for value in facts.allocations)
                + len(facts.amount_ceiling_usd)
                + 20
            )
            total = sum((money(value.amount_usd, c) for value in facts.allocations), Decimal(0))
        if total != money(facts.amount_ceiling_usd, c):
            raise ContractError("forbidden")
        return plans, reserve.evidence_ref, raw

    def __call__(self, claim: BudgetEvidenceClaim) -> bool:
        c, tx = self.control, self.tx
        if type(claim) is not BudgetEvidenceClaim or claim.project_id != c.access.project_id:
            raise ContractError("forbidden")
        tx.table("runs")  # Explicitly enforce active transaction lifetime.
        if (
            type(claim.request_bytes) is not bytes
            or hashlib.sha256(claim.request_bytes).hexdigest() != claim.request_digest
        ):
            raise ContractError("hash_mismatch")
        authorize(c, claim.purpose, claim.project_id, claim.run_id)
        raw, _ = read_artifact(claim.evidence_ref, c, evidence=True)
        _, auth = read_model(claim.authorization_ref, RunAuthorization, c)
        if (auth.project_id, auth.run_id) != (claim.project_id, claim.run_id):
            raise ContractError("forbidden")
        request: Any
        if claim.purpose == "install_run_authorization":
            request = RunAuthorization.from_wire(
                claim.request_bytes, limits_for(c, "kf.run-authorization.v1")
            )
            if (
                request != auth
                or claim.request_bytes != read_artifact(claim.authorization_ref, c)[0]
            ):
                raise ContractError("hash_mismatch")
        elif claim.purpose == "reserve_attempt":
            request = ExecutionPlan.from_wire(
                claim.request_bytes, limits_for(c, "kf.execution-plan.v1")
            )
        elif claim.purpose == "reserve_storage":
            request = load_json(claim.request_bytes, limits_for(c, "kf.budget-event.v1"))
            if (
                type(request) is not dict
                or set(request)
                != {"projectId", "runId", "authorizationDigest", "currency", "amountUsd"}
                or request["projectId"] != claim.project_id
                or request["runId"] != claim.run_id
                or request["authorizationDigest"] != claim.authorization_ref.digest
                or request["currency"] != "USD"
            ):
                raise ContractError("forbidden")
        elif claim.purpose == "billing_adjustment":
            request = BillingAdjustment.from_wire(
                claim.request_bytes, limits_for(c, "kf.billing-adjustment.v1")
            )
        else:
            request = BudgetEvent.from_wire(
                claim.request_bytes, limits_for(c, "kf.budget-event.v1")
            )
        if isinstance(request, (BudgetEvent, BillingAdjustment)) and (
            request.project_id != claim.project_id
            or request.run_id != claim.run_id
            or request.reservation_id != claim.reservation_id
            or identity(request.evidence_ref) != identity(claim.evidence_ref)
            or (isinstance(request, BudgetEvent) and request.attempt_id != claim.attempt_id)
        ):
            raise ContractError("forbidden")
        plans: tuple[VerifiedPlan, ...] = ()
        if claim.plan_ref is not None:
            plan = verified_plan(
                claim.plan_ref,
                claim.authorization_ref,
                tx,
                c,
                spending=claim.purpose == "reserve_attempt",
            )
            if claim.execution_config_ref is not None and identity(
                claim.execution_config_ref
            ) != identity(plan.model.execution_config_ref):
                raise ContractError("forbidden")
            if claim.purpose == "reserve_attempt" and plan.data != claim.request_bytes:
                raise ContractError("hash_mismatch")
            plans = (plan,)
        elif claim.purpose == "reserve_attempt":
            raise ContractError("forbidden")
        binding = EvidenceBinding.from_budget(claim)
        funding_ref, funding_raw = None, None
        if (
            claim.plan_ref is None
            and claim.reservation_id is not None
            and claim.attempt_id is None
            and claim.purpose not in {"reserve_storage", "install_run_authorization"}
        ):
            plans, funding_ref, funding_raw = self._storage_funding(claim)
        proof = BudgetProof(claim, binding, raw, auth, plans, funding_ref, funding_raw)
        try:
            facts = c.evidence_authority.budget(proof)
        except Exception:
            raise ContractError("forbidden") from None
        if type(facts) not in {GrantFacts, EstimateFacts, BillingFacts}:
            raise ContractError("forbidden")
        check_binding(facts.binding, binding)
        if claim.purpose == "install_run_authorization":
            if type(facts) is not GrantFacts or (
                facts.approved_grant_digest != claim.authorization_ref.digest
                or facts.actor_id != auth.actor_id
                or facts.actor_id != c.access.actor_id
                or facts.previous_authorization_id != claim.expected_previous_authorization_id
            ):
                raise ContractError("forbidden")
            return True
        if claim.purpose in {"reserve_attempt", "reserve_storage", "reserve"}:
            if type(facts) is not EstimateFacts or facts.currency != "USD":
                raise ContractError("forbidden")
            if type(facts.plan_refs) is not tuple or not facts.plan_refs:
                raise ContractError("forbidden")
            if len(facts.plan_refs) > limits_for(c, "kf.execution-plan.v1").max_array_items:
                raise ContractError("limit_exceeded")
            if claim.purpose == "reserve_storage" and (
                len({ref.digest for ref in facts.plan_refs}) != len(facts.plan_refs)
                or {ref.digest for ref in facts.plan_refs} != set(auth.allowed_plan_digests)
            ):
                raise ContractError("forbidden")
            if plans and tuple(identity(p.ref) for p in plans) != tuple(
                identity(r) for r in facts.plan_refs
            ):
                raise ContractError("forbidden")
            if not plans:
                plans = tuple(
                    verified_plan(ref, claim.authorization_ref, tx, c, spending=True)
                    for ref in facts.plan_refs
                )
                final = c.evidence_authority.budget(replace(proof, plans=plans))
                if type(final) is not EstimateFacts or final != facts:
                    raise ContractError("forbidden")
            _capabilities(facts, plans, c)
            allocations = facts.allocations
            if type(allocations) is not tuple or len(allocations) > 6:
                raise ContractError("forbidden")
            categories = tuple(value.category for value in allocations)
            required = {"cpu", "ram", "runtime", "transfer", "storage", "region"}
            if (
                any(type(value) is not CostAllocation for value in allocations)
                or len(set(categories)) != len(categories)
                or set(categories) - required
                or (claim.purpose == "reserve_attempt" and set(categories) != required)
                or (claim.purpose == "reserve_storage" and "storage" not in categories)
            ):
                raise ContractError("forbidden")
            ceiling = money(facts.amount_ceiling_usd, c)
            with localcontext() as arithmetic:
                arithmetic.prec = (
                    sum(len(value.amount_usd) for value in allocations)
                    + len(facts.amount_ceiling_usd)
                    + 20
                )
                total = sum((money(value.amount_usd, c) for value in allocations), Decimal(0))
            requested = (
                request.budget.max_attempt_cost
                if isinstance(request, ExecutionPlan)
                else request.amount_usd
                if isinstance(request, BudgetEvent)
                else request["amountUsd"]
            )
            if total != ceiling or ceiling > money(requested, c):
                raise ContractError("forbidden")
            return True
        if type(facts) is not BillingFacts:
            raise ContractError("forbidden")
        if not isinstance(request, (BudgetEvent, BillingAdjustment)):
            raise ContractError("forbidden")
        amount = (
            request.revised_actual_usd
            if isinstance(request, BillingAdjustment)
            else request.amount_usd
        )
        status = "actual" if isinstance(request, BillingAdjustment) else request.cost_status
        expected_fact_amount = amount
        if claim.purpose in {"release_unspent", "final_no_effect"}:
            row = tx.connection.execute(
                sql.SQL(
                    "SELECT reserved_usd::text,released_usd::text FROM {} WHERE project_id=%s "
                    "AND run_id=%s AND reservation_id=%s"
                ).format(tx.table("reservations")),
                (claim.project_id, claim.run_id, claim.reservation_id),
            ).fetchone()
            if row is None or amount is None:
                raise ContractError("forbidden")
            if claim.purpose == "final_no_effect":
                if money(amount, c) != money(row[0], c):
                    raise ContractError("forbidden")
                expected_fact_amount = "0"
            else:
                entries = tx.connection.execute(
                    sql.SQL(
                        "SELECT record_bytes FROM {} WHERE project_id=%s AND run_id=%s "
                        "AND reservation_id=%s LIMIT %s"
                    ).format(tx.table("budget_events")),
                    (
                        claim.project_id,
                        claim.run_id,
                        claim.reservation_id,
                        limits_for(c, "kf.budget-event.v1").max_array_items + 1,
                    ),
                ).fetchall()
                if len(entries) > limits_for(c, "kf.budget-event.v1").max_array_items:
                    raise ContractError("limit_exceeded")
                settlements = [
                    BudgetEvent.from_wire(bytes(entry[0]), limits_for(c, "kf.budget-event.v1"))
                    for entry in entries
                ]
                settlements = [entry for entry in settlements if entry.event_type == "settle"]
                if (
                    len(settlements) != 1
                    or identity(settlements[0].evidence_ref) != identity(claim.evidence_ref)
                    or money(amount, c) != money(row[1], c)
                ):
                    raise ContractError("forbidden")
                expected_fact_amount = settlements[0].amount_usd
        if (
            facts.cost_status != status
            or (facts.amount_usd is None) != (expected_fact_amount is None)
            or (
                facts.amount_usd is not None
                and expected_fact_amount is not None
                and money(facts.amount_usd, c) != money(expected_fact_amount, c)
            )
        ):
            raise ContractError("forbidden")
        if amount is not None:
            money(amount, c)
        if claim.purpose in {
            "final_billing",
            "billing_adjustment",
            "release_unspent",
            "final_no_effect",
        }:
            if (
                facts.final is not True
                or facts.no_further_liability is not True
                or status != "actual"
            ):
                raise ContractError("forbidden")
        if claim.purpose == "final_no_effect" and facts.no_external_effect is not True:
            raise ContractError("forbidden")
        return True


def budget_context(control: ControlContext, *, tx: LedgerTxn) -> BudgetContext:
    tx.table("runs")
    return BudgetContext(
        clock(control),
        control.access,
        current_policy(control, control.access.project_id),
        control.limits_by_schema,
        control.authorize,
        BudgetVerifier(control, tx),
    )
