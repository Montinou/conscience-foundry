"""Verified canonical registration and bounded immutable enrichment operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from conscience_foundry.contracts.canonical import DocumentRevision
from conscience_foundry.contracts.common import ContractError, Digest, Id, Ref
from conscience_foundry.enrichment.context import EnrichmentContext
from conscience_foundry.execution.evidence import identity, read_artifact
from conscience_foundry.ledger.db import Ledger, LedgerTxn
from conscience_foundry.policy.access import require_permission
from conscience_foundry.release.build import _lineage
from conscience_foundry.release.context import ReleaseAuthority, ReleaseContext
from conscience_foundry.release.coverage import capture, review_records


@dataclass(frozen=True)
class VerifiedCanonicalInput:
    revision: DocumentRevision
    text: bytes
    source_id: Id
    asset_id: Id
    operation_key: Digest
    admission_ref: Ref
    state_digest: Digest
    profile_id: str
    profile_version: str


def verify_canonical_input(
    revision_ref: Ref, admission_ref: Ref, *, tx: LedgerTxn, context: EnrichmentContext
) -> VerifiedCanonicalInput:
    if (
        type(context) is not EnrichmentContext
        or type(revision_ref) is not Ref
        or revision_ref.project_id != context.access.project_id
        or revision_ref.artifact_schema != "cf.document-revision.v1"
    ):
        raise ContractError("forbidden")
    release = ReleaseContext(
        context.access,
        context.store,
        context.clock,
        context.limits_by_schema,
        context.output_store_id,
        lambda project: context.current_policy(),
        cast(ReleaseAuthority, None),
    )
    snapshot = capture((admission_ref,), tx, release)
    reviews = review_records(snapshot, release)
    matches = [
        (op, row)
        for (op, digest), (row, review) in reviews.items()
        if digest == revision_ref.digest
        and review.decision == "accepted"
        and identity(Ref.model_validate(row["revision_ref"])) == identity(revision_ref)
    ]
    if len(matches) != 1:
        raise ContractError("unavailable")
    op, _ = matches[0]
    revision, admission_digest = _lineage(op, revision_ref, snapshot, tx, release)
    if admission_digest != admission_ref.digest:
        raise ContractError("forbidden")
    require_permission(context.access, snapshot.policy, revision.source_id, "enrich")
    raw, _ = read_artifact(revision.text_ref, release)
    view = next(
        item for item in snapshot.admissions if identity(item.ref) == identity(admission_ref)
    )
    return VerifiedCanonicalInput(
        revision,
        raw,
        revision.source_id,
        revision.asset_id,
        op,
        admission_ref,
        snapshot.digest,
        view.manifest.profile_id,
        view.manifest.profile_version,
    )


_METADATA_CORE_ROLES = frozenset(
    {
        "cf.policy.v1",
        "cf.local-resource-policy.v1",
        "cf.contract-limits.v1",
        "json-schema.2020-12",
        "cf.semantic-rules.v1",
    }
)


def _check_metadata_role(ref: Ref) -> None:
    from conscience_foundry.contracts.registry import registered_schema_ids

    if (
        ref.artifact_schema in registered_schema_ids()
        and ref.artifact_schema not in _METADATA_CORE_ROLES
    ):
        raise ContractError("forbidden")


def _read_opaque_tariff(ref: Ref, context: EnrichmentContext) -> bytes:
    """Read an operator-defined tariff identity under explicit role-specific limits."""
    import hashlib

    from conscience_foundry.contracts.common import ContractLimits

    if type(ref) is not Ref or ref.project_id != context.access.project_id:
        raise ContractError("forbidden")
    ref = Ref.model_validate(ref.model_dump())
    _check_metadata_role(ref)
    limits = context.limits_by_schema.get(ref.artifact_schema)
    if type(limits) is not ContractLimits:
        raise ContractError("limits_missing")
    ceiling = limits.max_output_bytes
    if ref.size_bytes > ceiling:
        raise ContractError("limit_exceeded")
    value = context.store.read_verified(ref, context.access, ceiling)
    raw = value.data
    if (
        type(raw) is not bytes
        or len(raw) != ref.size_bytes
        or hashlib.sha256(raw).hexdigest() != ref.digest
        or value.digest != ref.digest
    ):
        raise ContractError("hash_mismatch")
    from conscience_foundry.contracts.registry import registered_schema_ids, validate_artifact

    if ref.artifact_schema in registered_schema_ids():
        validate_artifact(ref, raw, limits_by_schema=context.limits_by_schema)
    return raw


def _read_spec_metadata(ref: Ref, context: EnrichmentContext) -> bytes:
    """Verify one named spec metadata slot, without interpreting private bytes."""
    import hashlib

    from conscience_foundry.contracts.common import ContractLimits
    from conscience_foundry.contracts.registry import registered_schema_ids
    from conscience_foundry.enrichment.task_schemas import _VerificationContext

    if type(ref) is not Ref or ref.project_id != context.access.project_id:
        raise ContractError("forbidden")
    ref = Ref.model_validate(ref.model_dump())
    _check_metadata_role(ref)
    if ref.artifact_schema in registered_schema_ids():
        return read_artifact(ref, _VerificationContext(context))[0]
    limits = context.limits_by_schema.get(ref.artifact_schema)
    if type(limits) is not ContractLimits:
        raise ContractError("limits_missing")
    ceiling = limits.max_output_bytes
    if ref.size_bytes > ceiling:
        raise ContractError("limit_exceeded")
    value = context.store.read_verified(ref, context.access, ceiling)
    raw = value.data
    if (
        type(raw) is not bytes
        or len(raw) != ref.size_bytes
        or hashlib.sha256(raw).hexdigest() != ref.digest
        or value.digest != ref.digest
    ):
        raise ContractError("hash_mismatch")
    return raw


def _verify_omitted_ref(
    ref: Ref, canonical: VerifiedCanonicalInput, *, revision_ref: Ref, context: EnrichmentContext
) -> None:
    from conscience_foundry.contracts.canonical import DocumentSpan, validate_span_shape
    from conscience_foundry.enrichment.task_schemas import _VerificationContext

    if ref == revision_ref or ref == canonical.revision.text_ref:
        read_artifact(ref, _VerificationContext(context))
        return
    if ref.artifact_schema != "cf.document-span.v1":
        raise ContractError("forbidden")
    _, value = read_artifact(ref, _VerificationContext(context))
    if type(value) is not DocumentSpan:
        raise ContractError("unsupported_schema")
    validate_span_shape(value, canonical.revision, len(canonical.text.decode("utf-8")))


def register_operation(
    operation_ref: Ref,
    plan_ref: Ref,
    authorization_ref: Ref,
    *,
    ledger: Ledger,
    context: EnrichmentContext,
) -> Digest:
    import hashlib
    import json
    from decimal import Decimal

    from psycopg import sql
    from psycopg.types.json import Jsonb

    from conscience_foundry.contracts.canonical import validate_span_shape
    from conscience_foundry.contracts.common import ContractLimits
    from conscience_foundry.contracts.enrichment import (
        EnrichmentAllocationPolicy,
        EnrichmentOperation,
        EnrichmentPayload,
        EnrichmentPlan,
        TaskSchemaInstallation,
        enrichment_operation_key,
    )
    from conscience_foundry.contracts.execution import RunAuthorization
    from conscience_foundry.contracts.extensions import EnrichmentSpec
    from conscience_foundry.contracts.project import PolicyArtifact
    from conscience_foundry.contracts.registry import ContractSet, registered_schema_ids
    from conscience_foundry.enrichment.context import approve
    from conscience_foundry.enrichment.schema import validate_payload
    from conscience_foundry.enrichment.task_schemas import _VerificationContext, load_task_schemas
    from conscience_foundry.execution.evidence import clock, encoded, read_model
    from conscience_foundry.ledger.enrichment import require_enrichment_schema

    if type(context) is not EnrichmentContext:
        raise ContractError("forbidden")
    v = _VerificationContext(context)
    plan_raw, plan = read_model(plan_ref, EnrichmentPlan, v)
    _, auth = read_model(authorization_ref, RunAuthorization, v)
    _, operation = read_model(operation_ref, EnrichmentOperation, v)
    now = clock(v)
    project = context.access.project_id
    if (
        plan.project_id != project
        or auth.project_id != project
        or operation.project_id != project
        or plan.operation_ref != operation_ref
        or plan.operation_key
        != enrichment_operation_key(
            operation, limits=context.limits_by_schema["cf.enrichment-operation.v1"]
        )
        or plan_ref.digest not in auth.allowed_plan_digests
        or plan.run_id != auth.run_id
        or plan.budget.authorization_id != auth.authorization_id
        or plan.admission_report_ref.digest != auth.admission_report_digest
        or Decimal(plan.budget.max_run_cost) != Decimal(auth.max_run_cost)
        or plan.resources.max_concurrent_attempts > auth.max_concurrent_attempts
        or plan.expires_at > auth.expires_at
    ):
        raise ContractError("forbidden")
    if (
        not auth.authorized_at
        <= now
        < min(auth.expires_at, plan.expires_at, plan.budget.valid_until)
    ):
        raise ContractError("authorization_expired")
    with ledger.transaction() as tx:
        require_enrichment_schema(tx)
        tx.lock(project, plan.run_id)
        row = tx.connection.execute(
            sql.SQL(
                "SELECT r.current_authorization_id::text,a.authorization_ref,"
                "a.allowed_plan_digests,"
                "a.max_run_cost,a.max_concurrent_attempts,a.actor_id::text FROM {} r JOIN {} a ON "
                "(r.project_id,r.run_id,r.current_authorization_id)="
                "(a.project_id,a.run_id,a.authorization_id) WHERE r.project_id=%s AND r.run_id=%s"
            ).format(tx.table("runs"), tx.table("authorizations")),
            (project, plan.run_id),
        ).fetchone()
        if (
            row is None
            or row[0] != auth.authorization_id
            or Ref.model_validate(row[1]) != authorization_ref
            or tuple(row[2]) != auth.allowed_plan_digests
            or Decimal(row[3]) != Decimal(auth.max_run_cost)
            or row[4] != auth.max_concurrent_attempts
            or row[5] != auth.actor_id
        ):
            raise ContractError("forbidden")
        _, bundle = read_model(plan.contract_set_ref, ContractSet, v)
        if tuple(b.schema_id for b in bundle.contracts) != registered_schema_ids():
            raise ContractError("unsupported_schema")
        pins = tuple(read_model(ref, ContractLimits, v)[1] for ref in plan.limits_refs)
        if any(
            context.limits_by_schema.get(schema) not in pins for schema in registered_schema_ids()
        ):
            raise ContractError("limits_missing")
        policy_raw, policy = read_model(operation.policy_ref, PolicyArtifact, v)
        if policy_raw != encoded(context.current_policy()) or policy.effective_at > now:
            raise ContractError("forbidden")
        _, allocation = read_model(plan.allocation_policy_ref, EnrichmentAllocationPolicy, v)
        if (
            allocation.tariff_ref != plan.budget.tariff_ref
            or not allocation.funded_from <= now < allocation.funded_until
            or plan.expires_at > allocation.funded_until
            or plan.budget.valid_until > allocation.funded_until
            or Decimal(allocation.fixed_charge_usd) > Decimal(plan.budget.max_attempt_cost)
        ):
            raise ContractError("forbidden")
        _read_opaque_tariff(plan.budget.tariff_ref, context)
        canonical = verify_canonical_input(
            operation.canonical_revision_ref, plan.admission_report_ref, tx=tx, context=context
        )
        if canonical.asset_id != operation.asset_id:
            raise ContractError("revision_mismatch")
        for span in operation.context_spans:
            validate_span_shape(span, canonical.revision, len(canonical.text.decode("utf-8")))
        _, spec = read_model(operation.spec_ref, EnrichmentSpec, v)
        if (spec.profile_id, spec.profile_version) != (
            canonical.profile_id,
            canonical.profile_version,
        ):
            raise ContractError("forbidden")
        _, receipt = read_model(plan.task_schema_installation_ref, TaskSchemaInstallation, v)
        if receipt.spec_ref != operation.spec_ref or receipt.policy_ref != operation.policy_ref:
            raise ContractError("forbidden")
        registry = load_task_schemas(
            plan.task_schema_installation_ref, spec_ref=operation.spec_ref, tx=tx, context=context
        )
        metadata_refs = (
            spec.prompt_ref,
            spec.context_policy_ref,
            spec.model_route_ref,
            spec.generation_settings_ref,
            spec.validation_policy_ref,
            spec.review_policy_ref,
            spec.execution_limits_ref,
            spec.runtime_ref,
            *(() if spec.graph_spec_ref is None else (spec.graph_spec_ref,)),
        )
        for ref in metadata_refs:
            _read_spec_metadata(ref, context)
        for ref in operation.omitted_context_refs:
            _verify_omitted_ref(
                ref, canonical, revision_ref=operation.canonical_revision_ref, context=context
            )
        _, payload = read_model(operation.input_ref, EnrichmentPayload, v)
        if payload.schema_ref != spec.input_schema_ref:
            raise ContractError("hash_mismatch")
        raw_schema = next((raw for ref, raw in registry.schemas if ref == payload.schema_ref), None)
        if raw_schema is None:
            raise ContractError("forbidden")
        validate_payload(
            raw_schema,
            json.dumps(payload.value, ensure_ascii=False, separators=(",", ":")).encode(),
            limits=context.limits_by_schema["cf.enrichment-payload.v1"],
        )
        request = json.dumps(
            {
                "operationRef": operation_ref.model_dump(mode="json", by_alias=True),
                "planRef": plan_ref.model_dump(mode="json", by_alias=True),
                "authorizationRef": authorization_ref.model_dump(mode="json", by_alias=True),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        approve(
            context,
            "register",
            request,
            canonical.state_digest,
            (
                operation_ref,
                plan_ref,
                authorization_ref,
                plan.allocation_policy_ref,
                plan.task_schema_installation_ref,
                plan.budget.tariff_ref,
                spec.input_schema_ref,
                spec.output_schema_ref,
                operation.canonical_revision_ref,
                operation.spec_ref,
                operation.policy_ref,
                operation.input_ref,
                *metadata_refs,
                *operation.omitted_context_refs,
            ),
            run_id=plan.run_id,
            operation_key=plan.operation_key,
        )
        current_time = clock(v)
        if (
            encoded(context.current_policy()) != policy_raw
            or current_time < max(auth.authorized_at, allocation.funded_from, policy.effective_at)
            or current_time
            >= min(
                auth.expires_at, plan.expires_at, plan.budget.valid_until, allocation.funded_until
            )
        ):
            raise ContractError("unavailable")
        sidecar = sql.Identifier(tx.schema, "enrichment_operations")
        existing = tx.connection.execute(
            sql.SQL("SELECT operation_ref FROM {} WHERE project_id=%s AND operation_key=%s").format(
                sidecar
            ),
            (project, plan.operation_key),
        ).fetchone()
        if existing is None:
            tx.connection.execute(
                sql.SQL(
                    "INSERT INTO {} (project_id,operation_key,asset_id) VALUES (%s,%s,%s)"
                ).format(tx.table("operations")),
                (project, plan.operation_key, operation.asset_id),
            )
            tx.connection.execute(
                sql.SQL(
                    "INSERT INTO {} (project_id,operation_key,operation_ref,operation_digest) "
                    "VALUES (%s,%s,%s,%s)"
                ).format(sidecar),
                (
                    project,
                    plan.operation_key,
                    Jsonb(operation_ref.model_dump(mode="json", by_alias=True)),
                    operation_ref.digest,
                ),
            )
        elif Ref.model_validate(existing[0]) != operation_ref:
            raise ContractError("determinism_conflict")
        old_plan = tx.connection.execute(
            sql.SQL(
                "SELECT run_id::text,plan_ref,authorization_id::text,operation_key FROM {} "
                "WHERE project_id=%s AND plan_id=%s"
            ).format(tx.table("plans")),
            (project, plan.plan_id),
        ).fetchone()
        if old_plan is None:
            tx.connection.execute(
                sql.SQL(
                    "INSERT INTO {} (project_id,plan_id,run_id,plan_digest,plan_ref,"
                    "authorization_id,operation_key) VALUES (%s,%s,%s,%s,%s,%s,%s)"
                ).format(tx.table("plans")),
                (
                    project,
                    plan.plan_id,
                    plan.run_id,
                    hashlib.sha256(plan_raw).hexdigest(),
                    Jsonb(plan_ref.model_dump(mode="json", by_alias=True)),
                    auth.authorization_id,
                    plan.operation_key,
                ),
            )
        elif (old_plan[0], Ref.model_validate(old_plan[1]), old_plan[2], old_plan[3]) != (
            plan.run_id,
            plan_ref,
            auth.authorization_id,
            plan.operation_key,
        ):
            raise ContractError("determinism_conflict")
        return plan.operation_key
