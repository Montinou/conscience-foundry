"""Bounded F1 result verification and immutable deterministic-selection chains."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from uuid import uuid4

from psycopg import sql

from conscience_foundry.contracts.accounting import OperationResultRecord
from conscience_foundry.contracts.artifacts import ArtifactManifest
from conscience_foundry.contracts.canonical import (
    REQUIRED_F1_CHECK_IDS,
    DocumentRevision,
    ExtractionSpec,
    OriginMap,
    QualityReport,
)
from conscience_foundry.contracts.common import ContractError, Ref
from conscience_foundry.contracts.execution import ResultManifest, StageAttempt
from conscience_foundry.core.comparison import (
    F1Comparison,
    comparison_digest,
    quality_projection_digest,
)
from conscience_foundry.core.identity import RevisionInputs, revision_id, structure_digest
from conscience_foundry.execution.evidence import (
    ResultPlan,
    VerificationContext,
    clock,
    current_policy,
    identity,
    limits_for,
    put_record,
    read_artifact,
    read_model,
)
from conscience_foundry.execution.ports import ControlContext
from conscience_foundry.ledger.attempts import json_ref
from conscience_foundry.ledger.db import LedgerTxn
from conscience_foundry.policy.access import require_permission
from conscience_foundry.processing.text_utf8 import process_text
from conscience_foundry.release.edges import edge_roles
from conscience_foundry.storage.local import VerifiedBytes


@dataclass(frozen=True)
class VerifiedResult:
    manifest: ResultManifest
    revision: DocumentRevision | None
    comparison_digest: str | None


def verify_result(
    ref: Ref, attempt: StageAttempt, plan: ResultPlan, control: VerificationContext
) -> VerifiedResult:
    raw, result = read_model(ref, ResultManifest, control)
    if (
        result.project_id != attempt.project_id
        or result.plan_id != attempt.plan_id
        or result.operation_key != attempt.operation_key
        or result.attempt_id != attempt.attempt_id
        or result.input_digests != (plan.source_asset.original_ref.digest,)
        or identity(result.usage.tariff_ref) != identity(plan.config.tariff_ref)
        or result.completed_at > clock(control)
        or result.completed_at < attempt.created_at
    ):
        raise ContractError("result_incomplete")
    policy = current_policy(control, attempt.project_id)
    for effect in ("read", "extract"):
        require_permission(control.access, policy, plan.source_asset.source_id, effect)
    revision = None
    quality = None
    if result.status == "succeeded":
        if result.document_revision_ref is None or result.quality_report_ref is None:
            raise ContractError("result_incomplete")
        _, revision = read_model(result.document_revision_ref, DocumentRevision, control)
        _, quality = read_model(result.quality_report_ref, QualityReport, control)
        # Correlate every content-bearing ref before traversing a worker graph.
        if (
            revision.asset_id != plan.source_asset.asset_id
            or revision.source_id != plan.source_asset.source_id
            or revision.project_id != attempt.project_id
            or quality.source_id != revision.source_id
            or identity(revision.original_ref) != identity(plan.source_asset.original_ref)
            or identity(revision.extraction_spec_ref) != identity(plan.model.extraction_spec_ref)
            or identity(revision.quality_report_ref) != identity(result.quality_report_ref)
            or revision.text_ref.artifact_schema != "kf.canonical-text.v1"
            or revision.text_ref.digest != revision.original_ref.digest
            or revision.text_ref.size_bytes != revision.original_ref.size_bytes
        ):
            raise ContractError("revision_mismatch")
        expected_refs = {
            identity(result.document_revision_ref),
            identity(result.quality_report_ref),
            identity(revision.text_ref),
            identity(revision.origin_map_ref),
        }
        if any(
            identity(output) not in expected_refs
            and output.artifact_schema != "kf.artifact-manifest.v1"
            for output in result.outputs
        ):
            raise ContractError("result_incomplete")
    elif any(
        output.artifact_schema not in {"kf.quality-report.v1", "kf.artifact-manifest.v1"}
        for output in result.outputs
    ):
        raise ContractError("unsupported_schema")
    allowed = {
        "kf.document-revision.v1",
        "kf.quality-report.v1",
        "kf.origin-map.v1",
        "kf.canonical-text.v1",
        "kf.artifact-manifest.v1",
    }
    if any(output.artifact_schema not in allowed for output in result.outputs):
        raise ContractError("unsupported_schema")
    bound = limits_for(control, "kf.result.v1")
    if len(result.outputs) > bound.max_array_items:
        raise ContractError("limit_exceeded")
    total = len(raw)
    seen: dict[tuple[object, ...], object] = {}
    active: set[tuple[object, ...]] = set()
    inputs = {
        identity(plan.source_asset.original_ref),
        identity(plan.model.extraction_spec_ref),
        *(identity(value) for value in plan.model.limits_refs),
    }

    def visit(reference: Ref) -> None:
        nonlocal total
        key = identity(reference)
        if key in active:
            raise ContractError("result_incomplete")
        if key in seen:
            return
        if len(seen) >= bound.max_array_items:
            raise ContractError("limit_exceeded")
        data, value = read_artifact(reference, control)
        if key not in inputs:
            total += len(data)
            if total > min(bound.max_output_bytes, plan.model.resources.max_output_bytes):
                raise ContractError("limit_exceeded")
        active.add(key)
        seen[key] = value
        for edge in edge_roles(reference.artifact_schema, value):
            if edge.role == "content":
                visit(edge.ref)
        active.remove(key)

    for output in result.outputs:
        visit(output)
    if result.status == "failed":
        return VerifiedResult(result, None, None)
    assert revision is not None and quality is not None
    for required in (revision.origin_map_ref, revision.text_ref, revision.quality_report_ref):
        if not any(identity(required) == identity(output) for output in result.outputs):
            raise ContractError("result_incomplete")
    original_raw, _ = read_artifact(revision.original_ref, control)
    text_raw, _ = read_artifact(revision.text_ref, control)
    _, spec = read_model(revision.extraction_spec_ref, ExtractionSpec, control)
    limits_raw, pinned_limits = read_model(spec.limits_ref, type(bound), control)
    expected = process_text(
        plan.source_asset,
        VerifiedBytes(original_raw, revision.original_ref.digest),
        spec,
        limits=pinned_limits,
        limits_bytes=limits_raw,
    )
    _, mapping = read_model(revision.origin_map_ref, OriginMap, control)
    if (
        text_raw != expected.text
        or mapping != expected.origin_map
        or revision.sections != expected.sections
        or quality.disposition != expected.quality.disposition
    ):
        raise ContractError("hash_mismatch")
    expected_checks = {
        check.check_id: (check.outcome, check.reason.code if check.reason else None)
        for check in expected.quality.checks
    }
    actual_checks = {
        check.check_id: (check.outcome, check.reason.code if check.reason else None)
        for check in quality.checks
    }
    if any(actual_checks.get(name) != expected_checks[name] for name in REQUIRED_F1_CHECK_IDS):
        raise ContractError("result_incomplete")
    revision.validate_f1(len(expected.text.decode("utf-8")))
    structure = structure_digest(revision.sections, limits=pinned_limits)
    actual_revision = revision_id(
        RevisionInputs(
            attempt.project_id,
            revision.source_id,
            revision.original_ref.digest,
            revision.text_ref.digest,
            revision.extraction_spec_ref.digest,
            structure,
            revision.origin_map_ref.digest,
        ),
        limits=pinned_limits,
    )
    if actual_revision != revision.revision_id:
        raise ContractError("revision_mismatch")
    for output in result.outputs:
        value = seen[identity(output)]
        if isinstance(value, ArtifactManifest) and (
            value.operation_key != attempt.operation_key
            or value.attempt_id != attempt.attempt_id
            or value.producer.image_digest != spec.image_digest
            or value.producer.code_version != spec.code_version
            or value.producer.processor_id != spec.processor_id
            or value.producer.processor_version != spec.processor_version
        ):
            raise ContractError("result_incomplete")
    digest = comparison_digest(
        F1Comparison(
            attempt.project_id,
            revision.asset_id,
            revision.source_id,
            attempt.operation_key,
            revision.revision_id,
            revision.original_ref.digest,
            revision.text_ref.digest,
            revision.extraction_spec_ref.digest,
            structure,
            revision.origin_map_ref.digest,
            quality_projection_digest(quality, limits=pinned_limits),
        ),
        limits=pinned_limits,
    )
    return VerifiedResult(result, revision, digest)


def integrity_hold(
    tx: LedgerTxn, attempt: StageAttempt, evidence_ref: Ref, control: ControlContext
) -> None:
    tx.connection.execute(
        sql.SQL("UPDATE {} SET held=true WHERE project_id=%s AND operation_key=%s").format(
            tx.table("operations")
        ),
        (attempt.project_id, attempt.operation_key),
    )
    tx.connection.execute(
        sql.SQL(
            "INSERT INTO {} (project_id,hold_id,operation_key,evidence_ref,created_at) "
            "VALUES (%s,%s,%s,%s,%s)"
        ).format(tx.table("integrity_holds")),
        (
            attempt.project_id,
            str(uuid4()),
            attempt.operation_key,
            json_ref(evidence_ref),
            clock(control),
        ),
    )


def select_result(
    tx: LedgerTxn,
    attempt: StageAttempt,
    result_ref: Ref,
    result: VerifiedResult,
    evidence_ref: Ref,
    control: ControlContext,
) -> OperationResultRecord:
    if result.comparison_digest is None:
        raise ContractError("result_incomplete")
    old = tx.connection.execute(
        sql.SQL(
            "SELECT record_ref FROM {} WHERE project_id=%s AND attempt_id=%s "
            "AND result_ref->>'digest'=%s LIMIT 1"
        ).format(tx.table("operation_results")),
        (attempt.project_id, attempt.attempt_id, result_ref.digest),
    ).fetchone()
    if old:
        return read_model(Ref.model_validate(old[0]), OperationResultRecord, control)[1]
    row = tx.connection.execute(
        sql.SQL(
            "SELECT selected_result_ref,selected_comparison_digest,latest_event_id::text,held "
            "FROM {} "
            "WHERE project_id=%s AND operation_key=%s FOR UPDATE"
        ).format(tx.table("operations")),
        (attempt.project_id, attempt.operation_key),
    ).fetchone()
    if row is None or (row[0] is None and row[3]):
        raise ContractError("forbidden")
    outcome: Literal["selected", "equivalent", "conflict"] = (
        "selected"
        if row[0] is None
        else ("equivalent" if row[1] == result.comparison_digest else "conflict")
    )
    selected = result_ref if row[0] is None else Ref.model_validate(row[0])
    record = OperationResultRecord(
        schema_version="kf.operation-result-record.v1",
        project_id=attempt.project_id,
        operation_key=attempt.operation_key,
        event_id=str(uuid4()),
        attempt_id=attempt.attempt_id,
        result_ref=result_ref,
        comparison_digest=result.comparison_digest,
        outcome=outcome,
        selected_result_ref=selected,
        evidence_ref=evidence_ref,
        recorded_at=clock(control),
        **({"previous_event_id": row[2]} if row[2] is not None else {}),
    )
    record_ref = put_record(record, control)
    tx.connection.execute(
        sql.SQL(
            "INSERT INTO {} (project_id,event_id,operation_key,previous_event_id,"
            "attempt_id,outcome,"
            "result_ref,selected_result_ref,comparison_digest,evidence_ref,recorded_at,record_ref) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        ).format(tx.table("operation_results")),
        (
            record.project_id,
            record.event_id,
            record.operation_key,
            record.previous_event_id,
            record.attempt_id,
            outcome,
            json_ref(result_ref),
            json_ref(selected),
            record.comparison_digest,
            json_ref(evidence_ref),
            record.recorded_at,
            json_ref(record_ref),
        ),
    )
    updated = tx.connection.execute(
        sql.SQL(
            "UPDATE {} SET latest_event_id=%s,selected_result_ref=%s,selected_comparison_digest=%s "
            "WHERE project_id=%s AND operation_key=%s "
            "AND latest_event_id IS NOT DISTINCT FROM %s::uuid"
        ).format(tx.table("operations")),
        (
            record.event_id,
            json_ref(selected),
            row[1] or record.comparison_digest,
            record.project_id,
            record.operation_key,
            row[2],
        ),
    )
    if updated.rowcount != 1:
        raise ContractError("determinism_conflict")
    if outcome == "conflict":
        integrity_hold(tx, attempt, evidence_ref, control)
    return record
