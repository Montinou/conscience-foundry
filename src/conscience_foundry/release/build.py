"""Authenticated operator review and private, unverified release candidates."""

from __future__ import annotations

import hashlib
import io
from uuid import uuid4

from psycopg import sql
from psycopg.types.json import Jsonb
from pydantic import TypeAdapter

from conscience_foundry.contracts.accounting import OperationResultRecord
from conscience_foundry.contracts.canonical import DocumentRevision, QualityReport, RevisionReview
from conscience_foundry.contracts.codec import hash_jcs, load_json
from conscience_foundry.contracts.common import (
    ArtifactLocation,
    ContractError,
    Digest,
    Id,
    Reason,
    Ref,
)
from conscience_foundry.contracts.execution import ResultManifest, StageAttempt
from conscience_foundry.contracts.registry import validate_artifact
from conscience_foundry.contracts.release import LibraryRelease, ReleaseSource
from conscience_foundry.execution.evidence import (
    clock,
    current_policy,
    historical_result_plan,
    identity,
    limits_for,
    put_record,
    read_artifact,
    read_model,
)
from conscience_foundry.ledger.acceptance import verify_result
from conscience_foundry.ledger.attempts import json_ref, load_attempt
from conscience_foundry.ledger.db import Ledger, LedgerTxn
from conscience_foundry.policy.access import AccessContext, require_permission
from conscience_foundry.release.context import (
    ReleaseContext,
    approve,
    bounded_model,
    checked_context,
    recheck_policy,
    request_bytes,
    require_audit,
)
from conscience_foundry.release.coverage import (
    Snapshot,
    bounded_rows,
    build_coverage,
    capture,
    metadata_ids,
    review_records,
)
from conscience_foundry.release.provenance import build_provenance, run_reports
from conscience_foundry.storage.local import ObjectStore


def _store_exact(raw: bytes, schema: str, release: ReleaseContext) -> Ref:
    digest = hashlib.sha256(raw).hexdigest()
    ref = Ref(
        schema_version="kf.artifact-ref.v1",
        project_id=release.access.project_id,
        digest=digest,
        size_bytes=len(raw),
        media_type="application/json",
        artifact_schema=schema,
        locations=(
            ArtifactLocation(
                store_id=release.output_store_id, object_key=f"sha256/{digest[:2]}/{digest}"
            ),
        ),
    )
    validate_artifact(ref, raw, limits_by_schema=release.limits_by_schema)
    try:
        release.store.put_verified(io.BytesIO(raw), ref, release.access)
    except OSError:
        raise ContractError("storage_full") from None
    return ref


def _operation_admissions(
    operation_key: str, tx: LedgerTxn, release: ReleaseContext
) -> tuple[Ref, ...]:
    TypeAdapter(Digest).validate_python(operation_key)
    project = release.access.project_id
    if "auditMetadataRead" not in release.access.scopes:
        raise ContractError("forbidden")
    routes = metadata_ids(
        tx,
        sql.SQL(
            "SELECT r.admission_report_digest FROM {} a JOIN {} r ON "
            "(a.project_id,a.run_id)=(r.project_id,r.run_id) WHERE "
            "a.project_id=%s AND a.operation_key=%s"
        ).format(tx.table("attempts"), tx.table("runs")),
        (project, operation_key),
        release,
    )
    digests = sorted({row[0] for row in routes})
    sources = metadata_ids(
        tx,
        sql.SQL(
            "SELECT DISTINCT source_id::text FROM {} WHERE project_id=%s AND report_digest=ANY(%s)"
        ).format(tx.table("admission_entries")),
        (project, digests),
        release,
    )
    require_audit(release, current_policy(release, project), tuple(row[0] for row in sources))
    rows = bounded_rows(
        tx,
        "admission_reports",
        sql.SQL("t.project_id=%s AND t.report_digest=ANY(%s)"),
        (project, digests),
        release,
    )
    if not rows:
        raise ContractError("unavailable")
    return tuple(Ref.model_validate(row["report_ref"]) for row in rows)


# Approval evidence must be administrative metadata; content-bearing schemas
# (raw originals, canonical text, revisions, spans, results) need source read/extract.
EVIDENCE_SCHEMAS = frozenset(
    {
        "kf.admission-report.v1",
        "kf.intake.v1",
        "kf.operation-result-record.v1",
        "kf.run-report.v1",
        "kf.coverage-report.v1",
        "kf.provenance-report.v1",
        "kf.revision-review.v1",
        "kf.budget-event.v1",
        "kf.billing-adjustment.v1",
    }
)


def _evidence(ref: Ref, release: ReleaseContext) -> bytes:
    if type(ref) is not Ref or ref.artifact_schema not in EVIDENCE_SCHEMAS:
        raise ContractError("unsupported_schema")
    return read_artifact(ref, release)[0]


def _lineage(
    operation_key: str,
    revision_ref: Ref,
    snapshot: Snapshot,
    tx: LedgerTxn,
    release: ReleaseContext,
) -> tuple[DocumentRevision, str]:
    operations = [
        row for row in snapshot.rows["operations"] if row["operation_key"] == operation_key
    ]
    if len(operations) != 1:
        raise ContractError("unavailable")
    operation = operations[0]
    assets = [row for row in snapshot.rows["assets"] if row["asset_id"] == operation["asset_id"]]
    if len(assets) != 1:
        raise ContractError("unavailable")
    asset = assets[0]
    for effect in ("read", "extract", "auditMetadataRead"):
        require_permission(release.access, snapshot.policy, asset["source_id"], effect)
    if operation["held"] or any(
        row["operation_key"] == operation_key for row in snapshot.rows["integrity_holds"]
    ):
        raise ContractError("determinism_conflict")
    records = [
        row for row in snapshot.rows["operation_results"] if row["operation_key"] == operation_key
    ]
    initial = [row for row in records if row["outcome"] == "selected"]
    if len(initial) != 1 or operation["selected_result_ref"] is None:
        raise ContractError("unavailable")
    initial_row = initial[0]
    selected_result = Ref.model_validate(operation["selected_result_ref"])
    if identity(Ref.model_validate(initial_row["result_ref"])) != identity(selected_result):
        raise ContractError("hash_mismatch")
    for row in records:
        _, record = read_model(
            Ref.model_validate(row["record_ref"]), OperationResultRecord, release
        )
        if (
            record.project_id,
            record.operation_key,
            record.event_id,
            record.attempt_id,
            record.outcome,
            record.previous_event_id,
        ) != (
            release.access.project_id,
            operation_key,
            row["event_id"],
            row["attempt_id"],
            row["outcome"],
            row["previous_event_id"],
        ):
            raise ContractError("hash_mismatch")
        if (
            identity(record.result_ref) != identity(Ref.model_validate(row["result_ref"]))
            or identity(record.selected_result_ref) != identity(selected_result)
            or record.comparison_digest != row["comparison_digest"]
        ):
            raise ContractError("hash_mismatch")
        if record.outcome == "conflict":
            raise ContractError("determinism_conflict")
    if operation["latest_event_id"] not in {row["event_id"] for row in records}:
        raise ContractError("hash_mismatch")
    _, manifest = read_model(selected_result, ResultManifest, release)
    if manifest.document_revision_ref is None or identity(
        manifest.document_revision_ref
    ) != identity(revision_ref):
        raise ContractError("revision_mismatch")
    # Only this explicitly selected operation's content can now be traversed.
    attempt_ref, _, plan_ref, authorization_ref = load_attempt(
        tx, release.access.project_id, initial_row["attempt_id"]
    )
    _, attempt = read_model(attempt_ref, StageAttempt, release)
    if (
        attempt.state != "succeeded"
        or attempt.result_manifest_ref is None
        or identity(attempt.result_manifest_ref) != identity(selected_result)
    ):
        raise ContractError("unavailable")
    plan = historical_result_plan(plan_ref, authorization_ref, tx, release)
    if (
        plan.source_asset.asset_id != asset["asset_id"]
        or plan.source_asset.source_id != asset["source_id"]
    ):
        raise ContractError("revision_mismatch")
    result = verify_result(selected_result, attempt, plan, release)
    if (
        result.revision is None
        or result.comparison_digest != operation["selected_comparison_digest"]
    ):
        raise ContractError("hash_mismatch")
    withdrawn = [
        row
        for row in snapshot.rows["admission_withdrawals"]
        if row["batch_id"] == plan.manifest.batch_id and row["asset_id"] == asset["asset_id"]
    ]
    if withdrawn:
        raise ContractError("forbidden")
    return result.revision, plan.model.admission_report_ref.digest


def record_review(
    review: RevisionReview,
    context: AccessContext,
    ledger: Ledger,
    store: ObjectStore,
    *,
    release: ReleaseContext,
    operation_key: str,
    revision_ref: Ref,
    review_bytes: bytes,
    evidence_ref: Ref,
) -> Ref:
    checked_context(context, store, release)
    checked = RevisionReview.from_wire(review_bytes, limits_for(release, "kf.revision-review.v1"))
    if (
        type(review) is not RevisionReview
        or checked != review
        or review.project_id != context.project_id
        or review.actor_id != context.actor_id
        or review.reviewed_at > clock(release)
    ):
        raise ContractError("forbidden")
    bounded_model(revision_ref, release, "kf.artifact-ref.v1")
    with ledger.transaction() as tx:
        tx.lock(context.project_id)
        snapshot = capture(_operation_admissions(operation_key, tx, release), tx, release)
        if review.policy_version != snapshot.policy.policy_version:
            raise ContractError("permission_unknown")
        evidence_bytes = _evidence(evidence_ref, release)
        approve(
            release,
            "record_review",
            review_bytes,
            snapshot.digest,
            evidence_ref,
            evidence_bytes,
            revision_ref,
        )
        revision, _ = _lineage(operation_key, revision_ref, snapshot, tx, release)
        _, quality = read_model(
            revision.quality_report_ref,
            QualityReport,
            release,
        )
        review.validate_quality(revision, quality)
        if review.revision_id != revision.revision_id:
            raise ContractError("revision_mismatch")
        old = bounded_rows(
            tx,
            "reviews",
            sql.SQL("t.project_id=%s AND t.review_ref->>'digest'=%s"),
            (context.project_id, hashlib.sha256(review_bytes).hexdigest()),
            release,
        )
        if old:
            if any(
                row["operation_key"] != operation_key
                or identity(Ref.model_validate(row["revision_ref"])) != identity(revision_ref)
                or row["revision_digest"] != review.revision_id
                for row in old
            ):
                raise ContractError("determinism_conflict")
            return Ref.model_validate(old[0]["review_ref"])
        recheck_policy(snapshot.policy, release)
        ref = _store_exact(review_bytes, review.schema_version, release)
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,review_id,revision_digest,revision_re"
                "f,operation_key,review_ref,actor_id,reviewed_at) VALUES "
                "(%s,%s,%s,%s,%s,%s,%s,%s)"
            ).format(tx.table("reviews")),
            (
                context.project_id,
                str(uuid4()),
                review.revision_id,
                json_ref(revision_ref),
                operation_key,
                json_ref(ref),
                context.actor_id,
                review.reviewed_at,
            ),
        )
        return ref


def record_admission_withdrawal(
    batch_id: str,
    asset_id: str,
    decision_id: str,
    context: AccessContext,
    ledger: Ledger,
    store: ObjectStore,
    *,
    release: ReleaseContext,
    reason: Reason,
    evidence_ref: Ref,
) -> str:
    checked_context(context, store, release)
    for value in (batch_id, asset_id, decision_id):
        TypeAdapter(Id).validate_python(value)
    if "auditMetadataRead" not in context.scopes:
        raise ContractError("forbidden")
    bounded_model(reason, release, "kf.revision-review.v1")
    with ledger.transaction() as tx:
        tx.lock(context.project_id)
        routes = metadata_ids(
            tx,
            sql.SQL(
                "SELECT DISTINCT e.source_id::text FROM {} e JOIN {} r ON "
                "(e.project_id,e.report_digest)=(r.project_id,r.report_digest) "
                "WHERE e.project_id=%s AND r.batch_id=%s AND e.asset_id=%s"
            ).format(tx.table("admission_entries"), tx.table("admission_reports")),
            (context.project_id, batch_id, asset_id),
            release,
        )
        if len(routes) != 1:
            raise ContractError("unavailable")
        source_id = routes[0][0]
        policy = current_policy(release, context.project_id)
        require_audit(release, policy, (source_id,))
        evidence_bytes = _evidence(evidence_ref, release)
        prior = bounded_rows(
            tx,
            "admission_withdrawals",
            sql.SQL("t.project_id=%s AND t.decision_id=%s"),
            (context.project_id, decision_id),
            release,
        )
        if prior:
            row = prior[0]
            if (
                row["batch_id"],
                row["asset_id"],
                row["source_id"],
                row["actor_id"],
                row["reason"],
                identity(Ref.model_validate(row["evidence_ref"])),
            ) != (
                batch_id,
                asset_id,
                source_id,
                context.actor_id,
                reason.model_dump(mode="json", by_alias=True),
                identity(evidence_ref),
            ):
                raise ContractError("determinism_conflict")
            raw = bytes.fromhex(row["record_bytes"][2:])
            if hashlib.sha256(raw).hexdigest() != row["request_digest"]:
                raise ContractError("hash_mismatch")
            old = load_json(raw, limits_for(release, "kf.revision-review.v1"))
            approve(
                release,
                "withdraw_admission",
                raw,
                str(old["stateDigest"]),
                evidence_ref,
                evidence_bytes,
            )
            return decision_id
        state = request_bytes(
            {
                "projectId": context.project_id,
                "batchId": batch_id,
                "assetId": asset_id,
                "sourceId": source_id,
                "policy": policy.model_dump(mode="json", by_alias=True),
            },
            release,
        )
        state_digest = hashlib.sha256(state).hexdigest()
        raw = request_bytes(
            {
                "projectId": context.project_id,
                "batchId": batch_id,
                "assetId": asset_id,
                "sourceId": source_id,
                "decisionId": decision_id,
                "actorId": context.actor_id,
                "reason": reason.model_dump(mode="json", by_alias=True),
                "decidedAt": clock(release),
                "evidenceRef": evidence_ref.model_dump(mode="json", by_alias=True),
                "stateDigest": state_digest,
            },
            release,
        )
        approve(release, "withdraw_admission", raw, state_digest, evidence_ref, evidence_bytes)
        recheck_policy(policy, release)
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,batch_id,asset_id,source_id,decision_"
                "id,actor_id,reason,evidence_ref,request_digest,record_bytes,deci"
                "ded_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            ).format(tx.table("admission_withdrawals")),
            (
                context.project_id,
                batch_id,
                asset_id,
                source_id,
                decision_id,
                context.actor_id,
                Jsonb(reason.model_dump(mode="json", by_alias=True)),
                json_ref(evidence_ref),
                hashlib.sha256(raw).hexdigest(),
                raw,
                clock(release),
            ),
        )
        return decision_id


def build_release(
    selected: tuple[ReleaseSource, ...],
    admissions: tuple[Ref, ...],
    context: AccessContext,
    ledger: Ledger,
    store: ObjectStore,
    *,
    release: ReleaseContext,
) -> LibraryRelease:
    checked_context(context, store, release)
    bound = limits_for(release, "kf.library-release.v1")
    if type(selected) is not tuple or not selected or len(selected) > bound.max_array_items:
        raise ContractError("invalid_schema")
    for source in selected:
        if type(source) is not ReleaseSource:
            raise ContractError("invalid_schema")
        bounded_model(source, release, "kf.library-release.v1")
    ids = tuple(source.source_id for source in selected)
    if ids != tuple(sorted(set(ids))):
        raise ContractError("invalid_schema")
    selection = [source.model_dump(mode="json", by_alias=True) for source in selected]
    selection_digest = hash_jcs("kf.release-selection.v1", selection)
    with ledger.transaction() as tx:
        tx.lock(context.project_id)
        snapshot = capture(admissions, tx, release)
        raw = request_bytes(
            {
                "sourceEntries": selection,
                "admissionReportRefs": [
                    ref.model_dump(mode="json", by_alias=True) for ref in admissions
                ],
                "stateDigest": snapshot.digest,
            },
            release,
        )
        approve(release, "build_release", raw, snapshot.digest)
        reviews = review_records(snapshot, release)
        for source in selected:
            matching = [
                (row, review)
                for row, review in reviews.values()
                if identity(Ref.model_validate(row["review_ref"])) == identity(source.review_ref)
                and identity(Ref.model_validate(row["revision_ref"]))
                == identity(source.revision_ref)
            ]
            if len(matching) != 1 or matching[0][1].decision != "accepted":
                raise ContractError("forbidden")
            row, review = matching[0]
            revision, producing_admission = _lineage(
                row["operation_key"], source.revision_ref, snapshot, tx, release
            )
            if (
                revision.source_id != source.source_id
                or review.revision_id != revision.revision_id
                or producing_admission not in {ref.digest for ref in admissions}
            ):
                raise ContractError("revision_mismatch")
            _, quality = read_model(
                revision.quality_report_ref,
                QualityReport,
                release,
            )
            review.validate_quality(revision, quality)
        coverage = build_coverage(snapshot, selected, selection_digest, reviews)
        reports = run_reports(snapshot, reviews, release)
        provenance = build_provenance(snapshot, selected, selection_digest, reviews, reports)
        profile = {
            (view.manifest.profile_id, view.manifest.profile_version)
            for view in snapshot.admissions
            if identity(view.ref) in {identity(ref) for ref in admissions}
        }
        if len(profile) != 1:
            raise ContractError("unsupported_capability")
        profile_id, profile_version = next(iter(profile))
        coverage_ref, provenance_ref = (
            put_record(coverage, release),
            put_record(provenance, release),
        )
        candidate = LibraryRelease(
            schema_version="kf.library-release.v1",
            project_id=context.project_id,
            release_id=str(uuid4()),
            profile_id=profile_id,
            profile_version=profile_version,
            capabilities=("canonical_text",),
            source_entries=selected,
            component_refs=(),
            coverage_report_ref=coverage_ref,
            provenance_report_ref=provenance_ref,
            created_at=snapshot.report_at,
        )
        candidate.validate_f1()
        coverage.validate_selection(candidate)
        provenance.validate_selection(candidate)
        recheck_policy(snapshot.policy, release)
        ref = put_record(candidate, release)
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,release_digest,release_ref,selection_"
                "digest,local_verified) VALUES (%s,%s,%s,%s,false)"
            ).format(tx.table("releases")),
            (context.project_id, ref.digest, json_ref(ref), selection_digest),
        )
        return candidate
