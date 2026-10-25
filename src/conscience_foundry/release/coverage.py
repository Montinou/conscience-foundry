"""Bounded authoritative admission snapshots and truthful per-item coverage."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from psycopg import sql

from conscience_foundry.contracts.admission import AdmissionReport, IntakeManifest
from conscience_foundry.contracts.canonical import RevisionReview
from conscience_foundry.contracts.common import ContractError, Reason, Ref
from conscience_foundry.contracts.project import PolicyArtifact
from conscience_foundry.contracts.release import CoverageEntry, CoverageReport, ReleaseSource
from conscience_foundry.execution.evidence import (
    clock,
    current_policy,
    identity,
    limits_for,
    read_model,
)
from conscience_foundry.ledger.db import LedgerTxn
from conscience_foundry.policy.access import AccessContext, require_permission
from conscience_foundry.release.context import (
    ReleaseContext,
    bounded_model,
    request_bytes,
    require_audit,
)

Row = dict[str, Any]


@dataclass(frozen=True)
class AdmissionView:
    ref: Ref
    manifest: IntakeManifest
    report: AdmissionReport


@dataclass(frozen=True)
class Snapshot:
    admissions: tuple[AdmissionView, ...]
    supplied: tuple[Ref, ...]
    rows: dict[str, tuple[Row, ...]]
    policy: PolicyArtifact
    access: AccessContext
    report_at: str
    digest: str


@dataclass
class QueryBudget:
    rows: int = 0
    size: int = 0


_MONEY_COLUMNS = {
    "runs": ("max_run_cost",),
    "authorizations": ("max_run_cost",),
    "reservations": ("reserved_usd", "outstanding_usd", "settled_usd", "released_usd"),
}


def bounded_rows(
    tx: LedgerTxn,
    table: str,
    where: sql.Composable,
    parameters: tuple[object, ...],
    release: ReleaseContext,
    budget: QueryBudget | None = None,
) -> tuple[Row, ...]:
    """Server-side count and encoded-byte gates precede Python materialization."""
    bound = limits_for(release, "kf.coverage-report.v1")
    projection: sql.Composable = sql.SQL("to_jsonb(t)")
    money = _MONEY_COLUMNS.get(table, ())
    if money:
        pairs = sql.SQL(",").join(
            sql.SQL("{},t.{}::text").format(sql.Literal(key), sql.Identifier(key)) for key in money
        )
        projection = sql.SQL("to_jsonb(t) || jsonb_build_object({})").format(pairs)
    query = sql.SQL("SELECT {} AS record FROM {} t WHERE {} LIMIT %s").format(
        projection, tx.table(table), where
    )
    args = (*parameters, bound.max_array_items + 1)
    count, size = tx.connection.execute(
        sql.SQL("SELECT count(*),COALESCE(sum(octet_length(record::text)),0) FROM ({}) q").format(
            query
        ),
        args,
    ).fetchone()  # type: ignore[misc]
    if count > bound.max_array_items or size > min(bound.max_json_bytes, bound.max_output_bytes):
        raise ContractError("limit_exceeded")
    if budget is not None:
        budget.rows += count
        budget.size += size
        if budget.rows > bound.max_array_items or budget.size > min(
            bound.max_json_bytes, bound.max_output_bytes
        ):
            raise ContractError("limit_exceeded")
    return tuple(row[0] for row in tx.connection.execute(query, args).fetchall())


def metadata_ids(
    tx: LedgerTxn,
    query: sql.Composable,
    parameters: tuple[object, ...],
    release: ReleaseContext,
) -> tuple[tuple[str, ...], ...]:
    """Minimal identity routing is used only to evaluate all-source audit access."""
    bound = limits_for(release, "kf.coverage-report.v1")
    guarded = sql.SQL("SELECT * FROM ({}) routing LIMIT %s").format(query)
    count, size = tx.connection.execute(
        sql.SQL(
            "SELECT count(*),COALESCE(sum(octet_length(row_to_json(r)::text)),0) FROM ({}) r"
        ).format(guarded),
        (*parameters, bound.max_array_items + 1),
    ).fetchone()  # type: ignore[misc]
    if count > bound.max_array_items or size > min(bound.max_json_bytes, bound.max_output_bytes):
        raise ContractError("limit_exceeded")
    return tuple(
        tuple(str(value) for value in row)
        for row in tx.connection.execute(
            guarded, (*parameters, bound.max_array_items + 1)
        ).fetchall()
    )


def capture(
    admissions: tuple[Ref, ...],
    tx: LedgerTxn,
    release: ReleaseContext,
) -> Snapshot:
    project = release.access.project_id
    if "auditMetadataRead" not in release.access.scopes:
        raise ContractError("forbidden")
    bound = limits_for(release, "kf.coverage-report.v1")
    if type(admissions) is not tuple or not admissions or len(admissions) > bound.max_array_items:
        raise ContractError("invalid_schema")
    for ref in admissions:
        if (
            type(ref) is not Ref
            or ref.project_id != project
            or ref.artifact_schema != "kf.admission-report.v1"
        ):
            raise ContractError("invalid_schema")
        bounded_model(ref, release, "kf.artifact-ref.v1")
    if len({identity(ref) for ref in admissions}) != len(admissions):
        raise ContractError("invalid_schema")
    tx.lock(project)
    digests = tuple(ref.digest for ref in admissions)
    # No administrative payload is retrieved before this fixed identity-only
    # routing finds every source implicated by supplied batches and related runs.
    assets = tuple(
        row[0]
        for row in metadata_ids(
            tx,
            sql.SQL(
                "SELECT asset_id::text FROM {} WHERE project_id=%s AND report_digest=ANY(%s)"
            ).format(tx.table("admission_entries")),
            (project, list(digests)),
            release,
        )
    )
    ops = tuple(
        row[0]
        for row in metadata_ids(
            tx,
            sql.SQL(
                "SELECT operation_key FROM {} WHERE project_id=%s AND asset_id=ANY(%s::uuid[])"
            ).format(tx.table("operations")),
            (project, list(assets)),
            release,
        )
    )
    runs = metadata_ids(
        tx,
        sql.SQL(
            "SELECT run_id::text,admission_report_digest FROM {} WHERE "
            "project_id=%s AND (admission_report_digest=ANY(%s) OR run_id IN "
            "(SELECT run_id FROM {} WHERE project_id=%s AND "
            "operation_key=ANY(%s)))"
        ).format(tx.table("runs"), tx.table("attempts")),
        (project, list(digests), project, list(ops)),
        release,
    )
    run_ids = tuple(row[0] for row in runs)
    all_digests = tuple(sorted(set(digests) | {row[1] for row in runs}))
    sources = tuple(
        row[0]
        for row in metadata_ids(
            tx,
            sql.SQL(
                "SELECT DISTINCT source_id::text FROM {} WHERE project_id=%s AND "
                "report_digest=ANY(%s)"
            ).format(tx.table("admission_entries")),
            (project, list(all_digests)),
            release,
        )
    )
    policy = current_policy(release, project)
    require_audit(release, policy, sources)
    budget = QueryBudget()
    rows: dict[str, tuple[Row, ...]] = {}
    rows["admission_reports"] = bounded_rows(
        tx,
        "admission_reports",
        sql.SQL("t.project_id=%s AND t.report_digest=ANY(%s)"),
        (project, list(all_digests)),
        release,
        budget,
    )
    by_digest = {row["report_digest"]: row for row in rows["admission_reports"]}
    if set(by_digest) != set(all_digests):
        raise ContractError("unavailable")
    for ref in admissions:
        if identity(Ref.model_validate(by_digest[ref.digest]["report_ref"])) != identity(ref):
            raise ContractError("hash_mismatch")
    batch_ids = list({row["batch_id"] for row in rows["admission_reports"]})
    rows["batches"] = bounded_rows(
        tx,
        "batches",
        sql.SQL("t.project_id=%s AND t.batch_id=ANY(%s::uuid[])"),
        (project, batch_ids),
        release,
        budget,
    )
    batches = {row["batch_id"]: row for row in rows["batches"]}
    views = []
    for digest in all_digests:
        row = by_digest[digest]
        ref = Ref.model_validate(row["report_ref"])
        manifest_ref = Ref.model_validate(batches[row["batch_id"]]["manifest_ref"])
        policy_ref = Ref.model_validate(row["policy_ref"])
        _, manifest = read_model(manifest_ref, IntakeManifest, release)
        _, report = read_model(ref, AdmissionReport, release)
        _, pinned = read_model(policy_ref, PolicyArtifact, release)
        if report.manifest_digest != manifest_ref.digest or identity(
            manifest.policy_ref
        ) != identity(policy_ref):
            raise ContractError("hash_mismatch")
        report.validate_manifest(manifest, pinned)
        require_audit(release, policy, tuple(item.source_id for item in manifest.items))
        views.append(AdmissionView(ref, manifest, report))
    rows["admission_entries"] = bounded_rows(
        tx,
        "admission_entries",
        sql.SQL("t.project_id=%s AND t.report_digest=ANY(%s)"),
        (project, list(all_digests)),
        release,
        budget,
    )
    all_assets = list({entry["asset_id"] for entry in rows["admission_entries"]})
    rows["assets"] = bounded_rows(
        tx,
        "assets",
        sql.SQL("t.project_id=%s AND t.asset_id=ANY(%s::uuid[])"),
        (project, all_assets),
        release,
        budget,
    )
    rows["runs"] = bounded_rows(
        tx,
        "runs",
        sql.SQL("t.project_id=%s AND t.run_id=ANY(%s::uuid[])"),
        (project, list(run_ids)),
        release,
        budget,
    )
    rows["attempts"] = bounded_rows(
        tx,
        "attempts",
        sql.SQL("t.project_id=%s AND (t.run_id=ANY(%s::uuid[]) OR t.operation_key=ANY(%s))"),
        (project, list(run_ids), list(ops)),
        release,
        budget,
    )
    all_ops = list(set(ops) | {row["operation_key"] for row in rows["attempts"]})
    attempts = list({row["attempt_id"] for row in rows["attempts"]})
    for table in (
        "authorizations",
        "plans",
        "reservations",
        "budget_events",
        "billing_adjustments",
    ):
        rows[table] = bounded_rows(
            tx,
            table,
            sql.SQL("t.project_id=%s AND t.run_id=ANY(%s::uuid[])"),
            (project, list(run_ids)),
            release,
            budget,
        )
    for table in ("operations", "operation_results", "integrity_holds", "reviews"):
        rows[table] = bounded_rows(
            tx,
            table,
            sql.SQL("t.project_id=%s AND t.operation_key=ANY(%s)"),
            (project, all_ops),
            release,
            budget,
        )
    for table in ("dispatch_claims", "attempt_observations"):
        rows[table] = bounded_rows(
            tx,
            table,
            sql.SQL("t.project_id=%s AND t.attempt_id=ANY(%s::uuid[])"),
            (project, attempts),
            release,
            budget,
        )
    rows["admission_withdrawals"] = bounded_rows(
        tx,
        "admission_withdrawals",
        sql.SQL("t.project_id=%s AND t.batch_id=ANY(%s::uuid[]) AND t.asset_id=ANY(%s::uuid[])"),
        (project, batch_ids, all_assets),
        release,
        budget,
    )
    # Stable ordering is independent of database scan order.
    import json

    for table in rows:
        rows[table] = tuple(sorted(rows[table], key=lambda row: json.dumps(row, sort_keys=True)))
    projection = {
        table: [
            {
                key: (
                    {
                        "digest": hashlib.sha256(bytes.fromhex(value[2:])).hexdigest(),
                        "sizeBytes": (len(value) - 2) // 2,
                    }
                    if key == "record_bytes"
                    else value
                )
                for key, value in row.items()
            }
            for row in values
        ]
        for table, values in rows.items()
    }
    raw = request_bytes(
        {"rows": projection, "policy": policy.model_dump(mode="json", by_alias=True)}, release
    )
    return Snapshot(
        tuple(views),
        admissions,
        rows,
        policy,
        release.access,
        clock(release),
        hashlib.sha256(b"kf.release-snapshot.internal.v1\n" + raw).hexdigest(),
    )


def unique_refs(refs: list[Ref]) -> tuple[Ref, ...]:
    result: dict[tuple[object, ...], Ref] = {}
    for ref in refs:
        result.setdefault(identity(ref), ref)
    return tuple(result.values())


def review_records(
    snapshot: Snapshot, release: ReleaseContext
) -> dict[tuple[str, str], tuple[Row, RevisionReview]]:
    grouped: dict[tuple[str, str], list[tuple[Row, RevisionReview]]] = {}
    for row in snapshot.rows["reviews"]:
        _, review = read_model(Ref.model_validate(row["review_ref"]), RevisionReview, release)
        if (review.project_id, review.actor_id, review.revision_id) != (
            release.access.project_id,
            row["actor_id"],
            row["revision_digest"],
        ):
            raise ContractError("hash_mismatch")
        key = row["operation_key"], Ref.model_validate(row["revision_ref"]).digest
        grouped.setdefault(key, []).append((row, review))
    latest = {}
    for key, values in grouped.items():
        stamp = max(review.reviewed_at for _, review in values)
        candidates = [pair for pair in values if pair[1].reviewed_at == stamp]
        if len({pair[1].decision for pair in candidates}) != 1:
            raise ContractError("unavailable")
        latest[key] = candidates[-1]
    return latest


def outcome(
    snapshot: Snapshot,
    view: AdmissionView,
    asset_id: str,
    reviews: dict[tuple[str, str], tuple[Row, RevisionReview]],
    selected: ReleaseSource | None = None,
    *,
    run_id: str | None = None,
) -> CoverageEntry:
    entry = next(entry for entry in view.report.entries if entry.asset_id == asset_id)
    reasons = [Reason(code="unavailable", message="Not selected for this release")]
    evidence = [view.ref]
    withdrawn = [
        row
        for row in snapshot.rows["admission_withdrawals"]
        if row["batch_id"] == view.manifest.batch_id and row["asset_id"] == asset_id
    ]
    status = "pending"
    revision: Ref | None = None
    chosen = False
    if withdrawn:
        status = "withdrawn"
        evidence.extend(Ref.model_validate(row["evidence_ref"]) for row in withdrawn)
        reasons = [Reason.model_validate(row["reason"]) for row in withdrawn]
    elif entry.status != "admitted":
        status = "blocked"
        reasons = list(entry.reasons) or [Reason(code="forbidden", message="Admission unavailable")]
    else:
        try:
            for effect in ("read", "extract"):
                # No content is acquired here; this only classifies current eligibility.
                require_permission(snapshot.access, snapshot.policy, entry.source_id, effect)
        except ContractError:
            status = "blocked"
            reasons = [Reason(code="forbidden", message="Current source content is unavailable")]
        else:
            operations = [row for row in snapshot.rows["operations"] if row["asset_id"] == asset_id]
            if run_id is not None:
                keys = {
                    row["operation_key"]
                    for row in snapshot.rows["attempts"]
                    if row["run_id"] == run_id
                }
                operations = [row for row in operations if row["operation_key"] in keys]
            keys = {row["operation_key"] for row in operations}
            records = [
                row for row in snapshot.rows["operation_results"] if row["operation_key"] in keys
            ]
            evidence.extend(Ref.model_validate(row["record_ref"]) for row in records)
            evidence.extend(
                Ref.model_validate(row["evidence_ref"])
                for row in snapshot.rows["integrity_holds"]
                if row["operation_key"] in keys
            )
            candidates = [
                (row, review)
                for (op, _), (row, review) in reviews.items()
                if op in keys
                and review.decision == "accepted"
                and not any(item["operation_key"] == op and item["held"] for item in operations)
            ]
            if selected is not None:
                candidates = [
                    (row, review)
                    for row, review in candidates
                    if identity(Ref.model_validate(row["revision_ref"]))
                    == identity(selected.revision_ref)
                    and identity(Ref.model_validate(row["review_ref"]))
                    == identity(selected.review_ref)
                ]
            if len(candidates) > 1:
                raise ContractError("unavailable")
            if candidates:
                row, _ = candidates[0]
                revision = Ref.model_validate(row["revision_ref"])
                evidence.append(Ref.model_validate(row["review_ref"]))
                status = "accepted"
                chosen = selected is not None
                reasons = [] if chosen else reasons
            elif any(row["held"] for row in operations):
                status = "blocked"
                reasons = [Reason(code="determinism_conflict", message="Operation integrity hold")]
            elif any(row["selected_result_ref"] for row in operations):
                status = "needs_review"
                reasons = [Reason(code="unavailable", message="Operator acceptance required")]
            else:
                attempts = [
                    row for row in snapshot.rows["attempts"] if row["operation_key"] in keys
                ]
                if any(
                    row["state"]
                    in {
                        "planned",
                        "reserved",
                        "dispatching",
                        "running",
                        "unknown_outcome",
                        "cancel_requested",
                    }
                    for row in attempts
                ):
                    status = "running"
                elif attempts:
                    status = "failed"
                    reasons = [
                        Reason(code="remote_failed", message="No eligible canonical candidate")
                    ]
    return CoverageEntry.model_validate(
        {
            "batchId": view.manifest.batch_id,
            "assetId": asset_id,
            "sourceId": entry.source_id,
            "status": status,
            "selected": chosen,
            "outcomeEvidenceRefs": unique_refs(evidence),
            "reasons": reasons,
            **({"revisionRef": revision} if revision is not None else {}),
        }
    )


def build_coverage(
    snapshot: Snapshot,
    selected: tuple[ReleaseSource, ...],
    selection_digest: str,
    reviews: dict[tuple[str, str], tuple[Row, RevisionReview]],
) -> CoverageReport:
    selected_by_source = {source.source_id: source for source in selected}
    entries = []
    for view in snapshot.admissions:
        if identity(view.ref) not in {identity(ref) for ref in snapshot.supplied}:
            continue
        for item in view.manifest.items:
            choice = selected_by_source.get(item.source_id)
            # The exact persisted review-operation linkage identifies the selected asset.
            if choice is not None and not any(
                row["asset_id"] == item.asset_id
                and any(
                    key[0] == row["operation_key"]
                    and identity(Ref.model_validate(pair[0]["revision_ref"]))
                    == identity(choice.revision_ref)
                    for key, pair in reviews.items()
                )
                for row in snapshot.rows["operations"]
            ):
                choice = None
            entries.append(outcome(snapshot, view, item.asset_id, reviews, choice))
    return CoverageReport(
        schema_version="kf.coverage-report.v1",
        project_id=snapshot.policy.project_id,
        selection_digest=selection_digest,
        admission_report_refs=snapshot.supplied,
        entries=tuple(sorted(entries, key=lambda entry: (entry.batch_id, entry.asset_id))),
        report_at=snapshot.report_at,
    )
