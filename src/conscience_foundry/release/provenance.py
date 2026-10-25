"""Immutable run/accounting snapshots and exact selected-operation provenance."""

from __future__ import annotations

import hashlib
from decimal import Decimal, localcontext

from conscience_foundry.contracts.accounting import BudgetEvent, CostSummary, ItemOutcome, RunReport
from conscience_foundry.contracts.canonical import RevisionReview
from conscience_foundry.contracts.common import ContractError, Ref
from conscience_foundry.contracts.release import ProvenanceEntry, ProvenanceReport, ReleaseSource
from conscience_foundry.execution.evidence import identity, limits_for, put_record
from conscience_foundry.release.context import ReleaseContext
from conscience_foundry.release.coverage import Row, Snapshot, outcome, unique_refs


def money_text(value: Decimal) -> str:
    return format(value, "f")


def accounting_events(snapshot: Snapshot, release: ReleaseContext) -> tuple[BudgetEvent, ...]:
    result = []
    bound = limits_for(release, "kf.budget-event.v1")
    for row in snapshot.rows["budget_events"]:
        raw = bytes.fromhex(row["record_bytes"][2:])
        if hashlib.sha256(raw).hexdigest() != row["record_digest"]:
            raise ContractError("hash_mismatch")
        event = BudgetEvent.from_wire(raw, bound)
        if (event.project_id, event.run_id, event.reservation_id, event.event_id) != (
            row["project_id"],
            row["run_id"],
            row["reservation_id"],
            row["event_id"],
        ):
            raise ContractError("hash_mismatch")
        result.append(event)
    return tuple(result)


def cost_summary(snapshot: Snapshot, run_id: str, events: tuple[BudgetEvent, ...]) -> CostSummary:
    reservations = [row for row in snapshot.rows["reservations"] if row["run_id"] == run_id]
    # SQL numeric text is bounded by snapshot acquisition before exact Decimal work.
    with localcontext() as ctx:
        ctx.prec = (
            max(
                (
                    len(str(row[key]))
                    for row in reservations
                    for key in ("reserved_usd", "outstanding_usd", "settled_usd")
                ),
                default=1,
            )
            + len(str(len(reservations)))
            + 10
        )
        settled = sum((Decimal(row["settled_usd"]) for row in reservations), Decimal(0))
        outstanding = sum((Decimal(row["outstanding_usd"]) for row in reservations), Decimal(0))
        estimated = Decimal(0)
        for row in reservations:
            if row["final_billing"]:
                continue
            observed = [
                Decimal(event.amount_usd)
                for event in events
                if event.reservation_id == row["reservation_id"]
                and event.event_type == "record_usage"
                and event.amount_usd is not None
            ]
            estimated += max([Decimal(row["reserved_usd"]), *observed])
    return CostSummary(
        settled_actual_usd=money_text(settled),
        reserved_outstanding_usd=money_text(outstanding),
        estimated_usd=money_text(estimated),
        has_unknown_cost=any(not row["final_billing"] for row in reservations),
    )


def attempt_refs(
    snapshot: Snapshot, *, operation_key: str | None = None, run_id: str | None = None
) -> tuple[Ref, ...]:
    rows = [
        row
        for row in snapshot.rows["attempts"]
        if (operation_key is None or row["operation_key"] == operation_key)
        and (run_id is None or row["run_id"] == run_id)
    ]
    ids = {row["attempt_id"] for row in rows}
    refs = []
    for row in rows:
        if row["attempt_ref"] is None:
            raise ContractError("unavailable")
        refs.append(Ref.model_validate(row["attempt_ref"]))
    for row in snapshot.rows["dispatch_claims"]:
        if row["attempt_id"] in ids:
            refs.extend(
                Ref.model_validate(row[key])
                for key in ("reserved_attempt_ref", "dispatched_attempt_ref")
            )
    for row in snapshot.rows["attempt_observations"]:
        if row["attempt_id"] in ids:
            refs.append(Ref.model_validate(row["attempt_ref"]))
    return unique_refs(refs)


def run_reports(
    snapshot: Snapshot,
    reviews: dict[tuple[str, str], tuple[Row, RevisionReview]],
    release: ReleaseContext,
) -> dict[str, Ref]:
    events = accounting_events(snapshot, release)
    views = {view.ref.digest: view for view in snapshot.admissions}
    reports = {}
    for run in snapshot.rows["runs"]:
        view = views[run["admission_report_digest"]]
        items = []
        for item in view.manifest.items:
            entry = outcome(snapshot, view, item.asset_id, reviews, run_id=run["run_id"])
            items.append(
                ItemOutcome.model_validate(
                    {
                        "assetId": item.asset_id,
                        "status": entry.status,
                        "reasons": entry.reasons,
                        **({"revisionRef": entry.revision_ref} if entry.revision_ref else {}),
                    }
                )
            )
        report = RunReport(
            schema_version="kf.run-report.v1",
            project_id=release.access.project_id,
            run_id=run["run_id"],
            batch_id=view.manifest.batch_id,
            admission_report_ref=view.ref,
            attempts=attempt_refs(snapshot, run_id=run["run_id"]),
            item_outcomes=tuple(items),
            cost_summary=cost_summary(snapshot, run["run_id"], events),
            report_at=snapshot.report_at,
        )
        reports[run["run_id"]] = put_record(report, release)
    return reports


def build_provenance(
    snapshot: Snapshot,
    selected: tuple[ReleaseSource, ...],
    selection_digest: str,
    reviews: dict[tuple[str, str], tuple[Row, RevisionReview]],
    reports: dict[str, Ref],
) -> ProvenanceReport:
    entries = []
    for source in selected:
        matches = [
            row
            for row, _ in reviews.values()
            if identity(Ref.model_validate(row["review_ref"])) == identity(source.review_ref)
            and identity(Ref.model_validate(row["revision_ref"])) == identity(source.revision_ref)
        ]
        if len(matches) != 1:
            raise ContractError("unavailable")
        key = matches[0]["operation_key"]
        selected_records = [
            row
            for row in snapshot.rows["operation_results"]
            if row["operation_key"] == key and row["outcome"] == "selected"
        ]
        if len(selected_records) != 1:
            raise ContractError("unavailable")
        run_ids = sorted(
            {row["run_id"] for row in snapshot.rows["attempts"] if row["operation_key"] == key}
        )
        entries.append(
            ProvenanceEntry(
                source_id=source.source_id,
                revision_ref=source.revision_ref,
                review_ref=source.review_ref,
                operation_result_ref=Ref.model_validate(selected_records[0]["record_ref"]),
                attempt_refs=attempt_refs(snapshot, operation_key=key),
                run_report_refs=tuple(reports[run] for run in run_ids),
            )
        )
    return ProvenanceReport(
        schema_version="kf.provenance-report.v1",
        project_id=snapshot.policy.project_id,
        selection_digest=selection_digest,
        entries=tuple(entries),
        report_at=snapshot.report_at,
    )
