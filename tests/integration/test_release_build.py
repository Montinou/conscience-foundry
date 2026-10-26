"""Synthetic private release assembly; excluded content is never traversed."""

from __future__ import annotations

import hashlib
import io
import json
from collections.abc import Callable
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
import test_execution_control as execution_case
from psycopg import sql
from test_execution_control import Case, Executor
from test_ledger_db import (
    ACTOR,
    ASSET,
    BATCH,
    PROJECT,
    RUN,
    TIME,
    Admission,
    admission,
    encoded,
    reference,
)

from conscience_foundry.contracts.accounting import BudgetEvent, RunReport
from conscience_foundry.contracts.admission import IntakeManifest
from conscience_foundry.contracts.canonical import RevisionReview
from conscience_foundry.contracts.common import ContractError, Reason, Ref
from conscience_foundry.contracts.execution import ResultManifest
from conscience_foundry.contracts.release import CoverageReport, ProvenanceReport, ReleaseSource
from conscience_foundry.execution.control import reconcile
from conscience_foundry.ledger.attempts import json_ref
from conscience_foundry.ledger.db import Ledger
from conscience_foundry.release.build import (
    build_release,
    record_admission_withdrawal,
    record_review,
)
from conscience_foundry.release.context import ReleaseApproval, ReleaseContext
from conscience_foundry.release.coverage import Snapshot, bounded_rows
from conscience_foundry.release.provenance import cost_summary

pytestmark = pytest.mark.database
B_ASSET = "00000000-0000-0000-0000-000000000009"
B_SOURCE = "00000000-0000-0000-0000-000000000008"


def two_sources(first: bytes = b"Synthetic text") -> Admission:
    data = admission(extra_asset=True)
    manifest = IntakeManifest.from_wire(
        data.evidence.manifest_bytes, data.evidence.limits_by_schema["kf.intake.v1"]
    )
    refs = [
        reference(payload, "kf.raw-original.v1").model_copy(update={"media_type": "text/plain"})
        for payload in (first, b"Excluded synthetic source")
    ]
    items = tuple(
        item.model_copy(update={"original_digest": ref.digest, "size_bytes": ref.size_bytes})
        for item, ref in zip(manifest.items, refs, strict=True)
    )
    manifest = manifest.model_copy(update={"items": items})
    raw = encoded(manifest)
    report = data.report.model_copy(
        update={
            "manifest_digest": hashlib.sha256(raw).hexdigest(),
            "entries": tuple(
                entry.model_copy(update={"snapshot_ref": ref})
                for entry, ref in zip(data.report.entries, refs, strict=True)
            ),
        }
    )
    report_bytes = encoded(report)
    return Admission(
        reference(raw, manifest.schema_version),
        report,
        reference(report_bytes, report.schema_version),
        replace(data.evidence, manifest_bytes=raw, report_bytes=report_bytes),
    )


def approval_request(value: object) -> bytes:
    import json

    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


class Authority:
    """Independent synthetic approval policy, not document-supplied actor authority."""

    def __init__(self) -> None:
        self.allowed: set[tuple[str, bytes]] = set()
        self.fail = False
        self.wrong_binding = False
        self.hook: Callable[[], None] | None = None

    def approve(self, proof: Any) -> ReleaseApproval:
        import json

        request = json.loads(proof.request_bytes)
        if self.hook is not None:
            self.hook()
        if self.fail:
            raise ContractError("forbidden")
        # Fixtures pre-register exact review bytes, selection or withdrawal identity.
        if proof.action == "record_review":
            key = proof.action, proof.request_bytes
        else:
            key = (
                proof.action,
                approval_request({k: v for k, v in request.items() if k != "stateDigest"}),
            )
        if key not in self.allowed:
            raise ContractError("forbidden")
        return ReleaseApproval(
            project_id=PROJECT,
            actor_id=ACTOR,
            action=proof.action,
            request_digest="0" * 64
            if self.wrong_binding
            else hashlib.sha256(proof.request_bytes).hexdigest(),
            state_digest=proof.state_digest,
            evidence_digest=proof.evidence_ref.digest if proof.evidence_ref else None,
            revision_ref=proof.revision_ref,
        )


class ReleaseCase:
    def __init__(self, case: Case, ledger: Ledger) -> None:
        self.case, self.ledger = case, ledger
        self.authority = Authority()
        # Every digest the store is asked for, by a bounded read or by a verified open (the
        # backup, restore and retention copies), so a test can see content that was touched.
        self.reads: list[str] = []
        self.read = case.store.read_verified
        self.open = case.store.open_verified

        def record(ref: Ref, access: Any, limit: int) -> Any:
            self.reads.append(ref.digest)
            return self.read(ref, access, limit)

        def record_open(ref: Ref, access: Any) -> Any:
            self.reads.append(ref.digest)
            return self.open(ref, access)

        case.store.read_verified = record  # type: ignore[method-assign]
        case.store.open_verified = record_open  # type: ignore[method-assign]
        self.release = ReleaseContext(
            case.access,
            case.store,
            lambda: TIME,
            case.schemas,
            "synthetic",
            lambda project: case.policy,
            self.authority,
        )

    def review(
        self,
        revision_ref: Ref,
        *,
        decision: str = "accepted",
        approved: bool = True,
        reviewed_at: str = TIME,
        reason: str = "Synthetic operator decision",
        **overrides: Any,
    ) -> Ref:
        revision = self.read(revision_ref, self.case.access, 65536).data
        import json

        logical = json.loads(revision)["revisionId"]
        fields: dict[str, Any] = {
            "schema_version": "kf.revision-review.v1",
            "project_id": PROJECT,
            "revision_id": logical,
            "decision": decision,
            "actor_id": ACTOR,
            "policy_version": self.case.policy.policy_version,
            "reviewed_at": reviewed_at,
            "reason": Reason(code="unavailable", message=reason),
        }
        review = RevisionReview(**{**fields, **overrides})
        raw = encoded(review)
        if approved:
            self.authority.allowed.add(("record_review", raw))
        return self.submit(review, raw, revision_ref)

    def submit(self, review: RevisionReview, raw: bytes, revision_ref: Ref) -> Ref:
        return record_review(
            review,
            self.case.access,
            self.ledger,
            self.case.store,
            release=self.release,
            operation_key=self.case.plan.operation_key,
            revision_ref=revision_ref,
            review_bytes=raw,
            evidence_ref=self.case.data.report_ref,
        )

    def count(self, table: str) -> int:
        with self.ledger.transaction() as tx:
            row = tx.connection.execute(
                sql.SQL("SELECT count(*) FROM {}").format(tx.table(table))
            ).fetchone()
            assert row is not None
            return int(row[0])

    def build(self, selected: tuple[ReleaseSource, ...], **overrides: Any) -> Any:
        arguments: dict[str, Any] = {"release": self.release, **overrides}
        return build_release(
            selected,
            (self.case.data.report_ref,),
            self.case.access,
            self.ledger,
            self.case.store,
            **arguments,
        )

    def allow_build(self, selected: tuple[ReleaseSource, ...]) -> None:
        self.authority.allowed.add(
            (
                "build_release",
                approval_request(
                    {
                        "sourceEntries": [
                            s.model_dump(mode="json", by_alias=True) for s in selected
                        ],
                        "admissionReportRefs": [
                            self.case.data.report_ref.model_dump(mode="json", by_alias=True)
                        ],
                    }
                ),
            )
        )


def make_case(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, first: bytes
) -> ReleaseCase:
    data = two_sources(first)
    monkeypatch.setattr(execution_case, "admission", lambda: data)
    case = Case(tmp_path, source_bytes=first)
    second = data.report.entries[1].snapshot_ref
    assert second is not None
    case.store.put_verified(io.BytesIO(b"Excluded synthetic source"), second, case.access)
    case.setup(ledger)
    return ReleaseCase(case, ledger)


@pytest.fixture
def release_case(ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReleaseCase:
    return make_case(ledger, tmp_path, monkeypatch, b"Synthetic text")


def produced_revision(value: ReleaseCase) -> Ref:
    case = value.case
    executor = Executor(case)
    attempt = case.dispatch(value.ledger, executor)
    result_ref = executor.success(attempt)
    assert reconcile(attempt.attempt_id, value.ledger, executor, case.store, control=case.control)
    result = ResultManifest.from_wire(value.read(result_ref, case.access, 65536).data, case.bound)
    assert result.document_revision_ref is not None
    return result.document_revision_ref


def selected_source(value: ReleaseCase) -> ReleaseSource:
    revision_ref = produced_revision(value)
    return ReleaseSource(
        source_id=value.case.data.report.entries[0].source_id,
        revision_ref=revision_ref,
        review_ref=value.review(revision_ref),
    )


def deny_b(value: ReleaseCase, *, audit: str = "allow") -> None:
    sources = tuple(
        source.model_copy(update={"read": "deny", "extract": "deny", "audit_metadata_read": audit})
        if source.source_id == B_SOURCE
        else source
        for source in value.case.policy.sources
    )
    value.case.policy = value.case.policy.model_copy(update={"sources": sources})


def test_partial_release_keeps_revoked_denominator(release_case: ReleaseCase) -> None:
    selected = (selected_source(release_case),)
    deny_b(release_case)
    value = release_case
    reason = Reason(code="forbidden", message="Synthetic admission withdrawn")
    decision_id = str(uuid4())
    value.authority.allowed.add(
        (
            "withdraw_admission",
            approval_request(
                {
                    "projectId": PROJECT,
                    "batchId": BATCH,
                    "assetId": B_ASSET,
                    "sourceId": B_SOURCE,
                    "decisionId": decision_id,
                    "actorId": ACTOR,
                    "reason": reason.model_dump(mode="json", by_alias=True),
                    "decidedAt": TIME,
                    "evidenceRef": value.case.data.report_ref.model_dump(
                        mode="json", by_alias=True
                    ),
                }
            ),
        )
    )
    record_admission_withdrawal(
        BATCH,
        B_ASSET,
        decision_id,
        value.case.access,
        value.ledger,
        value.case.store,
        release=value.release,
        reason=reason,
        evidence_ref=value.case.data.report_ref,
    )
    value.allow_build(selected)
    value.reads.clear()
    result = build_release(
        selected,
        (value.case.data.report_ref,),
        value.case.access,
        value.ledger,
        value.case.store,
        release=value.release,
    )
    coverage = CoverageReport.from_wire(
        value.read(result.coverage_report_ref, value.case.access, 65536).data, value.case.bound
    )
    provenance = ProvenanceReport.from_wire(
        value.read(result.provenance_report_ref, value.case.access, 65536).data, value.case.bound
    )
    assert [s.source_id for s in result.source_entries] == [selected[0].source_id]
    assert [e.asset_id for e in coverage.entries] == [ASSET, B_ASSET]
    assert coverage.entries[1].status == "withdrawn"
    assert coverage.entries[0].selected and not coverage.entries[1].selected
    assert provenance.entries[0].revision_ref == selected[0].revision_ref
    assert value.case.data.report.entries[1].snapshot_ref.digest not in value.reads  # type: ignore[union-attr]
    with value.ledger.transaction() as tx:
        assert tx.connection.execute(
            sql.SQL("SELECT local_verified FROM {}").format(tx.table("releases"))
        ).fetchone() == (False,)


@pytest.mark.parametrize("audit", ["deny", "unknown"])
def test_audit_permission_is_not_content_permission(release_case: ReleaseCase, audit: str) -> None:
    selected = (selected_source(release_case),)
    release_case.allow_build(selected)
    deny_b(release_case, audit=audit)
    release_case.reads.clear()
    with pytest.raises(ContractError):
        build_release(
            selected,
            (release_case.case.data.report_ref,),
            release_case.case.access,
            release_case.ledger,
            release_case.case.store,
            release=release_case.release,
        )
    assert release_case.reads == []


def withdraw(
    value: ReleaseCase, decision_id: str, reason: Reason, *, asset_id: str = B_ASSET, **extra: Any
) -> str:
    source = B_SOURCE if asset_id == B_ASSET else value.case.data.report.entries[0].source_id
    value.authority.allowed.add(
        (
            "withdraw_admission",
            approval_request(
                {
                    "projectId": PROJECT,
                    "batchId": BATCH,
                    "assetId": asset_id,
                    "sourceId": source,
                    "decisionId": decision_id,
                    "actorId": ACTOR,
                    "reason": reason.model_dump(mode="json", by_alias=True),
                    "decidedAt": TIME,
                    "evidenceRef": value.case.data.report_ref.model_dump(
                        mode="json", by_alias=True
                    ),
                }
            ),
        )
    )
    return record_admission_withdrawal(
        BATCH,
        asset_id,
        decision_id,
        value.case.access,
        value.ledger,
        value.case.store,
        release=value.release,
        reason=reason,
        evidence_ref=value.case.data.report_ref,
        **extra,
    )


def code(error: pytest.ExceptionInfo[ContractError]) -> str:
    return error.value.code


def test_whitespace_only_text_is_reviewable_but_never_accepted(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = make_case(ledger, tmp_path, monkeypatch, " \n\t\u00a0 ".encode())
    revision_ref = produced_revision(value)
    with pytest.raises(ContractError):
        value.review(revision_ref)
    assert value.count("reviews") == 0
    held = value.review(revision_ref, decision="needs_review")
    assert value.count("reviews") == 1
    source = ReleaseSource(
        source_id=value.case.data.report.entries[0].source_id,
        revision_ref=revision_ref,
        review_ref=held,
    )
    value.allow_build((source,))
    with pytest.raises(ContractError) as error:
        value.build((source,))
    assert code(error) == "forbidden"
    assert value.count("releases") == 0


def test_alternate_wrapper_with_same_logical_revision_is_not_interchangeable(
    release_case: ReleaseCase,
) -> None:
    import json

    value = release_case
    revision_ref = produced_revision(value)
    raw = value.read(revision_ref, value.case.access, 65536).data
    alternate = json.dumps(json.loads(raw), indent=1, sort_keys=True).encode()
    assert alternate != raw
    alternate_ref = reference(alternate, "kf.document-revision.v1")
    value.case.store.put_verified(io.BytesIO(alternate), alternate_ref, value.case.access)
    with pytest.raises(ContractError):
        value.review(alternate_ref)
    assert value.count("reviews") == 0
    review_ref = value.review(revision_ref)
    swapped = ReleaseSource(
        source_id=value.case.data.report.entries[0].source_id,
        revision_ref=alternate_ref,
        review_ref=review_ref,
    )
    value.allow_build((swapped,))
    with pytest.raises(ContractError) as error:
        value.build((swapped,))
    assert code(error) == "forbidden"
    with value.ledger.transaction() as tx:
        stored = tx.connection.execute(
            sql.SQL("SELECT revision_digest,revision_ref->>'digest' FROM {}").format(
                tx.table("reviews")
            )
        ).fetchall()
    logical = json.loads(raw)["revisionId"]
    assert stored == [(logical, revision_ref.digest)]
    assert logical != revision_ref.digest


def test_review_requires_exact_independent_approval_and_binding(
    release_case: ReleaseCase,
) -> None:
    value = release_case
    revision_ref = produced_revision(value)
    with pytest.raises(ContractError):
        value.review(revision_ref, approved=False)
    value.authority.wrong_binding = True
    with pytest.raises(ContractError):
        value.review(revision_ref)
    value.authority.wrong_binding = False
    value.authority.fail = True
    with pytest.raises(ContractError):
        value.review(revision_ref)
    value.authority.fail = False
    with pytest.raises(ContractError):
        value.review(revision_ref, actor_id=B_SOURCE)
    with pytest.raises(ContractError) as error:
        value.review(revision_ref, policy_version="stale.v0")
    assert code(error) == "permission_unknown"
    review = RevisionReview(
        schema_version="kf.revision-review.v1",
        project_id=PROJECT,
        revision_id="e" * 64,
        decision="accepted",
        actor_id=ACTOR,
        policy_version=value.case.policy.policy_version,
        reviewed_at=TIME,
        reason=Reason(code="unavailable", message="Different logical revision"),
    )
    raw = encoded(review)
    value.authority.allowed.add(("record_review", raw))
    with pytest.raises(ContractError):
        value.submit(review, raw, revision_ref)
    other = review.model_copy(update={"decision": "rejected"})
    with pytest.raises(ContractError):
        value.submit(other, raw, revision_ref)
    assert value.count("reviews") == 0
    assert value.review(revision_ref)
    assert value.count("reviews") == 1


def test_review_context_must_agree_with_trusted_inputs(release_case: ReleaseCase) -> None:
    value = release_case
    revision_ref = produced_revision(value)
    other = replace(value.release, access=replace(value.case.access, actor_id=B_SOURCE))
    with pytest.raises(ContractError):
        build_release(
            (),
            (value.case.data.report_ref,),
            value.case.access,
            value.ledger,
            value.case.store,
            release=other,
        )
    with pytest.raises(ContractError):
        value.build((), release=other)
    foreign = replace(value.release, store=object())  # type: ignore[arg-type]
    with pytest.raises(ContractError):
        value.build((), release=foreign)
    assert value.review(revision_ref)


def test_review_records_are_append_only_and_latest_wins(release_case: ReleaseCase) -> None:
    value = release_case
    revision_ref = produced_revision(value)
    earlier = "2026-10-24T00:00:00.000Z"
    rejected = value.review(revision_ref, decision="rejected", reviewed_at=earlier)
    assert value.review(revision_ref, decision="rejected", reviewed_at=earlier) == rejected
    assert value.count("reviews") == 1
    accepted = value.review(revision_ref)
    assert accepted != rejected and value.count("reviews") == 2
    source = ReleaseSource(
        source_id=value.case.data.report.entries[0].source_id,
        revision_ref=revision_ref,
        review_ref=accepted,
    )
    value.allow_build((source,))
    assert value.build((source,)).source_entries == (source,)
    stale = source.model_copy(update={"review_ref": rejected})
    value.allow_build((stale,))
    with pytest.raises(ContractError) as error:
        value.build((stale,))
    assert code(error) == "forbidden"


def test_same_instant_contradictory_reviews_block_release(release_case: ReleaseCase) -> None:
    value = release_case
    revision_ref = produced_revision(value)
    accepted = value.review(revision_ref)
    value.review(revision_ref, decision="rejected", reason="Same instant contradiction")
    source = ReleaseSource(
        source_id=value.case.data.report.entries[0].source_id,
        revision_ref=revision_ref,
        review_ref=accepted,
    )
    value.allow_build((source,))
    with pytest.raises(ContractError) as error:
        value.build((source,))
    assert code(error) == "unavailable"
    assert value.count("releases") == 0


def test_integrity_hold_blocks_review_and_release(release_case: ReleaseCase) -> None:
    value = release_case
    source = selected_source(value)
    key = value.case.plan.operation_key
    with value.ledger.transaction() as tx:
        tx.lock(PROJECT)
        tx.connection.execute(
            sql.SQL("UPDATE {} SET held=true WHERE operation_key=%s").format(
                tx.table("operations")
            ),
            (key,),
        )
        tx.connection.execute(
            sql.SQL("INSERT INTO {} VALUES (%s,%s,%s,%s,%s)").format(tx.table("integrity_holds")),
            (
                PROJECT,
                str(uuid4()),
                key,
                json_ref(value.case.data.report_ref),
                TIME,
            ),
        )
    value.allow_build((source,))
    with pytest.raises(ContractError):
        value.build((source,))
    with pytest.raises(ContractError):
        value.review(source.revision_ref, reason="Cannot override integrity hold")
    assert value.count("releases") == 0 and value.count("reviews") == 1


def test_withdrawal_is_exact_replay_noop_and_scoped(release_case: ReleaseCase) -> None:
    value = release_case
    decision = str(uuid4())
    reason = Reason(code="forbidden", message="Synthetic admission withdrawn")
    assert withdraw(value, decision, reason) == decision
    assert withdraw(value, decision, reason) == decision
    assert value.count("admission_withdrawals") == 1
    changed = Reason(code="forbidden", message="A different justification")
    with pytest.raises(ContractError) as error:
        withdraw(value, decision, changed)
    assert code(error) == "determinism_conflict"
    value.authority.allowed.clear()
    with pytest.raises(ContractError):
        record_admission_withdrawal(
            BATCH,
            ASSET,
            str(uuid4()),
            value.case.access,
            value.ledger,
            value.case.store,
            release=value.release,
            reason=reason,
            evidence_ref=value.case.data.report_ref,
        )
    assert value.count("admission_withdrawals") == 1


def test_withdrawn_producing_admission_cannot_be_selected(release_case: ReleaseCase) -> None:
    value = release_case
    source = selected_source(value)
    withdraw(
        value,
        str(uuid4()),
        Reason(code="forbidden", message="Producing admission withdrawn"),
        asset_id=ASSET,
    )
    value.allow_build((source,))
    with pytest.raises(ContractError):
        value.build((source,))
    with pytest.raises(ContractError):
        value.review(source.revision_ref, reason="Cannot review a withdrawn admission")
    assert value.count("releases") == 0


def test_denied_read_alone_does_not_invent_withdrawn_status(release_case: ReleaseCase) -> None:
    value = release_case
    selected = (selected_source(value),)
    deny_b(value)
    value.allow_build(selected)
    result = value.build(selected)
    coverage = CoverageReport.from_wire(
        value.read(result.coverage_report_ref, value.case.access, 65536).data, value.case.bound
    )
    assert [(e.asset_id, e.status) for e in coverage.entries] == [
        (ASSET, "accepted"),
        (B_ASSET, "blocked"),
    ]
    assert coverage.entries[1].reasons and not coverage.entries[1].selected


@pytest.mark.parametrize("target", ["excluded_raw", "selected_revision"])
def test_content_artifacts_are_never_read_as_approval_evidence(
    release_case: ReleaseCase, target: str
) -> None:
    value = release_case
    revision_ref = produced_revision(value)
    deny_b(value)
    excluded = value.case.data.report.entries[1].snapshot_ref
    assert excluded is not None
    evidence = excluded if target == "excluded_raw" else revision_ref
    review = RevisionReview(
        schema_version="kf.revision-review.v1",
        project_id=PROJECT,
        revision_id=json.loads(value.read(revision_ref, value.case.access, 65536).data)[
            "revisionId"
        ],
        decision="accepted",
        actor_id=ACTOR,
        policy_version=value.case.policy.policy_version,
        reviewed_at=TIME,
        reason=Reason(code="unavailable", message="Evidence must be metadata"),
    )
    raw = encoded(review)
    value.authority.allowed.add(("record_review", raw))
    value.reads.clear()
    with pytest.raises(ContractError) as error:
        record_review(
            review,
            value.case.access,
            value.ledger,
            value.case.store,
            release=value.release,
            operation_key=value.case.plan.operation_key,
            revision_ref=revision_ref,
            review_bytes=raw,
            evidence_ref=evidence,
        )
    assert code(error) == "unsupported_schema"
    reason = Reason(code="forbidden", message="Evidence must be metadata")
    with pytest.raises(ContractError) as error:
        record_admission_withdrawal(
            BATCH,
            B_ASSET,
            str(uuid4()),
            value.case.access,
            value.ledger,
            value.case.store,
            release=value.release,
            reason=reason,
            evidence_ref=evidence,
        )
    assert code(error) == "unsupported_schema"
    assert evidence.digest not in value.reads
    assert value.count("reviews") == 0 and value.count("admission_withdrawals") == 0


def test_report_preserves_attempts_and_unresolved_cost(release_case: ReleaseCase) -> None:
    value = release_case
    selected = (selected_source(value),)
    value.allow_build(selected)
    result = value.build(selected)
    provenance = ProvenanceReport.from_wire(
        value.read(result.provenance_report_ref, value.case.access, 65536).data, value.case.bound
    )
    entry = provenance.entries[0]
    assert entry.attempt_refs and len(entry.run_report_refs) == 1
    run = RunReport.from_wire(
        value.read(entry.run_report_refs[0], value.case.access, 65536).data, value.case.bound
    )
    assert run.attempts == entry.attempt_refs
    assert run.cost_summary.has_unknown_cost
    assert run.cost_summary.reserved_outstanding_usd != "0"
    assert Decimal(run.cost_summary.estimated_usd) >= Decimal(
        run.cost_summary.reserved_outstanding_usd
    )
    assert (
        result.release_id
        not in value.read(result.coverage_report_ref, value.case.access, 65536).data.decode()
    )


@pytest.mark.parametrize("cap", [{"max_array_items": 1}, {"max_json_bytes": 400}])
def test_snapshot_row_cap_precedes_materialization(
    release_case: ReleaseCase, cap: dict[str, int]
) -> None:
    value = release_case
    selected = (selected_source(value),)
    value.allow_build(selected)
    tight = dict(value.release.limits_by_schema)
    tight["kf.coverage-report.v1"] = value.case.bound.model_copy(update=cap)
    with pytest.raises(ContractError) as error:
        value.build(selected, release=replace(value.release, limits_by_schema=tight))
    assert code(error) == "limit_exceeded"
    assert value.count("releases") == 0


@pytest.mark.parametrize("cap", [{"max_array_items": 1}, {"max_json_bytes": 400}])
def test_row_and_byte_caps_fail_before_rows_are_fetched(
    release_case: ReleaseCase, cap: dict[str, int]
) -> None:
    value = release_case
    tight = dict(value.release.limits_by_schema)
    tight["kf.coverage-report.v1"] = value.case.bound.model_copy(update=cap)
    limited = replace(value.release, limits_by_schema=tight)
    where = sql.SQL("t.project_id=%s")
    with value.ledger.transaction() as tx:
        assert len(bounded_rows(tx, "assets", where, (PROJECT,), value.release)) == 2
        with pytest.raises(ContractError) as error:
            bounded_rows(tx, "assets", where, (PROJECT,), limited)
    assert code(error) == "limit_exceeded"


def test_current_policy_instability_fails_unavailable_without_candidate(
    release_case: ReleaseCase,
) -> None:
    value = release_case
    selected = (selected_source(value),)
    value.allow_build(selected)
    original = value.case.policy

    def flip() -> None:
        value.case.policy = original.model_copy(update={"policy_version": "synthetic.v2"})

    value.authority.hook = flip
    with pytest.raises(ContractError) as error:
        value.build(selected)
    assert code(error) == "unavailable"
    assert value.count("releases") == 0


def reservation(
    rid: str, reserved: str, outstanding: str, settled: str, final: bool
) -> dict[str, Any]:
    return {
        "run_id": RUN,
        "reservation_id": rid,
        "reserved_usd": reserved,
        "outstanding_usd": outstanding,
        "settled_usd": settled,
        "final_billing": final,
    }


def usage(rid: str, amount: str | None, *, scope: str = "attempt") -> BudgetEvent:
    fields: dict[str, Any] = {
        "schema_version": "kf.budget-event.v1",
        "project_id": PROJECT,
        "run_id": RUN,
        "reservation_id": rid,
        "scope": scope,
        "event_id": str(uuid4()),
        "event_type": "record_usage",
        "cost_status": "unknown" if amount is None else "estimated",
        "evidence_ref": reference(b"synthetic-evidence", "kf.raw-original.v1"),
        "created_at": TIME,
    }
    if scope == "attempt":
        fields["attempt_id"] = str(uuid4())
    if amount is not None:
        fields["amount_usd"] = amount
    return BudgetEvent(**fields)


def projection(rows: list[dict[str, Any]], events: tuple[BudgetEvent, ...]) -> Any:
    snapshot = Snapshot((), (), {"reservations": tuple(rows)}, None, None, TIME, "0" * 64)  # type: ignore[arg-type]
    return cost_summary(snapshot, RUN, events)


R1, R2, R3 = (f"00000000-0000-0000-0000-0000000001{n:02d}" for n in (1, 2, 3))


def test_cost_projection_is_conservative_exact_and_order_independent() -> None:
    rows = [reservation(R1, "10.000000001", "10.000000001", "0", False)]
    tied = (usage(R1, "4"), usage(R1, "4"), usage(R1, "7"))
    forward = projection(rows, tied)
    assert forward == projection(rows, tuple(reversed(tied)))
    assert forward.estimated_usd == "10.000000001"
    assert forward.has_unknown_cost and forward.reserved_outstanding_usd == "10.000000001"
    # A full observed overrun is never clipped to the reservation.
    over = projection(rows, (usage(R1, "15.5"), usage(R1, "3")))
    assert over.estimated_usd == "15.5" and over.settled_actual_usd == "0"
    # Unknown observations contribute no amount but keep the liability unresolved.
    unknown = projection(rows, (usage(R1, None),))
    assert unknown.estimated_usd == "10.000000001" and unknown.has_unknown_cost


def test_cost_projection_includes_storage_and_final_closure_replaces_estimates() -> None:
    rows = [
        reservation(R1, "10", "0", "6.25", True),
        reservation(R2, "2", "2", "0", False),
        reservation(R3, "1.5", "0.5", "1", False),
    ]
    events = (usage(R1, "99"), usage(R1, None), usage(R2, None, scope="run_storage"))
    result = projection(rows, events)
    assert result.settled_actual_usd == "7.25"
    assert result.reserved_outstanding_usd == "2.5"
    assert result.estimated_usd == "3.5"
    assert result.has_unknown_cost
    closed = projection([reservation(R1, "10", "0", "6.25", True)], events[:2])
    assert (closed.estimated_usd, closed.has_unknown_cost) == ("0", False)
    assert projection([], ()).settled_actual_usd == "0"
