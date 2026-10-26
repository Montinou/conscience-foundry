"""Cross-system offline fault matrix: every spec denominator accounted for, denied cases included.

Each case drives production code (operator CLI, ledger, execution control, release, recovery,
Dagster) over test-owned fake transport and scripted faults, and ends in an `AcceptanceReport`
that exists only in test output. Gates that need another phase or live authority are `not_run`.
"""

from __future__ import annotations

import hashlib
import json
import re
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import test_f1_roundtrip as base
from test_f1_roundtrip import (
    AcceptanceReport,
    Flow,
    emit,
    fresh_ledger,
    load_fixture,
    trap_imports,
    watch_network,
)
from test_ledger_db import ACTOR, ASSET, BATCH, PROJECT, TIME, admission, reference  # noqa: E402

from conscience_foundry.cli.config import TrustedServices
from conscience_foundry.ledger.db import Ledger
from conscience_foundry.orchestration.assets import PROCESSING as PROCESSING_STAGE

FIXTURE = load_fixture()
CASES: dict[str, dict[str, Any]] = {case["caseId"]: case for case in FIXTURE["cases"]}
REPORTS: dict[str, AcceptanceReport] = {}
FAILURES: dict[str, str] = {}
RUNNERS: dict[str, Callable[[Harness], None]] = {}


@dataclass
class Harness:
    case_id: str
    ledger: Ledger
    tmp: Path
    mp: pytest.MonkeyPatch
    evidence: list[str] = field(default_factory=list)

    def note(self, **facts: object) -> None:
        self.evidence.extend(f"{key}={value}" for key, value in facts.items())

    def flow(self, **options: Any) -> Flow:
        return Flow(self.ledger, self.tmp, self.mp, **options)

    @property
    def inputs(self) -> dict[str, Any]:
        value = FIXTURE["inputs"][self.case_id]
        assert isinstance(value, dict)
        return value


def case(case_id: str) -> Callable[[Callable[[Harness], None]], Callable[[Harness], None]]:
    def register(runner: Callable[[Harness], None]) -> Callable[[Harness], None]:
        assert case_id in CASES and case_id not in RUNNERS
        RUNNERS[case_id] = runner
        return runner

    return register


def run_case(case_id: str, root: Path) -> AcceptanceReport:
    """Run one case once with its own schema, directory, network watch and import trap."""
    if case_id in REPORTS:
        return REPORTS[case_id]
    spec = CASES[case_id]
    with pytest.MonkeyPatch.context() as mp, fresh_ledger() as ledger:
        network = watch_network(mp)
        trap = trap_imports(mp)
        tmp = root / case_id
        tmp.mkdir(parents=True)
        harness = Harness(case_id, ledger, tmp, mp)
        outcome = "pass"
        try:
            runner = RUNNERS.get(case_id)
            assert runner is not None, "no runner is registered for this case"
            runner(harness)
            assert not network.attempts, "a network contact was attempted"
            assert not trap.attempts, "a model or consumer package was imported"
        except Exception as error:  # a failing case is reported, never skipped
            outcome = "fail"
            FAILURES[case_id] = "".join(traceback.format_exception(error))[-1500:]
    evidence = tuple(harness.evidence) if outcome == "pass" else ("failure:see-test-output",)
    report = AcceptanceReport(case_id, tuple(spec["specRefs"]), outcome, evidence)  # type: ignore[arg-type]
    REPORTS[case_id] = report
    emit(report)
    return report


def reports_for_all(root: Path) -> dict[str, AcceptanceReport]:
    return {case_id: run_case(case_id, root) for case_id in CASES}


@pytest.mark.database
@pytest.mark.parametrize("case_id", sorted(CASES))
def test_case_passes(case_id: str, tmp_path: Path) -> None:
    report = run_case(case_id, tmp_path)
    assert report.outcome == "pass", FAILURES.get(case_id)


def not_run_reports() -> list[AcceptanceReport]:
    """Gates that need F2, F4, line L or live authority: reported, never silently passed."""
    return [
        AcceptanceReport(row["caseId"], tuple(row["specRefs"]), "not_run", (row["reason"],))
        for row in FIXTURE["notRun"]
    ]


@pytest.mark.database
def test_fault_matrix_has_complete_denominators(tmp_path: Path) -> None:
    reports = reports_for_all(tmp_path)
    denominators = FIXTURE["denominators"]
    failed = {
        case_id: FAILURES.get(case_id) for case_id, r in reports.items() if r.outcome != "pass"
    }
    assert failed == {}
    # A01..A12, A16 and the four corrected F0 decisions are each covered by an executed case.
    covered = {ref for report in reports.values() for ref in report.spec_refs}
    assert set(denominators["specRefs"]) <= covered, sorted(set(denominators["specRefs"]) - covered)
    faults = {fault for spec in CASES.values() for fault in spec["faults"]}
    assert set(denominators["faultKinds"]) <= faults, sorted(
        set(denominators["faultKinds"]) - faults
    )
    # Denied and unknown cases are accounted for with their own passing case, never omitted.
    assert len(denominators["deniedOrUnknown"]) >= 5
    for row in denominators["deniedOrUnknown"]:
        assert reports[row["caseId"]].outcome == "pass", row
    for case_id, required in denominators["requiredEvidence"].items():
        assert set(required) <= set(reports[case_id].evidence_refs), case_id
    # Runtime report: what needs another phase or live authority is not_run, never a success.
    pending = not_run_reports()
    assert {report.case_id for report in pending} == {
        "GATE-f2-bridge", "GATE-f4-enrichment", "GATE-line-l", "GATE-live",
    }  # fmt: skip
    assert all(report.outcome == "not_run" for report in pending)
    assert {"A13", "A14", "A15"}.isdisjoint(covered)  # F4 and line L are not claimed here
    for report in pending:
        emit(report)
    # Evidence is public: no raw text, private path, credential or database detail.
    forbidden = [str(tmp_path), "Synthetic", "SECRETMARK", "password", "alpha beta", "/Users/"]
    for report in reports.values():
        for evidence in report.evidence_refs:
            assert not [marker for marker in forbidden if marker in evidence], (
                report.case_id, evidence,
            )  # fmt: skip


def test_fixture_is_synthetic_public_and_complete() -> None:
    text = base.FIXTURE.read_text(encoding="utf-8")
    for marker in ("/users/", "/private/", "/tmp/", "/var/", "password", "secret", "token"):
        assert marker not in text.lower(), marker
    assert not re.search(r"\bsk-[a-z0-9]{8,}|akia[0-9a-z]{12,}|begin [a-z ]*key", text.lower())
    assert FIXTURE["schemaVersion"] == "f1.acceptance-cases.v1"
    ids = [spec["caseId"] for spec in FIXTURE["cases"]]
    assert len(ids) == len(set(ids)) and set(ids) == set(RUNNERS)  # one runner per case, no extras
    assert all(spec["specRefs"] and spec["summary"] for spec in FIXTURE["cases"])
    inputs = set(FIXTURE["inputs"])
    assert inputs <= set(ids)


# --- A01/A02: admission through the operator CLI ------------------------------------------------

SOURCE_A = "00000000-0000-0000-0000-000000000005"
SOURCE_B = "00000000-0000-0000-0000-000000000008"
ASSET_B = "00000000-0000-0000-0000-000000000009"
SERVICES = TrustedServices(clock=lambda: TIME)


def synthetic_id(index: int) -> str:
    return f"00000000-0000-0000-0001-{index:012d}"


def intake_document(
    policy_ref: Any,
    batch_id: str,
    items: list[tuple[str, str, str, bytes]],
    profile_id: str = "technical_minimal",
) -> str:
    """An intake manifest whose declared digest and size describe the declared bytes."""
    return json.dumps(
        {
            "schemaVersion": "kf.intake.v1",
            "projectId": PROJECT,
            "batchId": batch_id,
            "profileId": profile_id,
            "profileVersion": "synthetic.profile.v1",
            "policyRef": json.loads(policy_ref.model_dump_json(by_alias=True)),
            "createdAt": TIME,
            "items": [
                {
                    "assetId": asset,
                    "sourceId": source,
                    "originalDigest": hashlib.sha256(declared).hexdigest(),
                    "sizeBytes": len(declared),
                    "mediaType": "text/plain",
                    "custodyRef": {"rootId": "synthetic-input", "relativePath": path},
                    "metadata": {"title": "Synthetic manual"},
                }
                for asset, source, path, declared in items
            ],
        }
    )


def admission_environment(h: Harness) -> tuple[Any, Path, Any]:
    env, root = base.cli_case.admit_environment(h.tmp, h.mp, h.ledger)
    policy_bytes = admission().evidence.pinned_policy.model_dump_json(by_alias=True).encode()
    return env, root, reference(policy_bytes, "kf.policy.v1")


def table_rows(ledger: Ledger, table: str) -> int:
    return base.cli_case.count(ledger, table)


def object_names(env: Any) -> list[str]:
    return base.cli_case.file_names(env.objects)


@case("A01-batch-identity")
def a01(h: Harness) -> None:
    env, root, policy_ref = admission_environment(h)
    same = b"identical synthetic bytes"
    (root / "a.txt").write_bytes(same)
    (root / "b.txt").write_bytes(same)
    items = [(ASSET, SOURCE_A, "a.txt", same), (ASSET_B, SOURCE_B, "b.txt", same)]
    manifest = env.input("manifest.json", intake_document(policy_ref, BATCH, items))
    first = env.invoke("admit", "--manifest", manifest, "--execute", services=SERVICES)
    assert first.exit == 0, first.raw
    # Same bytes under two source ids: two identities, one scoped object in custody.
    with h.ledger.transaction() as tx:
        sources = tx.connection.execute(
            "SELECT count(DISTINCT source_id) FROM " + tx.schema + ".assets"
        ).fetchone()
    assert sources == (2,) and table_rows(h.ledger, "assets") == 2
    blobs = [name for name in object_names(env) if name.endswith(hashlib.sha256(same).hexdigest())]
    assert len(blobs) == 1
    before = (
        table_rows(h.ledger, "batches"),
        table_rows(h.ledger, "admission_reports"),
        table_rows(h.ledger, "admission_entries"),
    )
    # The same batch id with a different manifest is a conflict, never a silent replacement.
    changed = [(ASSET, SOURCE_A, "a.txt", same), (ASSET_B, SOURCE_B, "b.txt", same + b"!")]
    (root / "b.txt").write_bytes(same + b"!")
    other = env.input("changed.json", intake_document(policy_ref, BATCH, changed))
    second = env.invoke("admit", "--manifest", other, "--execute", services=SERVICES)
    assert second.exit != 0 and second.code is not None, second.raw
    assert before == (
        table_rows(h.ledger, "batches"),
        table_rows(h.ledger, "admission_reports"),
        table_rows(h.ledger, "admission_entries"),
    )
    # Replaying the identical manifest over the original bytes stays idempotent.
    (root / "b.txt").write_bytes(same)
    again = env.invoke("admit", "--manifest", manifest, "--execute", services=SERVICES)
    assert again.exit == 0 and table_rows(h.ledger, "admission_reports") == 1
    h.note(
        admission_rows=before[2],
        shared_objects=len(blobs),
        changed_manifest=second.code,
        batches=before[0],
    )


def mutating_open(original: Callable[..., int], victim: Path) -> Callable[..., int]:
    """An `os.open` that rewrites the victim right after it is opened for the snapshot copy."""

    def mutate_after_open(target: Any, *args: Any, **kwargs: Any) -> int:
        descriptor = original(target, *args, **kwargs)
        if target == victim.name:
            victim.write_bytes(b"changed during the snapshot")
        return descriptor

    return mutate_after_open


@case("A02-hostile-input")
def a02(h: Harness) -> None:
    import os

    env, root, policy_ref = admission_environment(h)
    good = b"good synthetic bytes"
    (root / "ok.txt").write_bytes(good)
    outside = h.tmp / "outside.txt"
    outside.write_bytes(b"outside the custody root")
    (root / "link.txt").symlink_to(outside)
    (root / "big.txt").write_bytes(b"x" * 5000)  # over the configured per-source ceiling
    (root / "drift.txt").write_bytes(b"bytes declared in the manifesx")  # same size, other bytes
    (root / "mutate.txt").write_bytes(b"stable before the copy")
    scenarios = {
        "symlink": ("link.txt", b"outside the custody root"),
        "traversal": ("../outside.txt", b"outside the custody root"),
        "oversized_declared": ("big.txt", b"x" * 5000),
        "oversized_on_disk": ("big.txt", b"x" * 20),
        "changed": ("drift.txt", b"bytes declared in the manifest"),
        "mutated": ("mutate.txt", b"stable before the copy"),
    }
    reasons: dict[str, str] = {}
    for index, (name, (path, declared)) in enumerate(scenarios.items()):
        batch = synthetic_id(index + 1)
        items = [
            (synthetic_id(100 + index), SOURCE_A, "ok.txt", good),
            (synthetic_id(200 + index), SOURCE_B, path, declared),
        ]
        manifest = env.input(f"{name}.json", intake_document(policy_ref, batch, items))
        if name == "mutated":
            with pytest.MonkeyPatch.context() as inner:
                inner.setattr(os, "open", mutating_open(os.open, root / "mutate.txt"))
                done = env.invoke("admit", "--manifest", manifest, "--execute", services=SERVICES)
        else:
            done = env.invoke("admit", "--manifest", manifest, "--execute", services=SERVICES)
        if name in {"traversal", "oversized_declared"}:
            # Such a manifest is not even valid: no row is written and no byte is read.
            assert done.exit == 1 and done.code == "invalid_schema", done.raw
            reasons[name] = done.code
            continue
        # The affected item is blocked and the report keeps both rows; the good one is admitted.
        assert done.exit == 3 and done.code == "admission_blocked", (name, done.raw)
        statuses = sorted(row["status"] for row in done.payload["entries"])
        assert statuses == ["admitted", "blocked"], (name, statuses)
        blocked = next(row for row in done.payload["entries"] if row["status"] == "blocked")
        reasons[name] = blocked["reasonCodes"][0]
        env.assert_redacted(done)
    # No object ever came from outside the root, and the outside file was never altered.
    outside_digest = hashlib.sha256(outside.read_bytes()).hexdigest()
    assert not [name for name in object_names(env) if name.endswith(outside_digest)]
    assert outside.read_bytes() == b"outside the custody root"
    assert table_rows(h.ledger, "admission_entries") == 2 * (len(scenarios) - 2)
    # An oversized manifest document is refused before it can touch any state.
    huge = env.input("huge.json", " " * (base.cli_case.limits().max_json_bytes + 1))
    refused = env.invoke("admit", "--manifest", huge, "--execute", services=SERVICES)
    assert refused.exit != 0 and refused.code is not None
    assert table_rows(h.ledger, "admission_reports") == len(scenarios) - 2
    h.note(
        blocked_reasons=",".join(f"{key}:{value}" for key, value in sorted(reasons.items())),
        admission_rows=table_rows(h.ledger, "admission_entries"),
        oversized_manifest=refused.code,
    )


# --- A03/A04/A05: canonical text, decode gates and explicit anchors -----------------------------


def read_text_file(flow: Flow, ref: Any, source: Any, start: int, end: int, name: str) -> str:
    target = flow.tmp / f"{name}.txt"
    result = flow.read_span(ref.digest, flow.span(source, start, end), target)
    assert result.exit == 0, result.raw
    return target.read_bytes().decode("utf-8")  # never universal-newline decoded


@case("A03-unicode-coordinates")
def a03(h: Harness) -> None:
    from conscience_foundry.core.spans import scalar_to_bytes, scalar_to_utf16

    fixture = h.inputs
    text: str = fixture["text"]
    raw = text.encode("utf-8")
    assert (len(text), len(raw)) == (fixture["scalarLength"], fixture["byteLength"])
    assert len(text.encode("utf-16-le")) // 2 == fixture["utf16Length"]
    flow = h.flow(source=raw)
    source, ref = flow.verified()
    revision = json.loads(flow.value.read(source.revision_ref, flow.case.access, 65536).data)
    stored = flow.value.read(
        base.Ref.model_validate(revision["textRef"]), flow.case.access, 65536
    ).data
    # Identity processing: CRLF and the combining sequence survive byte for byte, unnormalized.
    assert stored == raw and b"\r\n" in stored and "é" not in stored.decode()
    bound = flow.case.bound
    for span in fixture["spans"]:
        assert scalar_to_bytes(raw, span["start"], span["end"], limits=bound) == tuple(
            span["bytes"]
        )
        assert scalar_to_utf16(raw, span["start"], span["end"], limits=bound) == tuple(
            span["utf16"]
        )
    astral = read_text_file(flow, ref, source, 1, 2, "astral")
    combining = read_text_file(flow, ref, source, 2, 4, "combining")
    assert astral == "\U0001f600" and combining == "é" and combining != "é"
    assert read_text_file(flow, ref, source, 0, 7, "whole") == text
    # A UTF-16 unit is not a generic span unit: the bridge converts, the core refuses.
    with pytest.raises(Exception) as unit:
        flow.span(source, 1, 3, offset_unit="utf16")
    assert type(unit.value).__name__ in {"ValidationError", "ContractError"}
    h.note(
        scalars=len(text), utf8_bytes=len(raw), utf16_units=fixture["utf16Length"], exact_bytes=True
    )


@case("A04-decode-gates")
def a04(h: Harness) -> None:
    import test_text_utf8 as text_case

    from conscience_foundry.contracts.common import ContractError

    fixture = h.inputs
    codes = {}
    for row in fixture["rejected"]:
        with pytest.raises(ContractError) as caught:
            text_case.run(bytes.fromhex(row["hex"]))
        assert caught.value.code == row["code"], row["label"]
        codes[row["label"]] = caught.value.code
    sample = bytes.fromhex(fixture["needsReview"]["hex"])
    output = text_case.run(sample)
    assert output.text == sample  # kept exactly as received, as a diagnostic candidate
    assert output.quality.disposition == "needs_review"
    # Through the whole flow: it can be held for review but never accepted into a release.
    flow = h.flow(source=sample)
    flow.prepare()
    result_ref, _ = flow.settle()
    revision_ref = flow.revision_ref(result_ref)
    refused, _ = flow.submit_review(revision_ref, decision="accepted")
    assert refused.exit != 0 and flow.rows("reviews") == 0, refused.raw
    held = flow.review(revision_ref, decision="needs_review")
    assert flow.rows("reviews") == 1
    built = flow.build(held)
    assert built.exit == 3 and built.code == "forbidden" and flow.rows("releases") == 0
    h.note(rejected=",".join(sorted(codes)), whitespace_only="needs_review", releases=0)


@case("A05-explicit-anchors")
def a05(h: Harness) -> None:
    from conscience_foundry.contracts.canonical import DocumentRevision
    from conscience_foundry.contracts.common import ContractError
    from conscience_foundry.core.spans import check_exact_quote

    fixture = h.inputs
    text = fixture["text"]
    flow = h.flow(source=text.encode())
    source, ref = flow.verified()
    revision = DocumentRevision.from_wire(
        flow.value.read(source.revision_ref, flow.case.access, 65536).data, flow.case.bound
    )
    full = flow.value.read(revision.text_ref, flow.case.access, 65536)
    assert text.count(fixture["quote"]) == 2  # the quote is ambiguous without a range
    accepted = 0
    for item in fixture["ranges"]:
        span = flow.span(source, item["start"], item["end"])
        if item["valid"]:
            check_exact_quote(
                full, span, fixture["quote"], revision=revision, limits=flow.case.bound
            )
            assert flow.read_span(ref.digest, span).exit == 0
            accepted += 1
        else:
            with pytest.raises(ContractError) as wrong:
                check_exact_quote(
                    full, span, fixture["quote"], revision=revision, limits=flow.case.bound
                )
            assert wrong.value.code == "invalid_span"
    # No fuzzy match: a near quote at the right range is not the quote.
    for near in ("Alpha", "alpha ", "alph"):
        with pytest.raises(ContractError):
            check_exact_quote(
                full, flow.span(source, 0, 5), near, revision=revision, limits=flow.case.bound
            )
    stale = flow.read_span(ref.digest, flow.span(source, 0, 5, revision_id="e" * 64))
    assert stale.exit != 0 and stale.code == "revision_mismatch"
    outside = flow.read_span(ref.digest, flow.span(source, 0, 99))
    assert outside.exit != 0 and outside.code == "invalid_span"
    h.note(valid_ranges=accepted, stale_revision=stale.code, out_of_bounds=outside.code, fuzzy=0)


# --- A06..A09: execution control through the CLI, the ledger and Dagster ------------------------


def attempt_states(ledger: Ledger) -> list[str]:
    with ledger.transaction() as tx:
        rows = tx.connection.execute(
            "SELECT state FROM " + tx.schema + ".attempts ORDER BY attempt_number"
        ).fetchall()
    return [row[0] for row in rows]


def outstanding_usd(ledger: Ledger) -> int:
    with ledger.transaction() as tx:
        row = tx.connection.execute(
            "SELECT coalesce(sum(outstanding_usd),0) FROM " + tx.schema + ".reservations"
        ).fetchone()
    assert row is not None
    return int(row[0])


@case("A06-last-allowance-race")
def a06(h: Harness) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from decimal import Decimal
    from threading import Barrier

    import test_budget as budget_case

    from conscience_foundry.contracts.common import ContractError

    # Money: two claimants of 6 against a cap of 10 -> exactly one reservation, nothing negative.
    money = budget_case.case(cost="6")
    budget_case.setup(h.ledger, money)
    gate = Barrier(2)

    def claim_money() -> str:
        gate.wait(timeout=5)
        try:
            budget_case.allocate(h.ledger, money)
            return "admitted"
        except ContractError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        verdicts = sorted(pool.map(lambda _: claim_money(), range(2)))
    assert verdicts == ["admitted", "budget_exhausted"], verdicts
    settled, outstanding, released, _ = budget_case.balances(h.ledger)
    assert (settled, outstanding, released) == (Decimal(0), Decimal(6), Decimal(0))

    # Workers: two dispatchers of one operation -> one claim, one remote submit, one reservation.
    with fresh_ledger() as other:
        (h.tmp / "dispatch").mkdir()
        flow = Flow(other, h.tmp / "dispatch", h.mp)
        flow.prepare()
        start = Barrier(2)

        def claim_dispatch() -> str:
            start.wait(timeout=5)
            try:
                return flow.case.dispatch(other, flow.executor).state
            except ContractError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = sorted(pool.map(lambda _: claim_dispatch(), range(2)))
        assert outcomes[1] == "running" and outcomes[0] != "running", outcomes
        assert flow.executor.calls == 1
        assert flow.rows("attempts") == 1 and flow.rows("reservations") == 1
        assert outstanding_usd(other) == 4  # the losing claimant held back nothing
    h.note(
        money_verdicts="+".join(verdicts),
        outstanding=outstanding,
        dispatch_outcomes="+".join(outcomes),
    )


@case("A07-disconnect-after-submit")
def a07(h: Harness) -> None:
    flow = h.flow(lost=True)
    flow.prepare()
    first = flow.dispatch()
    assert first.exit == 1 and first.code == "unknown_outcome", first.raw
    found = first.payload["attempt"]
    assert found["state"] == "unknown_outcome"
    assert outstanding_usd(flow.ledger) == 4  # the reservation is retained, not released
    # "The PC shut down": a fresh process sees only the ledger; a retry must not blindly submit.
    second = flow.dispatch()
    assert second.exit == 3 and second.code == "dispatch_unknown", second.raw
    assert flow.executor.calls == 1 and flow.rows("attempts") == 1
    before = (flow.rows("attempts"), flow.rows("reservations"), outstanding_usd(flow.ledger))
    for _ in range(2):  # new Dagster runs of the same partition observe, never resubmit
        rerun = flow.dagster(PROCESSING_STAGE)
        assert not rerun.success
        assert base.dagster_case.failure_codes(rerun) == ["unresolved_attempt"]
    assert flow.executor.calls == 1
    assert before == (
        flow.rows("attempts"),
        flow.rows("reservations"),
        outstanding_usd(flow.ledger),
    )
    # The remote later proves the work finished; reconciliation, not a retry, resolves it.
    attempt = type("Attempt", (), {})()
    attempt.attempt_id, attempt.remote_call_id = found["attemptId"], found.get("remoteCallId")
    flow.executor.success(attempt)
    done = flow.reconcile(attempt.attempt_id)
    assert done.exit == 0 and done.payload["selection"]["outcome"] == "selected", done.raw
    assert flow.executor.calls == 1 and flow.rows("operation_results") == 1
    # Worker bounds are part of the pinned plan; whether a provider honors them is a live gate.
    assert flow.case.plan.resources.max_wall_seconds == 10
    assert flow.case.plan.resources.automatic_retries == 0
    h.note(
        unknown_outcome="reservation_retained",
        second_dispatch=second.code,
        dagster_rerun="unresolved_attempt",
        remote_submits=flow.executor.calls,
        resolved_by="reconcile",
    )


def hold_state(ledger: Ledger) -> list[bool]:
    with ledger.transaction() as tx:
        rows = tx.connection.execute("SELECT held FROM " + tx.schema + ".operations").fetchall()
    return [row[0] for row in rows]


def second_attempt(flow: Flow, *, extra_check: bool) -> tuple[Any, Any]:
    """A later attempt for the same operation, allowed only once the first is resolved."""
    flow.fresh_estimate()
    dispatched = flow.dispatch()
    assert dispatched.exit == 0 and dispatched.payload["attempt"]["state"] == "running", (
        dispatched.raw
    )
    found = dispatched.payload["attempt"]
    attempt = type("Attempt", (), {})()
    attempt.attempt_id, attempt.remote_call_id = found["attemptId"], found.get("remoteCallId")
    flow.executor.success(attempt, extra_check=extra_check)
    return attempt, flow.reconcile(attempt.attempt_id)


@case("A08-duplicate-and-conflicting-results")
def a08(h: Harness) -> None:
    flow = h.flow()
    flow.prepare()
    result_ref, first_attempt = flow.settle()
    stored = flow.value.read(result_ref, flow.case.access, 65536).data
    # A duplicate delivery of the same result changes nothing: one selected operation result.
    again = flow.reconcile(first_attempt)
    assert again.exit == 0, again.raw
    assert flow.rows("operation_results") == 1 and hold_state(flow.ledger) == [False]
    # A later attempt whose deterministic output differs (one more reported check) conflicts.
    _, conflict = second_attempt(flow, extra_check=True)
    assert conflict.exit == 0 and conflict.payload["selection"]["outcome"] == "conflict", (
        conflict.raw
    )
    assert hold_state(flow.ledger) == [True]  # acceptance is blocked for this operation
    assert flow.rows("operation_results") == 2  # the conflict is recorded, nothing is dropped
    assert outstanding_usd(flow.ledger) == 8  # every attempt's cost stays attributed
    assert flow.value.read(result_ref, flow.case.access, 65536).data == stored  # history intact
    blocked = flow.dispatch()
    assert blocked.exit != 0 and flow.executor.calls == 2
    h.note(selected_results=1, conflict="held", attempts=flow.rows("attempts"), outstanding=8)


@case("D07-late-integrity-hold")
def d07(h: Harness) -> None:
    flow = h.flow()
    source, ref = flow.verified()
    span = flow.span(source, 0, 9)
    before = flow.read_span(ref.digest, span)
    assert before.exit == 0
    receipt_before = flow.value.count("releases")
    # The conflicting result arrives after the release already looked successful.
    _, conflict = second_attempt(flow, extra_check=True)
    assert conflict.payload["selection"]["outcome"] == "conflict", conflict.raw
    assert hold_state(flow.ledger) == [True]
    reread = flow.read_span(ref.digest, span)
    assert reread.exit != 0 and reread.code == "determinism_conflict", reread.raw
    reimport = flow.import_release(ref)
    assert reimport.exit != 0 and reimport.code == "determinism_conflict", reimport.raw
    # Eligibility changed; the immutable release and its earlier local receipt did not.
    assert flow.value.count("releases") == receipt_before
    with flow.ledger.transaction() as tx:
        verified = tx.connection.execute(
            "SELECT local_verified FROM " + tx.schema + ".releases"
        ).fetchall()
    assert verified == [(True,)]
    h.note(late_conflict="held", read_after_hold=reread.code, import_after_hold=reimport.code)


@case("A09-cancellation-and-expiry")
def a09(h: Harness) -> None:
    from conscience_foundry.execution.ports import Observation

    flow = h.flow()
    flow.prepare()

    def control(action: str, version: int) -> list[str]:
        proof = flow.case.proof()
        flow.case.authority.controls[proof.digest] = (action, None, (), False, False)
        return [
            "--scope", "project", "--expected-version", str(version),
            "--reason-code", "unavailable", "--reason-message", "operator decision",
            "--evidence-ref", flow.ref_file(f"{action}-{version}.json", proof),
        ]  # fmt: skip

    paused = flow.run("pause", *control("pause", 0), "--execute")
    assert paused.exit == 0 and paused.payload["pause"]["paused"] is True
    blocked = flow.dispatch()
    assert blocked.exit == 3 and blocked.code == "paused"
    assert flow.executor.calls == 0 and flow.minted == [] and flow.rows("attempts") == 0
    resumed = flow.run("resume", *control("resume", 1), "--execute")
    assert resumed.exit == 0 and resumed.payload["pause"]["paused"] is False
    running = flow.dispatch()
    assert running.exit == 0 and running.payload["attempt"]["state"] == "running"
    found = running.payload["attempt"]
    # Cancellation is a request until the provider proves termination; the money stays held.
    command = control("cancel_attempt", 0)[-6:]
    observed = flow.case.proof()
    flow.executor.next = Observation("cancelled", None, None, observed)
    remote = found.get("remoteCallId")
    flow.case.authority.observations[observed.digest] = (remote, "cancelled", None, False, False)
    cancel = ["cancel", "--attempt-id", found["attemptId"], *command, "--execute"]
    unconfirmed = flow.run(*cancel)
    assert unconfirmed.exit != 0
    assert attempt_states(flow.ledger) != ["cancelled"] and outstanding_usd(flow.ledger) == 4
    flow.case.authority.observations[observed.digest] = (remote, "cancelled", None, False, True)
    confirmed = flow.run(*cancel)
    assert confirmed.exit == 0 and confirmed.payload["attempt"]["state"] == "cancelled"
    assert outstanding_usd(flow.ledger) == 4  # not assumed free: it waits for the bill
    # After the authorization window closes nothing new starts, and nothing is minted for it.
    flow.fresh_estimate()
    flow.now = "2026-10-27T00:00:00.000Z"
    minted, calls, attempts = len(flow.minted), flow.executor.calls, flow.rows("attempts")
    expired = flow.dispatch()
    assert expired.exit != 0 and expired.code is not None, expired.raw
    assert (len(flow.minted), flow.executor.calls, flow.rows("attempts")) == (
        minted,
        calls,
        attempts,
    )
    h.note(
        paused=blocked.code,
        cancel_unconfirmed="state_kept",
        cancel_confirmed="cancelled",
        cancelled_outstanding_usd=4,
        after_expiry=expired.code,
    )


# --- faults on the ledger and on the current permission ------------------------------------------


@case("FAULT-database-unavailable")
def fault_database(h: Harness) -> None:
    import psycopg

    from conscience_foundry.contracts.common import ContractError, Reason
    from conscience_foundry.execution.control import mark_unknown_outcome
    from conscience_foundry.execution.ports import Submission

    flow = h.flow()
    flow.prepare()
    # The ledger is unreachable before any claim: nothing may reach the remote side.
    flow.database_down = True
    refused = flow.dispatch()
    flow.database_down = False
    assert refused.exit != 0 and refused.code is not None, refused.raw
    flow.env.assert_redacted(refused)  # no credential, driver text or path leaks
    assert flow.executor.calls == 0 and flow.minted == []
    assert flow.rows("attempts") == 0 and flow.rows("dispatch_claims") == 0  # no stale claim

    # The ledger drops right after the remote side accepted the submit: the claim is stranded.
    def accepted_then_disconnect(plan: Any, attempt: Any, grants: Any) -> Submission:
        flow.executor.calls += 1
        flow.database_down = True
        return Submission("synthetic-call-" + attempt.attempt_id, True)

    flow.executor.submit = accepted_then_disconnect  # type: ignore[method-assign]
    lost = flow.dispatch()
    flow.database_down = False
    assert lost.exit != 0, lost.raw
    assert flow.executor.calls == 1 and attempt_states(flow.ledger) == ["dispatching"]
    assert outstanding_usd(flow.ledger) == 4  # the reservation survived the disconnect
    retry = flow.dispatch()  # a stranded claim blocks a blind resubmit
    assert retry.exit != 0 and flow.executor.calls == 1 and flow.rows("attempts") == 1
    stranded = _stranded_attempt_id(flow.ledger)
    reason = Reason(code="unavailable", message="synthetic stale claim")
    with pytest.raises(ContractError):  # only registered evidence may move it
        mark_unknown_outcome(
            stranded, flow.ledger, control=flow.case.control, reason=reason,
            evidence_ref=flow.case.proof(),
        )  # fmt: skip
    assert attempt_states(flow.ledger) == ["dispatching"]
    command = flow.case.proof()
    flow.case.authority.controls[command.digest] = ("mark_unknown_outcome", None, (), False, False)
    marked = mark_unknown_outcome(
        stranded, flow.ledger, control=flow.case.control, reason=reason, evidence_ref=command
    )
    assert marked.state == "unknown_outcome" and outstanding_usd(flow.ledger) == 4
    still = flow.dispatch()
    assert still.exit == 3 and still.code == "dispatch_unknown" and flow.executor.calls == 1
    attempt = type("Attempt", (), {})()
    attempt.attempt_id, attempt.remote_call_id = stranded, None
    flow.executor.success(attempt)
    done = flow.reconcile(stranded)
    assert done.exit == 0 and done.payload["selection"]["outcome"] == "selected", done.raw
    assert isinstance(psycopg.OperationalError("x"), Exception)
    h.note(
        down_before_claim=refused.code,
        stranded_state="dispatching",
        resolved_by="evidenced_unknown_outcome_then_reconcile",
        remote_submits=flow.executor.calls,
    )


def _stranded_attempt_id(ledger: Ledger) -> str:
    with ledger.transaction() as tx:
        row = tx.connection.execute(
            "SELECT attempt_id::text FROM " + tx.schema + ".attempts"
        ).fetchone()
    assert row is not None
    return str(row[0])


@case("FAULT-shifted-current-permission")
def fault_permission(h: Harness) -> None:
    flow = h.flow()
    flow.prepare()
    source = flow.case.data.report.entries[0].source_id
    seen: dict[str, str | None] = {}
    # Authorization was granted under an older policy; dispatch reads the permission again.
    for shifted in ("deny", "unknown"):
        flow.set_permission(source, remote_transfer=shifted)
        blocked = flow.dispatch()
        assert blocked.exit == 3 and blocked.code in {"forbidden", "permission_unknown"}, (
            blocked.raw
        )
        seen[f"remote_transfer_{shifted}"] = blocked.code
        assert flow.minted == [] and flow.executor.calls == 0 and flow.rows("attempts") == 0
    flow.set_permission(source, remote_transfer="allow")
    # A permission that shifts while the remote work runs blocks acceptance of its result.
    running = flow.dispatch()
    assert running.exit == 0, running.raw
    found = running.payload["attempt"]
    attempt = type("Attempt", (), {})()
    attempt.attempt_id, attempt.remote_call_id = found["attemptId"], found.get("remoteCallId")
    flow.executor.success(attempt)
    for shifted, expected in (("deny", "forbidden"), ("unknown", "permission_unknown")):
        flow.set_permission(source, extract=shifted)
        refused = flow.reconcile(attempt.attempt_id)
        assert refused.exit != 0 and refused.code == expected, refused.raw
        assert flow.rows("operation_results") == 0
        seen[f"extract_{shifted}"] = refused.code
    flow.set_permission(source, extract="allow")
    accepted = flow.reconcile(attempt.attempt_id)
    assert accepted.exit == 0 and accepted.payload["selection"]["outcome"] == "selected"
    h.note(**seen, accepted_after_restore="selected")


# --- release-level cases: import, reads, revocation and the D09 content/audit edges -------------


def library(h: Harness, source: bytes = base.SOURCE_TEXT) -> Any:
    """A privately built, never-imported release of source A with source B excluded."""
    value = base.release_build.make_case(h.ledger, h.tmp, h.mp, source)
    return base.import_case.build_library(value, h.tmp / "objects")


def release_digest_row(lib: Any, digest: str) -> tuple[bool, Any]:
    return lib.row(digest)


def coverage_rows(lib: Any, model: Any) -> list[Any]:
    from conscience_foundry.contracts.release import CoverageReport

    raw = lib.value.read(model.coverage_report_ref, lib.access, 65536).data
    return list(CoverageReport.from_wire(raw, lib.value.case.bound).entries)


def text_blob(lib: Any) -> Path:
    revision = json.loads(lib.value.read(lib.source.revision_ref, lib.access, 65536).data)
    digest = revision["textRef"]["digest"]
    return lib.root / "sha256" / digest[:2] / digest


@case("A10-partial-transfer-and-disk-full")
def a10(h: Harness) -> None:
    import io

    from conscience_foundry.contracts.common import ContractError

    lib = library(h)
    imp = base.import_case
    imp.seed_active(lib, lib.old_digest)
    lib.allow_import()
    codes: dict[str, str] = {}

    def attempt() -> str:
        with pytest.raises(ContractError) as error:
            lib.import_()
        assert lib.row() == (False, None)  # no local_verified, no receipt
        assert imp.active_digest(lib) == lib.old_digest  # the active generation did not move
        return str(error.value.code)

    lib.disk.full = True
    codes["disk_full"] = attempt()
    assert codes["disk_full"] == "storage_full"
    lib.disk.full = False
    blob = text_blob(lib)
    good = blob.read_bytes()
    blob.write_bytes(good[:-3])  # a partial transfer left a truncated object behind
    codes["partial_object"] = attempt()
    blob.write_bytes(b"Synthetic tex!")  # same size, wrong hash
    codes["wrong_hash"] = attempt()
    assert codes["wrong_hash"] == "hash_mismatch"
    blob.unlink()  # a result manifest naming an object that never arrived
    codes["missing_object"] = attempt()
    # A truncated stream never becomes an object: the store refuses it before anything is visible.
    ref = lib.source.revision_ref
    raw = lib.value.read(ref, lib.access, 65536).data
    assert len(raw) > 3
    with pytest.raises(ContractError) as partial:
        lib.value.case.store.put_verified(io.BytesIO(raw[:-3]), ref.model_copy(), lib.access)
    assert partial.value.code in {"hash_mismatch", "limit_exceeded", "storage_incomplete"}
    blob.write_bytes(good)
    assert lib.import_().status == "local_verified"
    assert imp.active_digest(lib) == lib.old_digest  # importing never moves the pointer
    h.note(
        **{f"import_{key}": value for key, value in codes.items()}, receipt_only_after_repair=True
    )


@case("A12-pinned-release-and-revocation")
def a12(h: Harness) -> None:
    import errno

    from conscience_foundry.contracts.common import ContractError
    from conscience_foundry.release.read import resolve_span

    imp = base.import_case
    lib = library(h)
    imp.advance(lib, "published")
    imp.move(lib, imp.activation(lib, lib.digest, None))
    other = imp.other_library(lib)
    imp.advance(other, "published")
    imp.move(lib, imp.activation(lib, other.digest, lib.digest))  # the published pointer moves
    assert imp.active_digest(lib) == other.digest
    span = imp.span_of(lib, 0, 9)
    assert imp.resolve(lib, span).text == "Synthetic"  # the pinned release stays readable
    seen: dict[str, str] = {}
    for permission, expected in (("deny", "forbidden"), ("unknown", "permission_unknown")):
        imp.revoke_a(lib, read=permission)
        with pytest.raises(ContractError) as blocked:
            imp.resolve(lib, span)
        assert blocked.value.code == expected
        seen[f"read_{permission}"] = blocked.value.code
    imp.revoke_a(lib, read="allow")
    assert imp.resolve(lib, span).text == "Synthetic"

    class Unreachable:
        """An unavailable local copy or a network fault: every access fails, none is a verdict."""

        def __getattr__(self, name: str) -> Any:
            def fail(*args: Any, **kwargs: Any) -> Any:
                raise OSError(errno.EHOSTUNREACH, "unreachable")

            return fail

    unreachable: Any = Unreachable()
    release = replace_release(lib, unreachable)
    with pytest.raises(Exception) as outage:
        resolve_span(
            lib.access, lib.digest, span, lib.ledger, unreachable, release=release, pin=lib.pin
        )
    assert not isinstance(outage.value, AssertionError)
    seen["store_unreachable"] = getattr(outage.value, "code", type(outage.value).__name__)
    assert seen["store_unreachable"] not in {"ok", ""}
    assert (
        imp.resolve(lib, span).text == "Synthetic"
    )  # an outage never revoked or verified anything
    h.note(**seen, pointer_moved=True)


def replace_release(lib: Any, store: Any) -> Any:
    from dataclasses import replace

    return replace(lib.value.release, store=store)


@case("D08-substring-trust-boundary")
def d08(h: Harness) -> None:
    import hashlib as digest_lib
    from dataclasses import replace

    from conscience_foundry.contracts.canonical import DocumentRevision
    from conscience_foundry.contracts.common import ContractError
    from conscience_foundry.release.read import ResolvedSlice, verify_resolved_slice

    flow = h.flow()
    source, ref = flow.verified()
    span = flow.span(source, 0, 9)
    target = flow.tmp / "slice.txt"
    served = flow.read_span(ref.digest, span, target)
    assert served.exit == 0 and served.payload["independentlyVerified"] is False
    text = target.read_bytes().decode("utf-8")
    resolved = ResolvedSlice(text, served.payload["textDigest"], served.payload["revisionId"], span)
    revision = DocumentRevision.from_wire(
        flow.value.read(source.revision_ref, flow.case.access, 65536).data, flow.case.bound
    )
    # With separately authorized full bytes the exact slice is independently confirmed.
    full = flow.value.read(revision.text_ref, flow.case.access, 65536)
    verify_resolved_slice(resolved, full, revision, limits=flow.case.bound)
    forged = "Synthetiq"
    consistent = replace(
        resolved, text=forged, text_digest=digest_lib.sha256(forged.encode()).hexdigest()
    )
    # The forged slice is self-consistent, so the slice alone could not expose it.
    assert consistent.text_digest == digest_lib.sha256(consistent.text.encode()).hexdigest()
    with pytest.raises(ContractError):
        verify_resolved_slice(consistent, full, revision, limits=flow.case.bound)
    # Tampered stored full text is caught on the next trusted read, never served as verified.
    blob = flow.tmp / "objects" / "sha256" / revision.text_ref.digest[:2] / revision.text_ref.digest
    good = blob.read_bytes()
    blob.write_bytes(b"Synthetic tex!")
    tampered = flow.read_span(ref.digest, flow.span(source, 0, 9))
    assert tampered.exit != 0 and tampered.code == "hash_mismatch"
    blob.write_bytes(good)
    h.note(
        server_trust_label="independentlyVerified=false",
        forged_slice="detected_with_full_bytes",
        tampered_full_text=tampered.code,
    )


def rebuild(lib: Any) -> Any:
    """Build through the library's own release context (its store wrapper is the trusted one)."""
    from conscience_foundry.release.build import build_release

    return build_release(
        (lib.source,),
        (lib.value.case.data.report_ref,),
        lib.access,
        lib.ledger,
        lib.value.release.store,
        release=lib.value.release,
    )


def withdraw_b(lib: Any, decision_id: str, reason: Any) -> None:
    """Record the operator's withdrawal of source B through the production release code."""
    from conscience_foundry.release.build import record_admission_withdrawal

    value = lib.value
    report_ref = value.case.data.report_ref
    value.authority.allowed.add(
        (
            "withdraw_admission",
            base.release_build.approval_request(
                {
                    "projectId": PROJECT,
                    "batchId": BATCH,
                    "assetId": base.release_build.B_ASSET,
                    "sourceId": base.release_build.B_SOURCE,
                    "decisionId": decision_id,
                    "actorId": ACTOR,
                    "reason": reason.model_dump(mode="json", by_alias=True),
                    "decidedAt": TIME,
                    "evidenceRef": report_ref.model_dump(mode="json", by_alias=True),
                }
            ),
        )
    )
    record_admission_withdrawal(
        BATCH,
        base.release_build.B_ASSET,
        decision_id,
        lib.access,
        lib.ledger,
        value.release.store,
        release=value.release,
        reason=reason,
        evidence_ref=report_ref,
    )


@case("D09-partial-release-revoked-source")
def d09_partial(h: Harness) -> None:
    from dataclasses import replace
    from uuid import uuid4

    from conscience_foundry.contracts.common import Reason

    imp, build = base.import_case, base.release_build
    lib = library(h)
    build.deny_b(lib.value)  # content denied, audit metadata still allowed
    withdraw_b(lib, str(uuid4()), Reason(code="forbidden", message="Synthetic withdrawal"))
    lib.value.allow_build((lib.source,))
    lib.value.reads.clear()
    candidate = rebuild(lib)
    assert imp.b_content_reads(lib) == 0  # assembling the partial release opened no B content
    ref = imp.release_ref_of(lib, imp.release_digest(candidate))
    partial = replace(
        lib, ref=ref, model=candidate, pin=replace(lib.pin, release_digest=ref.digest)
    )
    rows = coverage_rows(partial, candidate)
    assert [row.status for row in rows] == ["accepted", "withdrawn"]
    assert [row.selected for row in rows] == [True, False]
    excluded = lib.value.case.data.report.entries[1].snapshot_ref
    assert excluded is not None
    partial.allow_import()
    assert partial.import_().status == "local_verified"
    served = imp.resolve(partial, imp.span_of(partial, 0, 9))
    assert served.text == "Synthetic"
    # Backup follows the same content/audit edges and never pulls B's bytes along.
    from test_recovery import local_store, take

    destination = local_store(h.tmp / "backup", "backup", lib)
    manifest = take(partial, destination)
    held = [r for r in manifest.content_refs + manifest.audit_refs if r.digest == excluded.digest]
    assert held == []
    assert imp.b_content_reads(lib) == 0
    h.note(
        coverage_rows_retained=len(rows),
        statuses="+".join(row.status for row in rows),
        b_content_reads=imp.b_content_reads(lib),
        backup_b_content_refs=len(held),
    )


def audit_denial(h: Harness, audit: str, expected: str) -> None:
    from conscience_foundry.contracts.common import ContractError

    imp, build = base.import_case, base.release_build
    lib = library(h)
    rows_before = len(coverage_rows(lib, lib.model))
    releases_before = lib.value.count("releases")
    lib.allow_import()
    build.deny_b(lib.value, audit=audit)
    lib.value.reads.clear()
    # Report metadata is not authorized: the release is withheld, B's row is not silently dropped.
    with pytest.raises(ContractError) as imported:
        lib.import_()
    assert imported.value.code == expected
    assert (
        lib.row() == (False, None) and lib.model.coverage_report_ref.digest not in lib.value.reads
    )
    lib.value.allow_build((lib.source,))
    with pytest.raises(ContractError) as rebuilt:
        rebuild(lib)
    assert rebuilt.value.code == expected
    assert lib.value.count("releases") == releases_before  # no replacement without the B row
    assert imp.b_content_reads(lib) == 0
    assert rows_before == 2
    h.note(
        coverage_rows_retained=rows_before,
        b_content_reads=imp.b_content_reads(lib),
        import_result=imported.value.code,
        rebuild_result=rebuilt.value.code,
        releases=releases_before,
    )


@case("D09-audit-metadata-denied")
def d09_denied(h: Harness) -> None:
    audit_denial(h, "deny", "forbidden")


@case("D09-audit-metadata-unknown")
def d09_unknown(h: Harness) -> None:
    audit_denial(h, "unknown", "permission_unknown")


# --- A11/A16/D05 ----------------------------------------------------------------------------------

RECOVERY_GRANTS = {
    **base.cli_case.ALL_GRANTS,
    "recovery": ["backup", "restore", "retention-report"],
}
READY = "2026-10-25T00:10:00.000Z"


def recovery_env(
    h: Harness, flow: Flow, root: Path | None, ledger: Ledger, backup_root: Path
) -> Any:
    """The flow's own operator config with recovery granted, or a fresh one for a new ledger."""
    if root is None:
        env = flow.env
        env.grants = RECOVERY_GRANTS
    else:
        env = base.cli_case.database_env(root, h.mp, ledger, flow.case, grants=RECOVERY_GRANTS)
    backup_root.mkdir(exist_ok=True)
    env.extra["backupStore"] = {
        "storeId": "backup",
        "rootPath": str(backup_root),
        "limits": env.bound.model_dump(by_alias=True),
    }
    env.write_config()
    return env


@case("A11-lost-store-and-ledger")
def a11(h: Harness) -> None:
    import test_recovery as recovery

    from conscience_foundry.contracts.common import ContractError
    from conscience_foundry.release.read import resolve_span

    flow = h.flow()
    source, ref = flow.verified()
    # One more attempt whose submit response is lost: remote work may still be running.
    flow.fresh_estimate()
    flow.executor.lost = True
    lost = flow.dispatch()
    assert lost.exit == 1 and lost.code == "unknown_outcome", lost.raw
    objects_before = recovery.object_files(h.tmp / "objects")
    backup_root = h.tmp / "backup"
    source_env = recovery_env(h, flow, None, flow.ledger, backup_root)
    services = TrustedServices(clock=lambda: READY)
    manifest = h.tmp / "recovery.json"
    done = source_env.invoke(
        "backup", "--manifest-output", str(manifest), "--execute", services=services
    )
    assert done.exit == 0 and done.payload["pendingAttempts"] == 1, done.raw
    assert done.payload["independentMedia"] is False  # mechanics only, not independent media
    policy = source_env.input("retention.json", recovery.POLICY.model_dump_json(by_alias=True))
    report = source_env.invoke("retention-report", "--policy", policy, services=services)
    assert report.exit == 0 and report.payload["deleted"] == 0
    assert report.payload["entries"] and not any(e["eligible"] for e in report.payload["entries"])
    assert recovery.object_files(h.tmp / "objects") == objects_before  # report-only, never deletes
    # The local store and the ledger are lost; recovery starts from the backup alone.
    with fresh_ledger() as target:
        (h.tmp / "target").mkdir()
        target_env = recovery_env(h, flow, h.tmp / "target", target, backup_root)
        restored = target_env.invoke(
            "restore", "--manifest", str(manifest), "--execute", services=services
        )
        assert restored.exit == 0, restored.raw
        assert restored.payload["dispatchBlocked"] is True
        assert restored.payload["accessBlocked"] is True
        assert restored.payload["missingRefs"] == []
        assert recovery.pause_rows(target) == [(True, 1, recovery.BARRIER_REASON)]
        recovery.assert_unverified(target)
        with pytest.raises(ContractError) as barrier:
            flow.case.dispatch(target, base.Executor(flow.case))
        assert barrier.value.code == "forbidden"
        recovery.lift(target)  # the operator lifts the pause; the unresolved attempt still holds
        with pytest.raises(ContractError) as unresolved:
            flow.case.dispatch(target, base.Executor(flow.case))
        assert unresolved.value.code == "dispatch_unknown"
        # Reads need a fresh import under today's policy; the old allow does not carry over.
        pin = base.import_case.TrustedReleasePin(
            PROJECT, ref.digest, base.import_case.STORE_ID, base.import_case.CONSUMER,
            ("canonical_text",),
        )  # fmt: skip
        with pytest.raises(ContractError) as stale_read:
            resolve_span(
                flow.value.release.access, ref.digest, flow.span(source, 0, 9), target,
                flow.value.release.store, release=flow.value.release, pin=pin,
            )  # fmt: skip
        # Local verification was cleared by the restore: only a fresh import makes it readable.
        assert stale_read.value.code == "unavailable"
        assert recovery.release_rows(target) == [(False, None)]
    h.note(
        backup_pending_attempts=1,
        cleanup_eligible_entries=0,
        restore_dispatch_blocked=True,
        redispatch_after_lift=unresolved.value.code,
        objects_deleted=0,
    )


ISOLATION_PROBE = """
import importlib, json, pkgutil, sys
BANNED = {banned!r}
attempted = []
class Block:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in BANNED:
            attempted.append(name)
            raise ImportError(name)
sys.meta_path.insert(0, Block())
import conscience_foundry
for module in pkgutil.walk_packages(conscience_foundry.__path__, "conscience_foundry."):
    importlib.import_module(module.name)
loaded = sorted(name for name in sys.modules if name.split(".")[0] in BANNED)
print(json.dumps({{"attempted": attempted, "loaded": loaded}}))
"""


@case("A16-generic-independence")
def a16(h: Harness) -> None:
    import subprocess
    import sys
    from dataclasses import replace

    from conscience_foundry.contracts.common import ContractError

    # 1. With every model and consumer package unimportable, the whole package still imports.
    probe = ISOLATION_PROBE.format(banned=sorted(base.MODEL_AND_CONSUMER_PACKAGES))
    done = subprocess.run(
        [sys.executable, "-I", "-c", probe], capture_output=True, text=True, check=True
    )
    assert json.loads(done.stdout) == {"attempted": [], "loaded": []}

    # 2. A consumer-shaped profile is refused at admission; the technical profile still works.
    env, root, policy_ref = admission_environment(h)
    good = b"generic synthetic bytes"
    (root / "a.txt").write_bytes(good)
    items = [(ASSET, SOURCE_A, "a.txt", good)]
    mismatch = env.input("m.json", intake_document(policy_ref, BATCH, items, "agora_eve"))
    refused = env.invoke("admit", "--manifest", mismatch, "--execute", services=SERVICES)
    assert refused.exit == 1 and refused.code == "invalid_schema", refused.raw
    originals = {}
    for name in ("project.json", "profile.json"):
        path = env.private / name
        originals[path] = path.read_text()
        path.write_text(originals[path].replace("technical_minimal", "agora_eve"))
    consistent = env.input("c.json", intake_document(policy_ref, BATCH, items, "agora_eve"))
    unsupported = env.invoke("admit", "--manifest", consistent, "--execute", services=SERVICES)
    assert unsupported.exit == 3 and unsupported.code == "unsupported_schema", unsupported.raw
    assert table_rows(h.ledger, "admission_reports") == 0  # nothing was registered
    for path, text in originals.items():
        path.write_text(text)
    generic = env.input("g.json", intake_document(policy_ref, BATCH, items))
    admitted = env.invoke("admit", "--manifest", generic, "--execute", services=SERVICES)
    assert admitted.exit == 0, admitted.raw

    # 3. An unknown bridge or consumer contract is refused at import; nothing consumer-side is made.
    with fresh_ledger() as other:
        (h.tmp / "bridge").mkdir()
        lib = library(Harness(h.case_id, other, h.tmp / "bridge", h.mp))
        lib.allow_import()
        for pin, expected in (
            (replace(lib.pin, capabilities=("unknown_consumer_export",)), "unsupported_capability"),
            (replace(lib.pin, consumer_contract=""), "forbidden"),
        ):
            with pytest.raises(ContractError) as bridge:
                lib.import_(pin=pin)
            assert bridge.value.code == expected
        assert lib.row() == (False, None)
        consumer_rows = sum(lib.value.count(table) for table in base.CONSUMER_TABLES)
        assert consumer_rows == 0
        assert lib.import_().status == "local_verified"  # the generic path is unaffected
        assert sum(lib.value.count(table) for table in base.CONSUMER_TABLES) == 0
    h.note(
        package_import_without_consumers=True,
        agora_profile=f"{refused.code}+{unsupported.code}",
        unknown_bridge="unsupported_capability",
        consumer_receipts=consumer_rows,
    )


def reservation_amounts(ledger: Ledger) -> tuple[int, int, int]:
    with ledger.transaction() as tx:
        row = tx.connection.execute(
            "SELECT coalesce(sum(settled_usd),0),coalesce(sum(outstanding_usd),0),"
            "coalesce(sum(released_usd),0) FROM " + tx.schema + ".reservations"
        ).fetchone()
    assert row is not None
    return int(row[0]), int(row[1]), int(row[2])


@case("D05-billing-correction")
def d05(h: Harness) -> None:
    from uuid import uuid4

    from conscience_foundry.contracts.accounting import BillingAdjustment, BudgetEvent
    from conscience_foundry.contracts.common import ContractError
    from conscience_foundry.execution.evidence import budget_context
    from conscience_foundry.ledger.budget import apply_billing_adjustment, apply_budget_event

    encoded = base.encoded
    flow = h.flow()
    flow.prepare()
    _, attempt_id = flow.settle()
    case_ = flow.case
    reservation = _reservation_id(flow.ledger)

    def bill(amount: str) -> Any:
        ref = case_.proof()
        case_.authority.billings[ref.digest] = ("actual", amount, True, True, False)
        return ref

    settled = BudgetEvent(
        schema_version="kf.budget-event.v1", project_id=PROJECT, run_id=base.execution_case.RUN,
        reservation_id=reservation, attempt_id=attempt_id, scope="attempt",
        event_id=str(uuid4()), event_type="settle", amount_usd="4", cost_status="actual",
        evidence_ref=bill("4"), created_at=TIME,
    )  # fmt: skip

    def apply(event: Any) -> None:
        with flow.ledger.transaction() as tx:
            apply_budget_event(
                event, tx, event_bytes=encoded(event), context=budget_context(case_.control, tx=tx)
            )

    def adjust(prior: str, revised: str, *, replays: int = 1) -> Any:
        correction = BillingAdjustment(
            schema_version="kf.billing-adjustment.v1", project_id=PROJECT,
            run_id=base.execution_case.RUN, reservation_id=reservation, adjustment_id=str(uuid4()),
            settlement_event_id=settled.event_id, expected_prior_actual_usd=prior,
            revised_actual_usd=revised, evidence_ref=bill(revised), created_at=TIME,
        )  # fmt: skip
        for _ in range(replays):
            with flow.ledger.transaction() as tx:
                apply_billing_adjustment(
                    correction, tx, adjustment_bytes=encoded(correction),
                    context=budget_context(case_.control, tx=tx),
                )  # fmt: skip
        return correction

    apply(settled)
    assert reservation_amounts(flow.ledger) == (4, 0, 0)
    adjust("4", "3", replays=2)  # replay of the same correction is idempotent
    assert reservation_amounts(flow.ledger) == (3, 0, 0)  # replaced, not added; no refund credited
    first = adjust("3", "5")  # a later, higher bill replaces the effective actual again
    assert reservation_amounts(flow.ledger) == (5, 0, 0)  # overrun is recorded in full, not capped
    stale = first.model_copy(
        update={"adjustment_id": str(uuid4()), "expected_prior_actual_usd": "4"}
    )
    case_.authority.billings[stale.evidence_ref.digest] = ("actual", "5", True, True, False)
    with pytest.raises(ContractError) as conflict:  # CAS: a stale view cannot win
        with flow.ledger.transaction() as tx:
            apply_billing_adjustment(
                stale, tx, adjustment_bytes=encoded(stale),
                context=budget_context(case_.control, tx=tx),
            )  # fmt: skip
    assert conflict.value.code == "determinism_conflict"
    assert reservation_amounts(flow.ledger) == (5, 0, 0)
    with flow.ledger.transaction() as tx:
        frozen = tx.connection.execute("SELECT frozen FROM " + tx.schema + ".runs").fetchone()
    assert frozen == (True,)  # the overrun freezes the run instead of reopening funds
    flow.fresh_estimate()
    blocked = flow.dispatch()
    assert blocked.exit != 0 and flow.executor.calls == 1
    h.note(
        effective_actual_usd=5,
        replays_idempotent=True,
        stale_correction=conflict.value.code,
        run_frozen=True,
        released_usd=0,
    )


def _reservation_id(ledger: Ledger) -> str:
    with ledger.transaction() as tx:
        row = tx.connection.execute(
            "SELECT reservation_id::text FROM " + tx.schema + ".reservations"
        ).fetchone()
    assert row is not None
    return str(row[0])
