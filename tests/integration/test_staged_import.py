"""Staged-result import and the control hooks around it; no provider or network is contacted.

A fake S3 client stands in for the staging destination. The worker side writes through an
attempt-scoped store, the control side reads through a read-only attempt reader, and only the
import brings the result into the local store that `verify_result` reads.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from psycopg import sql
from test_execution_control import Case, Executor, attempt_row
from test_ledger_db import ASSET, PROJECT, RUN, TIME, encoded

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapters"))
from test_staging_s3 import FakeS3, make_store  # noqa: E402

from conscience_foundry.contracts.accounting import BudgetEvent, ResourceUsage  # noqa: E402
from conscience_foundry.contracts.common import ContractError, Reason, Ref  # noqa: E402
from conscience_foundry.contracts.execution import ResultManifest  # noqa: E402
from conscience_foundry.execution.control import (  # noqa: E402
    cancel_attempt,
    dispatch,
    mark_unknown_outcome,
    reconcile,
)
from conscience_foundry.execution.evidence import budget_context  # noqa: E402
from conscience_foundry.execution.ports import ControlContext, Observation  # noqa: E402
from conscience_foundry.execution.staged_import import import_staged_result  # noqa: E402
from conscience_foundry.ledger.budget import (  # noqa: E402
    apply_budget_event,
    ledger_storage_gate,
    reserve_storage,
)
from conscience_foundry.ledger.db import Ledger  # noqa: E402
from conscience_foundry.policy.access import AccessContext  # noqa: E402
from conscience_foundry.storage.local import LocalObjectStore, ObjectStore  # noqa: E402
from conscience_foundry.storage.staging_s3 import S3StagingStore  # noqa: E402

pytestmark = pytest.mark.database

BIG = {"max_object_bytes": 65536, "transfer_chunk_bytes": 4096}


class Tee:
    """What the worker sees: reads come from the local inputs, writes go to the staging store."""

    def __init__(self, local: ObjectStore, remote: ObjectStore) -> None:
        self.local, self.remote = local, remote
        self.written: list[Ref] = []

    def put_verified(self, stream: Any, expected: Ref, context: AccessContext) -> Ref:
        self.written.append(expected)
        return self.remote.put_verified(stream, expected, context)

    def open_verified(self, ref: Ref, context: AccessContext) -> Any:
        return self.local.open_verified(ref, context)

    def read_verified(self, ref: Ref, context: AccessContext, limit: int) -> Any:
        return self.local.read_verified(ref, context, limit)


class Remote:
    """A staging destination holding results the local store has never seen."""

    def __init__(self, case: Case) -> None:
        self.case = case
        self.client = FakeS3()
        self.staging: S3StagingStore = make_store(self.client, **BIG)
        self.readers: list[tuple[str, str]] = []

    def reader(self, project: str, attempt: str) -> S3StagingStore:
        self.readers.append((project, attempt))
        return self.staging.attempt_reader(project, attempt)

    def control(self) -> ControlContext:
        return replace(self.case.control, staged_reader=self.reader)

    def stage(self, attempt: Any, build: Any) -> tuple[Ref, list[Ref]]:
        """Run `build` with the case writing into this attempt's staging prefix only."""
        c = self.case
        tee = Tee(c.store, self.staging.scoped_to(c.plan, attempt.attempt_id))
        local = c.store
        c.store = tee
        try:
            ref = build()
        finally:
            c.store = local
        return ref, tee.written

    def arriving(self, written: list[Ref]) -> list[Ref]:
        """What import must bring over; the canonical text is the original's bytes, held locally."""
        return [ref for ref in written if ref.digest != self.case.original.digest]

    def key(self, attempt_id: str, ref: Ref) -> str:
        return f"staging/f1/{PROJECT}/attempts/{attempt_id}/sha256/{ref.digest[:2]}/{ref.digest}"


def observe(
    c: Case, executor: Executor, attempt: Any, result: Ref, state: str = "succeeded"
) -> Observation:
    evidence = c.proof()
    executor.next = Observation(state, result, None, evidence)
    c.authority.observations[evidence.digest] = (
        attempt.remote_call_id,
        state,
        result.digest,
        False,
        True,
    )
    c.authority.billings[evidence.digest] = ("unknown", None, False, False, False)
    return executor.next


def missing(c: Case, ref: Ref) -> bool:
    try:
        c.store.open_verified(ref, c.access).close()
    except ContractError as error:
        return error.code == "artifact_missing"
    return False


def started(ledger: Ledger, tmp_path: Path) -> tuple[Case, Executor, Any, Remote]:
    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c)
    attempt = c.dispatch(ledger, executor)
    assert attempt.state == "running"
    return c, executor, attempt, Remote(c)


def failed_manifest(c: Case, attempt: Any) -> Ref:
    """A worker-side failure that still returns a manifest: one quality output, one error."""
    quality = c.put(_quality(c))
    return c.put(
        ResultManifest(
            schema_version="cf.result.v1",
            project_id=PROJECT,
            plan_id=c.plan.plan_id,
            operation_key=c.plan.operation_key,
            attempt_id=attempt.attempt_id,
            input_digests=(c.original.digest,),
            status="failed",
            outputs=(quality,),
            quality_report_ref=quality,
            errors=(Reason(code="remote_failed", message="synthetic worker failure"),),
            usage=ResourceUsage(
                provider_request_ids=(), cost_status="unknown", tariff_ref=c.config.tariff_ref
            ),
            completed_at=TIME,
        )
    )


def _quality(c: Case) -> Any:
    from conscience_foundry.contracts.admission import IntakeManifest, SourceAsset
    from conscience_foundry.processing.text_utf8 import process_text

    manifest = IntakeManifest.from_wire(c.data.evidence.manifest_bytes, c.bound)
    asset = SourceAsset(
        schema_version="cf.source-asset.v1",
        project_id=PROJECT,
        asset_id=ASSET,
        source_id=c.data.report.entries[0].source_id,
        original_ref=c.original,
        admission_report_ref=c.data.report_ref,
        metadata=manifest.items[0].metadata,
    )
    return process_text(
        asset,
        c.store.read_verified(c.original, c.access, 4096),
        c.spec,
        limits=c.bound,
        limits_bytes=encoded(c.bound),
    ).quality


def test_remote_result_imports_and_verifies(ledger: Ledger, tmp_path: Path) -> None:
    c, executor, attempt, remote = started(ledger, tmp_path)
    result, written = remote.stage(attempt, lambda: c.result(attempt))
    staged = remote.arriving(written)
    assert staged and all(missing(c, ref) for ref in staged)
    observe(c, executor, attempt, result)

    record = reconcile(attempt.attempt_id, ledger, executor, c.store, control=remote.control())

    assert record is not None and record.outcome == "selected"
    assert attempt_row(ledger, attempt.attempt_id)[0] == "succeeded"
    assert not any(missing(c, ref) for ref in staged)
    assert remote.readers == [(PROJECT, attempt.attempt_id)]


def test_remote_result_imports_on_cancel_path(ledger: Ledger, tmp_path: Path) -> None:
    c, executor, attempt, remote = started(ledger, tmp_path)
    result, written = remote.stage(attempt, lambda: c.result(attempt))
    observe(c, executor, attempt, result)
    command = c.proof()
    c.authority.controls[command.digest] = ("cancel_attempt", None, (), False, False)

    done = cancel_attempt(
        attempt.attempt_id,
        ledger,
        executor,
        control=remote.control(),
        reason=Reason(code="unavailable", message="synthetic cancellation"),
        evidence_ref=command,
    )

    assert done.state == "succeeded"
    assert not any(missing(c, ref) for ref in remote.arriving(written))


def test_import_refuses_after_partial_copy(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import conscience_foundry.execution.control as control_module

    c, executor, attempt, remote = started(ledger, tmp_path)
    result, written = remote.stage(attempt, lambda: c.result(attempt))
    # The quality report is read after the origin map, so the copy stops half way.
    quality = next(r for r in written if r.artifact_schema == "cf.quality-report.v1")
    origin_map = next(r for r in written if r.artifact_schema == "cf.origin-map.v1")
    corrupt = remote.key(attempt.attempt_id, quality)
    remote.client.objects[corrupt] = b"X" * len(remote.client.objects[corrupt])
    observe(c, executor, attempt, result)
    verified: list[Any] = []
    real = control_module.verify_result

    def spy(*args: Any, **kwargs: Any) -> Any:
        verified.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(control_module, "verify_result", spy)

    assert (
        reconcile(attempt.attempt_id, ledger, executor, c.store, control=remote.control()) is None
    )

    assert attempt_row(ledger, attempt.attempt_id)[0] == "unknown_outcome"
    assert verified == []
    assert not missing(c, origin_map)  # the copy really was partial
    assert missing(c, result)  # the manifest is the last object to arrive
    with ledger.transaction() as tx:
        assert tx.connection.execute(
            sql.SQL("SELECT count(*) FROM {}").format(tx.table("operation_results"))
        ).fetchone() == (0,)


def test_import_rerun_already_present(ledger: Ledger, tmp_path: Path) -> None:
    c, _, attempt, remote = started(ledger, tmp_path)
    result, _ = remote.stage(attempt, lambda: c.result(attempt))
    reader = remote.staging.attempt_reader(PROJECT, attempt.attempt_id)

    first = import_staged_result(reader, c.store, result, c.access, limits_by_schema=c.schemas)
    calls = len(remote.client.calls)
    second = import_staged_result(reader, c.store, result, c.access, limits_by_schema=c.schemas)

    assert (first, second) == ("imported", "already_present")
    assert len(remote.client.calls) == calls  # nothing was fetched again


def test_dispatch_stages_inputs_before_grant(ledger: Ledger, tmp_path: Path) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    order: list[str] = []
    seen: list[Any] = []

    def stage(plan: Any, context: AccessContext) -> tuple[Ref, ...]:
        order.append("stage")
        seen.append((plan, context))
        return plan.input_refs

    def issuer(attempt: Any) -> Any:
        order.append("mint")
        return c.grants(attempt_id=attempt.attempt_id)

    class Ordered(Executor):
        def submit(self, plan: Any, attempt: Any, grants: Any) -> Any:
            order.append("submit")
            return super().submit(plan, attempt, grants)

    control = replace(c.control, stage_inputs=stage)
    attempt = dispatch(
        c.plan,
        c.auth,
        c.access,
        ledger,
        Ordered(c),
        issuer,
        control=control,
        plan_ref=c.plan_ref,
        authorization_ref=c.auth_ref,
        asset_id=ASSET,
        evidence_ref=c.estimate,
    )

    assert order == ["stage", "mint", "submit"]
    assert seen == [(c.plan, c.access)]
    assert attempt.state == "running"


def test_hooks_none_keeps_f1_behavior(ledger: Ledger, tmp_path: Path) -> None:
    c = Case(tmp_path)
    assert c.control.staged_reader is None and c.control.stage_inputs is None
    c.setup(ledger)
    executor = Executor(c)
    attempt = c.dispatch(ledger, executor)
    executor.success(attempt)  # the result lands straight in the local store, as in F1

    record = reconcile(attempt.attempt_id, ledger, executor, c.store, control=c.control)

    assert record is not None
    assert attempt_row(ledger, attempt.attempt_id)[0] == "succeeded"


def test_failed_manifest_with_result_ref_is_imported(ledger: Ledger, tmp_path: Path) -> None:
    c, executor, attempt, remote = started(ledger, tmp_path)
    result, written = remote.stage(attempt, lambda: failed_manifest(c, attempt))
    observe(c, executor, attempt, result, "failed")

    assert (
        reconcile(attempt.attempt_id, ledger, executor, c.store, control=remote.control()) is None
    )

    assert attempt_row(ledger, attempt.attempt_id)[0] == "failed"
    assert remote.arriving(written)
    assert not any(missing(c, ref) for ref in remote.arriving(written))


@pytest.mark.parametrize(
    ("code", "state"),
    [
        ("forbidden", "failed"),
        ("limit_exceeded", "failed"),
        ("dispatch_unknown", "unknown_outcome"),
    ],
)
def test_stage_inputs_refusal_marks_failed_without_submit(
    ledger: Ledger, tmp_path: Path, code: str, state: str
) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c)
    minted: list[str] = []

    def refuse(plan: Any, context: AccessContext) -> tuple[Ref, ...]:
        raise ContractError(code)

    def issuer(attempt: Any) -> Any:
        minted.append(attempt.attempt_id)
        return c.grants(attempt_id=attempt.attempt_id)

    attempt = dispatch(
        c.plan,
        c.auth,
        c.access,
        ledger,
        executor,
        issuer,
        control=replace(c.control, stage_inputs=refuse),
        plan_ref=c.plan_ref,
        authorization_ref=c.auth_ref,
        asset_id=ASSET,
        evidence_ref=c.estimate,
    )

    assert attempt.state == state
    assert attempt_row(ledger, attempt.attempt_id)[0] == state
    assert executor.calls == 0 and minted == []


def test_state_change_between_attest_and_apply_refuses(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import conscience_foundry.execution.control as control_module

    c, executor, attempt, _ = started(ledger, tmp_path)
    executor.success(attempt)
    real = control_module._attest

    def attest_then_change(*args: Any, **kwargs: Any) -> Any:
        attested = real(*args, **kwargs)
        command = c.proof()
        c.authority.controls[command.digest] = ("mark_unknown_outcome", None, (), False, False)
        mark_unknown_outcome(
            attempt.attempt_id,
            ledger,
            control=c.control,
            reason=Reason(code="unavailable", message="synthetic stale claim"),
            evidence_ref=command,
        )
        return attested

    monkeypatch.setattr(control_module, "_attest", attest_then_change)

    with pytest.raises(ContractError) as refused:
        reconcile(attempt.attempt_id, ledger, executor, c.store, control=c.control)

    assert refused.value.code == "determinism_conflict"
    assert attempt_row(ledger, attempt.attempt_id)[0] == "unknown_outcome"


def test_ledger_storage_gate_requires_open_reservation(ledger: Ledger, tmp_path: Path) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    gate = ledger_storage_gate(ledger, RUN)
    elsewhere = ledger_storage_gate(ledger, str(uuid4()))
    foreign = AccessContext(str(uuid4()), c.access.actor_id, c.access.scopes)
    assert gate(c.original, c.access) is False

    proof = c.proof()
    c.authority.storage_estimates[proof.digest] = (
        "3",
        (c.plan_ref,),
        (c.authority.estimates[c.estimate.digest][1],),
    )
    with ledger.transaction() as tx:
        reservation = reserve_storage(RUN, "3", proof, tx, context=budget_context(c.control, tx=tx))
    assert gate(c.original, c.access) is True
    assert elsewhere(c.original, c.access) is False
    assert gate(c.original, foreign) is False  # a context of another project never passes

    receipt = c.proof()
    c.authority.billings[receipt.digest] = ("actual", "2", True, True, False)
    settlement = BudgetEvent(
        schema_version="cf.budget-event.v1",
        project_id=PROJECT,
        run_id=RUN,
        reservation_id=reservation,
        scope="run_storage",
        event_id=str(uuid4()),
        event_type="settle",
        amount_usd="2",
        cost_status="actual",
        evidence_ref=receipt,
        created_at=TIME,
    )
    release = settlement.model_copy(
        update={"event_id": str(uuid4()), "event_type": "release_unspent", "amount_usd": "1"}
    )
    with ledger.transaction() as tx:
        for event in (settlement, release):
            apply_budget_event(
                event, tx, event_bytes=encoded(event), context=budget_context(c.control, tx=tx)
            )
    assert gate(c.original, c.access) is False


def test_runtime_control_wires_hooks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from test_cli import Env

    from conscience_foundry.cli.config import Runtime, TrustedServices, load_config

    env = Env(tmp_path, monkeypatch)

    def reader(project: str, attempt: str) -> ObjectStore:
        raise AssertionError("not called")

    def stage(plan: Any, context: AccessContext) -> tuple[Ref, ...]:
        raise AssertionError("not called")

    wired = Runtime(
        load_config(env.config_path),
        TrustedServices(staged_reader=reader, stage_inputs=stage),
        "dispatch",
    ).control
    bare = Runtime(load_config(env.config_path), TrustedServices(), "dispatch").control

    assert wired.staged_reader is reader and wired.stage_inputs is stage
    assert bare.staged_reader is None and bare.stage_inputs is None
    assert isinstance(wired.store, LocalObjectStore)
