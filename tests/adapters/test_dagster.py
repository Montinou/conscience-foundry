"""Dagster partitions drive the same durable ledger as the CLI; everything runs in process.

No Dagster daemon, webserver or remote service is started. The `ExecutionControl` facade is a
test-owned deterministic fake for the pure orchestration rules and a test-owned thin wrapper over
the real T13 functions for the ledger-backed cases.
"""

from __future__ import annotations

import hashlib
import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

import dagster as dg
import pytest
from psycopg import sql

_INTEGRATION = str(Path(__file__).resolve().parents[1] / "integration")
if _INTEGRATION not in sys.path:
    sys.path.append(_INTEGRATION)

from test_execution_control import Case, Executor  # noqa: E402
from test_ledger_db import ASSET, PROJECT, RUN, TIME, reference  # noqa: E402

from conscience_foundry.contracts.accounting import OperationResultRecord  # noqa: E402
from conscience_foundry.contracts.common import ContractError, Id, Reason, Ref  # noqa: E402
from conscience_foundry.contracts.execution import AttemptState  # noqa: E402
from conscience_foundry.contracts.project import ProjectConfig  # noqa: E402
from conscience_foundry.execution.control import reconcile, set_pause  # noqa: E402
from conscience_foundry.execution.evidence import read_model  # noqa: E402
from conscience_foundry.ledger.db import Ledger  # noqa: E402
from conscience_foundry.orchestration.assets import (  # noqa: E402
    ADMISSION,
    JOB_NAME,
    PARTITIONS_NAME,
    PROCESSING,
    RECONCILIATION,
    RELEASE_CANDIDATE,
    AdmissionView,
    AttemptView,
    CandidateView,
    OperationView,
    PartitionIdentity,
    _fail,
    build_definitions,
    parse_partition_key,
    partition_key,
)

ORCHESTRATION_RUNTIMES = frozenset({"dagster", "dagster_pipes", "dagster_shared"})


@pytest.fixture(scope="module", autouse=True)
def isolate_orchestration_runtime() -> Iterator[None]:
    """Leave no Dagster modules loaded: core tests assert the core imports no runtime."""
    yield
    for name in [name for name in sys.modules if name.split(".")[0] in ORCHESTRATION_RUNTIMES]:
        del sys.modules[name]


OTHER_PROJECT = "00000000-0000-0000-0000-0000000000f1"
SPEC_DIGEST = hashlib.sha256(b"extraction-spec").hexdigest()
SECRET = "raw-source-text-and-token-must-not-surface"
UNRESOLVED: frozenset[AttemptState] = frozenset(
    {"planned", "reserved", "dispatching", "running", "unknown_outcome", "cancel_requested"}
)
STAGES = (ADMISSION, PROCESSING, RECONCILIATION, RELEASE_CANDIDATE)


def digest_of(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def key_for(asset: str = ASSET, project: str = PROJECT) -> str:
    return partition_key(project, asset, SPEC_DIGEST)


def project_config(project: str = PROJECT) -> ProjectConfig:
    def pin(schema: str) -> Ref:
        raw = (schema + project).encode()
        return reference(raw, schema).model_copy(update={"project_id": project})

    return ProjectConfig.model_validate(
        {
            "schemaVersion": "kf.project.v1",
            "projectId": project,
            "profileId": "technical_minimal",
            "profileVersion": "synthetic.profile.v1",
            "policyRef": pin("kf.policy.v1"),
            "limitsRefs": [pin("kf.contract-limits.v1")],
            "contractSetRef": pin("kf.contract-set.v1"),
            "storageConfigRef": pin("kf.storage-config.v1"),
            "executionConfigRef": pin("kf.execution-config.v1"),
        }
    )


def selection(
    operation_key: str,
    attempt_id: str,
    *,
    project: str = PROJECT,
    outcome: str = "selected",
) -> OperationResultRecord:
    def pin(label: str, schema: str) -> Ref:
        return reference(label.encode() + attempt_id.encode(), schema).model_copy(
            update={"project_id": project}
        )

    result = pin("result", "kf.result.v1")
    return OperationResultRecord.model_validate(
        {
            "schemaVersion": "kf.operation-result-record.v1",
            "projectId": project,
            "operationKey": operation_key,
            "eventId": str(uuid4()),
            **({"previousEventId": str(uuid4())} if outcome != "selected" else {}),
            "attemptId": attempt_id,
            "resultRef": result,
            "comparisonDigest": digest_of("comparison"),
            "outcome": outcome,
            "selectedResultRef": result,
            "evidenceRef": pin("evidence", "kf.control-evidence.v1"),
            "recordedAt": TIME,
        }
    )


class Instance:
    """Ephemeral in-process Dagster instance with dynamic partitions pre-registered."""

    def __init__(self, *keys: str) -> None:
        self.instance = dg.DagsterInstance.ephemeral()
        self.instance.add_dynamic_partitions(PARTITIONS_NAME, list(keys))

    def run(
        self,
        defs: dg.Definitions,
        key: str,
        *stages: str,
        run_config: Mapping[str, Any] | None = None,
    ) -> dg.ExecuteInProcessResult:
        return dg.materialize(
            [defs.get_assets_def(stage) for stage in stages],
            partition_key=key,
            instance=self.instance,
            run_config=run_config,
            raise_on_error=False,
        )

    def materializations(self, stage: str) -> list[dict[str, Any]]:
        result = self.instance.fetch_materializations(dg.AssetKey(stage), limit=100)
        return [
            {name: value.value for name, value in record.asset_materialization.metadata.items()}
            for record in result.records
            if record.asset_materialization is not None
        ]


def failure_codes(result: dg.ExecuteInProcessResult) -> list[str]:
    codes: list[str] = []
    for event in result.all_events:
        if event.is_step_failure:
            failure = event.step_failure_data.user_failure_data
            assert failure is not None, "unexpected non-Failure error escaped the asset"
            codes.append(str(failure.metadata["kf_code"].value))
        assert event.event_type != dg.DagsterEventType.STEP_UP_FOR_RETRY
    return codes


def serialized(result: dg.ExecuteInProcessResult) -> str:
    return "\n".join(repr(event.event_specific_data) for event in result.all_events)


# --- deterministic fake of the facade (pure orchestration rules) ---


@dataclass
class FakeControl:
    operation_key: str = field(default_factory=lambda: digest_of("operation-1"))
    admitted: bool = True
    paused: bool = False
    held: bool = False
    verify: bool = True
    status_only: bool = False
    resolve_failed: bool = False
    candidate: bool = True
    stale_selected: OperationResultRecord | None = None
    explode: BaseException | None = None
    attempts: dict[str, list[AttemptView]] = field(default_factory=dict)
    selected: dict[str, OperationResultRecord] = field(default_factory=dict)
    dispatches: list[str] = field(default_factory=list)
    reconciles: list[str] = field(default_factory=list)

    def admission(self, partition: PartitionIdentity) -> AdmissionView:
        return AdmissionView(
            self.admitted, digest_of("admission-report") if self.admitted else None
        )

    def operation(self, partition: PartitionIdentity) -> OperationView:
        if self.explode is not None:
            raise self.explode
        return OperationView(
            self.operation_key,
            self.paused,
            self.held,
            tuple(self.attempts.get(self.operation_key, ())),
            self.stale_selected or self.selected.get(self.operation_key),
        )

    def dispatch(self, partition: PartitionIdentity) -> AttemptView:
        if self.paused:
            raise ContractError("forbidden")
        self.dispatches.append(self.operation_key)
        attempt = AttemptView(str(uuid4()), str(uuid4()), "running")
        self.attempts.setdefault(self.operation_key, []).append(attempt)
        return attempt

    def _set(self, attempt_id: str, state: AttemptState) -> None:
        rows = self.attempts[self.operation_key]
        rows[:] = [
            AttemptView(row.attempt_id, row.plan_id, state) if row.attempt_id == attempt_id else row
            for row in rows
        ]

    def reconcile(
        self, partition: PartitionIdentity, attempt_id: Id
    ) -> OperationResultRecord | None:
        self.reconciles.append(attempt_id)
        if self.resolve_failed:
            self._set(attempt_id, "failed")  # the provider proved the attempt failed
            return None
        if self.status_only:
            self._set(attempt_id, "succeeded")  # worker said so; nothing verified or selected
            return None
        if not self.verify:
            return None
        self._set(attempt_id, "succeeded")
        record = selection(self.operation_key, attempt_id)
        self.selected.setdefault(self.operation_key, record)
        return record

    def release_candidate(self, partition: PartitionIdentity) -> CandidateView | None:
        if not self.candidate:
            return None
        return CandidateView(digest_of("release"), self.operation_key)


def fake_setup(control: FakeControl | None = None) -> tuple[FakeControl, dg.Definitions, Instance]:
    control = control or FakeControl()
    return control, build_definitions(control, project_config()), Instance(key_for())


# --- partition identity ---


def test_partition_key_is_unambiguous_and_round_trips() -> None:
    key = key_for()
    assert key == f"{PROJECT}:{ASSET}:{SPEC_DIGEST}"
    assert parse_partition_key(key) == PartitionIdentity(PROJECT, ASSET, SPEC_DIGEST)
    assert key_for(str(uuid4())) != key
    for bad in (
        ("A" + PROJECT[1:], ASSET, SPEC_DIGEST),
        (PROJECT, ASSET + ":x", SPEC_DIGEST),
        (PROJECT, "not-an-id", SPEC_DIGEST),
        (PROJECT, ASSET, SPEC_DIGEST[:-1]),
        (PROJECT, ASSET, SPEC_DIGEST + "0"),
        (PROJECT, ASSET, ""),
    ):
        with pytest.raises(ContractError):
            partition_key(*bad)
    for malformed in (
        "",
        f"{PROJECT}:{ASSET}",
        f"{PROJECT}:{ASSET}:{SPEC_DIGEST}:extra",
        f"{PROJECT}:{ASSET}:{SPEC_DIGEST[:-1]}",
    ):
        with pytest.raises(ContractError):
            parse_partition_key(malformed)


def test_definitions_are_a_small_partitioned_asset_set() -> None:
    defs = build_definitions(FakeControl(), project_config())
    assets = [
        definition
        for definition in defs.assets or ()
        if isinstance(definition, dg.AssetsDefinition)
    ]
    keys = sorted(key.to_user_string() for definition in assets for key in definition.keys)
    assert keys == sorted(STAGES)  # no asset per token or chunk
    for definition in assets:
        partitions = definition.partitions_def
        assert isinstance(partitions, dg.DynamicPartitionsDefinition)
        assert partitions.name == PARTITIONS_NAME
        assert set(definition.code_versions_by_key.values()) == {None}  # not a cache identity
    dependencies = {
        stage: {
            dep.to_user_string()
            for dep in defs.get_assets_def(stage).asset_deps[dg.AssetKey(stage)]
        }
        for stage in STAGES
    }
    assert dependencies == {
        ADMISSION: set(),
        PROCESSING: {ADMISSION},
        RECONCILIATION: {ADMISSION},
        RELEASE_CANDIDATE: {PROCESSING},
    }


def test_foreign_project_partition_is_refused_before_any_control_call() -> None:
    control, defs, instance = fake_setup()
    foreign = key_for(project=OTHER_PROJECT)
    instance.instance.add_dynamic_partitions(PARTITIONS_NAME, [foreign])
    for stage in STAGES:
        result = instance.run(defs, foreign, stage)
        assert not result.success and failure_codes(result) == ["forbidden"]
    assert control.dispatches == [] and control.reconciles == []


# --- named behavior tests ---


def test_partition_is_not_cache_identity() -> None:
    control, defs, instance = fake_setup()
    key = key_for()
    first = instance.run(defs, key, ADMISSION, PROCESSING)
    assert first.success
    old_operation = control.operation_key
    (old,) = instance.materializations(PROCESSING)
    assert old["kf_operation_key"] == old_operation

    # Same partition, but pinned policy/contracts changed, so the ledger derives a new operation.
    control.operation_key = digest_of("operation-2-after-policy-change")
    second = instance.run(defs, key, PROCESSING)
    assert second.success
    newest, previous = instance.materializations(PROCESSING)
    assert newest["kf_operation_key"] == control.operation_key != old_operation
    assert previous == old
    assert control.dispatches == [old_operation, control.operation_key]  # no reuse of the old one
    assert newest["kf_attempt_id"] != old["kf_attempt_id"]

    # A stale or hostile facade answer for another operation is not accepted as this one.
    control.operation_key = digest_of("operation-3")
    control.stale_selected = control.selected[old_operation]
    third = instance.run(defs, key, PROCESSING)
    assert not third.success and failure_codes(third) == ["result_unverified"]
    assert len(instance.materializations(PROCESSING)) == 2
    assert len(control.dispatches) == 2

    # Paid retries stay disabled for every layer Dagster configures.
    for stage in (PROCESSING, RECONCILIATION):
        policy = defs.get_assets_def(stage).node_def.retry_policy
        assert policy is not None and policy.max_retries == 0
    assert _fail(PROCESSING, "unresolved_attempt").allow_retries is False
    job = defs.resolve_job_def(JOB_NAME)
    assert job.tags["dagster/max_retries"] == "0"
    assert job.executor_def.name == "in_process"  # injected control never crosses processes
    control.explode = RuntimeError(SECRET)
    attempts_before = len(control.dispatches)
    failing = instance.run(defs, key, PROCESSING)
    assert not failing.success and failure_codes(failing) == ["control_unavailable"]
    assert SECRET not in serialized(failing)
    assert len(control.dispatches) == attempts_before


@pytest.mark.parametrize(
    "flavor", ["status_only", "unverified", "conflict", "foreign_project", "foreign_operation"]
)
def test_materialization_only_follows_a_verified_ledger_selection(flavor: str) -> None:
    control = FakeControl()
    control, defs, instance = fake_setup(control)
    if flavor == "status_only":
        control.status_only = True
    elif flavor == "unverified":
        control.verify = False
    elif flavor == "conflict":
        control.held = True
    elif flavor == "foreign_project":
        control.stale_selected = selection(
            control.operation_key, str(uuid4()), project=OTHER_PROJECT
        )
    else:  # a selection for another operation whose attempt id happens to be present here
        attempt = str(uuid4())
        control.attempts[control.operation_key] = [AttemptView(attempt, str(uuid4()), "succeeded")]
        control.stale_selected = selection(digest_of("another-operation"), attempt)
    result = instance.run(defs, key_for(), PROCESSING)
    assert not result.success
    if flavor in {"conflict", "foreign_project", "foreign_operation"}:
        assert control.dispatches == []  # a hold or a bad selection never leads to a new claim
    assert instance.materializations(PROCESSING) == []
    assert failure_codes(result) == [
        {
            "status_only": "result_unverified",
            "unverified": "result_pending",
            "conflict": "integrity_hold",
            "foreign_project": "result_unverified",
            "foreign_operation": "result_unverified",
        }[flavor]
    ]


def test_conflicting_selection_is_not_a_materialization() -> None:
    control, defs, instance = fake_setup()
    attempt = str(uuid4())
    control.attempts[control.operation_key] = [AttemptView(attempt, str(uuid4()), "succeeded")]
    control.stale_selected = selection(control.operation_key, attempt, outcome="conflict")
    result = instance.run(defs, key_for(), PROCESSING)
    assert not result.success and failure_codes(result) == ["integrity_hold"]
    assert instance.materializations(PROCESSING) == []


def test_unresolved_attempt_is_reconciled_and_never_redispatched() -> None:
    control, defs, instance = fake_setup()
    control.verify = False
    key = key_for()
    for _ in range(3):
        result = instance.run(defs, key, PROCESSING)
        assert not result.success and failure_codes(result) == ["result_pending"]
    assert len(control.dispatches) == 1  # one claim; later runs only observe it
    assert len(control.reconciles) == 1 + 2  # post-dispatch observation, then each rerun
    control.verify = True
    done = instance.run(defs, key, PROCESSING)
    assert done.success and len(control.dispatches) == 1
    (row,) = instance.materializations(PROCESSING)
    assert row["kf_attempt_id"] == control.attempts[control.operation_key][0].attempt_id
    # A selected result is re-recorded from the ledger selection, never dispatched again.
    assert instance.run(defs, key, PROCESSING).success
    assert len(control.dispatches) == 1


def test_processing_needs_explicit_retry_intent_after_a_failed_attempt() -> None:
    control, defs, instance = fake_setup()
    control.resolve_failed = True
    key = key_for()
    unknown = AttemptView(str(uuid4()), str(uuid4()), "unknown_outcome")
    control.attempts[control.operation_key] = [unknown]
    # The reconcile inside this run proves the earlier attempt failed; paying again is a decision.
    for _ in range(2):
        result = instance.run(defs, key, PROCESSING)
        assert not result.success and failure_codes(result) == ["retry_requires_intent"]
    assert control.dispatches == [] and control.reconciles == [unknown.attempt_id]
    # Explicit run configuration is the retry intent; the ledger still repeats every gate.
    control.resolve_failed = False
    intent = {"ops": {PROCESSING: {"config": {"retry_after_failure": True}}}}
    done = instance.run(defs, key, PROCESSING, run_config=intent)
    assert done.success and len(control.dispatches) == 1
    # Intent is per run: a failed attempt never turns a later plain rerun into a retry.
    assert instance.run(defs, key, PROCESSING).success and len(control.dispatches) == 1


def test_reconciliation_asset_never_dispatches() -> None:
    control, defs, instance = fake_setup()
    result = instance.run(defs, key_for(), RECONCILIATION)
    assert not result.success and failure_codes(result) == ["no_attempt"]
    assert control.dispatches == []
    attempt = AttemptView(str(uuid4()), str(uuid4()), "unknown_outcome")
    control.attempts[control.operation_key] = [attempt]
    done = instance.run(defs, key_for(), RECONCILIATION)
    assert done.success and control.dispatches == []
    (row,) = instance.materializations(RECONCILIATION)
    assert row["kf_attempt_id"] == attempt.attempt_id
    assert row["kf_stage"] == RECONCILIATION


def test_materialization_metadata_is_public_identity_only() -> None:
    control, defs, instance = fake_setup()
    assert instance.run(defs, key_for(), ADMISSION, PROCESSING).success
    (admitted,) = instance.materializations(ADMISSION)
    assert admitted["kf_admission_report_digest"] == digest_of("admission-report")
    (row,) = instance.materializations(PROCESSING)
    attempt = control.attempts[control.operation_key][0]
    record = control.selected[control.operation_key]
    assert row == {
        "kf_stage": PROCESSING,
        "kf_project_id": PROJECT,
        "kf_asset_id": ASSET,
        "kf_extraction_spec_digest": SPEC_DIGEST,
        "kf_operation_key": control.operation_key,
        "kf_plan_id": attempt.plan_id,
        "kf_attempt_id": attempt.attempt_id,
        "kf_result_digest": record.selected_result_ref.digest,
        "kf_selection_outcome": "selected",
    }


def test_admission_requires_a_ledger_registered_asset() -> None:
    control, defs, instance = fake_setup()
    control.admitted = False
    result = instance.run(defs, key_for(), ADMISSION)
    assert not result.success and failure_codes(result) == ["not_admitted"]
    assert instance.materializations(ADMISSION) == []


def test_release_candidate_needs_a_verified_selection_and_ledger_approval() -> None:
    control, defs, instance = fake_setup()
    key = key_for()
    early = instance.run(defs, key, RELEASE_CANDIDATE)
    assert not early.success and failure_codes(early) == ["result_unverified"]
    assert instance.run(defs, key, PROCESSING).success
    control.candidate = False  # review/approval gate not satisfied in the ledger
    blocked = instance.run(defs, key, RELEASE_CANDIDATE)
    assert not blocked.success and failure_codes(blocked) == ["approval_required"]
    assert instance.materializations(RELEASE_CANDIDATE) == []
    control.candidate = True
    assert instance.run(defs, key, RELEASE_CANDIDATE).success
    (row,) = instance.materializations(RELEASE_CANDIDATE)
    assert row["kf_release_digest"] == digest_of("release")
    assert row["kf_operation_key"] == control.operation_key


def test_paused_ledger_stops_dagster_dispatch_but_not_observation() -> None:
    control, defs, instance = fake_setup()
    control.paused = True
    result = instance.run(defs, key_for(), PROCESSING)
    assert not result.success and failure_codes(result) == ["paused"]
    assert control.dispatches == []


# --- ledger-backed cases (real PostgreSQL ledger, T13 control, fake remote) ---


class LedgerControl:
    """Test-owned thin facade: no state of its own, only T13 calls and ledger reads."""

    def __init__(self, case: Case, ledger: Ledger, executor: Executor) -> None:
        self.case, self.ledger, self.executor = case, ledger, executor

    def admission(self, partition: PartitionIdentity) -> AdmissionView:
        with self.ledger.transaction() as tx:
            row = tx.connection.execute(
                sql.SQL("SELECT 1 FROM {} WHERE project_id=%s AND asset_id=%s").format(
                    tx.table("assets")
                ),
                (partition.project_id, partition.asset_id),
            ).fetchone()
        return AdmissionView(row is not None, self.case.data.report_ref.digest if row else None)

    def operation(self, partition: PartitionIdentity) -> OperationView:
        key = self.case.plan.operation_key
        with self.ledger.transaction() as tx:
            rows = tx.connection.execute(
                sql.SQL(
                    "SELECT attempt_id::text,plan_id::text,state FROM {} "
                    "WHERE project_id=%s AND operation_key=%s ORDER BY attempt_number"
                ).format(tx.table("attempts")),
                (partition.project_id, key),
            ).fetchall()
            op = tx.connection.execute(
                sql.SQL(
                    "SELECT held, latest_event_id::text FROM {} "
                    "WHERE project_id=%s AND operation_key=%s"
                ).format(tx.table("operations")),
                (partition.project_id, key),
            ).fetchone()
            record = None
            if op is not None and op[1] is not None:
                selected = tx.connection.execute(
                    sql.SQL("SELECT record_ref FROM {} WHERE project_id=%s AND event_id=%s").format(
                        tx.table("operation_results")
                    ),
                    (partition.project_id, op[1]),
                ).fetchone()
                assert selected is not None
                record = read_model(
                    Ref.model_validate(selected[0]), OperationResultRecord, self.case.control
                )[1]
            paused = (
                tx.get_pause("project", partition.project_id, None).paused
                or tx.get_pause("run", partition.project_id, RUN).paused
            )
        return OperationView(
            key,
            paused,
            bool(op and op[0]),
            tuple(AttemptView(row[0], row[1], row[2]) for row in rows),
            record,
        )

    def dispatch(self, partition: PartitionIdentity) -> AttemptView:
        attempt = self.case.dispatch(self.ledger, self.executor)
        return AttemptView(attempt.attempt_id, attempt.plan_id, attempt.state)

    def reconcile(
        self, partition: PartitionIdentity, attempt_id: Id
    ) -> OperationResultRecord | None:
        return reconcile(
            attempt_id, self.ledger, self.executor, self.case.store, control=self.case.control
        )

    def release_candidate(self, partition: PartitionIdentity) -> CandidateView | None:
        return None


def ledger_counts(ledger: Ledger) -> dict[str, Any]:
    with ledger.transaction() as tx:
        values: dict[str, Any] = {}
        for name in ("attempts", "reservations", "budget_events", "dispatch_claims"):
            row = tx.connection.execute(
                sql.SQL("SELECT count(*) FROM {}").format(tx.table(name))
            ).fetchone()
            values[name] = row[0]
        outstanding = tx.connection.execute(
            sql.SQL(
                "SELECT coalesce(sum(outstanding_usd),0), coalesce(sum(settled_usd),0) FROM {}"
            ).format(tx.table("reservations"))
        ).fetchone()
        values["outstanding"], values["settled"] = outstanding
        return values


def ledger_setup(
    ledger: Ledger, tmp_path: Path, *, lost: bool
) -> tuple[Case, Executor, LedgerControl, dg.Definitions, Instance]:
    case = Case(tmp_path)
    case.setup(ledger)
    executor = Executor(case, lost=lost)
    control = LedgerControl(case, ledger, executor)
    defs = build_definitions(control, project_config())
    return case, executor, control, defs, Instance(key_for())


@pytest.mark.database
def test_backfill_reconciles_unknown_attempt(ledger: Ledger, tmp_path: Path) -> None:
    case, executor, _, defs, instance = ledger_setup(ledger, tmp_path, lost=True)
    first = case.dispatch(ledger, executor)  # a lost submit response: the outcome is unknown
    assert first.state == "unknown_outcome" and executor.calls == 1
    before = ledger_counts(ledger)
    assert before["attempts"] == 1 and before["reservations"] == 1

    # A new Dagster run for the same partition, with the remote still unobservable.
    for _ in range(2):
        rerun = instance.run(defs, key_for(), PROCESSING)
        assert not rerun.success and failure_codes(rerun) == ["unresolved_attempt"]
    assert executor.calls == 1  # same_partition_new_run_does_not_resubmit_unknown
    assert ledger_counts(ledger) == before  # budget_unchanged
    assert instance.materializations(PROCESSING) == []

    # The remote later proves success; the next run reconciles that very attempt.
    executor.success(first)
    backfill = instance.run(defs, key_for(), ADMISSION, PROCESSING)
    assert backfill.success
    assert executor.calls == 1
    after = ledger_counts(ledger)
    assert after["attempts"] == 1 and after["reservations"] == 1 and after["dispatch_claims"] == 1
    assert after["outstanding"] == before["outstanding"]
    (row,) = instance.materializations(PROCESSING)
    assert row["kf_attempt_id"] == first.attempt_id
    assert row["kf_plan_id"] == first.plan_id
    assert row["kf_operation_key"] == case.plan.operation_key
    # Re-running materializes from the ledger selection and still submits nothing.
    assert instance.run(defs, key_for(), PROCESSING).success
    assert executor.calls == 1 and ledger_counts(ledger)["attempts"] == 1


@pytest.mark.database
def test_durable_pause_blocks_cli_and_dagster_claims(ledger: Ledger, tmp_path: Path) -> None:
    case, executor, _, defs, instance = ledger_setup(ledger, tmp_path, lost=False)
    proof = case.proof()
    case.authority.controls[proof.digest] = ("pause", None, (), False, False)
    state = set_pause(
        "project",
        PROJECT,
        None,
        True,
        0,
        case.access,
        ledger,
        control=case.control,
        reason=Reason(code="unavailable", message="synthetic pause"),
        evidence_ref=proof,
    )
    assert state.paused
    before = ledger_counts(ledger)

    with pytest.raises(ContractError):  # CLI-style claim
        case.dispatch(ledger, executor)

    result = instance.run(defs, key_for(), PROCESSING)  # Dagster claim
    assert not result.success and failure_codes(result) == ["paused"]

    class StaleView(LedgerControl):  # a facade that wrongly reports not-paused
        def operation(self, partition: PartitionIdentity) -> OperationView:
            view = super().operation(partition)
            return OperationView(view.operation_key, False, view.held, view.attempts, view.selected)

    stale = build_definitions(StaleView(case, ledger, executor), project_config())
    refused = instance.run(stale, key_for(), PROCESSING)
    assert not refused.success and failure_codes(refused) == ["forbidden"]  # the ledger gate itself

    assert executor.calls == 0
    assert ledger_counts(ledger) == before
    assert instance.materializations(PROCESSING) == []


@pytest.mark.database
def test_late_result_still_reconciles_under_pause(ledger: Ledger, tmp_path: Path) -> None:
    case, executor, _, defs, instance = ledger_setup(ledger, tmp_path, lost=False)
    attempt = case.dispatch(ledger, executor)
    assert attempt.state == "running"
    proof = case.proof()
    case.authority.controls[proof.digest] = ("pause", None, (), False, False)
    set_pause(
        "run",
        PROJECT,
        RUN,
        True,
        0,
        case.access,
        ledger,
        control=case.control,
        reason=Reason(code="unavailable", message="synthetic pause"),
        evidence_ref=proof,
    )
    executor.success(attempt)
    done = instance.run(defs, key_for(), RECONCILIATION)
    assert done.success and executor.calls == 1
    (row,) = instance.materializations(RECONCILIATION)
    assert row["kf_attempt_id"] == attempt.attempt_id
