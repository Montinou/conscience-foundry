"""Lifecycle contracts for the cooperative local executor."""

import hashlib
from unittest.mock import Mock

import pytest
from test_modal import StepClock, build, make_ref

from conscience_foundry.contracts.common import ContractError
from conscience_foundry.execution.local_contracts import LocalWorkerGrant
from conscience_foundry.execution.local_executor import LocalExecutor


@pytest.fixture
def situation(tmp_path, monkeypatch):
    scenario = build()
    digest = hashlib.sha256(scenario.plan_bytes).hexdigest()
    grant = LocalWorkerGrant(
        scenario.plan.project_id,
        scenario.plan.run_id,
        digest,
        scenario.attempt.attempt_id,
        "local",
        scenario.grants.expires_at,
        b"synthetic scope",
        "secret-nonce",
    )
    monkeypatch.setattr(
        "conscience_foundry.execution.local_executor.verify_runtime", lambda digest: None
    )
    store = Mock()
    closure = (
        scenario.plan.extraction_spec_ref,
        *scenario.plan.limits_refs,
        scenario.plan.admission_report_ref,
        *scenario.plan.input_refs,
    )
    store.stage_inputs.return_value = closure
    store.root = tmp_path
    store.input_refs = closure

    def evidence(schema, data):
        return make_ref(data, schema)

    executor = LocalExecutor(tmp_path, "local", "a" * 64, StepClock(), evidence, lambda a, g: store)
    return scenario, grant, executor, store


def test_unknown_grant_refuses_before_spawn(situation, monkeypatch):
    scenario, grant, executor, store = situation
    spawn = Mock()
    monkeypatch.setattr("subprocess.Popen", spawn)
    with pytest.raises(ContractError):
        executor.submit(scenario.plan, scenario.attempt, object())
    spawn.assert_not_called()


def test_duplicate_submit_never_respawns(situation, monkeypatch):
    scenario, grant, executor, store = situation
    spawn = Mock(side_effect=OSError("lost ack"))
    monkeypatch.setattr("subprocess.Popen", spawn)
    executor.submit(scenario.plan, scenario.attempt, grant)
    with pytest.raises(ContractError):
        executor.submit(scenario.plan, scenario.attempt, grant)
    assert spawn.call_count == 1


def test_cancel_without_owned_identity_never_signals(situation, monkeypatch):
    scenario, grant, executor, store = situation
    terminate = Mock()
    monkeypatch.setattr("os.kill", terminate)
    observation = executor.cancel(scenario.attempt)
    assert observation.state in {"unknown_outcome", "cancel_requested"}
    terminate.assert_not_called()


def test_worker_missing_authority_refuses(tmp_path):
    import subprocess
    import sys

    job = tmp_path / "job.json"
    job.write_text("{}")
    result = subprocess.run(
        [sys.executable, "-m", "conscience_foundry.execution.local_worker", str(job)],
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0


def test_restart_cannot_respawn_after_lost_ack(situation, monkeypatch):
    scenario, grant, executor, store = situation
    spawn = Mock(side_effect=OSError("lost ack"))
    monkeypatch.setattr("subprocess.Popen", spawn)
    executor.submit(scenario.plan, scenario.attempt, grant)
    restarted = LocalExecutor(
        executor.journal_root, "local", "a" * 64, StepClock(), executor.evidence, lambda a, g: store
    )
    with pytest.raises(ContractError):
        restarted.submit(scenario.plan, scenario.attempt, grant)
    assert spawn.call_count == 1


def test_expired_grant_refuses_without_spawn(situation, monkeypatch):
    from dataclasses import replace

    scenario, grant, executor, store = situation
    spawn = Mock()
    monkeypatch.setattr("subprocess.Popen", spawn)
    with pytest.raises(ContractError):
        executor.submit(
            scenario.plan, scenario.attempt, replace(grant, expires_at="2000-01-01T00:00:00.000Z")
        )
    spawn.assert_not_called()


def test_runtime_drift_refuses_without_spawn(situation, monkeypatch):
    scenario, grant, executor, store = situation
    spawn = Mock()
    monkeypatch.setattr("subprocess.Popen", spawn)
    monkeypatch.setattr(
        "conscience_foundry.execution.local_executor.verify_runtime",
        Mock(side_effect=ContractError("hash_mismatch")),
        raising=False,
    )
    with pytest.raises(ContractError):
        executor.submit(scenario.plan, scenario.attempt, grant)
    spawn.assert_not_called()


def test_observe_missing_journal_is_unknown(situation):
    scenario, _, executor, _ = situation
    assert executor.observe(scenario.attempt).state == "unknown_outcome"


def identity_files(executor, attempt, *, handshake_nonce="challenge", process_time=10.0):
    import json

    directory = executor.journal_root / attempt.attempt_id
    directory.mkdir()

    def write(name, value):
        (directory / name).write_text(json.dumps(value))

    write(
        "intent.json",
        {
            "attempt_id": attempt.attempt_id,
            "project_id": attempt.project_id,
            "nonce": "challenge",
            "attempt": attempt.model_dump(mode="json", by_alias=True, exclude_none=True),
        },
    )
    write("process.json", {"pid": 1234, "create_time": process_time, "nonce": "challenge"})
    write("handshake.json", {"pid": 1234, "create_time": 10.0, "nonce": handshake_nonce})


@pytest.mark.parametrize("nonce,created", [("forged", 10.0), ("challenge", 9.0)])
def test_forged_handshake_and_reused_pid_never_signalled(situation, monkeypatch, nonce, created):
    scenario, _, executor, _ = situation
    identity_files(executor, scenario.attempt, handshake_nonce=nonce)
    process = Mock()
    process.create_time.return_value = created
    monkeypatch.setattr("psutil.Process", lambda pid: process)
    observation = executor.cancel(scenario.attempt)
    assert observation.state in {"unknown_outcome", "cancel_requested"}
    process.terminate.assert_not_called()


def test_only_matching_owned_process_is_signalled(situation, monkeypatch):
    scenario, _, executor, _ = situation
    identity_files(executor, scenario.attempt)
    process = Mock()
    process.create_time.return_value = 10.0
    process.is_running.return_value = True
    monkeypatch.setattr("psutil.Process", lambda pid: process)
    observation = executor.cancel(scenario.attempt)
    assert observation.state == "cancel_requested"
    process.terminate.assert_called_once_with()


def test_result_without_verified_journal_remains_unknown(situation):
    scenario, _, executor, _ = situation
    assert executor.observe(scenario.attempt).state == "unknown_outcome"


def test_recovery_reads_pointer_without_writing_or_authority(tmp_path, monkeypatch):
    import io

    from test_local_attempt_store import SyntheticAuthority
    from test_modal import ATTEMPT, PROJECT, RUN, execute, read_manifest

    from conscience_foundry.policy.access import AccessContext
    from conscience_foundry.storage.local_attempt import (
        LocalAttemptStore,
        local_output_scope,
        read_local_result,
    )

    scenario = build()
    manifest_ref = execute(scenario)
    manifest = read_manifest(scenario, manifest_ref)
    scope = local_output_scope(
        tmp_path,
        destination_id="local",
        project_id=PROJECT,
        run_id=RUN,
        attempt_id=ATTEMPT,
        plan_digest=hashlib.sha256(scenario.plan_bytes).hexdigest(),
    )
    grant = LocalWorkerGrant(
        PROJECT,
        RUN,
        hashlib.sha256(scenario.plan_bytes).hexdigest(),
        ATTEMPT,
        "local",
        scenario.grants.expires_at,
        scope,
        "nonce",
    )
    context = AccessContext(PROJECT, ATTEMPT, frozenset({"read", "extract"}))
    store = LocalAttemptStore(
        tmp_path,
        PROJECT,
        ATTEMPT,
        scenario.store,
        scenario.plan.input_refs,
        grant,
        StepClock(),
        SyntheticAuthority(),
    )
    for ref in (*manifest.outputs, manifest_ref):
        store.put_verified(io.BytesIO(scenario.store.objects[ref.digest]), ref, context)
    store.publish_result(ATTEMPT, manifest_ref)
    before = set(tmp_path.rglob("*"))
    assert read_local_result(tmp_path, grant) == (manifest, manifest_ref)
    assert set(tmp_path.rglob("*")) == before


def test_missing_attempt_recovery_creates_no_directory(tmp_path):
    from test_modal import ATTEMPT, PROJECT, RUN

    from conscience_foundry.storage.local_attempt import local_output_scope, read_local_result

    scope = local_output_scope(
        tmp_path,
        destination_id="local",
        project_id=PROJECT,
        run_id=RUN,
        attempt_id=ATTEMPT,
        plan_digest="a" * 64,
    )
    grant = LocalWorkerGrant(
        PROJECT, RUN, "a" * 64, ATTEMPT, "local", "2040-01-01T00:00:00.000Z", scope, "nonce"
    )
    with pytest.raises(ContractError):
        read_local_result(tmp_path, grant)
    assert not list(tmp_path.iterdir())


def test_stage_read_closure_includes_pinned_metadata(situation, monkeypatch):
    scenario, grant, executor, store = situation
    expected = (
        scenario.plan.extraction_spec_ref,
        *scenario.plan.limits_refs,
        scenario.plan.admission_report_ref,
        *scenario.plan.input_refs,
    )
    store.input_refs = expected
    store.stage_inputs.return_value = expected
    spawn = Mock(side_effect=OSError("lost ack"))
    monkeypatch.setattr("subprocess.Popen", spawn)
    executor.submit(scenario.plan, scenario.attempt, grant)
    assert spawn.call_count == 1


def test_substituted_stage_closure_refuses_spawn(situation, monkeypatch):
    scenario, grant, executor, store = situation
    store.input_refs = (scenario.source_ref,)
    store.stage_inputs.return_value = store.input_refs
    spawn = Mock()
    monkeypatch.setattr("subprocess.Popen", spawn)
    executor.submit(scenario.plan, scenario.attempt, grant)
    spawn.assert_not_called()


def test_restart_observes_durable_pointer_before_worker_record(tmp_path, monkeypatch):
    import io

    from test_local_attempt_store import SyntheticAuthority
    from test_modal import execute, read_manifest

    from conscience_foundry.execution.local_executor import local_staged_refs
    from conscience_foundry.policy.access import AccessContext
    from conscience_foundry.storage.local_attempt import LocalAttemptStore, local_output_scope

    scenario = build()
    manifest_ref = execute(scenario)
    manifest = read_manifest(scenario, manifest_ref)
    artifact_root = tmp_path / "artifacts"
    journal_root = tmp_path / "journal"
    artifact_root.mkdir()
    journal_root.mkdir()
    digest = hashlib.sha256(scenario.plan_bytes).hexdigest()
    scope = local_output_scope(
        artifact_root,
        destination_id="local",
        project_id=scenario.plan.project_id,
        run_id=scenario.plan.run_id,
        attempt_id=scenario.attempt.attempt_id,
        plan_digest=digest,
    )
    grant = LocalWorkerGrant(
        scenario.plan.project_id,
        scenario.plan.run_id,
        digest,
        scenario.attempt.attempt_id,
        "local",
        scenario.grants.expires_at,
        scope,
        "nonce",
    )
    store = LocalAttemptStore(
        artifact_root,
        grant.project_id,
        grant.attempt_id,
        scenario.store,
        local_staged_refs(scenario.plan),
        grant,
        StepClock(),
        SyntheticAuthority(),
    )

    def evidence(schema, data):
        return make_ref(data, schema)

    executor = LocalExecutor(
        journal_root, "local", "a" * 64, StepClock(), evidence, lambda a, g: store
    )
    monkeypatch.setattr(
        "conscience_foundry.execution.local_executor.verify_runtime", lambda digest: None
    )
    monkeypatch.setattr("subprocess.Popen", Mock(side_effect=OSError("lost response")))
    assert executor.submit(scenario.plan, scenario.attempt, grant).accepted is None
    assert executor.observe(scenario.attempt).state == "unknown_outcome"
    context = AccessContext(grant.project_id, grant.attempt_id, frozenset({"read", "extract"}))
    for ref in (*manifest.outputs, manifest_ref):
        store.put_verified(io.BytesIO(scenario.store.objects[ref.digest]), ref, context)
    store.publish_result(grant.attempt_id, manifest_ref)
    reopened_factory = Mock(side_effect=AssertionError("observe must not create store"))
    restarted = LocalExecutor(
        journal_root, "local", "a" * 64, StepClock(), evidence, reopened_factory
    )
    before = set(tmp_path.rglob("*"))
    observed = restarted.observe(scenario.attempt)
    assert (observed.state, observed.result_ref) == ("unknown_outcome", None)
    assert set(tmp_path.rglob("*")) == before
    reopened_factory.assert_not_called()
    import json

    intent = json.loads((journal_root / grant.attempt_id / "intent.json").read_text())
    identity = {"pid": 1234, "create_time": 10.0, "nonce": intent["nonce"]}
    (journal_root / grant.attempt_id / "process.json").write_text(json.dumps(identity))
    (journal_root / grant.attempt_id / "handshake.json").write_text(json.dumps(identity))
    process = Mock()
    process.create_time.return_value = 10.0
    process.is_running.return_value = True
    monkeypatch.setattr("psutil.Process", lambda pid: process)
    observed_running = restarted.observe(scenario.attempt)
    assert observed_running.state in {"running", "unknown_outcome"}
    assert observed_running.result_ref is None
    (journal_root / grant.attempt_id / "exit.json").write_text(
        json.dumps({**identity, "exit_code": 0})
    )
    completed = restarted.observe(scenario.attempt)
    assert (completed.state, completed.result_ref) == ("succeeded", manifest_ref)

    intent_path = journal_root / grant.attempt_id / "intent.json"
    intent = json.loads(intent_path.read_text())
    intent["config_digest"] = "0" * 64
    intent_path.write_text(json.dumps(intent))
    assert restarted.observe(scenario.attempt).state == "unknown_outcome"


def test_real_worker_valid_private_job_refuses_without_authority(situation, monkeypatch):
    import subprocess
    import sys

    scenario, grant, executor, store = situation
    real_popen = subprocess.Popen
    with monkeypatch.context() as patch:
        patch.setattr("subprocess.Popen", Mock(side_effect=OSError("lost acknowledgement")))
        executor.submit(scenario.plan, scenario.attempt, grant)
    job = executor.journal_root / scenario.attempt.attempt_id / "job.json"
    process = real_popen(
        [sys.executable, "-m", "conscience_foundry.execution.local_worker", str(job)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/bin:/usr/bin", "PYTHONNOUSERSITE": "1"},
    )
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 3
    assert stdout == stderr == b""
    assert (job.parent / "handshake.json").exists()


def test_confirmed_owned_termination_is_recorded_for_restart(situation, monkeypatch):
    scenario, _, executor, store = situation
    identity_files(executor, scenario.attempt)
    process = Mock()
    process.create_time.return_value = 10.0
    process.is_running.return_value = True
    process.wait.return_value = -15
    monkeypatch.setattr("psutil.Process", lambda pid: process)
    observation = executor.cancel(scenario.attempt)
    assert observation.state == "cancel_requested"
    executor._waiters[scenario.attempt.attempt_id].join(timeout=2)
    process.terminate.assert_called_once_with()
    assert (executor.journal_root / scenario.attempt.attempt_id / "exit.json").is_file()


def test_confirmed_termination_remains_cancelled_after_restart(situation, monkeypatch):
    import json

    from test_local_attempt_store import SyntheticAuthority

    from conscience_foundry.execution.local_executor import local_staged_refs
    from conscience_foundry.storage.local_attempt import LocalAttemptStore, local_output_scope

    scenario, grant, executor, _ = situation
    from dataclasses import replace

    artifact_root = executor.journal_root / "artifacts"
    artifact_root.mkdir()
    scope = local_output_scope(
        artifact_root,
        destination_id="local",
        project_id=grant.project_id,
        run_id=grant.run_id,
        attempt_id=grant.attempt_id,
        plan_digest=grant.plan_digest,
    )
    grant = replace(grant, output_scope=scope)
    store = LocalAttemptStore(
        artifact_root,
        grant.project_id,
        grant.attempt_id,
        scenario.store,
        local_staged_refs(scenario.plan),
        grant,
        StepClock(),
        SyntheticAuthority(),
    )
    executor.store_factory = lambda a, g: store
    monkeypatch.setattr("subprocess.Popen", Mock(side_effect=OSError("lost acknowledgement")))
    executor.submit(scenario.plan, scenario.attempt, grant)
    directory = executor.journal_root / scenario.attempt.attempt_id
    intent = json.loads((directory / "intent.json").read_text())
    identity = {"pid": 1234, "create_time": 10.0, "nonce": intent["nonce"]}
    (directory / "process.json").write_text(json.dumps(identity))
    (directory / "handshake.json").write_text(json.dumps(identity))
    process = Mock()
    process.create_time.return_value = 10.0
    process.is_running.return_value = True
    process.wait.return_value = -15
    monkeypatch.setattr("psutil.Process", lambda pid: process)
    assert executor.cancel(scenario.attempt).state == "cancel_requested"
    executor._waiters[scenario.attempt.attempt_id].join(timeout=2)
    restarted = LocalExecutor(
        executor.journal_root, "local", "a" * 64, StepClock(), executor.evidence, lambda a, g: store
    )
    assert restarted.observe(scenario.attempt).state == "cancelled"


def test_wrong_attempt_binding_never_signals(situation, monkeypatch):
    scenario, _, executor, _ = situation
    identity_files(executor, scenario.attempt)
    altered = scenario.attempt.model_copy(update={"operation_key": "f" * 64})
    process = Mock()
    process.create_time.return_value = 10.0
    process.is_running.return_value = True
    monkeypatch.setattr("psutil.Process", lambda pid: process)
    assert executor.cancel(altered).state == "unknown_outcome"
    process.terminate.assert_not_called()


def test_normal_exit_during_cancel_does_not_claim_cancelled(situation, monkeypatch):
    scenario, _, executor, _ = situation
    identity_files(executor, scenario.attempt)
    process = Mock()
    process.create_time.return_value = 10.0
    process.is_running.return_value = True
    process.wait.return_value = 0
    monkeypatch.setattr("psutil.Process", lambda pid: process)
    assert executor.cancel(scenario.attempt).state in {"unknown_outcome", "cancel_requested"}
    assert not (executor.journal_root / scenario.attempt.attempt_id / "terminal.json").exists()


def test_asynchronous_cancellation_records_exit(situation, monkeypatch):
    import threading

    import psutil

    from conscience_foundry.execution import local_executor

    scenario, _, executor, _ = situation
    identity_files(executor, scenario.attempt)
    process = Mock()
    process.create_time.return_value = 10.0
    process.is_running.return_value = True
    allowed_exit = threading.Event()
    observed_exit = threading.Event()

    def wait(timeout=None):
        if timeout == 0:
            raise psutil.TimeoutExpired(0)
        assert allowed_exit.wait(2)
        return -15

    process.wait.side_effect = wait
    monkeypatch.setattr("psutil.Process", lambda pid: process)
    original = local_executor._exclusive

    def record(directory, name, value):
        original(directory, name, value)
        if name == "exit.json":
            observed_exit.set()

    monkeypatch.setattr(local_executor, "_exclusive", record)
    assert executor.cancel(scenario.attempt).state == "cancel_requested"
    allowed_exit.set()
    assert observed_exit.wait(2), "no independently observed termination was persisted"
    process.terminate.assert_called_once_with()


def test_non_child_wait_without_exit_code_remains_unresolved(situation, monkeypatch):
    scenario, _, executor, _ = situation
    identity_files(executor, scenario.attempt)
    process = Mock()
    process.create_time.return_value = 10.0
    process.is_running.return_value = True
    process.wait.return_value = None
    monkeypatch.setattr("psutil.Process", lambda pid: process)
    assert executor.cancel(scenario.attempt).state == "cancel_requested"
    executor._waiters[scenario.attempt.attempt_id].join(timeout=2)
    directory = executor.journal_root / scenario.attempt.attempt_id
    assert (directory / "signal_sent.json").exists()
    assert not (directory / "exit.json").exists()
