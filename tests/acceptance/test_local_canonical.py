"""Synthetic local CLI path through independently approved operator configuration."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

for _sibling in ("integration", "adapters"):
    _path = str(Path(__file__).resolve().parents[1] / _sibling)
    if _path not in sys.path:
        sys.path.append(_path)

from test_cli import Env, count, ref_file, register  # noqa: E402
from test_ledger_db import ASSET, PROJECT, RUN  # noqa: E402
from test_local_authority import local_case  # noqa: E402

from conscience_foundry.cli.config import now  # noqa: E402
from conscience_foundry.cli.live import build_services  # noqa: E402
from conscience_foundry.cli.local_authority import LocalAllocationEstimate, LocalWorkerBootstrap  # noqa: E402
from conscience_foundry.contracts.admission import IntakeManifest  # noqa: E402
from conscience_foundry.core.identity import F1Operation, operation_key  # noqa: E402
from conscience_foundry.execution.evidence import encoded  # noqa: E402
from conscience_foundry.execution.local_allocation import LocalAllocator  # noqa: E402
from conscience_foundry.execution.local_runtime import runtime_digest, runtime_manifest  # noqa: E402

pytestmark = pytest.mark.database


@pytest.mark.parametrize(
    ("pretty_bootstrap", "interrupted", "expired", "rollback", "drift", "cancelled", "failed"),
    [
        (False, False, False, False, False, False, False),
        (False, False, False, False, False, False, True),
        (False, False, False, False, False, True, False),
        (True, True, False, False, False, False, False),
        (False, False, True, False, False, False, False),
        (False, False, False, True, False, False, False),
        (False, False, False, False, True, False, False),
    ],
)
def test_real_local_cli_canonical_flow(
    ledger,
    tmp_path,
    monkeypatch,
    pretty_bootstrap,
    interrupted,
    expired,
    rollback,
    drift,
    cancelled,
    failed,
):
    """No injected estimator or observation facts and no seeded canonical result."""
    current = now()
    expiry = (datetime.now(UTC) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    funded_from = (
        (datetime.now(UTC) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        if expired
        else current
    )
    funded_until = (
        (datetime.now(UTC) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        if expired
        else expiry
    )
    import test_execution_control as fixtures

    monkeypatch.setattr(fixtures, "TIME", current)
    monkeypatch.setattr(fixtures, "EXPIRY", expiry)
    if not failed:
        from dataclasses import replace

        from test_ledger_db import admission, reference

        def distinct_admission():
            base = admission(extra_asset=True)
            payload = b"Second synthetic text"
            intake = IntakeManifest.from_wire(base.evidence.manifest_bytes, case_bound)
            second_item = intake.items[1].model_copy(
                update={
                    "original_digest": hashlib.sha256(payload).hexdigest(),
                    "size_bytes": len(payload),
                }
            )
            intake = intake.model_copy(update={"items": (intake.items[0], second_item)})
            intake_raw = encoded(intake)
            snapshot = reference(payload, "cf.raw-original.v1").model_copy(
                update={"media_type": "text/plain"}
            )
            entry = base.report.entries[1].model_copy(update={"snapshot_ref": snapshot})
            report = base.report.model_copy(
                update={
                    "manifest_digest": hashlib.sha256(intake_raw).hexdigest(),
                    "entries": (base.report.entries[0], entry),
                }
            )
            report_raw = encoded(report)
            return replace(
                base,
                manifest_ref=reference(intake_raw, "cf.intake.v1"),
                report=report,
                report_ref=reference(report_raw, "cf.admission-report.v1"),
                evidence=replace(base.evidence, manifest_bytes=intake_raw, report_bytes=report_raw),
            )

        from test_ledger_db import limits

        case_bound = limits()
        monkeypatch.setattr(fixtures, "admission", distinct_admission)
    if failed:
        from dataclasses import replace

        from test_ledger_db import admission, reference

        def invalid_admission():
            base = admission()
            payload = b"\xff"
            intake = IntakeManifest.from_wire(
                base.evidence.manifest_bytes, base.evidence.limits_by_schema["cf.intake.v1"]
            )
            item = intake.items[0].model_copy(
                update={
                    "original_digest": hashlib.sha256(payload).hexdigest(),
                    "size_bytes": len(payload),
                }
            )
            intake = intake.model_copy(update={"items": (item,)})
            intake_raw = encoded(intake)
            snapshot = reference(payload, "cf.raw-original.v1").model_copy(
                update={"media_type": "text/plain"}
            )
            entry = base.report.entries[0].model_copy(update={"snapshot_ref": snapshot})
            report = base.report.model_copy(
                update={
                    "manifest_digest": hashlib.sha256(intake_raw).hexdigest(),
                    "entries": (entry,),
                }
            )
            report_raw = encoded(report)
            evidence = replace(base.evidence, manifest_bytes=intake_raw, report_bytes=report_raw)
            return replace(
                base,
                manifest_ref=reference(intake_raw, "cf.intake.v1"),
                report=report,
                report_ref=reference(report_raw, "cf.admission-report.v1"),
                evidence=evidence,
            )

        monkeypatch.setattr(fixtures, "admission", invalid_admission)
    case = local_case(tmp_path, source_bytes=b"\xff" if failed else b"Synthetic text")
    if not failed:
        import io

        second_original = case.data.report.entries[1].snapshot_ref
        assert second_original is not None
        case.store.put_verified(io.BytesIO(b"Second synthetic text"), second_original, case.access)
    else:
        second_original = case.original
    manifest = runtime_manifest()
    identity = runtime_digest(manifest)
    case.spec = case.spec.model_copy(update={"image_digest": identity})
    case.spec_ref = case.put(case.spec)
    case.config = case.config.model_copy(update={"image_digest": identity})
    case.config_ref = case.put(case.config)
    intake = IntakeManifest.from_wire(case.data.evidence.manifest_bytes, case.bound)
    key = operation_key(
        F1Operation(
            PROJECT,
            ASSET,
            intake.items[0].source_id,
            (case.original.digest,),
            case.spec_ref.digest,
            intake.profile_id,
            intake.profile_version,
            intake.policy_ref.digest,
            case.plan.contract_set_ref.digest,
            (case.limits_ref.digest,),
        ),
        limits=case.bound,
    )
    case.plan = case.plan.model_copy(
        update={
            "extraction_spec_ref": case.spec_ref,
            "execution_config_ref": case.config_ref,
            "operation_key": key,
            "resources": case.plan.resources.model_copy(update={"max_wall_seconds": 30}),
            "budget": case.plan.budget.model_copy(update={"valid_until": expiry}),
            "expires_at": expiry,
        }
    )
    case.plan_ref = case.put(case.plan)
    second = intake.items[1] if not failed else intake.items[0]
    second_key = operation_key(
        F1Operation(
            PROJECT,
            second.asset_id,
            second.source_id,
            (second_original.digest,),
            case.spec_ref.digest,
            intake.profile_id,
            intake.profile_version,
            intake.policy_ref.digest,
            case.plan.contract_set_ref.digest,
            (case.limits_ref.digest,),
        ),
        limits=case.bound,
    )
    other_plan = case.plan.model_copy(
        update={
            "plan_id": "00000000-0000-0000-0000-0000000000f1",
            "operation_key": second_key,
            "input_refs": (second_original,),
        }
    )
    other_ref = case.put(other_plan)
    case.auth = case.auth.model_copy(
        update={
            "allowed_plan_digests": (case.plan_ref.digest, other_ref.digest),
            "authorized_at": current,
            "expires_at": expiry,
        }
    )
    case.auth_ref = case.put(case.auth)
    quotes = []
    for scope, amount in (("attempt", "4"), ("run_storage", "1")):
        quote = LocalAllocationEstimate(
            schema_version="cfoundry.local-allocation-estimate.v1",
            project_id=PROJECT,
            scope=scope,
            authorization_ref=case.auth_ref,
            plan_refs=(case.plan_ref, other_ref),
            config_refs=(case.config_ref,),
            resource_policy_ref=case.config.resource_policy_ref,
            funded_from=funded_from,
            funded_until=funded_until,
            ceiling_usd=amount,
        )
        quotes.append((case.put(quote), encoded(quote)))
    for name in (
        "cfoundry.local-allocation-estimate.v1",
        "cf.local-process-observation.v1",
        "cfoundry.local-attempt-allocation.v1",
        "cfoundry.local-storage-allocation.v1",
    ):
        case.schemas[name] = case.bound
    # Each installed schema has an independent byte ceiling.
    case.schemas["cfoundry.local-allocation-estimate.v1"] = case.bound.model_copy(
        update={"max_json_bytes": max(len(raw) for _, raw in quotes)}
    )
    # Runtime file inventory can be larger than a single contract payload.
    metadata = case.bound.model_copy(
        update={
            "max_json_bytes": 100_000_000,
            "max_array_items": 500_000,
            "max_string_scalars": 65_536,
        }
    )
    case.schemas["cf.metadata-schema.v1"] = metadata
    from conftest import approved_database_dsn

    env = Env(
        tmp_path,
        monkeypatch,
        schemas=case.schemas,
        bound=case.bound,
        policy=lambda: case.policy,
        scopes=case.access.scopes,
        dsn=approved_database_dsn(),
        schema_name=ledger.schema,
    )
    root, output, journal = (tmp_path / name for name in ("allocator", "attempt-root", "journal"))
    for directory in (root, output, journal):
        directory.mkdir()
    astat, ostat, sstat, pstat = map(os.stat, (root, output, env.objects, env.policy_path.parent))
    bootstrap = LocalWorkerBootstrap(
        schema_version="cfoundry.local-worker-bootstrap.v1",
        project_id=PROJECT,
        actor_id=case.access.actor_id,
        allocator_root=str(root),
        allocator_device=str(astat.st_dev),
        allocator_inode=str(astat.st_ino),
        output_root=str(output),
        output_device=str(ostat.st_dev),
        output_inode=str(ostat.st_ino),
        operator_store_root=str(env.objects),
        operator_device=str(sstat.st_dev),
        operator_inode=str(sstat.st_ino),
        operator_store_id="synthetic",
        policy_path=str(env.policy_path),
        policy_parent_device=str(pstat.st_dev),
        policy_parent_inode=str(pstat.st_ino),
        policy_limits=case.bound,
        attempt_price_usd="4",
        storage_price_usd="1",
        run_storage_capacity_bytes=2_000_000,
        operator_storage_capacity_bytes=4_000_000,
        resource_policy_ref=case.config.resource_policy_ref,
        funded_from=funded_from,
        funded_until=funded_until,
        semantics="cooperative",
    )
    bootstrap_path = tmp_path / "bootstrap.json"
    bootstrap_raw = (
        json.dumps(json.loads(encoded(bootstrap)), indent=2).encode()
        if pretty_bootstrap
        else encoded(bootstrap)
    )
    bootstrap_path.write_bytes(bootstrap_raw)
    bootstrap_digest = hashlib.sha256(bootstrap_raw).hexdigest()
    LocalAllocator.initialize(
        root,
        bootstrap.allocation_policy(),
        case.store,
        now,
        operator_store_id="synthetic",
        operator_store_root=env.objects,
    )
    allocator = LocalAllocator(
        root,
        bootstrap.allocation_policy(),
        case.store,
        now,
        operator_store_id="synthetic",
        operator_store_root=env.objects,
    )
    allocator.register_worker_bootstrap(bootstrap_path, bootstrap_digest)

    def entry(ref, raw):
        return {
            "ref": ref.model_dump(mode="json", by_alias=True),
            "bytesBase64": base64.b64encode(raw).decode(),
        }

    quote_path = tmp_path / "quotes.json"
    quote_path.write_text(
        json.dumps(
            {
                "schemaVersion": "cfoundry.local-quote-manifest.v1",
                "projectId": PROJECT,
                "authorizationRef": case.auth_ref.model_dump(mode="json", by_alias=True),
                "plans": [
                    entry(case.plan_ref, encoded(case.plan)),
                    entry(other_ref, encoded(other_plan)),
                ],
                "configs": [entry(case.config_ref, encoded(case.config))],
                "estimates": [entry(ref, raw) for ref, raw in quotes],
            }
        )
    )
    runtime_path = tmp_path / "runtime.json"
    runtime_path.write_text(json.dumps(manifest))
    env.grants = {
        **env.grants,
        "execution": [*env.grants["execution"], "local-receipts", "close-local-storage"],
    }
    env.extra.update(
        {
            "releaseAuthority": {"kind": "local"},
            "projectMaxLiveAttempts": 3,
            "localExecution": {
                "journalRoot": str(journal),
                "allocatorRoot": str(root),
                "bootstrapPath": str(bootstrap_path),
                "bootstrapDigest": bootstrap_digest,
                "attemptRoot": str(output),
                "runtimeManifestPath": str(runtime_path),
                "trustedQuoteManifestPath": str(quote_path),
                "destinationId": "local",
                "attemptPriceUsd": "4",
                "storagePriceUsd": "1",
                "runStorageCapacityBytes": 2_000_000,
                "operatorStorageCapacityBytes": 4_000_000,
                "resourcePolicyRef": case.config.resource_policy_ref.model_dump(
                    mode="json", by_alias=True
                ),
                "fundedFrom": funded_from,
                "fundedUntil": funded_until,
                "semantics": "cooperative",
                "controlActions": ["mark_unknown_outcome", "cancel_attempt"],
            },
        }
    )
    env.write_config()
    from conscience_foundry.cli.config import load_config

    services = build_services(load_config(env.config_path))
    from conscience_foundry.cli.config import Runtime

    first = Runtime(load_config(env.config_path), services, "prepare-run")
    try:
        assert first.services.local is not services.local
        assert not hasattr(services.local, "allocator")
        assert callable(first.services.local.receipt_issuer)
    finally:
        first.close()
    from dataclasses import replace

    from conscience_foundry.contracts.common import ContractError

    with pytest.raises(ContractError):
        Runtime(load_config(env.config_path), replace(services, executor=object()), "dispatch")
    original_config = load_config(env.config_path)
    mismatched = original_config.model_copy(
        update={
            "local_execution": original_config.local_execution.model_copy(
                update={"attempt_root": str(tmp_path / "other-root")}
            )
        }
    )
    with pytest.raises(ContractError):
        Runtime(mismatched, build_services(mismatched), "dispatch")
    register(case, ledger)

    def run(*args):
        return env.invoke(*args, services=services)

    plan = env.input("plan.json", encoded(case.plan))
    auth = env.input("authorization.json", encoded(case.auth))
    assert run("prepare-run", "--plan", plan, "--execute").exit == 0
    other_file = env.input("other-plan.json", encoded(other_plan))
    assert run("prepare-run", "--plan", other_file, "--execute").exit == 0
    assert run("authorize-run", "--authorization", auth, "--execute").exit == 0
    storage_ref = ref_file(env, "storage-quote.json", quotes[1][0])
    storage_result = run(
        "reserve-storage", "--run-id", RUN, "--amount", "1", "--evidence", storage_ref, "--execute"
    )
    if expired:
        assert storage_result.exit != 0
        assert count(ledger, "reservations") == 0
        assert not list(journal.iterdir())
        return
    assert storage_result.exit == 0, storage_result.raw
    from conscience_foundry.execution import local_executor

    if cancelled:
        # Test-only gate holds the real worker after its own durable handshake.
        original_bootstrap = local_executor._WORKER_BOOTSTRAP
        gate = """import time
import conscience_foundry.execution.local_worker as worker
original = worker.reconstruct_authority
def held(*args):
    time.sleep(30)
    return original(*args)
worker.reconstruct_authority = held
raise SystemExit(worker.main())
"""
        target = (
            "runpy.run_module('conscience_foundry.execution.local_worker', run_name='__main__')"
        )
        assert target in original_bootstrap
        monkeypatch.setattr(
            local_executor, "_WORKER_BOOTSTRAP", original_bootstrap.replace(target, gate)
        )
    child_environments = []
    real_popen = local_executor.subprocess.Popen

    def observe_spawn(*args, **kwargs):
        child_environments.append(set(kwargs["env"]))
        return real_popen(*args, **kwargs)

    monkeypatch.setenv("CF_SYNTHETIC_PARENT_SECRET", "synthetic-only")
    monkeypatch.setattr(local_executor.subprocess, "Popen", observe_spawn)
    dispatch_args = (
        "dispatch",
        "--plan-ref",
        ref_file(env, "plan-ref.json", case.plan_ref),
        "--authorization-ref",
        ref_file(env, "auth-ref.json", case.auth_ref),
        "--evidence-ref",
        ref_file(env, "attempt-quote.json", quotes[0][0]),
        "--asset-id",
        ASSET,
        "--execute",
    )
    if drift:
        from conscience_foundry.execution import local_runtime

        before = (root / "allocator.json").read_bytes()
        changed = {**manifest, "os": [*manifest["os"][:-1], "different-architecture"]}
        monkeypatch.setattr(local_runtime, "runtime_manifest", lambda: changed)
        outcome = run(*dispatch_args)
        assert (root / "allocator.json").read_bytes() == before, outcome.raw
        assert not list(journal.iterdir()) and not child_environments
        assert count(ledger, "attempts") == 1  # committed claim; liability remains conservative
        return
    if rollback:
        from conscience_foundry.execution import control as control_module

        original_claim = control_module.claim_attempt
        before = (root / "allocator.json").read_bytes()

        def rollback_claim(*args, **kwargs):
            original_claim(*args, **kwargs)
            raise ContractError("forbidden")

        with monkeypatch.context() as patch:
            patch.setattr(control_module, "claim_attempt", rollback_claim)
            refused = run(*dispatch_args)
        assert refused.exit != 0
        assert count(ledger, "attempts") == 0
        assert count(ledger, "reservations") == 1  # only prior storage funding remains
        assert (root / "allocator.json").read_bytes() == before
        assert not list(journal.iterdir()) and not child_environments
        return
    if interrupted:
        from psycopg import sql

        from conscience_foundry.execution.local_executor import LocalExecutor

        original_submit = LocalExecutor.submit

        def interrupt_after_spawn(self, plan, attempt, grant):
            original_submit(self, plan, attempt, grant)
            raise KeyboardInterrupt

        with monkeypatch.context() as patch:
            patch.setattr(LocalExecutor, "submit", interrupt_after_spawn)
            with pytest.raises(KeyboardInterrupt):
                run(*dispatch_args)
        with ledger.transaction() as tx:
            rows = tx.connection.execute(
                sql.SQL("SELECT attempt_id::text FROM {}").format(tx.table("attempts"))
            ).fetchall()
        assert len(rows) == 1
        attempt_id = rows[0][0]
    else:
        dispatch = run(*dispatch_args)
        assert dispatch.exit == 0, dispatch.raw
        attempt_id = dispatch.payload["attempt"]["attemptId"]
    assert count(ledger, "attempts") == 1
    if cancelled or failed:
        import time

        deadline = time.monotonic() + 15
        while (
            not (journal / attempt_id / "handshake.json").exists() and time.monotonic() < deadline
        ):
            time.sleep(0.05)
        assert (journal / attempt_id / "handshake.json").exists()
        if cancelled:
            cancellation = run(
                "cancel",
                "--attempt-id",
                attempt_id,
                "--reason-code",
                "unavailable",
                "--reason-message",
                "Synthetic cancellation",
                "--evidence-ref",
                ref_file(env, "cancel-evidence.json", case.data.report_ref),
                "--execute",
            )
            assert cancellation.exit == 0, cancellation.raw
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            observed = run("reconcile", "--attempt-id", attempt_id, "--execute")
            if observed.exit == 0 and observed.payload["attempt"]["state"] == (
                "cancelled" if cancelled else "failed"
            ):
                break
            time.sleep(0.05)
        assert observed.payload["attempt"]["state"] == ("cancelled" if cancelled else "failed"), (
            observed.raw
        )
        candidates = run("local-receipts", "--attempt-id", attempt_id, "--execute")
        assert candidates.exit == 0, candidates.raw
        billed = run(
            "record-billing",
            "--attempt-id",
            attempt_id,
            "--amount",
            "4",
            "--evidence",
            env.input("cancel-attempt.json", json.dumps(candidates.payload["attemptRef"])),
            "--execute",
        )
        assert billed.exit == 0, billed.raw
        closed = run(
            "close-local-storage",
            "--run-id",
            RUN,
            "--evidence",
            env.input("cancel-storage.json", json.dumps(candidates.payload["storageRef"])),
            "--execute",
        )
        assert closed.exit == 0, closed.raw
        return

    # Trusted core requires the matching deadline token before consulting local authority.
    from dataclasses import replace

    from conscience_foundry.contracts.common import Reason
    from conscience_foundry.execution.control import mark_unknown_outcome

    token = object()
    active = Runtime(load_config(env.config_path), services, "reconcile")
    try:
        context = replace(active.control, deadline_token=token)
        reason = Reason(code="limit_exceeded", message="Synthetic controller interruption")
        with pytest.raises(ContractError):
            mark_unknown_outcome(
                attempt_id,
                active.ledger,
                control=context,
                reason=reason,
                evidence_ref=case.data.report_ref,
                deadline_token=object(),
            )
        # Empty local allowlist refuses even a valid deadline token and command grant.
        empty_config = load_config(env.config_path)
        empty_config = empty_config.model_copy(
            update={
                "local_execution": empty_config.local_execution.model_copy(
                    update={"control_actions": ()}
                )
            }
        )
        empty = Runtime(empty_config, build_services(empty_config), "reconcile")
        try:
            with pytest.raises(ContractError):
                mark_unknown_outcome(
                    attempt_id,
                    empty.ledger,
                    control=replace(empty.control, deadline_token=token),
                    reason=reason,
                    evidence_ref=case.data.report_ref,
                    deadline_token=token,
                )
        finally:
            empty.close()
        denied = Runtime(load_config(env.config_path), services, "pause")
        try:
            with pytest.raises(ContractError):
                mark_unknown_outcome(
                    attempt_id,
                    denied.ledger,
                    control=replace(denied.control, deadline_token=token),
                    reason=reason,
                    evidence_ref=case.data.report_ref,
                    deadline_token=token,
                )
        finally:
            denied.close()
        marked = mark_unknown_outcome(
            attempt_id,
            active.ledger,
            control=context,
            reason=reason,
            evidence_ref=case.data.report_ref,
            deadline_token=token,
        )
        assert marked.state == "unknown_outcome"
    finally:
        active.close()
    assert count(ledger, "attempts") == 1
    # Drop the controller services and reconstruct them from operator pins.
    services = build_services(load_config(env.config_path))
    retry = run(
        "dispatch",
        "--plan-ref",
        ref_file(env, "plan-ref.json", case.plan_ref),
        "--authorization-ref",
        ref_file(env, "auth-ref.json", case.auth_ref),
        "--evidence-ref",
        ref_file(env, "attempt-quote.json", quotes[0][0]),
        "--asset-id",
        ASSET,
        "--execute",
    )
    assert count(ledger, "attempts") == 1, retry.raw
    assert len(list(journal.iterdir())) == 1
    assert child_environments == [{"PATH", "PYTHONNOUSERSITE"}]
    # A fresh command invocation must recover the same attempt without another spawn.
    import time

    for _ in range(100):
        result = run("reconcile", "--attempt-id", attempt_id, "--execute")
        if result.exit == 0 and result.payload["attempt"]["state"] == "succeeded":
            break
        time.sleep(0.1)
    assert result.payload["attempt"]["state"] == "succeeded"
    assert result.payload["selection"]["outcome"] == "selected"
    assert count(ledger, "operation_results") == 1
    assert count(ledger, "attempts") == 1
    # Exercise the actual composed executor callback with independent schema limits.
    from contextlib import contextmanager

    from conscience_foundry.cli.local_authority import LocalCommittedGuard, LocalProcessObservation
    from conscience_foundry.contracts.execution import StageAttempt
    from conscience_foundry.execution import evidence as evidence_module

    # The deliberately tiny stage limit cannot admit the persisted attempt itself.
    # Verify that read under its installed limit, then isolate the composed writer
    # with independently acquired committed facts and the two synthetic bounds.
    original_read_model = evidence_module.read_model

    def read_committed_with_installed_limit(ref, model, control):
        if model is not StageAttempt:
            return original_read_model(ref, model, control)
        configured = bound_limits[stage_schema]
        bound_limits[stage_schema] = stage_original
        try:
            return original_read_model(ref, model, control)
        finally:
            bound_limits[stage_schema] = configured

    with monkeypatch.context() as patch:
        patch.setattr(evidence_module, "read_model", read_committed_with_installed_limit)
        bound_runtime = Runtime(load_config(env.config_path), services, "reconcile")
    try:
        stage_schema = "cf.stage-attempt.v1"
        obs_schema = "cf.local-process-observation.v1"
        bound_limits = bound_runtime.limits
        stage_original, obs_original = bound_limits[stage_schema], bound_limits[obs_schema]
        bound_attempt, _ = bound_runtime.services.local.committed(PROJECT, attempt_id)
        bound_guard = bound_runtime.services.local.guard_for(bound_attempt)
        with bound_guard.evidence(bound_attempt) as bound_facts:
            pass
        observation_model = LocalProcessObservation(
            schema_version="cf.local-process-observation.v1",
            attempt_id=attempt_id,
            action="observe",
            observed_state=bound_runtime.services.executor._inspect(bound_attempt).state,
        )
        observation = json.dumps(
            json.loads(encoded(observation_model)), sort_keys=True, separators=(",", ":")
        ).encode()
        strict = case.bound.model_copy(update={"max_json_bytes": len(observation) - 1})
        ample = case.bound.model_copy(update={"max_json_bytes": len(observation)})
        writes = []
        original_import = bound_runtime.services.local.allocator.import_writer

        def track_import(*args):
            writes.append(True)
            return original_import(*args)

        @contextmanager
        def already_verified(guard, candidate):
            assert candidate == bound_attempt
            yield bound_facts

        outcomes = []
        with monkeypatch.context() as patch:
            patch.setattr(LocalCommittedGuard, "evidence", already_verified)
            patch.setattr(bound_runtime.services.local.allocator, "import_writer", track_import)
            for stage_bound, obs_bound in ((strict, ample), (ample, strict), (ample, None)):
                bound_limits[stage_schema] = stage_bound
                if obs_bound is None:
                    bound_limits.pop(obs_schema, None)
                else:
                    bound_limits[obs_schema] = obs_bound
                writes.clear()
                try:
                    bound_runtime.services.executor.evidence(bound_attempt, obs_schema, observation)
                    outcomes.append(("published", len(writes)))
                except ContractError as error:
                    outcomes.append((error.code, len(writes)))
            bound_limits[stage_schema], bound_limits[obs_schema] = stage_original, obs_original
        assert outcomes == [("published", 1), ("limit_exceeded", 0), ("limits_missing", 0)], (
            outcomes
        )
    finally:
        bound_runtime.close()
    from test_execution_control import attempt_row
    from test_ledger_db import ACTOR

    from conscience_foundry.contracts.canonical import RevisionReview
    from conscience_foundry.contracts.common import Reason, Ref
    from conscience_foundry.contracts.execution import ResultManifest

    result_ref = Ref.model_validate(attempt_row(ledger, attempt_id)[1])
    result_model = ResultManifest.from_wire(
        case.store.read_verified(result_ref, case.access, 65536).data, case.bound
    )
    revision_ref = result_model.document_revision_ref
    assert revision_ref is not None
    revision = json.loads(case.store.read_verified(revision_ref, case.access, 65536).data)
    review = RevisionReview(
        schema_version="cf.revision-review.v1",
        project_id=PROJECT,
        revision_id=revision["revisionId"],
        decision="accepted",
        actor_id=ACTOR,
        policy_version=case.policy.policy_version,
        reviewed_at=now(),
        reason=Reason(code="unavailable", message="Synthetic operator decision"),
    )
    reviewed = run(
        "review",
        "--review",
        env.input("review.json", encoded(review)),
        "--operation-key",
        case.plan.operation_key,
        "--revision-ref",
        ref_file(env, "revision.json", revision_ref),
        "--evidence-ref",
        ref_file(env, "report.json", case.data.report_ref),
        "--execute",
    )
    assert reviewed.exit == 0, reviewed.raw

    # A local settlement uses explicit metered candidates and closes the retained set.
    candidates = run("local-receipts", "--attempt-id", attempt_id, "--execute")
    assert candidates.exit == 0, candidates.raw
    attempt_receipt = candidates.payload["attemptRef"]
    storage_receipt = candidates.payload["storageRef"]
    second_dispatch = run(
        "dispatch",
        "--plan-ref",
        ref_file(env, "first-plan-ref.json", other_ref),
        "--authorization-ref",
        ref_file(env, "first-auth-ref.json", case.auth_ref),
        "--evidence-ref",
        ref_file(env, "first-attempt-quote.json", quotes[0][0]),
        "--asset-id",
        second.asset_id,
        "--execute",
    )
    assert second_dispatch.exit == 0, second_dispatch.raw
    second_attempt = second_dispatch.payload["attempt"]["attemptId"]
    assert second_attempt != attempt_id
    for _ in range(100):
        second_result = run("reconcile", "--attempt-id", second_attempt, "--execute")
        if second_result.exit == 0 and second_result.payload["attempt"]["state"] in (
            "succeeded",
            "failed",
        ):
            break
        time.sleep(0.1)
    assert second_result.payload["attempt"]["state"] == "succeeded", second_result.raw
    second_candidates = run("local-receipts", "--attempt-id", second_attempt, "--execute")
    assert second_candidates.exit == 0, second_candidates.raw
    second_storage = Ref.model_validate(second_candidates.payload["storageRef"])
    assert second_storage != Ref.model_validate(storage_receipt)
    second_billed = run(
        "record-billing",
        "--attempt-id",
        second_attempt,
        "--amount",
        "4",
        "--evidence",
        env.input(
            "second-attempt-receipt.json", json.dumps(second_candidates.payload["attemptRef"])
        ),
        "--execute",
    )
    assert second_billed.exit == 0, second_billed.raw
    assert {Ref.model_validate(storage_receipt), second_storage} <= set(
        allocator.durable_refs(PROJECT, RUN)
    )
    storage_file = env.input("storage-receipt.json", json.dumps(storage_receipt))
    import io

    from test_ledger_db import reference

    from conscience_foundry.cli.local_authority import LocalAllocationReceipt
    from conscience_foundry.contracts.common import ArtifactLocation

    original_ref = Ref.model_validate(storage_receipt)
    alternative_ref = original_ref.model_copy(
        update={
            "locations": (
                *original_ref.locations,
                ArtifactLocation(store_id="synthetic", object_key="alternate"),
            )
        }
    )
    extra_runtime = Runtime(load_config(env.config_path), services, "local-receipts")
    try:
        raw = extra_runtime.store.read_verified(
            original_ref, extra_runtime.access, case.bound.max_json_bytes
        ).data
        writer = extra_runtime.services.local.allocator.import_writer(PROJECT, RUN, attempt_id)
        writer.put_verified(io.BytesIO(raw), alternative_ref, extra_runtime.access)
        forged_model = LocalAllocationReceipt.from_wire(raw, case.bound).model_copy(
            update={"amount_usd": "2"}
        )
        forged_raw = encoded(forged_model)
        forged_storage = reference(forged_raw, forged_model.schema_version)
        writer.put_verified(io.BytesIO(forged_raw), forged_storage, extra_runtime.access)
    finally:
        extra_runtime.close()
    alternative_file = env.input(
        "alternate-receipt.json", alternative_ref.model_dump_json(by_alias=True)
    )
    forged_file = env.input("forged-storage.json", forged_storage.model_dump_json(by_alias=True))
    early = run("close-local-storage", "--run-id", RUN, "--evidence", storage_file, "--execute")
    assert early.exit != 0
    billed = run(
        "record-billing",
        "--attempt-id",
        attempt_id,
        "--amount",
        "4",
        "--evidence",
        env.input("attempt-receipt.json", json.dumps(attempt_receipt)),
        "--execute",
    )
    assert billed.exit == 0, billed.raw
    # Both durable candidates independently pass the production pre-close validator.
    # Stop at close_storage so neither call can close or settle the reservation.
    before_candidates = (root / "allocator.json").read_bytes()
    prior_events = count(ledger, "budget_events")
    preclose_reached = []

    def stop_before_close(self, *args):
        preclose_reached.append(True)
        raise RuntimeError("synthetic stop after pre-close validation")

    second_storage_file = env.input(
        "second-storage.json", second_storage.model_dump_json(by_alias=True)
    )
    with monkeypatch.context() as patch:
        patch.setattr(LocalAllocator, "close_storage", stop_before_close)
        for candidate_file in (storage_file, second_storage_file):
            previous = len(preclose_reached)
            checked = run(
                "close-local-storage", "--run-id", RUN, "--evidence", candidate_file, "--execute"
            )
            assert checked.exit != 0
            assert len(preclose_reached) == previous + 1
    assert (root / "allocator.json").read_bytes() == before_candidates
    assert count(ledger, "budget_events") == prior_events
    # A cross-run or tampered candidate must not mutate the allocator.
    before_close = (root / "allocator.json").read_bytes()
    wrong_run = run(
        "close-local-storage",
        "--run-id",
        "00000000-0000-0000-0000-000000000001",
        "--evidence",
        storage_file,
        "--execute",
    )
    assert wrong_run.exit != 0
    tampered = dict(storage_receipt, digest="0" * 64)
    tampered_file = env.input("tampered-storage.json", json.dumps(tampered))
    assert (
        run("close-local-storage", "--run-id", RUN, "--evidence", tampered_file, "--execute").exit
        != 0
    )
    assert (
        run("close-local-storage", "--run-id", RUN, "--evidence", forged_file, "--execute").exit
        != 0
    )
    assert (root / "allocator.json").read_bytes() == before_close

    # Change the reservation-bound authorization after prevalidation, before the DB-held guard.
    from contextlib import contextmanager

    from psycopg import sql
    from psycopg.types.json import Jsonb

    from conscience_foundry.cli.local_authority import LocalClosureGuard

    original_guard = LocalClosureGuard.__call__
    changed_auth = case.auth_ref.model_copy(
        update={"locations": (ArtifactLocation(store_id="synthetic", object_key="altered-auth"),)}
    )

    @contextmanager
    def substitute_auth(guard, project, run_id):
        with ledger.transaction() as tx:
            tx.connection.execute(
                sql.SQL(
                    "UPDATE {} SET authorization_ref=%s WHERE project_id=%s AND run_id=%s"
                ).format(tx.table("authorizations")),
                (Jsonb(changed_auth.model_dump(mode="json", by_alias=True)), project, run_id),
            )
        try:
            with original_guard(guard, project, run_id) as verify:
                yield verify
        finally:
            with ledger.transaction() as tx:
                tx.connection.execute(
                    sql.SQL(
                        "UPDATE {} SET authorization_ref=%s WHERE project_id=%s AND run_id=%s"
                    ).format(tx.table("authorizations")),
                    (Jsonb(case.auth_ref.model_dump(mode="json", by_alias=True)), project, run_id),
                )

    with monkeypatch.context() as patch:
        patch.setattr(LocalClosureGuard, "__call__", substitute_auth)
        swapped = run(
            "close-local-storage", "--run-id", RUN, "--evidence", storage_file, "--execute"
        )
    assert swapped.exit != 0
    assert (root / "allocator.json").read_bytes() == before_close

    # A valid later run authorization does not rewrite this reservation's historical binding.
    from uuid import uuid4

    replacement_auth = case.auth.model_copy(update={"authorization_id": str(uuid4())})
    replacement_ref = case.put(replacement_auth)
    with ledger.transaction() as tx:
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,authorization_id,run_id,authorization_ref, "
                "allowed_plan_digests,max_run_cost,max_concurrent_attempts,actor_id,"
                "authorized_at,expires_at) "
                "SELECT project_id,%s,run_id,%s,allowed_plan_digests,max_run_cost, "
                "max_concurrent_attempts,actor_id,authorized_at,expires_at FROM {} "
                "WHERE project_id=%s AND run_id=%s AND authorization_id=%s"
            ).format(tx.table("authorizations"), tx.table("authorizations")),
            (
                replacement_auth.authorization_id,
                Jsonb(replacement_ref.model_dump(mode="json", by_alias=True)),
                PROJECT,
                RUN,
                case.auth.authorization_id,
            ),
        )
        tx.connection.execute(
            sql.SQL(
                "UPDATE {} SET current_authorization_id=%s WHERE project_id=%s AND run_id=%s"
            ).format(tx.table("runs")),
            (replacement_auth.authorization_id, PROJECT, RUN),
        )

    # Expiry refuses new candidates but permits closing already retained evidence.
    historical = (
        datetime.fromisoformat(funded_until.replace("Z", "+00:00")) + timedelta(seconds=1)
    ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    services = replace(services, clock=lambda: historical)
    assert run("local-receipts", "--attempt-id", attempt_id, "--execute").exit != 0

    # A crash after durable closure can still settle historical evidence.
    close_original = LocalAllocator.close_storage

    crash_reached = []

    def crash_after_close(self, *args):
        close_original(self, *args)
        crash_reached.append(True)
        raise RuntimeError("synthetic interruption")

    with monkeypatch.context() as patch:
        patch.setattr(LocalAllocator, "close_storage", crash_after_close)
        crashed = run(
            "close-local-storage", "--run-id", RUN, "--evidence", storage_file, "--execute"
        )
    assert crashed.exit != 0
    assert crash_reached == [True]
    state = json.loads((root / "allocator.json").read_bytes())["runs"][RUN]
    assert state["closed"]
    assert {Ref.model_validate(storage_receipt), second_storage} <= {
        Ref.model_validate(ref) for ref in state["closed_refs"]
    }
    with ledger.transaction() as tx:
        storage_row = tx.connection.execute(
            sql.SQL(
                "SELECT final_billing FROM {} WHERE project_id=%s AND run_id=%s "
                "AND scope='run_storage'"
            ).format(tx.table("reservations")),
            (PROJECT, RUN),
        ).fetchone()
    assert storage_row is not None and storage_row[0] is False
    closed = run("close-local-storage", "--run-id", RUN, "--evidence", storage_file, "--execute")
    assert closed.exit == 0, closed.raw
    before_replay = count(ledger, "budget_events")
    again = run("close-local-storage", "--run-id", RUN, "--evidence", storage_file, "--execute")
    assert again.exit == 0, again.raw
    assert count(ledger, "budget_events") == before_replay
    # A restored pre-close allocation cannot prove a committed settlement remains closed.
    allocator_file = root / "allocator.json"
    closed_snapshot = allocator_file.read_bytes()
    try:
        allocator_file.write_bytes(before_close)
        inconsistent = run(
            "close-local-storage", "--run-id", RUN, "--evidence", storage_file, "--execute"
        )
        assert inconsistent.exit != 0
        assert count(ledger, "budget_events") == before_replay
    finally:
        allocator_file.write_bytes(closed_snapshot)
    assert (
        run("close-local-storage", "--run-id", RUN, "--evidence", storage_file, "--execute").exit
        == 0
    )
    assert (
        run(
            "close-local-storage", "--run-id", RUN, "--evidence", alternative_file, "--execute"
        ).exit
        != 0
    )
    conflicting = run(
        "close-local-storage",
        "--run-id",
        RUN,
        "--evidence",
        second_storage_file,
        "--execute",
    )
    assert conflicting.exit != 0
    other_location = dict(
        storage_receipt, locations=[{"storeId": "synthetic", "objectKey": "wrong"}]
    )
    assert (
        run(
            "close-local-storage",
            "--run-id",
            RUN,
            "--evidence",
            env.input("other-receipt.json", json.dumps(other_location)),
            "--execute",
        ).exit
        != 0
    )
    assert count(ledger, "budget_events") == before_replay
    assert run("local-receipts", "--attempt-id", attempt_id, "--execute").exit != 0

    # A persisted attempt cannot select a plan outside the independently pinned manifest.
    from psycopg import sql
    from psycopg.types.json import Jsonb

    from conscience_foundry.contracts.common import ArtifactLocation

    forged_ref = other_ref.model_copy(
        update={"locations": (ArtifactLocation(store_id="synthetic", object_key="other"),)}
    )
    with ledger.transaction() as tx:
        tx.connection.execute(
            sql.SQL("UPDATE {} SET plan_ref=%s WHERE project_id=%s AND plan_id=%s").format(
                tx.table("plans")
            ),
            (Jsonb(forged_ref.model_dump(mode="json", by_alias=True)), PROJECT, other_plan.plan_id),
        )
    unpinned = Runtime(load_config(env.config_path), services, "reconcile")
    try:
        with pytest.raises(ContractError):
            unpinned.services.local.committed(PROJECT, second_attempt)
    finally:
        unpinned.close()
