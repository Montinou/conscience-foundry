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
    ("pretty_bootstrap", "interrupted", "expired", "rollback", "drift"),
    [
        (False, False, False, False, False),
        (True, True, False, False, False),
        (False, False, True, False, False),
        (False, False, False, True, False),
        (False, False, False, False, True),
    ],
)
def test_real_local_cli_canonical_flow(
    ledger, tmp_path, monkeypatch, pretty_bootstrap, interrupted, expired, rollback, drift
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
    case = local_case(tmp_path)
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
    other_plan = case.plan.model_copy(update={"plan_id": "00000000-0000-0000-0000-0000000000f1"})
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
                "controlActions": ["mark_unknown_outcome"],
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
        ref_file(env, "plan-ref.json", other_ref),
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
        ref_file(env, "plan-ref.json", other_ref),
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
            unpinned.services.local.committed(PROJECT, attempt_id)
    finally:
        unpinned.close()
