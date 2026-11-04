"""Synthetic tests for local control authority and metered result import."""

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from test_staged_import import observe, started

from conscience_foundry.contracts.common import ContractError
from conscience_foundry.execution.control import reconcile
from conscience_foundry.ledger.db import Ledger

pytestmark = pytest.mark.database


def test_staged_writer_refusal_keeps_result_unaccepted(ledger: Ledger, tmp_path: Path) -> None:
    case, executor, attempt, remote = started(ledger, tmp_path)
    result, _ = remote.stage(attempt, lambda: case.result(attempt))
    observe(case, executor, attempt, result)
    calls: list[tuple[str, str]] = []

    def refuse(project: str, attempt_id: str) -> Any:
        calls.append((project, attempt_id))
        raise ContractError("limit_exceeded")

    control = replace(remote.control(), staged_writer=refuse)
    assert reconcile(attempt.attempt_id, ledger, executor, case.store, control=control) is None
    assert calls == [(case.plan.project_id, attempt.attempt_id)]


def test_remote_control_import_does_not_require_local_extra() -> None:
    import subprocess
    import sys

    code = """\
import importlib.abc, sys
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'psutil' or fullname.startswith('psutil.'):
            raise ModuleNotFoundError(fullname)
sys.meta_path.insert(0, Block())
import conscience_foundry.execution.control
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, check=False)
    assert result.returncode == 0, result.stderr.decode()


def test_quote_rejects_zero_ceiling_and_mismatched_plan_config() -> None:
    from test_ledger_db import PROJECT, reference

    from conscience_foundry.cli.local_authority import LocalAllocationEstimate

    auth = reference(b"auth", "cf.run-authorization.v1")
    plan = reference(b"plan", "cf.execution-plan.v1")
    config = reference(b"config", "cf.local-execution-config.v1")
    policy = reference(b"policy", "cf.local-resource-policy.v1")
    quote = {
        "schema_version": "cfoundry.local-allocation-estimate.v1",
        "project_id": PROJECT,
        "scope": "attempt",
        "authorization_ref": auth,
        "plan_refs": (plan,),
        "config_refs": (config,),
        "resource_policy_ref": policy,
        "funded_from": "2026-01-01T00:00:00.000Z",
        "funded_until": "2026-01-03T00:00:00.000Z",
        "ceiling_usd": "1",
    }
    assert LocalAllocationEstimate(**quote).ceiling_usd == "1"
    with pytest.raises(ValueError):
        LocalAllocationEstimate(**(quote | {"ceiling_usd": "0"}))
    with pytest.raises(ValueError):
        LocalAllocationEstimate(**(quote | {"config_refs": ()}))


def test_estimate_verification_is_pure_and_rejects_forged_bytes(tmp_path: Path) -> None:
    import hashlib

    from test_execution_control import Case
    from test_ledger_db import PROJECT, RUN, TIME, encoded, reference

    from conscience_foundry.cli.local_authority import (
        LocalAllocationEstimate,
        LocalControlAuthority,
        LocalPlanPin,
    )
    from conscience_foundry.contracts.execution import LocalExecutionConfig
    from conscience_foundry.execution.local_allocation import LocalAllocationPolicy
    from conscience_foundry.execution.ports import BudgetProof, EvidenceBinding
    from conscience_foundry.ledger._budget_inputs import BudgetEvidenceClaim

    case = Case(tmp_path)
    resource = reference(b"resource", "cf.local-resource-policy.v1")
    config = LocalExecutionConfig(
        schema_version="cf.local-execution-config.v1",
        adapter_id="local",
        deployment_version="synthetic.v1",
        image_digest="a" * 64,
        tariff_ref=case.config.tariff_ref,
        resource_policy_ref=resource,
        local_destination_id="local",
    )
    config_ref = reference(encoded(config), config.schema_version)
    plan = case.plan.model_copy(update={"execution_config_ref": config_ref})
    plan_ref = reference(encoded(plan), plan.schema_version)
    auth = case.auth.model_copy(update={"allowed_plan_digests": (plan_ref.digest,)})
    auth_ref = reference(encoded(auth), auth.schema_version)
    policy = LocalAllocationPolicy(
        "1", "1", 100, 200, resource, TIME, auth.expires_at, "cooperative"
    )
    quote = LocalAllocationEstimate(
        schema_version="cfoundry.local-allocation-estimate.v1",
        project_id=PROJECT,
        scope="attempt",
        authorization_ref=auth_ref,
        plan_refs=(plan_ref,),
        config_refs=(config_ref,),
        resource_policy_ref=resource,
        funded_from=TIME,
        funded_until=auth.expires_at,
        ceiling_usd="1",
    )
    quote_bytes = encoded(quote)
    quote_ref = reference(quote_bytes, quote.schema_version)
    pin = LocalPlanPin(plan_ref, plan, config_ref, config)

    class Delegate:
        decoders: dict[str, Any] = {}

        def budget(self, proof: Any) -> str:
            return "delegated"

        def control(self, proof: Any) -> str:
            return "control"

        def transport(self, proof: Any) -> str:
            return "transport"

    authority = LocalControlAuthority(
        policy=policy,
        estimates=((quote_ref, quote_bytes),),
        plans=(pin,),
        limits=case.bound,
        delegate=Delegate(),
    )
    request = encoded(plan)
    claim = BudgetEvidenceClaim(
        "reserve_attempt",
        quote_ref,
        PROJECT,
        RUN,
        "00000000-0000-0000-0000-000000000099",
        "00000000-0000-0000-0000-000000000098",
        TIME,
        auth_ref,
        plan_ref,
        config_ref,
        request,
        hashlib.sha256(request).hexdigest(),
    )
    proof = BudgetProof(claim, EvidenceBinding.from_budget(claim), quote_bytes, auth, ())
    with pytest.raises(ContractError):
        authority.budget(replace(proof, evidence_bytes=quote_bytes + b" "))
    with pytest.raises(ContractError):
        authority.budget(proof)  # no initialized allocator is not an empty initialized run
    from conscience_foundry.execution.local_allocation import LocalAllocator

    allocator_root = tmp_path / "allocator"
    allocator_root.mkdir()
    LocalAllocator.initialize(
        allocator_root,
        policy,
        case.store,
        lambda: TIME,
        operator_store_id="synthetic",
        operator_store_root=tmp_path / "objects",
    )
    authority.allocator = LocalAllocator(
        allocator_root,
        policy,
        case.store,
        lambda: TIME,
        operator_store_id="synthetic",
        operator_store_root=tmp_path / "objects",
    )
    journal_before = (allocator_root / "allocator.json").read_bytes()
    first = authority.budget(proof)
    assert first == authority.budget(proof)
    assert (allocator_root / "allocator.json").read_bytes() == journal_before
    assert first.amount_ceiling_usd == "1"
    assert first.plan_refs == (plan_ref,)
    assert {item.category: item.amount_usd for item in first.allocations} == {
        "cpu": "0",
        "ram": "0",
        "runtime": "1",
        "transfer": "0",
        "storage": "0",
        "region": "0",
    }
    nonlocal_claim = replace(claim, purpose="install_run_authorization", evidence_ref=case.auth_ref)
    assert (
        authority.budget(
            replace(
                proof, claim=nonlocal_claim, binding=EvidenceBinding.from_budget(nonlocal_claim)
            )
        )
        == "delegated"
    )
    local_claim = replace(claim, purpose="final_billing")
    with pytest.raises(ContractError):
        authority.budget(
            replace(proof, claim=local_claim, binding=EvidenceBinding.from_budget(local_claim))
        )
    from conscience_foundry.execution.ports import ControlProof, TransportProof

    control_proof = ControlProof(
        proof.binding,
        case.auth_ref,
        b"proof",
        b"request",
        case.access.actor_id,
        "reconcile",
        None,
        TIME,
    )
    assert authority.control(control_proof) == "control"
    with pytest.raises(ContractError):
        authority.control(replace(control_proof, evidence_ref=quote_ref))
    transport_proof = TransportProof(
        PROJECT,
        plan_ref.digest,
        claim.attempt_id,
        "remote",
        auth.expires_at,
        plan.input_refs,
        (b"token",),
        "a" * 64,
        b"scope",
    )
    assert authority.transport(transport_proof) == "transport"


def test_grant_nonce_must_be_durable_and_never_rotated(tmp_path: Path) -> None:
    import hashlib
    from contextlib import contextmanager

    from test_ledger_db import reference
    from test_local_allocation import END, NOW, PROJECT, RUN_A, RUN_B, initialize, policy

    from conscience_foundry.execution.local_allocation import LocalActivationFacts, LocalAllocator
    from conscience_foundry.execution.local_contracts import LocalGrantProof
    from conscience_foundry.storage.local_attempt import local_output_scope

    initialize(tmp_path)
    attempt_root = tmp_path / "attempt-root"
    attempt_root.mkdir()
    source = reference(b"input", "cf.raw-original.v1")
    scope = local_output_scope(
        attempt_root,
        destination_id="local",
        project_id=PROJECT,
        run_id=RUN_A,
        attempt_id=RUN_B,
        plan_digest=source.digest,
    )
    facts = LocalActivationFacts(
        PROJECT,
        RUN_A,
        RUN_B,
        RUN_A,
        RUN_B,
        source,
        source,
        source,
        PROJECT,
        RUN_A,
        (source,),
        END,
        attempt_root,
        scope,
    )

    @contextmanager
    def guard(project: str, run: str, attempt: str):
        assert (project, run, attempt) == (PROJECT, RUN_A, RUN_B)
        yield facts

    value = LocalAllocator(
        tmp_path,
        policy(),
        object(),
        lambda: NOW,
        operator_store_id="operator",
        operator_store_root=tmp_path / "operator",
        activation_guard=guard,
        policy_reader=lambda *_: None,
    )
    value.activate_attempt(PROJECT, RUN_A, RUN_B)
    digest = hashlib.sha256(b"first").hexdigest()
    proof = LocalGrantProof(
        PROJECT, RUN_A, source.digest, RUN_B, "local", END, (source,), scope, digest
    )
    with pytest.raises(ContractError):
        value.local_grant(proof)
    value.bind_grant(PROJECT, RUN_A, RUN_B, digest)
    assert value.local_grant(proof).scopes == frozenset({"read", "extract"})
    with value.write_permit(PROJECT, RUN_A, RUN_B, source):
        assert value.local_grant(proof).scopes == frozenset({"read", "extract"})
        with pytest.raises(ContractError):
            value.local_grant(replace(proof, attempt_id=RUN_A))
        value.revalidate_write(PROJECT, RUN_A, RUN_B, source)
    with pytest.raises(ContractError):
        value.bind_grant(PROJECT, RUN_A, RUN_B, hashlib.sha256(b"second").hexdigest())
    reopened = LocalAllocator(
        tmp_path,
        policy(),
        object(),
        lambda: NOW,
        operator_store_id="operator",
        operator_store_root=tmp_path / "operator",
        activation_guard=guard,
        policy_reader=lambda *_: None,
    )
    assert reopened.local_grant(proof).nonce_digest == digest


def test_local_grant_requires_independent_matching_facts(tmp_path: Path) -> None:
    from test_execution_control import EXPIRY, Case
    from test_ledger_db import encoded, reference

    from conscience_foundry.contracts.execution import LocalExecutionConfig
    from conscience_foundry.execution.control import _local_grants
    from conscience_foundry.execution.local_contracts import LocalGrantFacts, LocalWorkerGrant

    case = Case(tmp_path)
    resource = reference(b"resource", "cf.local-resource-policy.v1")
    config = LocalExecutionConfig(
        schema_version="cf.local-execution-config.v1",
        adapter_id="local",
        deployment_version="synthetic.v1",
        image_digest="a" * 64,
        tariff_ref=case.config.tariff_ref,
        resource_policy_ref=resource,
        local_destination_id="local",
    )
    config_ref = reference(encoded(config), config.schema_version)
    plan = case.plan.model_copy(update={"execution_config_ref": config_ref})
    plan_ref = reference(encoded(plan), plan.schema_version)
    auth = case.auth.model_copy(update={"allowed_plan_digests": (plan_ref.digest,)})
    grant = LocalWorkerGrant(
        plan.project_id,
        plan.run_id,
        plan_ref.digest,
        "00000000-0000-0000-0000-000000000098",
        "local",
        EXPIRY,
        b"private scope",
        "nonce",
    )

    class LocalAuthority:
        def local_grant(self, proof: Any) -> LocalGrantFacts:
            return LocalGrantFacts(**proof.__dict__, scopes=frozenset({"read", "extract"}))

    local_control = replace(case.control, evidence_authority=LocalAuthority())
    _local_grants(grant, plan, auth, plan_ref, config, local_control)
    with pytest.raises(ContractError):
        _local_grants(grant, plan, auth, plan_ref, case.config, local_control)
    with pytest.raises(ContractError):
        _local_grants(
            replace(grant, run_id="00000000-0000-0000-0000-000000000099"),
            plan,
            auth,
            plan_ref,
            config,
            local_control,
        )
    with pytest.raises(ContractError):
        _local_grants(
            grant,
            plan,
            auth,
            plan_ref,
            config.model_copy(update={"adapter_id": "forged"}),
            local_control,
        )


def local_case(tmp_path: Path, *, source_bytes: bytes = b"Synthetic text") -> Any:
    from test_execution_control import Case

    from conscience_foundry.contracts.execution import LocalExecutionConfig
    from conscience_foundry.contracts.local_resource import LocalResourcePolicy
    from conscience_foundry.execution.ports import CapabilityFacts

    case = Case(tmp_path, source_bytes=source_bytes)
    policy = LocalResourcePolicy(
        schema_version="cf.local-resource-policy.v1",
        semantics="cooperative",
        max_cpu_milli=1000,
        max_memory_mib=256,
        max_wall_seconds=30,
        max_output_bytes=65536,
        max_concurrent_attempts=3,
        max_attempts_per_operation=3,
    )
    resource = case.put(policy)
    case.config = LocalExecutionConfig(
        schema_version="cf.local-execution-config.v1",
        adapter_id="local",
        deployment_version="synthetic.v1",
        image_digest="a" * 64,
        tariff_ref=case.config.tariff_ref,
        resource_policy_ref=resource,
        local_destination_id="local",
    )
    case.config_ref = case.put(case.config)
    case.plan = case.plan.model_copy(update={"execution_config_ref": case.config_ref})
    case.plan_ref = case.put(case.plan)
    case.auth = case.auth.model_copy(update={"allowed_plan_digests": (case.plan_ref.digest,)})
    case.auth_ref = case.put(case.auth)
    case.authority.grants[case.auth_ref.digest] = (case.auth_ref.digest, None)
    case.authority.estimates[case.estimate.digest] = (
        "4",
        CapabilityFacts(
            case.config_ref,
            case.config.tariff_ref,
            resource,
            case.config.image_digest,
            case.config.local_destination_id,
            case.plan.resources,
        ),
    )
    return case


def test_local_dispatch_mints_only_after_committed_claim(
    ledger: Ledger, tmp_path: Path, monkeypatch: Any
) -> None:
    from test_execution_control import EXPIRY, attempt_row
    from test_ledger_db import ASSET, PROJECT, RUN

    from conscience_foundry.cli.local_authority import LocalCommittedGuard, LocalPlanPin
    from conscience_foundry.execution.control import dispatch
    from conscience_foundry.execution.evidence import budget_context
    from conscience_foundry.execution.local_contracts import LocalGrantFacts, LocalWorkerGrant
    from conscience_foundry.execution.local_executor import LocalExecutor
    from conscience_foundry.execution.ports import Submission
    from conscience_foundry.ledger.budget import reserve_storage

    case = local_case(tmp_path)
    case.setup(ledger)
    capability = case.authority.estimates[case.estimate.digest][1]
    case.authority.storage_estimates[case.estimate.digest] = ("1", (case.plan_ref,), (capability,))
    with ledger.transaction() as tx:
        storage_id = reserve_storage(
            RUN, "1", case.estimate, tx, context=budget_context(case.control, tx=tx)
        )
    attempt_root = tmp_path / "attempt-root"
    attempt_root.mkdir()
    guard = LocalCommittedGuard(
        ledger,
        case.control,
        pin=LocalPlanPin(case.plan_ref, case.plan, case.config_ref, case.config),
        authorization_ref=case.auth_ref,
        attempt_root=attempt_root,
    )
    case.authority.local_grant = lambda proof: LocalGrantFacts(
        **proof.__dict__, scopes=frozenset({"read", "extract"})
    )
    issued: list[str] = []

    def issuer(attempt: Any) -> LocalWorkerGrant:
        assert attempt_row(ledger, attempt.attempt_id)[0] == "dispatching"
        issued.append(attempt.attempt_id)
        with guard(PROJECT, RUN, attempt.attempt_id) as facts:
            assert facts.storage_reservation_id == storage_id
            assert facts.reservation_id == attempt.reservation_id
            return LocalWorkerGrant(
                case.plan.project_id,
                case.plan.run_id,
                case.plan_ref.digest,
                attempt.attempt_id,
                "local",
                EXPIRY,
                facts.output_scope,
                "nonce",
            )

    executor = LocalExecutor(
        tmp_path, "local", "a" * 64, object(), lambda *_: None, lambda *_: None
    )
    monkeypatch.setattr(
        executor, "submit", lambda plan, attempt, grant: Submission("synthetic", True)
    )
    control = replace(
        case.control, staged_reader=lambda *_: case.store, staged_writer=lambda *_: case.store
    )
    attempt = dispatch(
        case.plan,
        case.auth,
        case.access,
        ledger,
        executor,
        issuer,
        control=control,
        plan_ref=case.plan_ref,
        authorization_ref=case.auth_ref,
        asset_id=ASSET,
        evidence_ref=case.estimate,
    )
    assert attempt.state == "running"
    assert issued == [attempt.attempt_id]


def test_committed_activation_guard_refuses_missing_attempt(ledger: Ledger, tmp_path: Path) -> None:
    from test_ledger_db import PROJECT, RUN

    from conscience_foundry.cli.local_authority import LocalCommittedGuard, LocalPlanPin

    case = local_case(tmp_path)
    case.setup(ledger)
    root = tmp_path / "attempt-root"
    root.mkdir()
    pin = LocalPlanPin(case.plan_ref, case.plan, case.config_ref, case.config)
    guard = LocalCommittedGuard(
        ledger, case.control, pin=pin, authorization_ref=case.auth_ref, attempt_root=root
    )
    with pytest.raises(ContractError):
        with guard(PROJECT, RUN, "00000000-0000-0000-0000-000000000098"):
            pass


def test_uncommitted_rolled_back_attempt_cannot_activate(ledger: Ledger, tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from concurrent.futures import TimeoutError as FutureTimeout
    from threading import Event

    from psycopg import sql
    from test_ledger_db import ASSET, PROJECT, RUN, encoded

    from conscience_foundry.cli.local_authority import LocalCommittedGuard, LocalPlanPin
    from conscience_foundry.execution.evidence import (
        admission_evidence,
        budget_context,
        verified_plan,
    )
    from conscience_foundry.ledger.budget import reserve_attempt, reserve_storage

    case = local_case(tmp_path)
    case.setup(ledger)
    capability = case.authority.estimates[case.estimate.digest][1]
    case.authority.storage_estimates[case.estimate.digest] = ("1", (case.plan_ref,), (capability,))
    with ledger.transaction() as tx:
        reserve_storage(RUN, "1", case.estimate, tx, context=budget_context(case.control, tx=tx))
    root = tmp_path / "attempt-root"
    root.mkdir()
    guard = LocalCommittedGuard(
        ledger,
        case.control,
        pin=LocalPlanPin(case.plan_ref, case.plan, case.config_ref, case.config),
        authorization_ref=case.auth_ref,
        attempt_root=root,
    )
    started = Event()

    def activate(attempt_id: str) -> None:
        started.set()
        with guard(PROJECT, RUN, attempt_id):
            raise AssertionError("uncommitted activation succeeded")

    class Rollback(Exception):
        pass

    with ThreadPoolExecutor(max_workers=1) as pool:
        try:
            with ledger.transaction() as tx:
                verified = verified_plan(
                    case.plan_ref, case.auth_ref, tx, case.control, spending=True
                )
                admission, _, _ = admission_evidence(case.plan, tx, case.control)
                attempt = reserve_attempt(
                    case.plan,
                    case.auth,
                    case.estimate,
                    tx,
                    context=budget_context(case.control, tx=tx),
                    plan_ref=case.plan_ref,
                    plan_bytes=verified.data,
                    authorization_ref=case.auth_ref,
                    authorization_bytes=encoded(case.auth),
                    admission=admission,
                    asset_id=ASSET,
                    execution_config_bytes=verified.config_bytes,
                )
                blocked = pool.submit(activate, attempt.attempt_id)
                assert started.wait(5)
                with pytest.raises(FutureTimeout):
                    blocked.result(timeout=0.2)
                raise Rollback()
        except Rollback:
            pass
        with pytest.raises(ContractError):
            blocked.result(timeout=10)
    with ledger.transaction() as tx:
        row = tx.connection.execute(
            sql.SQL("SELECT count(*) FROM {} WHERE project_id=%s AND run_id=%s").format(
                tx.table("attempts")
            ),
            (PROJECT, RUN),
        ).fetchone()
        assert row is not None and row[0] == 0


def test_issuer_binds_nonce_to_committed_allocation(
    ledger: Ledger, tmp_path: Path, monkeypatch: Any
) -> None:
    from test_execution_control import attempt_row
    from test_ledger_db import ASSET, PROJECT, RUN, TIME

    from conscience_foundry.cli.local_authority import (
        LocalCommittedGuard,
        LocalGrantIssuer,
        LocalPlanPin,
    )
    from conscience_foundry.execution.control import dispatch
    from conscience_foundry.execution.evidence import budget_context
    from conscience_foundry.execution.local_allocation import LocalAllocationPolicy, LocalAllocator
    from conscience_foundry.execution.local_executor import LocalExecutor
    from conscience_foundry.execution.ports import Submission
    from conscience_foundry.ledger.budget import reserve_storage

    case = local_case(tmp_path)
    case.setup(ledger)
    capability = case.authority.estimates[case.estimate.digest][1]
    case.authority.storage_estimates[case.estimate.digest] = ("1", (case.plan_ref,), (capability,))
    with ledger.transaction() as tx:
        reserve_storage(RUN, "1", case.estimate, tx, context=budget_context(case.control, tx=tx))
    root, attempt_root = tmp_path / "allocator", tmp_path / "attempt-root"
    root.mkdir()
    attempt_root.mkdir()
    operator_root = tmp_path / "objects"
    alloc_policy = LocalAllocationPolicy(
        "1",
        "1",
        65536,
        131072,
        case.config.resource_policy_ref,
        TIME,
        case.auth.expires_at,
        "cooperative",
    )
    pin = LocalPlanPin(case.plan_ref, case.plan, case.config_ref, case.config)
    guard = LocalCommittedGuard(
        ledger, case.control, pin=pin, authorization_ref=case.auth_ref, attempt_root=attempt_root
    )
    LocalAllocator.initialize(
        root,
        alloc_policy,
        case.store,
        lambda: TIME,
        operator_store_id="synthetic",
        operator_store_root=operator_root,
    )
    alloc = LocalAllocator(
        root,
        alloc_policy,
        case.store,
        lambda: TIME,
        operator_store_id="synthetic",
        operator_store_root=operator_root,
        activation_guard=guard,
        policy_reader=lambda *_: None,
    )
    issuer = LocalGrantIssuer(allocator=alloc, guard=guard)
    case.authority.local_grant = alloc.local_grant
    captured: list[Any] = []
    executor = LocalExecutor(
        tmp_path, "local", "a" * 64, object(), lambda *_: None, lambda *_: None
    )
    monkeypatch.setattr(
        executor,
        "submit",
        lambda plan, attempt, grant: captured.append(grant) or Submission("synthetic", True),
    )
    control = replace(
        case.control, staged_reader=lambda *_: case.store, staged_writer=lambda *_: case.store
    )
    attempt = dispatch(
        case.plan,
        case.auth,
        case.access,
        ledger,
        executor,
        issuer,
        control=control,
        plan_ref=case.plan_ref,
        authorization_ref=case.auth_ref,
        asset_id=ASSET,
        evidence_ref=case.estimate,
    )
    assert attempt.state == "running"
    assert attempt_row(ledger, attempt.attempt_id)[0] == "running"
    with guard.evidence(attempt) as facts:
        assert facts.attempt_id == attempt.attempt_id
    with pytest.raises(ContractError):
        with guard.evidence(attempt.model_copy(update={"state": "cancel_requested"})):
            pass
    import json

    from conscience_foundry.cli.local_authority import LocalEvidenceWriter

    evidence_writer = LocalEvidenceWriter(
        guard=guard, allocator=alloc, executor=executor, operator=case.access
    )
    raw = json.dumps(
        {
            "schemaVersion": "cf.local-process-observation.v1",
            "attemptId": attempt.attempt_id,
            "action": "observe",
            "observedState": "unknown_outcome",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    evidence_ref = evidence_writer(attempt, "cf.local-process-observation.v1", raw)
    assert case.store.read_verified(evidence_ref, case.access, len(raw)).data == raw
    with pytest.raises(ContractError):
        evidence_writer(
            attempt.model_copy(update={"state": "cancel_requested"}),
            "cf.local-process-observation.v1",
            raw,
        )
    with pytest.raises(ContractError):
        evidence_writer(
            attempt,
            "cf.local-process-observation.v1",
            raw.replace(b"unknown_outcome", b"succeeded"),
        )
    from conscience_foundry.execution.local_executor import LocalInspection

    monkeypatch.setattr(
        executor,
        "_inspect_cancel",
        lambda _: LocalInspection("cancel_requested", None, "123", False),
    )
    cancel_raw = json.dumps(
        {
            "schemaVersion": "cf.local-process-observation.v1",
            "attemptId": attempt.attempt_id,
            "action": "cancel",
            "observedState": "cancel_requested",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    cancel_ref = evidence_writer(attempt, "cf.local-process-observation.v1", cancel_raw)
    assert case.store.read_verified(cancel_ref, case.access, len(cancel_raw)).data == cancel_raw
    assert len(captured) == 1
    from conscience_foundry.cli.local_authority import LocalStagingSource
    from conscience_foundry.policy.access import AccessContext

    source = LocalStagingSource(case.store, case.access, alloc, case.plan, captured[0])
    worker = AccessContext(PROJECT, attempt.attempt_id, frozenset({"read", "extract"}))
    with source.open_verified(case.original, worker) as stream:
        assert stream.read() == b"Synthetic text"
    with pytest.raises(ContractError):
        source.open_verified(case.original, case.access)
    with pytest.raises(ContractError):
        source.open_verified(case.auth_ref, worker)
    forged_plan = case.plan.model_copy(update={"admission_report_ref": case.auth_ref})
    with pytest.raises(ContractError):
        LocalStagingSource(case.store, case.access, alloc, forged_plan, captured[0]).open_verified(
            case.auth_ref, worker
        )

    def deny_current_policy(*_: object) -> None:
        raise ContractError("forbidden")

    alloc.policy_reader = deny_current_policy
    with pytest.raises(ContractError):
        source.open_verified(case.original, worker)
    with pytest.raises(ContractError):
        issuer(attempt)  # replay never rotates a nonce or submits a second process


def test_bootstrap_binding_refuses_content_change_and_replacement(tmp_path: Path) -> None:
    import hashlib

    from test_local_allocation import allocator, initialize

    initialize(tmp_path)
    value = allocator(tmp_path)
    bootstrap = tmp_path / "worker-bootstrap.json"
    bootstrap.write_bytes(b'{"synthetic":true}')
    digest = hashlib.sha256(bootstrap.read_bytes()).hexdigest()
    value.register_worker_bootstrap(bootstrap, digest)
    assert value.verify_worker_bootstrap(bootstrap, digest) == b'{"synthetic":true}'
    original = bootstrap.read_bytes()
    bootstrap.rename(tmp_path / "original-bootstrap.json")
    bootstrap.write_bytes(original)
    with pytest.raises(ContractError):
        value.verify_worker_bootstrap(bootstrap, digest)
    bootstrap.unlink()
    with pytest.raises(ContractError):
        value.verify_worker_bootstrap(bootstrap, digest)
    bootstrap.write_bytes(original)
    bootstrap.write_bytes(b'{"synthetic":false}')
    with pytest.raises(ContractError):
        value.verify_worker_bootstrap(bootstrap, digest)


def test_executor_keeps_bootstrap_in_trusted_launch_arguments(
    tmp_path: Path, monkeypatch: Any
) -> None:
    import hashlib
    from unittest.mock import Mock

    from test_modal import StepClock, build

    from conscience_foundry.execution.local_contracts import LocalWorkerGrant
    from conscience_foundry.execution.local_executor import LocalExecutor, local_staged_refs

    scenario = build()
    grant = LocalWorkerGrant(
        scenario.plan.project_id,
        scenario.plan.run_id,
        hashlib.sha256(scenario.plan_bytes).hexdigest(),
        scenario.attempt.attempt_id,
        "local",
        scenario.grants.expires_at,
        b"scope",
        "nonce",
    )
    store = Mock(root=tmp_path, input_refs=local_staged_refs(scenario.plan))
    store.stage_inputs.return_value = store.input_refs
    bootstrap_path = tmp_path / "operator-bootstrap.json"
    digest = "b" * 64
    executor = LocalExecutor(
        tmp_path,
        "local",
        "a" * 64,
        StepClock(),
        Mock(),
        lambda *_: store,
        bootstrap_path=bootstrap_path,
        bootstrap_digest=digest,
    )
    monkeypatch.setattr(
        "conscience_foundry.execution.local_executor.verify_runtime", lambda _: None
    )
    spawn = Mock(side_effect=OSError("synthetic spawn failure"))
    monkeypatch.setattr("subprocess.Popen", spawn)
    executor.submit(scenario.plan, scenario.attempt, grant)
    args = spawn.call_args.args[0]
    assert args[-2:] == [str(bootstrap_path), digest]
    job = (tmp_path / scenario.attempt.attempt_id / "job.json").read_text()
    assert str(bootstrap_path) not in job and digest not in job


def test_local_evidence_sink_receives_trusted_attempt(tmp_path: Path) -> None:
    from unittest.mock import Mock

    from test_modal import StepClock, build, make_ref

    from conscience_foundry.execution.local_executor import LocalExecutor

    scenario = build()
    calls: list[object] = []

    def sink(attempt: object, schema: str, data: bytes) -> Any:
        calls.append(attempt)
        return make_ref(data, schema)

    executor = LocalExecutor(tmp_path, "local", "a" * 64, StepClock(), sink, Mock())
    executor._finish(scenario.attempt, "observe", "unknown_outcome")
    assert calls == [scenario.attempt]


def test_child_calls_worker_with_reconstructed_authority(tmp_path: Path, monkeypatch: Any) -> None:
    import hashlib
    import sys
    from unittest.mock import Mock

    from test_modal import StepClock, build, make_ref

    from conscience_foundry.execution import local_worker
    from conscience_foundry.execution.local_contracts import LocalWorkerGrant
    from conscience_foundry.execution.local_executor import LocalExecutor, local_staged_refs

    scenario = build()
    grant = LocalWorkerGrant(
        scenario.plan.project_id,
        scenario.plan.run_id,
        hashlib.sha256(scenario.plan_bytes).hexdigest(),
        scenario.attempt.attempt_id,
        "local",
        scenario.grants.expires_at,
        b"scope",
        "nonce",
    )
    store = Mock(root=tmp_path, input_refs=local_staged_refs(scenario.plan))
    store.stage_inputs.return_value = store.input_refs
    executor = LocalExecutor(tmp_path, "local", "a" * 64, StepClock(), Mock(), lambda *_: store)
    monkeypatch.setattr(
        "conscience_foundry.execution.local_executor.verify_runtime", lambda _: None
    )
    monkeypatch.setattr("subprocess.Popen", Mock(side_effect=OSError("synthetic spawn failure")))
    executor.submit(scenario.plan, scenario.attempt, grant)
    job = tmp_path / scenario.attempt.attempt_id / "job.json"
    authority = object()
    bootstrap = Mock(output_root=str(tmp_path), project_id=scenario.plan.project_id)
    monkeypatch.setattr(local_worker, "reconstruct_authority", lambda *_: (authority, bootstrap))
    monkeypatch.setattr(local_worker, "LocalAttemptStore", Mock(return_value=store), raising=False)
    worker = Mock(return_value=make_ref(b"result", "cf.result-manifest.v1"))
    monkeypatch.setattr(local_worker, "run_worker", worker, raising=False)
    monkeypatch.setattr(
        sys, "argv", ["local_worker", str(job), str(tmp_path / "bootstrap.json"), "b" * 64]
    )
    assert local_worker.main() == 0
    assert worker.call_args.kwargs["local_authority"] is authority
    assert worker.call_args.kwargs["lease"] is store
    assert worker.call_args.kwargs["nonce"] == grant.nonce


def test_bootstrap_policy_reader_rechecks_policy_after_mint(tmp_path: Path) -> None:
    import os

    from test_ledger_db import TIME, encoded

    from conscience_foundry.cli.local_authority import LocalWorkerBootstrap, bootstrap_policy_reader

    case = local_case(tmp_path)
    allocator_root = tmp_path / "allocator"
    output_root = tmp_path / "attempt-root"
    allocator_root.mkdir()
    output_root.mkdir()
    policy_path = tmp_path / "operator-policy.json"
    policy_path.write_bytes(encoded(case.policy))
    operator_root = tmp_path / "objects"
    alloc_stat, output_stat, operator_stat, policy_stat = (
        os.stat(allocator_root),
        os.stat(output_root),
        os.stat(operator_root),
        os.stat(tmp_path),
    )
    bootstrap = LocalWorkerBootstrap(
        schema_version="cfoundry.local-worker-bootstrap.v1",
        project_id=case.plan.project_id,
        actor_id=case.access.actor_id,
        allocator_root=str(allocator_root),
        allocator_device=str(alloc_stat.st_dev),
        allocator_inode=str(alloc_stat.st_ino),
        output_root=str(output_root),
        output_device=str(output_stat.st_dev),
        output_inode=str(output_stat.st_ino),
        operator_store_root=str(operator_root),
        operator_device=str(operator_stat.st_dev),
        operator_inode=str(operator_stat.st_ino),
        operator_store_id="synthetic",
        policy_path=str(policy_path),
        policy_parent_device=str(policy_stat.st_dev),
        policy_parent_inode=str(policy_stat.st_ino),
        policy_limits=case.bound,
        attempt_price_usd="1",
        storage_price_usd="1",
        run_storage_capacity_bytes=65536,
        operator_storage_capacity_bytes=131072,
        resource_policy_ref=case.config.resource_policy_ref,
        funded_from=TIME,
        funded_until=case.auth.expires_at,
        semantics="cooperative",
    )
    import hashlib

    from conscience_foundry.execution.local_allocation import LocalAllocator
    from conscience_foundry.execution.local_worker import reconstruct_authority

    bootstrap_path = tmp_path / "bootstrap.json"
    raw = encoded(bootstrap)
    bootstrap_path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    LocalAllocator.initialize(
        allocator_root,
        bootstrap.allocation_policy(),
        case.store,
        lambda: TIME,
        operator_store_id="synthetic",
        operator_store_root=operator_root,
    )
    initial = LocalAllocator(
        allocator_root,
        bootstrap.allocation_policy(),
        case.store,
        lambda: TIME,
        operator_store_id="synthetic",
        operator_store_root=operator_root,
    )
    initial.register_worker_bootstrap(bootstrap_path, digest)
    rebuilt, trusted = reconstruct_authority(bootstrap_path, digest, lambda: TIME)
    assert trusted == bootstrap
    assert rebuilt.verify_worker_bootstrap(bootstrap_path, digest) == raw
    bootstrap_path.rename(tmp_path / "saved-bootstrap.json")
    bootstrap_path.write_bytes(raw)
    with pytest.raises(ContractError):
        reconstruct_authority(bootstrap_path, digest, lambda: TIME)

    read_policy = bootstrap_policy_reader(bootstrap, lambda: TIME)
    source = case.data.report.entries[0].source_id
    read_policy(case.plan.project_id, source, case.access.actor_id)
    changed = tuple(
        s.model_copy(update={"read": "deny"}) if s.source_id == source else s
        for s in case.policy.sources
    )
    policy_path.write_bytes(encoded(case.policy.model_copy(update={"sources": changed})))
    with pytest.raises(ContractError):
        read_policy(case.plan.project_id, source, case.access.actor_id)


@pytest.mark.parametrize(
    "capacity,mode",
    [
        (131072, "full"),
        (9000, "quota"),
        (131072, "revoke"),
        (131072, "prepublish"),
        (131072, "activation_failure"),
        (131072, "unknown_pid"),
        (131072, "cancelled"),
        (131072, "failed_manifest"),
    ],
)
def test_real_committed_worker_publishes_and_metered_import(
    ledger: Ledger, tmp_path: Path, monkeypatch: Any, capacity: int, mode: str
) -> None:
    import hashlib
    import os
    from datetime import UTC, datetime, timedelta

    import test_execution_control as fixture
    from test_ledger_db import ASSET, PROJECT, RUN, encoded

    from conscience_foundry.cli.config import now
    from conscience_foundry.cli.local_authority import (
        LocalAllocationEstimate,
        LocalCommittedGuard,
        LocalControlAuthority,
        LocalEvidenceWriter,
        LocalGrantIssuer,
        LocalPlanPin,
        LocalStagingSource,
        LocalWorkerBootstrap,
        bootstrap_policy_reader,
    )
    from conscience_foundry.contracts.admission import IntakeManifest
    from conscience_foundry.core.identity import F1Operation, operation_key
    from conscience_foundry.execution.control import dispatch
    from conscience_foundry.execution.evidence import budget_context
    from conscience_foundry.execution.local_allocation import LocalAllocationPolicy, LocalAllocator
    from conscience_foundry.execution.local_executor import LocalExecutor, local_staged_refs
    from conscience_foundry.execution.local_runtime import runtime_digest, runtime_manifest
    from conscience_foundry.execution.staged_import import import_staged_result
    from conscience_foundry.ledger.budget import reserve_storage
    from conscience_foundry.storage.local_attempt import LocalAttemptStore

    current = now()
    expiry = (datetime.now(UTC) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    monkeypatch.setattr(fixture, "TIME", current)
    monkeypatch.setattr(fixture, "EXPIRY", expiry)
    if mode == "failed_manifest":
        from test_ledger_db import admission, reference

        def invalid_admission() -> Any:
            base = admission()
            payload = b"\xff"
            manifest = IntakeManifest.from_wire(
                base.evidence.manifest_bytes, base.evidence.limits_by_schema["cf.intake.v1"]
            )
            item = manifest.items[0].model_copy(
                update={
                    "original_digest": hashlib.sha256(payload).hexdigest(),
                    "size_bytes": len(payload),
                }
            )
            manifest = manifest.model_copy(update={"items": (item,)})
            manifest_raw = encoded(manifest)
            snapshot = reference(payload, "cf.raw-original.v1").model_copy(
                update={"media_type": "text/plain"}
            )
            entry = base.report.entries[0].model_copy(update={"snapshot_ref": snapshot})
            report = base.report.model_copy(
                update={
                    "manifest_digest": hashlib.sha256(manifest_raw).hexdigest(),
                    "entries": (entry,),
                }
            )
            report_raw = encoded(report)
            evidence = replace(base.evidence, manifest_bytes=manifest_raw, report_bytes=report_raw)
            return replace(
                base,
                manifest_ref=reference(manifest_raw, "cf.intake.v1"),
                report=report,
                report_ref=reference(report_raw, "cf.admission-report.v1"),
                evidence=evidence,
            )

        monkeypatch.setattr(fixture, "admission", invalid_admission)
    case = local_case(
        tmp_path, source_bytes=b"\xff" if mode == "failed_manifest" else b"Synthetic text"
    )
    runtime = runtime_digest(runtime_manifest())
    case.spec = case.spec.model_copy(update={"image_digest": runtime})
    case.spec_ref = case.put(case.spec)
    case.config = case.config.model_copy(update={"image_digest": runtime})
    case.config_ref = case.put(case.config)
    manifest = IntakeManifest.from_wire(case.data.evidence.manifest_bytes, case.bound)
    key = operation_key(
        F1Operation(
            PROJECT,
            ASSET,
            manifest.items[0].source_id,
            (case.original.digest,),
            case.spec_ref.digest,
            manifest.profile_id,
            manifest.profile_version,
            manifest.policy_ref.digest,
            case.plan.contract_set_ref.digest,
            (case.limits_ref.digest,),
        ),
        limits=case.bound,
    )
    resources = case.plan.resources.model_copy(update={"max_wall_seconds": 30})
    budget = case.plan.budget.model_copy(update={"valid_until": expiry})
    case.plan = case.plan.model_copy(
        update={
            "extraction_spec_ref": case.spec_ref,
            "execution_config_ref": case.config_ref,
            "operation_key": key,
            "resources": resources,
            "budget": budget,
            "expires_at": expiry,
        }
    )
    case.plan_ref = case.put(case.plan)
    case.auth = case.auth.model_copy(
        update={
            "allowed_plan_digests": (case.plan_ref.digest,),
            "authorized_at": current,
            "expires_at": expiry,
        }
    )
    case.auth_ref = case.put(case.auth)
    case.authority.grants[case.auth_ref.digest] = (case.auth_ref.digest, None)
    policy = LocalAllocationPolicy(
        "4",
        "1",
        capacity,
        capacity * 2,
        case.config.resource_policy_ref,
        current,
        expiry,
        "cooperative",
    )
    pin = LocalPlanPin(case.plan_ref, case.plan, case.config_ref, case.config)
    quotes = []
    for scope, amount in (("attempt", "4"), ("run_storage", "1")):
        quote = LocalAllocationEstimate(
            schema_version="cfoundry.local-allocation-estimate.v1",
            project_id=PROJECT,
            scope=scope,
            authorization_ref=case.auth_ref,
            plan_refs=(case.plan_ref,),
            config_refs=(case.config_ref,),
            resource_policy_ref=case.config.resource_policy_ref,
            funded_from=current,
            funded_until=expiry,
            ceiling_usd=amount,
        )
        quotes.append((case.put(quote), encoded(quote)))
    case.schemas["cfoundry.local-allocation-estimate.v1"] = case.bound
    trusted = LocalControlAuthority(
        policy=policy,
        estimates=tuple(quotes),
        plans=(pin,),
        limits=case.bound,
        delegate=case.authority,
        operator=case.access,
    )
    quote_proofs: list[Any] = []
    original_quote_budget = trusted.budget

    def capture_quotes(proof: Any) -> Any:
        if proof.claim.purpose in {"reserve_attempt", "reserve_storage"}:
            quote_proofs.append(proof)
        return original_quote_budget(proof)

    trusted.budget = capture_quotes
    case.control = replace(case.control, clock=now, evidence_authority=trusted)
    case.setup(ledger)
    root, output, journal = tmp_path / "allocator", tmp_path / "attempt-root", tmp_path / "journal"
    root.mkdir()
    output.mkdir()
    journal.mkdir()
    operator = tmp_path / "objects"
    policy_path = tmp_path / "operator-policy.json"
    policy_path.write_bytes(encoded(case.policy))
    astat, ostat, sstat, pstat = map(os.stat, (root, output, operator, tmp_path))
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
        operator_store_root=str(operator),
        operator_device=str(sstat.st_dev),
        operator_inode=str(sstat.st_ino),
        operator_store_id="synthetic",
        policy_path=str(policy_path),
        policy_parent_device=str(pstat.st_dev),
        policy_parent_inode=str(pstat.st_ino),
        policy_limits=case.bound,
        attempt_price_usd="4",
        storage_price_usd="1",
        run_storage_capacity_bytes=capacity,
        operator_storage_capacity_bytes=capacity * 2,
        resource_policy_ref=case.config.resource_policy_ref,
        funded_from=current,
        funded_until=expiry,
        semantics="cooperative",
    )
    path = tmp_path / "bootstrap.json"
    raw = encoded(bootstrap)
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    assert policy == bootstrap.allocation_policy()
    guard = LocalCommittedGuard(
        ledger, case.control, pin=pin, authorization_ref=case.auth_ref, attempt_root=output
    )
    LocalAllocator.initialize(
        root, policy, case.store, now, operator_store_id="synthetic", operator_store_root=operator
    )
    alloc = LocalAllocator(
        root,
        policy,
        case.store,
        now,
        operator_store_id="synthetic",
        operator_store_root=operator,
        activation_guard=guard,
        policy_reader=bootstrap_policy_reader(bootstrap, now),
    )
    alloc.register_worker_bootstrap(path, digest)
    issuer = LocalGrantIssuer(allocator=alloc, guard=guard)
    if mode == "activation_failure":

        def refuse_activation(*_: Any) -> None:
            raise ContractError("forbidden")

        alloc.activate_attempt = refuse_activation
    trusted.allocator = alloc
    with ledger.transaction() as tx:
        storage_reservation = reserve_storage(
            RUN, "1", quotes[1][0], tx, context=budget_context(case.control, tx=tx)
        )
    stores: dict[str, Any] = {}
    grants: dict[str, Any] = {}

    class Clock:
        def now(self) -> str:
            return now()

    def factory(attempt: Any, grant: Any) -> Any:
        source = LocalStagingSource(case.store, case.access, alloc, case.plan, grant)
        result = LocalAttemptStore(
            output,
            PROJECT,
            attempt.attempt_id,
            source,
            local_staged_refs(case.plan),
            grant,
            Clock(),
            alloc,
        )
        stores[attempt.attempt_id] = result
        grants[attempt.attempt_id] = grant
        if mode in {"revoke", "prepublish"}:
            source_id = case.data.report.entries[0].source_id
            revoked = tuple(
                s.model_copy(update={"read": "deny"}) if s.source_id == source_id else s
                for s in case.policy.sources
            )

            def change_policy() -> None:
                policy_path.write_bytes(
                    encoded(case.policy.model_copy(update={"sources": revoked}))
                )

            if mode == "revoke":
                change_policy()
            else:
                original_revalidate = alloc.revalidate_write

                def revoked_before_publish(*args: Any) -> None:
                    change_policy()
                    original_revalidate(*args)

                alloc.revalidate_write = revoked_before_publish
        return result

    evidence_calls: list[object] = []

    def evidence(*args: object) -> Any:
        evidence_calls.append(args)
        return case.proof()

    executor = LocalExecutor(
        journal,
        "local",
        runtime,
        Clock(),
        evidence,
        factory,
        bootstrap_path=path,
        bootstrap_digest=digest,
    )
    trusted.executor = executor
    metered_evidence = LocalEvidenceWriter(
        guard=guard, allocator=alloc, executor=executor, operator=case.access
    )

    def production_evidence(*args: Any) -> Any:
        evidence_calls.append(args)
        return metered_evidence(*args)

    executor.evidence = production_evidence
    control = replace(
        case.control,
        staged_reader=lambda p, a: stores[a],
        staged_writer=lambda p, a: alloc.import_writer(p, RUN, a),
    )
    attempt = dispatch(
        case.plan,
        case.auth,
        case.access,
        ledger,
        executor,
        issuer,
        control=control,
        plan_ref=case.plan_ref,
        authorization_ref=case.auth_ref,
        asset_id=ASSET,
        evidence_ref=quotes[0][0],
    )
    if mode in {"revoke", "prepublish", "activation_failure"}:
        from psycopg import sql

        assert attempt.state == ("failed" if mode == "activation_failure" else "unknown_outcome")
        assert attempt.attempt_id not in executor._waiters
        assert not (journal / attempt.attempt_id / "job.json").exists()
        with ledger.transaction() as tx:
            row = tx.connection.execute(
                sql.SQL(
                    "SELECT outstanding_usd,final_billing FROM {} WHERE reservation_id=%s"
                ).format(tx.table("reservations")),
                (attempt.reservation_id,),
            ).fetchone()
            assert row is not None and row[0] > 0 and row[1] is False
        if mode == "prepublish":
            import json

            state = json.loads((root / "allocator.json").read_bytes())
            assert any(item["status"] == "pending" for item in state["runs"][RUN]["refs"].values())
        return
    assert attempt.state == "running"
    if mode == "cancelled":
        import time
        from uuid import uuid4

        from conscience_foundry.cli.local_authority import (
            LocalAllocationReceipt,
            LocalClosureGuard,
            LocalReceiptIssuer,
        )
        from conscience_foundry.contracts.accounting import BudgetEvent
        from conscience_foundry.contracts.common import Reason
        from conscience_foundry.execution.control import _load, cancel_attempt
        from conscience_foundry.ledger.budget import apply_budget_event

        deadline = time.monotonic() + 15
        handshake = journal / attempt.attempt_id / "handshake.json"
        while not handshake.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert handshake.exists()
        case.schemas["cf.local-process-observation.v1"] = case.bound
        local_control = replace(control, evidence_authority=trusted)
        command = case.proof()
        case.authority.controls[command.digest] = ("cancel_attempt", None, (), False, False)
        cancelled = cancel_attempt(
            attempt.attempt_id,
            ledger,
            executor,
            control=local_control,
            reason=Reason(code="unavailable", message="synthetic cancellation"),
            evidence_ref=command,
        )
        assert cancelled.state == "cancel_requested"
        executor._waiters[attempt.attempt_id].join(timeout=30)
        assert (
            reconcile(attempt.attempt_id, ledger, executor, case.store, control=local_control)
            is None
        )
        with ledger.transaction() as tx:
            terminal, _, _, _ = _load(tx, attempt.attempt_id, local_control)
        assert terminal.state == "cancelled"
        receipts = LocalReceiptIssuer(
            guard=guard, allocator=alloc, executor=executor, operator=case.access
        )
        attempt_ref = receipts.attempt_candidate(terminal)
        storage_ref = receipts.storage_candidate(terminal)
        for ref in (attempt_ref, storage_ref):
            case.schemas[ref.artifact_schema] = case.bound
            receipt = LocalAllocationReceipt.from_wire(
                case.store.read_verified(ref, case.access, case.bound.max_json_bytes).data,
                case.bound,
            )
            assert receipt.result_ref is None

        def settled(
            scope: str, reservation: str, ref: Any, amount: str, attempt_id: str | None
        ) -> Any:
            return BudgetEvent(
                schema_version="cf.budget-event.v1",
                project_id=PROJECT,
                run_id=RUN,
                reservation_id=reservation,
                scope=scope,
                event_id=str(uuid4()),
                event_type="settle",
                cost_status="actual",
                evidence_ref=ref,
                amount_usd=amount,
                created_at=now(),
                **({"attempt_id": attempt_id} if attempt_id else {}),
            )

        attempt_event = settled(
            "attempt", attempt.reservation_id, attempt_ref, "4", attempt.attempt_id
        )
        with ledger.transaction() as tx:
            apply_budget_event(
                attempt_event,
                tx,
                event_bytes=encoded(attempt_event),
                context=budget_context(local_control, tx=tx),
            )
        alloc.closure_guard = LocalClosureGuard(
            ledger=ledger, control=local_control, allocator=alloc, candidate=storage_ref
        )
        alloc.close_storage(RUN, alloc.durable_refs(PROJECT, RUN))
        storage_event = settled("run_storage", storage_reservation, storage_ref, "1", None)
        with ledger.transaction() as tx:
            apply_budget_event(
                storage_event,
                tx,
                event_bytes=encoded(storage_event),
                context=budget_context(local_control, tx=tx),
            )
        return
    executor._waiters[attempt.attempt_id].join(timeout=60)
    observation = executor.observe(attempt)
    if mode == "failed_manifest":
        from uuid import uuid4

        from conscience_foundry.cli.local_authority import (
            LocalAllocationReceipt,
            LocalClosureGuard,
            LocalReceiptIssuer,
            LocalRecoveryReader,
        )
        from conscience_foundry.contracts.accounting import BudgetEvent
        from conscience_foundry.execution.control import _load
        from conscience_foundry.ledger.budget import apply_budget_event

        assert observation.state == "failed" and observation.result_ref is not None
        case.schemas["cf.local-process-observation.v1"] = case.bound
        reader = LocalRecoveryReader(
            allocator=alloc,
            root=output,
            grant=grants[attempt.attempt_id],
            plan=case.plan,
            operator=case.access,
            limits_by_schema=case.schemas,
        )
        local_control = replace(
            control, evidence_authority=trusted, staged_reader=lambda *_: reader
        )
        assert (
            reconcile(attempt.attempt_id, ledger, executor, case.store, control=local_control)
            is None
        )
        with ledger.transaction() as tx:
            terminal, _, _, _ = _load(tx, attempt.attempt_id, local_control)
        assert terminal.state == "failed" and terminal.result_manifest_ref == observation.result_ref
        receipts = LocalReceiptIssuer(
            guard=guard, allocator=alloc, executor=executor, operator=case.access
        )
        attempt_ref, storage_ref = (
            receipts.attempt_candidate(terminal),
            receipts.storage_candidate(terminal),
        )
        for ref in (attempt_ref, storage_ref):
            case.schemas[ref.artifact_schema] = case.bound
            receipt = LocalAllocationReceipt.from_wire(
                case.store.read_verified(ref, case.access, case.bound.max_json_bytes).data,
                case.bound,
            )
            assert (
                receipt.terminal_state == "failed" and receipt.result_ref == observation.result_ref
            )

        def bill(
            scope: str, reservation: str, ref: Any, amount: str, attempt_id: str | None
        ) -> Any:
            return BudgetEvent(
                schema_version="cf.budget-event.v1",
                project_id=PROJECT,
                run_id=RUN,
                reservation_id=reservation,
                scope=scope,
                event_id=str(uuid4()),
                event_type="settle",
                cost_status="actual",
                evidence_ref=ref,
                amount_usd=amount,
                created_at=now(),
                **({"attempt_id": attempt_id} if attempt_id else {}),
            )

        attempt_event = bill(
            "attempt", attempt.reservation_id, attempt_ref, "4", attempt.attempt_id
        )
        with ledger.transaction() as tx:
            apply_budget_event(
                attempt_event,
                tx,
                event_bytes=encoded(attempt_event),
                context=budget_context(local_control, tx=tx),
            )
        alloc.closure_guard = LocalClosureGuard(
            ledger=ledger, control=local_control, allocator=alloc, candidate=storage_ref
        )
        alloc.close_storage(RUN, alloc.durable_refs(PROJECT, RUN))
        storage_event = bill("run_storage", storage_reservation, storage_ref, "1", None)
        with ledger.transaction() as tx:
            apply_budget_event(
                storage_event,
                tx,
                event_bytes=encoded(storage_event),
                context=budget_context(local_control, tx=tx),
            )
        return
    assert observation.state == "succeeded"
    assert observation.result_ref is not None
    assert len(evidence_calls) == 1
    inspection = executor._inspect(attempt)
    assert inspection.state == observation.state
    assert inspection.result_ref == observation.result_ref
    assert inspection.confirmed_termination is True
    assert len(evidence_calls) == 1
    case.schemas["cf.local-process-observation.v1"] = case.bound
    from conscience_foundry.contracts.accounting import BudgetEvent
    from conscience_foundry.execution.control import _observation
    from conscience_foundry.execution.ports import EvidenceBinding

    real_budget = trusted.budget

    def checked_budget(proof: Any) -> Any:
        if proof.claim.purpose == "record_usage":
            event = BudgetEvent.from_wire(proof.claim.request_bytes, case.bound)
            forged = encoded(event.model_copy(update={"amount_usd": "1"}))
            claim = replace(
                proof.claim, request_bytes=forged, request_digest=hashlib.sha256(forged).hexdigest()
            )
            with pytest.raises(ContractError):
                real_budget(replace(proof, claim=claim, binding=EvidenceBinding.from_budget(claim)))
            with pytest.raises(ContractError):
                real_budget(replace(proof, evidence_bytes=proof.evidence_bytes + b" "))
        return real_budget(proof)

    trusted.budget = checked_budget
    local_control = replace(control, evidence_authority=trusted)
    facts, _ = _observation(attempt, RUN, case.plan_ref, case.auth_ref, observation, local_control)
    assert facts.state == "succeeded" and facts.confirmed_termination is True
    assert len(evidence_calls) == 1
    with pytest.raises(ContractError):
        _observation(
            attempt,
            RUN,
            case.plan_ref,
            case.auth_ref,
            replace(observation, result_ref=case.auth_ref),
            local_control,
        )
    if mode == "unknown_pid":
        from psycopg import sql

        from conscience_foundry.execution.local_executor import LocalInspection

        monkeypatch.setattr(
            executor, "_inspect", lambda _: LocalInspection("unknown_outcome", None, None, False)
        )
        unknown = executor.observe(attempt)
        with pytest.raises(ContractError):
            _observation(
                attempt.model_copy(update={"remote_call_id": "999999999"}),
                RUN,
                case.plan_ref,
                case.auth_ref,
                unknown,
                local_control,
            )
        assert (
            reconcile(attempt.attempt_id, ledger, executor, case.store, control=local_control)
            is None
        )
        with ledger.transaction() as tx:
            state, outstanding = tx.connection.execute(
                sql.SQL(
                    "SELECT a.state,r.outstanding_usd FROM {} a JOIN {} r "
                    "ON a.reservation_id=r.reservation_id "
                    "AND a.project_id=r.project_id WHERE a.attempt_id=%s"
                ).format(tx.table("attempts"), tx.table("reservations")),
                (attempt.attempt_id,),
            ).fetchone()
            assert state == "unknown_outcome" and outstanding > 0
        return
    from conscience_foundry.cli.local_authority import LocalRecoveryReader

    reader = LocalRecoveryReader(
        allocator=alloc,
        root=output,
        grant=grants[attempt.attempt_id],
        plan=case.plan,
        operator=case.access,
        limits_by_schema=case.schemas,
    )
    with pytest.raises(ContractError):
        LocalRecoveryReader(
            allocator=alloc,
            root=output,
            grant=grants[attempt.attempt_id],
            plan=case.plan,
            operator=replace(case.access, actor_id=attempt.attempt_id),
            limits_by_schema=case.schemas,
        )
    if mode == "quota":
        with pytest.raises(ContractError, match="limit_exceeded"):
            import_staged_result(
                reader,
                alloc.import_writer(PROJECT, RUN, attempt.attempt_id),
                observation.result_ref,
                case.access,
                limits_by_schema=case.schemas,
            )
        return
    local_control = replace(local_control, staged_reader=lambda *_: reader)
    accepted = reconcile(attempt.attempt_id, ledger, executor, case.store, control=local_control)
    assert accepted is not None
    assert (
        import_staged_result(
            reader,
            alloc.import_writer(PROJECT, RUN, attempt.attempt_id),
            observation.result_ref,
            case.access,
            limits_by_schema=case.schemas,
        )
        == "already_present"
    )
    import io
    from uuid import uuid4

    from test_ledger_db import reference

    from conscience_foundry.cli.local_authority import (
        LocalAllocationReceipt,
        LocalClosureGuard,
        LocalReceiptIssuer,
    )
    from conscience_foundry.execution.control import _load
    from conscience_foundry.ledger.budget import apply_budget_event

    with ledger.transaction() as tx:
        terminal, _, _, _ = _load(tx, attempt.attempt_id, local_control)
    assert terminal.state == "succeeded"
    receipts = LocalReceiptIssuer(
        guard=guard, allocator=alloc, executor=executor, operator=case.access
    )
    attempt_receipt = receipts.attempt_candidate(terminal)
    storage_receipt = receipts.storage_candidate(terminal)
    assert receipts.attempt_candidate(terminal) == attempt_receipt
    assert receipts.storage_candidate(terminal) == storage_receipt
    for schema in ("cfoundry.local-attempt-allocation.v1", "cfoundry.local-storage-allocation.v1"):
        case.schemas[schema] = case.bound

    def forge_candidate(ref: Any, **changes: Any) -> Any:
        raw = case.store.read_verified(ref, case.access, case.bound.max_json_bytes).data
        receipt = LocalAllocationReceipt.from_wire(raw, case.bound).model_copy(update=changes)
        forged_raw = encoded(receipt)
        forged_ref = reference(forged_raw, receipt.schema_version)
        alloc.import_writer(PROJECT, RUN, attempt.attempt_id).put_verified(
            io.BytesIO(forged_raw), forged_ref, case.access
        )
        return forged_ref

    forged_attempt = forge_candidate(attempt_receipt, reservation_id=str(uuid4()))
    forged_storage = forge_candidate(storage_receipt, process_id="999999")

    def settlement(
        scope: str, reservation: str, ref: Any, amount: str, attempt_id: str | None
    ) -> Any:
        return BudgetEvent(
            schema_version="cf.budget-event.v1",
            project_id=PROJECT,
            run_id=RUN,
            reservation_id=reservation,
            scope=scope,
            event_id=str(uuid4()),
            event_type="settle",
            cost_status="actual",
            evidence_ref=ref,
            amount_usd=amount,
            created_at=now(),
            **({"attempt_id": attempt_id} if attempt_id is not None else {}),
        )

    attempt_bill = settlement(
        "attempt", attempt.reservation_id, attempt_receipt, "4", attempt.attempt_id
    )
    storage_bill = settlement("run_storage", storage_reservation, storage_receipt, "1", None)
    forged_attempt_bill = settlement(
        "attempt", attempt.reservation_id, forged_attempt, "4", attempt.attempt_id
    )
    with pytest.raises(ContractError):
        with ledger.transaction() as tx:
            apply_budget_event(
                forged_attempt_bill,
                tx,
                event_bytes=encoded(forged_attempt_bill),
                context=budget_context(local_control, tx=tx),
            )
    with pytest.raises(ContractError):
        with ledger.transaction() as tx:
            apply_budget_event(
                storage_bill,
                tx,
                event_bytes=encoded(storage_bill),
                context=budget_context(local_control, tx=tx),
            )
    reopened = LocalAllocator(
        root,
        policy,
        case.store,
        now,
        operator_store_id="synthetic",
        operator_store_root=operator,
        activation_guard=guard,
        policy_reader=bootstrap_policy_reader(bootstrap, now),
    )
    trusted.allocator = reopened
    with pytest.raises(ContractError):
        with ledger.transaction() as tx:
            apply_budget_event(
                storage_bill,
                tx,
                event_bytes=encoded(storage_bill),
                context=budget_context(local_control, tx=tx),
            )
    trusted.allocator = alloc
    with ledger.transaction() as tx:
        apply_budget_event(
            attempt_bill,
            tx,
            event_bytes=encoded(attempt_bill),
            context=budget_context(local_control, tx=tx),
        )
    with pytest.raises(ContractError):
        receipts.storage_candidate(terminal)
    closure_guard = LocalClosureGuard(
        ledger=ledger, control=local_control, allocator=alloc, candidate=storage_receipt
    )
    alloc.closure_guard = closure_guard
    refs = alloc.durable_refs(PROJECT, RUN)
    with pytest.raises(ContractError):
        alloc.close_storage(RUN, tuple(ref for ref in refs if ref != storage_receipt))
    from concurrent.futures import ThreadPoolExecutor
    from concurrent.futures import TimeoutError as FutureTimeout
    from contextlib import contextmanager
    from threading import Event

    from conscience_foundry.execution.evidence import admission_evidence, verified_plan
    from conscience_foundry.ledger.budget import reserve_attempt

    locked, release, claim_started, write_started = Event(), Event(), Event(), Event()

    @contextmanager
    def blocked_guard(project: str, run: str):
        with closure_guard(project, run) as verify:

            def blocked_verify(values: Any) -> bool:
                locked.set()
                assert release.wait(10)
                return verify(values)

            yield blocked_verify

    alloc.closure_guard = blocked_guard

    def another_claim() -> None:
        claim_started.set()
        with ledger.transaction() as tx:
            tx.lock(PROJECT, RUN)
            verified = verified_plan(case.plan_ref, case.auth_ref, tx, local_control, spending=True)
            admission, _, _ = admission_evidence(case.plan, tx, local_control)
            reserve_attempt(
                case.plan,
                case.auth,
                quotes[0][0],
                tx,
                context=budget_context(local_control, tx=tx),
                plan_ref=case.plan_ref,
                plan_bytes=verified.data,
                authorization_ref=case.auth_ref,
                authorization_bytes=encoded(case.auth),
                admission=admission,
                asset_id=ASSET,
                execution_config_bytes=verified.config_bytes,
            )
            raise AssertionError("closed run accepted a new reservation")

    def another_write() -> None:
        write_started.set()
        with alloc.write_permit(PROJECT, RUN, attempt.attempt_id, case.auth_ref):
            raise AssertionError("closed run accepted a new write")

    with ThreadPoolExecutor(max_workers=3) as pool:
        closing = pool.submit(alloc.close_storage, RUN, refs)
        assert locked.wait(10)
        claim = pool.submit(another_claim)
        write = pool.submit(another_write)
        assert claim_started.wait(10)
        assert write_started.wait(10)
        with pytest.raises(FutureTimeout):
            claim.result(timeout=0.2)
        with pytest.raises(FutureTimeout):
            write.result(timeout=0.2)
        release.set()
        closing.result(timeout=10)
        with pytest.raises(ContractError):
            claim.result(timeout=10)
        with pytest.raises(ContractError):
            write.result(timeout=10)
    from psycopg import sql

    with ledger.transaction() as tx:
        assert (
            tx.connection.execute(
                sql.SQL("SELECT count(*) FROM {} WHERE project_id=%s AND run_id=%s").format(
                    tx.table("attempts")
                ),
                (PROJECT, RUN),
            ).fetchone()[0]
            == 1
        )
    historical = next(p for p in quote_proofs if p.claim.purpose == "reserve_storage")
    assert original_quote_budget(historical).amount_ceiling_usd == "1"
    swapped_claim = replace(historical.claim, reservation_id=str(uuid4()))
    with pytest.raises(ContractError):
        original_quote_budget(
            replace(
                historical, claim=swapped_claim, binding=EvidenceBinding.from_budget(swapped_claim)
            )
        )
    assert reader.read_verified(observation.result_ref, case.access, case.bound.max_json_bytes).data
    with pytest.raises(ContractError):
        receipts.storage_candidate(terminal)
    forged_storage_bill = settlement("run_storage", storage_reservation, forged_storage, "1", None)
    with pytest.raises(ContractError):
        with ledger.transaction() as tx:
            apply_budget_event(
                forged_storage_bill,
                tx,
                event_bytes=encoded(forged_storage_bill),
                context=budget_context(local_control, tx=tx),
            )
    with ledger.transaction() as tx:
        apply_budget_event(
            storage_bill,
            tx,
            event_bytes=encoded(storage_bill),
            context=budget_context(local_control, tx=tx),
        )
    with pytest.raises(ContractError):
        with ledger.transaction() as tx:
            reserve_storage(
                RUN, "1", quotes[1][0], tx, context=budget_context(local_control, tx=tx)
            )
    with pytest.raises(ContractError):
        reader.read_verified(case.auth_ref, case.access, case.auth_ref.size_bytes)
    with pytest.raises(ContractError):
        reader.read_verified(
            observation.result_ref,
            replace(case.access, actor_id=attempt.attempt_id),
            case.bound.max_json_bytes,
        )

    alloc.clock = lambda: expiry
    assert reader.read_verified(observation.result_ref, case.access, case.bound.max_json_bytes).data
    with pytest.raises(ContractError):
        alloc.import_writer(PROJECT, RUN, attempt.attempt_id).put_verified(
            io.BytesIO(encoded(case.auth)), case.auth_ref, case.access
        )
    alloc.clock = now
    source_id = case.data.report.entries[0].source_id
    revoked = tuple(
        s.model_copy(update={"read": "deny"}) if s.source_id == source_id else s
        for s in case.policy.sources
    )
    policy_path.write_bytes(encoded(case.policy.model_copy(update={"sources": revoked})))
    with pytest.raises(ContractError):
        reader.read_verified(observation.result_ref, case.access, case.bound.max_json_bytes)
    policy_path.write_bytes(encoded(case.policy))
    state_path = root / "allocator.json"
    retained_state = state_path.read_bytes()
    attempt_directory = output / PROJECT / attempt.attempt_id
    for artifact in attempt_directory.iterdir():
        artifact.unlink()
    assert case.store.read_verified(
        observation.result_ref, case.access, case.bound.max_json_bytes
    ).data
    assert state_path.read_bytes() == retained_state  # manual deletion never reclaims quota


def test_shared_config_quote_selects_each_attempt_and_validates_complete_mapping(
    tmp_path: Path,
) -> None:
    import hashlib
    import json
    from uuid import uuid4

    from test_ledger_db import PROJECT, RUN, TIME, encoded

    from conscience_foundry.cli.local_authority import (
        LocalAllocationEstimate,
        LocalControlAuthority,
        LocalPlanPin,
    )
    from conscience_foundry.execution.local_allocation import LocalAllocationPolicy, LocalAllocator
    from conscience_foundry.execution.ports import BudgetProof, EvidenceBinding
    from conscience_foundry.ledger._budget_inputs import BudgetEvidenceClaim

    case = local_case(tmp_path)
    plan2 = case.plan.model_copy(update={"plan_id": str(uuid4())})
    ref2 = case.put(plan2)
    auth = case.auth.model_copy(
        update={"allowed_plan_digests": (case.plan_ref.digest, ref2.digest)}
    )
    auth_ref = case.put(auth)
    policy = LocalAllocationPolicy(
        "4",
        "1",
        10000,
        20000,
        case.config.resource_policy_ref,
        TIME,
        auth.expires_at,
        "cooperative",
    )
    root = tmp_path / "allocator"
    root.mkdir()
    LocalAllocator.initialize(
        root,
        policy,
        case.store,
        lambda: TIME,
        operator_store_id="synthetic",
        operator_store_root=tmp_path / "objects",
    )
    alloc = LocalAllocator(
        root,
        policy,
        case.store,
        lambda: TIME,
        operator_store_id="synthetic",
        operator_store_root=tmp_path / "objects",
    )
    pins = (
        LocalPlanPin(case.plan_ref, case.plan, case.config_ref, case.config),
        LocalPlanPin(ref2, plan2, case.config_ref, case.config),
    )
    quotes = []
    for scope, amount in (("attempt", "4"), ("run_storage", "1")):
        quote = LocalAllocationEstimate(
            schema_version="cfoundry.local-allocation-estimate.v1",
            project_id=PROJECT,
            scope=scope,
            authorization_ref=auth_ref,
            plan_refs=(case.plan_ref, ref2),
            config_refs=(case.config_ref,),
            resource_policy_ref=case.config.resource_policy_ref,
            funded_from=TIME,
            funded_until=auth.expires_at,
            ceiling_usd=amount,
        )
        quotes.append((case.put(quote), encoded(quote)))
    authority = LocalControlAuthority(
        policy=policy, estimates=tuple(quotes), plans=pins, limits=case.bound, allocator=alloc
    )
    for pin in pins:
        request = encoded(pin.plan)
        claim = BudgetEvidenceClaim(
            "reserve_attempt",
            quotes[0][0],
            PROJECT,
            RUN,
            str(uuid4()),
            str(uuid4()),
            TIME,
            auth_ref,
            pin.ref,
            pin.config_ref,
            request,
            hashlib.sha256(request).hexdigest(),
        )
        facts = authority.budget(
            BudgetProof(claim, EvidenceBinding.from_budget(claim), quotes[0][1], auth, ())
        )
        assert facts.plan_refs == (pin.ref,)
        assert (
            len(facts.capabilities) == 1
            and facts.capabilities[0].execution_config_ref == pin.config_ref
        )
    request = json.dumps(
        {
            "projectId": PROJECT,
            "runId": RUN,
            "authorizationDigest": auth_ref.digest,
            "currency": "USD",
            "amountUsd": "1",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    claim = BudgetEvidenceClaim(
        "reserve_storage",
        quotes[1][0],
        PROJECT,
        RUN,
        str(uuid4()),
        None,
        TIME,
        auth_ref,
        None,
        None,
        request,
        hashlib.sha256(request).hexdigest(),
    )
    storage = authority.budget(
        BudgetProof(claim, EvidenceBinding.from_budget(claim), quotes[1][1], auth, ())
    )
    assert storage.plan_refs == (case.plan_ref, ref2) and len(storage.capabilities) == 2
    extra_config = case.config.model_copy(update={"deployment_version": "extra.v1"})
    extra_ref = case.put(extra_config)
    for config_refs in ((extra_ref,), (case.config_ref, extra_ref)):
        forged_quote = quote.model_copy(update={"config_refs": config_refs})
        forged_ref = case.put(forged_quote)
        forged_authority = LocalControlAuthority(
            policy=policy,
            estimates=((forged_ref, encoded(forged_quote)),),
            plans=pins,
            limits=case.bound,
            allocator=alloc,
        )
        forged_claim = replace(claim, evidence_ref=forged_ref)
        with pytest.raises(ContractError):
            forged_authority.budget(
                BudgetProof(
                    forged_claim,
                    EvidenceBinding.from_budget(forged_claim),
                    encoded(forged_quote),
                    auth,
                    (),
                )
            )
    unrelated = case.plan.model_copy(update={"plan_id": str(uuid4())})
    unrelated_ref = case.put(unrelated)
    unrelated_raw = encoded(unrelated)
    unrelated_claim = BudgetEvidenceClaim(
        "reserve_attempt",
        quotes[0][0],
        PROJECT,
        RUN,
        str(uuid4()),
        str(uuid4()),
        TIME,
        auth_ref,
        unrelated_ref,
        case.config_ref,
        unrelated_raw,
        hashlib.sha256(unrelated_raw).hexdigest(),
    )
    with pytest.raises(ContractError):
        authority.budget(
            BudgetProof(
                unrelated_claim,
                EvidenceBinding.from_budget(unrelated_claim),
                quotes[0][1],
                auth,
                (),
            )
        )


def test_acceptance_rechecks_withdrawal_after_attestation(ledger: Ledger, tmp_path: Path) -> None:
    from uuid import uuid4

    from psycopg import sql
    from psycopg.types.json import Jsonb
    from test_ledger_db import ASSET, PROJECT, RUN, TIME

    from conscience_foundry.execution.control import _apply, _attest
    from conscience_foundry.execution.staged_import import import_staged_result

    case, executor, attempt, remote = started(ledger, tmp_path)
    result, _ = remote.stage(attempt, lambda: case.result(attempt))
    observation = observe(case, executor, attempt, result)
    control = remote.control()
    attested = _attest(attempt.attempt_id, ledger, observation, control)
    import_staged_result(
        remote.reader(PROJECT, attempt.attempt_id),
        case.store,
        result,
        case.access,
        limits_by_schema=case.schemas,
    )
    source = case.data.report.entries[0].source_id
    with ledger.transaction() as tx:
        tx.lock(PROJECT, RUN, attempt.operation_key)
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,batch_id,asset_id,source_id,decision_id,actor_id,"
                "reason,evidence_ref,request_digest,record_bytes,decided_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            ).format(tx.table("admission_withdrawals")),
            (
                PROJECT,
                case.data.report.batch_id,
                ASSET,
                source,
                str(uuid4()),
                case.access.actor_id,
                Jsonb({"code": "source_missing"}),
                Jsonb(case.auth_ref.model_dump(mode="json", by_alias=True)),
                "a" * 64,
                b"synthetic",
                TIME,
            ),
        )
    with pytest.raises(ContractError):
        _apply(attempt.attempt_id, ledger, attested, control)
    with ledger.transaction() as tx:
        row = tx.connection.execute(
            sql.SQL(
                "SELECT selected_result_ref FROM {} WHERE project_id=%s AND operation_key=%s"
            ).format(tx.table("operations")),
            (PROJECT, attempt.operation_key),
        ).fetchone()
        assert row is not None and row[0] is None


def test_two_committed_plans_share_config_and_fixed_attempt_quote(
    ledger: Ledger, tmp_path: Path, monkeypatch: Any
) -> None:
    from uuid import uuid4

    import test_execution_control as fixture
    from test_ledger_db import PROJECT, RUN, TIME, admission, encoded

    from conscience_foundry.cli.local_authority import (
        LocalAllocationEstimate,
        LocalControlAuthority,
        LocalPlanPin,
    )
    from conscience_foundry.contracts.admission import IntakeManifest
    from conscience_foundry.core.identity import F1Operation, operation_key
    from conscience_foundry.execution.evidence import (
        admission_evidence,
        budget_context,
        verified_plan,
    )
    from conscience_foundry.execution.local_allocation import LocalAllocationPolicy, LocalAllocator
    from conscience_foundry.ledger.budget import reserve_attempt, reserve_storage

    monkeypatch.setattr(fixture, "admission", lambda: admission(extra_asset=True))
    case = local_case(tmp_path)
    manifest = IntakeManifest.from_wire(case.data.evidence.manifest_bytes, case.bound)
    second = manifest.items[1]
    key = operation_key(
        F1Operation(
            PROJECT,
            second.asset_id,
            second.source_id,
            (case.original.digest,),
            case.spec_ref.digest,
            manifest.profile_id,
            manifest.profile_version,
            manifest.policy_ref.digest,
            case.plan.contract_set_ref.digest,
            (case.limits_ref.digest,),
        ),
        limits=case.bound,
    )
    plan2 = case.plan.model_copy(update={"plan_id": str(uuid4()), "operation_key": key})
    ref2 = case.put(plan2)
    case.auth = case.auth.model_copy(
        update={"allowed_plan_digests": (case.plan_ref.digest, ref2.digest)}
    )
    case.auth_ref = case.put(case.auth)
    case.authority.grants[case.auth_ref.digest] = (case.auth_ref.digest, None)
    policy = LocalAllocationPolicy(
        "4",
        "1",
        65536,
        131072,
        case.config.resource_policy_ref,
        TIME,
        case.auth.expires_at,
        "cooperative",
    )
    root = tmp_path / "allocator"
    root.mkdir()
    LocalAllocator.initialize(
        root,
        policy,
        case.store,
        lambda: TIME,
        operator_store_id="synthetic",
        operator_store_root=tmp_path / "objects",
    )
    alloc = LocalAllocator(
        root,
        policy,
        case.store,
        lambda: TIME,
        operator_store_id="synthetic",
        operator_store_root=tmp_path / "objects",
    )
    pins = (
        LocalPlanPin(case.plan_ref, case.plan, case.config_ref, case.config),
        LocalPlanPin(ref2, plan2, case.config_ref, case.config),
    )
    quotes = []
    for scope, amount in (("attempt", "4"), ("run_storage", "1")):
        quote = LocalAllocationEstimate(
            schema_version="cfoundry.local-allocation-estimate.v1",
            project_id=PROJECT,
            scope=scope,
            authorization_ref=case.auth_ref,
            plan_refs=(case.plan_ref, ref2),
            config_refs=(case.config_ref,),
            resource_policy_ref=case.config.resource_policy_ref,
            funded_from=TIME,
            funded_until=case.auth.expires_at,
            ceiling_usd=amount,
        )
        quotes.append((case.put(quote), encoded(quote)))
    case.schemas["cfoundry.local-allocation-estimate.v1"] = case.bound
    authority = LocalControlAuthority(
        policy=policy,
        estimates=tuple(quotes),
        plans=pins,
        limits=case.bound,
        allocator=alloc,
        delegate=case.authority,
    )
    control = replace(case.control, evidence_authority=authority)
    case.control = control
    case.setup(ledger)
    with ledger.transaction() as tx:
        reserve_storage(RUN, "1", quotes[1][0], tx, context=budget_context(control, tx=tx))
    ids = []
    for pin, asset in ((pins[0], manifest.items[0].asset_id), (pins[1], second.asset_id)):
        with ledger.transaction() as tx:
            verified = verified_plan(pin.ref, case.auth_ref, tx, control, spending=True)
            evidence, _, _ = admission_evidence(pin.plan, tx, control)
            attempt = reserve_attempt(
                pin.plan,
                case.auth,
                quotes[0][0],
                tx,
                context=budget_context(control, tx=tx),
                plan_ref=pin.ref,
                plan_bytes=verified.data,
                authorization_ref=case.auth_ref,
                authorization_bytes=encoded(case.auth),
                admission=evidence,
                asset_id=asset,
                execution_config_bytes=verified.config_bytes,
            )
            ids.append(attempt.attempt_id)
    assert len(set(ids)) == 2
