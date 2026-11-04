"""Local worker grants must never inherit remote authority by duck typing."""

import pytest
from test_modal import StepClock, build

from conscience_foundry.contracts.common import ContractError
from conscience_foundry.execution.worker import run_worker


def test_unknown_grant_rejected_before_input_reads() -> None:
    scenario = build()

    class UnknownGrant:
        project_id = scenario.grants.project_id
        plan_digest = scenario.grants.plan_digest
        attempt_id = scenario.grants.attempt_id
        expires_at = scenario.grants.expires_at
        output_scope = scenario.grants.output_scope

    with pytest.raises(ContractError):
        run_worker(
            scenario.plan_bytes, scenario.attempt_bytes, UnknownGrant(), scenario.store, StepClock()
        )
    assert scenario.store.log == []


def test_local_grant_validates_facts_and_uses_local_scopes(monkeypatch) -> None:
    from conscience_foundry.execution import worker
    from conscience_foundry.execution.local_contracts import LocalGrantFacts, LocalWorkerGrant

    scenario = build()
    grant = LocalWorkerGrant(
        scenario.plan.project_id,
        scenario.plan.run_id,
        scenario.grants.plan_digest,
        scenario.attempt.attempt_id,
        scenario.grants.destination_id,
        scenario.grants.expires_at,
        scenario.grants.output_scope,
        "nonce",
    )

    class Authority:
        def local_grant(self, proof):
            return LocalGrantFacts(**proof.__dict__, scopes=frozenset({"read", "extract"}))

    monkeypatch.setattr(worker, "verify_runtime", lambda expected: None)
    run_worker(
        scenario.plan_bytes,
        scenario.attempt_bytes,
        grant,
        scenario.store,
        StepClock(),
        local_authority=Authority(),
        expected_runtime_digest="a" * 64,
    )
    assert scenario.store.contexts
    assert all(
        context.scopes == frozenset({"read", "extract"}) for context in scenario.store.contexts
    )


@pytest.mark.parametrize(
    "field",
    [
        "project_id",
        "run_id",
        "plan_digest",
        "attempt_id",
        "destination_id",
        "expires_at",
        "input_refs",
        "output_scope",
        "nonce_digest",
        "scopes",
    ],
)
def test_forged_facts_rejected_before_reads(monkeypatch, field) -> None:
    from dataclasses import replace

    from conscience_foundry.execution import worker
    from conscience_foundry.execution.local_contracts import LocalGrantFacts, LocalWorkerGrant

    scenario = build()
    grant = LocalWorkerGrant(
        scenario.plan.project_id,
        scenario.plan.run_id,
        scenario.grants.plan_digest,
        scenario.attempt.attempt_id,
        scenario.grants.destination_id,
        scenario.grants.expires_at,
        scenario.grants.output_scope,
        "nonce",
    )
    values = {
        "project_id": "other",
        "run_id": "other",
        "plan_digest": "a" * 64,
        "attempt_id": "other",
        "destination_id": "other",
        "expires_at": "2000-01-01T00:00:00.000Z",
        "input_refs": (),
        "output_scope": b"other",
        "nonce_digest": "a" * 64,
        "scopes": frozenset({"read"}),
    }

    class Authority:
        def local_grant(self, proof):
            return replace(
                LocalGrantFacts(**proof.__dict__, scopes=frozenset({"read", "extract"})),
                **{field: values[field]},
            )

    monkeypatch.setattr(worker, "verify_runtime", lambda expected: None)
    with pytest.raises(ContractError):
        run_worker(
            scenario.plan_bytes,
            scenario.attempt_bytes,
            grant,
            scenario.store,
            StepClock(),
            local_authority=Authority(),
            expected_runtime_digest="a" * 64,
        )
    assert scenario.store.log == []


def test_missing_authority_runtime_and_expiry_refuse_before_reads(monkeypatch) -> None:
    from dataclasses import replace

    from conscience_foundry.execution import worker
    from conscience_foundry.execution.local_contracts import LocalGrantFacts, LocalWorkerGrant

    scenario = build()
    grant = LocalWorkerGrant(
        scenario.plan.project_id,
        scenario.plan.run_id,
        scenario.grants.plan_digest,
        scenario.attempt.attempt_id,
        scenario.grants.destination_id,
        scenario.grants.expires_at,
        scenario.grants.output_scope,
        "nonce",
    )

    class Authority:
        def local_grant(self, proof):
            return LocalGrantFacts(**proof.__dict__, scopes=frozenset({"read", "extract"}))

    monkeypatch.setattr(worker, "verify_runtime", lambda expected: None)
    for candidate, authority, digest in [
        (grant, None, "a" * 64),
        (grant, Authority(), None),
        (replace(grant, expires_at="2000-01-01T00:00:00.000Z"), Authority(), "a" * 64),
    ]:
        with pytest.raises(ContractError):
            run_worker(
                scenario.plan_bytes,
                scenario.attempt_bytes,
                candidate,
                scenario.store,
                StepClock(),
                local_authority=authority,
                expected_runtime_digest=digest,
            )
        assert scenario.store.log == []


def test_modal_refuses_local_grant_without_spawning() -> None:
    from test_modal import FakeModal, make_executor

    from conscience_foundry.execution.local_contracts import LocalWorkerGrant

    scenario = build()
    grant = LocalWorkerGrant(
        scenario.plan.project_id,
        scenario.plan.run_id,
        scenario.grants.plan_digest,
        scenario.attempt.attempt_id,
        scenario.grants.destination_id,
        scenario.grants.expires_at,
        scenario.grants.output_scope,
        "nonce",
    )
    sdk = FakeModal()
    with pytest.raises(ContractError):
        make_executor(scenario, sdk).submit(scenario.plan, scenario.attempt, grant)
    assert sdk.spawned == []


def test_local_lease_nonce_must_match_grant_before_claim(monkeypatch) -> None:
    from conscience_foundry.execution import worker
    from conscience_foundry.execution.local_contracts import LocalGrantFacts, LocalWorkerGrant

    scenario = build()
    grant = LocalWorkerGrant(
        scenario.plan.project_id,
        scenario.plan.run_id,
        scenario.grants.plan_digest,
        scenario.attempt.attempt_id,
        scenario.grants.destination_id,
        scenario.grants.expires_at,
        scenario.grants.output_scope,
        "grant-nonce",
    )

    class Authority:
        def local_grant(self, proof):
            return LocalGrantFacts(**proof.__dict__, scopes=frozenset({"read", "extract"}))

    class Lease:
        called = False

        def claim_lease(self, attempt_id, nonce):
            self.called = True
            return "won"

        def publish_result(self, attempt_id, ref):
            pass

    lease = Lease()
    monkeypatch.setattr(worker, "verify_runtime", lambda expected: None)
    with pytest.raises(ContractError):
        run_worker(
            scenario.plan_bytes,
            scenario.attempt_bytes,
            grant,
            scenario.store,
            StepClock(),
            lease=lease,
            nonce="other",
            local_authority=Authority(),
            expected_runtime_digest="a" * 64,
        )
    assert not lease.called
    assert scenario.store.log == []


def test_expiry_during_runtime_verification_does_not_claim_lease(monkeypatch) -> None:
    from conscience_foundry.execution import worker
    from conscience_foundry.execution.local_contracts import LocalGrantFacts, LocalWorkerGrant

    scenario = build()
    grant = LocalWorkerGrant(
        scenario.plan.project_id,
        scenario.plan.run_id,
        scenario.grants.plan_digest,
        scenario.attempt.attempt_id,
        scenario.grants.destination_id,
        scenario.grants.expires_at,
        scenario.grants.output_scope,
        "nonce",
    )

    class Authority:
        def local_grant(self, proof):
            return LocalGrantFacts(**proof.__dict__, scopes=frozenset({"read", "extract"}))

    class Lease:
        called = False

        def claim_lease(self, attempt_id, nonce):
            self.called = True
            return "won"

        def publish_result(self, attempt_id, ref):
            pass

    clock = StepClock()
    lease = Lease()
    monkeypatch.setattr(
        worker, "verify_runtime", lambda expected: setattr(clock, "base", grant.expires_at)
    )
    with pytest.raises(ContractError):
        run_worker(
            scenario.plan_bytes,
            scenario.attempt_bytes,
            grant,
            scenario.store,
            clock,
            lease=lease,
            nonce=grant.nonce,
            local_authority=Authority(),
            expected_runtime_digest="a" * 64,
        )
    assert not lease.called
    assert scenario.store.log == []
