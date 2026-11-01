"""Single-execution lease and result pointer, exercised offline through the S3 staging double.

No network, credential or provider payload is used; every identifier and byte string is
synthetic. Whether a compatible provider honors conditional creation is live preflight
evidence, not asserted here.
"""

from __future__ import annotations

import dataclasses
import io
from dataclasses import dataclass, field, replace
from typing import Any

import pytest
from test_modal import (
    ATTEMPT,
    GRANT_EXPIRY,
    PROJECT,
    SOURCE_BYTES,
    Scenario,
    StepClock,
    build,
    execute,
)
from test_staging_s3 import (
    BUCKET,
    CONTEXT,
    NOW,
    OTHER_PROJECT,
    FakeClientError,
    FakeS3,
    Issuer,
    config,
    make_store,
    ref_for,
)

from conscience_foundry.contracts.common import ArtifactRef, ContractError
from conscience_foundry.execution.ports import AttemptStaging, LeaseStore, TransportGrants
from conscience_foundry.execution.worker import DuplicateExecution, run_worker
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.staging_s3 import S3StagingStore, grant_storage_gate

ATTEMPT_PREFIX = f"staging/f1/{PROJECT}/attempts/{ATTEMPT}/"
LEASE_KEY = f"{ATTEMPT_PREFIX}lease"
RESULT_KEY = f"{ATTEMPT_PREFIX}result"
OUTPUTS = 5  # canonical text, origin map, quality report, revision and the manifest
OTHER_ATTEMPT = "00000000-0000-0000-0000-0000000000a9"
# the worker's own context: its project, with the attempt id as actor (see run_worker)
WORKER_CONTEXT = AccessContext(PROJECT, ATTEMPT, frozenset({"read", "remoteTransfer"}))


@dataclass
class Staged:
    scenario: Scenario
    client: FakeS3
    control: S3StagingStore
    grants: TransportGrants
    baseline: int = 0  # client calls made while the control side staged the inputs
    workers: list[S3StagingStore] = field(default_factory=list)

    def worker(self) -> S3StagingStore:
        """A worker-mode view: no authorizer, writes gated by what the grants allow."""
        store = S3StagingStore(
            config(max_object_bytes=65536, transfer_chunk_bytes=64),
            self.client,
            authorize=None,
            storage_reserved=grant_storage_gate(self.grants, StepClock()),
            clock=lambda: NOW,
            attempt_id=ATTEMPT,
        ).scoped_to(self.scenario.plan, ATTEMPT)
        self.workers.append(store)
        return store

    def run(
        self,
        store: S3StagingStore,
        nonce: str | None,
        lease: LeaseStore | None = None,
        grants: TransportGrants | None = None,
    ) -> ArtifactRef | DuplicateExecution:
        return run_worker(
            self.scenario.plan_bytes,
            self.scenario.attempt_bytes,
            grants or self.grants,
            store,
            StepClock(),
            lease=store if lease is None else lease,
            nonce=nonce,
        )

    def calls(self) -> list[tuple[str, str]]:
        """Every client call a worker made."""
        return list(self.client.calls[self.baseline :])

    def puts(self) -> list[str]:
        return [key for op, key in self.calls() if op == "put"]

    def output_puts(self) -> list[str]:
        return [key for key in self.puts() if key not in {LEASE_KEY, RESULT_KEY}]


def staged() -> Staged:
    scenario = build()
    client = FakeS3()
    control = make_store(client, issuer=Issuer(), max_object_bytes=65536, transfer_chunk_bytes=64)
    for ref, raw in (
        (scenario.limits_ref, scenario.limits.model_dump_json(by_alias=True).encode()),
        (scenario.spec_ref, scenario.store.objects[scenario.spec_ref.digest]),
        (scenario.report_ref, scenario.store.objects[scenario.report_ref.digest]),
        (scenario.source_ref, SOURCE_BYTES),
    ):
        control.put_verified(io.BytesIO(raw), ref, CONTEXT)
    grants = control.grant_transport(scenario.plan, scenario.attempt, CONTEXT)
    return Staged(scenario, client, control, grants, baseline=len(client.calls))


def test_two_workers_one_executes() -> None:
    case = staged()
    first, second = case.worker(), case.worker()
    seen: list[ArtifactRef | DuplicateExecution] = []

    class Interleaved:
        """The second worker starts while the first one still holds the lease."""

        def claim_lease(self, attempt_id: str, nonce: str) -> Any:
            outcome = first.claim_lease(attempt_id, nonce)
            seen.append(case.run(second, "nonce-b"))
            return outcome

        def publish_result(self, attempt_id: str, manifest: ArtifactRef) -> None:
            first.publish_result(attempt_id, manifest)

    winner = case.run(first, "nonce-a", lease=Interleaved())

    assert isinstance(winner, ArtifactRef) and winner.artifact_schema == "cf.result.v1"
    assert seen == [DuplicateExecution()]  # the loser found no pointer yet
    # one execution: each output written once, the loser wrote only its refused lease create
    assert len(case.output_puts()) == OUTPUTS == len(set(case.output_puts()))
    assert all(key.startswith(ATTEMPT_PREFIX) for key in case.puts())
    assert case.puts().count(LEASE_KEY) == 2
    assert case.client.objects[LEASE_KEY] == b"nonce-a"
    # a later duplicate resolves to the winner's pointer without executing again
    after = len(case.client.calls)
    assert case.run(case.worker(), "nonce-c") == winner
    assert [(op, key) for op, key in case.client.calls[after:] if op == "put"] == [
        ("put", LEASE_KEY)
    ]


def test_loser_returns_winner_pointer() -> None:
    case = staged()
    winner = case.run(case.worker(), "nonce-a")
    assert isinstance(winner, ArtifactRef)
    after = len(case.client.calls)

    loser = case.run(case.worker(), "nonce-b")

    assert loser == winner
    assert case.client.objects[LEASE_KEY] == b"nonce-a"  # the loser never replaced the lease
    assert case.puts().count(RESULT_KEY) == 1
    later = case.client.calls[after:]
    assert [key for op, key in later if op == "put"] == [LEASE_KEY]
    assert [key for op, key in later if op == "get"] == [RESULT_KEY]  # no input was read


def test_loser_without_pointer_returns_sentinel() -> None:
    case = staged()
    assert case.worker().claim_lease(ATTEMPT, "nonce-a") == "won"
    after = len(case.client.calls)

    outcome = case.run(case.worker(), "nonce-b")

    assert outcome == DuplicateExecution()
    assert dataclasses.fields(DuplicateExecution) == ()  # no fields: nothing to leak or compare
    with pytest.raises(dataclasses.FrozenInstanceError):
        DuplicateExecution().extra = 1  # type: ignore[attr-defined]
    later = case.client.calls[after:]
    assert [key for op, key in later if op == "put"] == [LEASE_KEY]
    assert all(key.startswith(ATTEMPT_PREFIX) for _, key in later)  # no input, no output


def test_lost_response_resolves_by_nonce() -> None:
    # the lease was stored but the response was lost: our own nonce reads back, we won
    mine = staged()
    mine.client.lose_put_response = True
    assert mine.worker().claim_lease(ATTEMPT, "nonce-a") == "won"
    assert mine.puts().count(LEASE_KEY) == 1  # never repeated

    # an ambiguous failure while another worker's lease is in place resolves as lost
    other = staged()
    other.client.objects[LEASE_KEY] = b"nonce-z"
    other.client.fail_put_before_store = TimeoutError("synthetic")
    assert other.worker().claim_lease(ATTEMPT, "nonce-a") == "lost"

    # a definite 412 is lost without reading anything back, even over our own nonce
    exists = staged()
    exists.client.objects[LEASE_KEY] = b"nonce-a"
    exists.client.fail_put_before_store = FakeClientError("PreconditionFailed", 412)
    assert exists.worker().claim_lease(ATTEMPT, "nonce-a") == "lost"
    assert [op for op, _ in exists.calls()] == ["put"]


def test_unreadable_lease_fails_closed() -> None:
    # ambiguous create and nothing readable afterwards
    absent = staged()
    absent.client.fail_put_before_store = TimeoutError("synthetic")
    with pytest.raises(ContractError) as missing:
        absent.worker().claim_lease(ATTEMPT, "nonce-a")
    assert missing.value.code == "dispatch_unknown"

    # ambiguous create and the read-back itself fails
    broken = staged()
    broken.client.objects[LEASE_KEY] = b"nonce-a"
    broken.client.fail_put_before_store = TimeoutError("synthetic")
    broken.client.get_faults = [ConnectionError("synthetic reset")]
    with pytest.raises(ContractError) as unreadable:
        broken.worker().claim_lease(ATTEMPT, "nonce-a")
    assert unreadable.value.code == "dispatch_unknown"

    # the run stops there: no input is read and nothing is written
    case = staged()
    case.client.fail_put_before_store = TimeoutError("synthetic")
    with pytest.raises(ContractError) as stopped:
        case.run(case.worker(), "nonce-a")
    assert stopped.value.code == "dispatch_unknown"
    assert case.calls() == [("put", LEASE_KEY), ("get", LEASE_KEY)]

    # a denied credential is a refusal, not an unknown outcome
    denied = staged()
    denied.client.fail_put_before_store = FakeClientError("AccessDenied", 403)
    with pytest.raises(ContractError) as refused:
        denied.worker().claim_lease(ATTEMPT, "nonce-a")
    assert refused.value.code == "forbidden"


def test_lease_checked_after_grants_and_bounds() -> None:
    # an expired grant raises before any put_object: no lease, no request at all
    expired = staged()
    stale = replace(expired.grants, expires_at="2029-12-31T23:59:59.000Z")
    with pytest.raises(ContractError) as late:
        expired.run(expired.worker(), "nonce-a", grants=stale)
    assert late.value.code == "authorization_expired"
    assert expired.calls() == []

    # grants minted for another attempt are refused before the lease
    foreign = staged()
    wrong = replace(foreign.grants, attempt_id=OTHER_ATTEMPT)
    with pytest.raises(ContractError) as forbidden:
        foreign.run(foreign.worker(), "nonce-a", grants=wrong)
    assert forbidden.value.code == "forbidden"
    assert foreign.calls() == []

    # the claim is the first request, before any input read; the pointer follows the manifest
    ordered = staged()
    store = ordered.worker()
    order: list[str] = []

    class Recording:
        def claim_lease(self, attempt_id: str, nonce: str) -> Any:
            order.append("claim")
            return store.claim_lease(attempt_id, nonce)

        def publish_result(self, attempt_id: str, manifest: ArtifactRef) -> None:
            order.append("publish")
            store.publish_result(attempt_id, manifest)

    winner = ordered.run(store, "nonce-a", lease=Recording())

    assert isinstance(winner, ArtifactRef)
    assert order == ["claim", "publish"]
    assert ordered.calls()[0] == ("put", LEASE_KEY)
    assert ordered.puts()[-1] == RESULT_KEY
    assert winner.digest in ordered.puts()[-2]  # the manifest is the last output before it


def test_no_lease_keeps_f1_behavior() -> None:
    scenario = build()
    manifest = execute(scenario)  # the F1 call shape: no lease, no nonce
    assert isinstance(manifest, ArtifactRef) and manifest.artifact_schema == "cf.result.v1"

    case = staged()
    result = run_worker(
        case.scenario.plan_bytes,
        case.scenario.attempt_bytes,
        case.grants,
        case.worker(),
        StepClock(),
    )
    assert isinstance(result, ArtifactRef)
    assert len(case.output_puts()) == OUTPUTS
    assert LEASE_KEY not in case.client.objects and RESULT_KEY not in case.client.objects

    # a lease without a nonce is a malformed call, never an anonymous claim
    fresh = staged()
    with pytest.raises(ContractError) as malformed:
        run_worker(
            fresh.scenario.plan_bytes,
            fresh.scenario.attempt_bytes,
            fresh.grants,
            fresh.worker(),
            StepClock(),
            lease=fresh.worker(),
        )
    assert malformed.value.code == "invalid_schema"
    assert fresh.calls() == []


def test_grant_storage_gate_refuses_outside_prefix_and_after_expiry() -> None:
    case = staged()
    ref = ref_for(b"synthetic output")
    other_project = ref_for(b"synthetic output", "00000000-0000-0000-0000-0000000000f1")
    assert case.grants.output_scope == f"{BUCKET}/{ATTEMPT_PREFIX}".encode()

    gate = grant_storage_gate(case.grants, StepClock())
    assert gate(ref, WORKER_CONTEXT) is True
    assert (
        gate(other_project, WORKER_CONTEXT) is False
    )  # its write key would leave the attempt prefix

    # the context must be this grant's own project and attempt, not just any caller's
    foreign_project = AccessContext(OTHER_PROJECT, ATTEMPT, WORKER_CONTEXT.scopes)
    foreign_attempt = AccessContext(PROJECT, OTHER_ATTEMPT, WORKER_CONTEXT.scopes)
    assert gate(ref, foreign_project) is False
    assert gate(ref, foreign_attempt) is False
    assert gate(ref, CONTEXT) is False  # a control-side actor is not the worker

    # the grant is only good before it expires, and not at the instant it does
    assert grant_storage_gate(case.grants, StepClock(base=case.grants.expires_at))(
        ref, WORKER_CONTEXT
    ) is (False)
    assert (
        grant_storage_gate(case.grants, StepClock(expire_at_call=1))(ref, WORKER_CONTEXT) is False
    )
    assert grant_storage_gate(case.grants, StepClock(base=NOW))(ref, WORKER_CONTEXT) is True

    # a scope that is not this grant's own attempt prefix grants nothing
    for bad in (
        b"synthetic-bucket/staging/attempts/",
        f"{BUCKET}/staging/f1/{PROJECT}/attempts/{OTHER_ATTEMPT}/".encode(),
        f"{BUCKET}/staging/f1/{PROJECT}/attempts/{ATTEMPT}".encode(),
        f"{BUCKET}/staging/f1/{OTHER_ATTEMPT}/attempts/{ATTEMPT}/".encode(),
        f"{BUCKET}/".encode(),
        b"",
    ):
        narrowed = replace(case.grants, output_scope=bad)
        assert grant_storage_gate(narrowed, StepClock())(ref, WORKER_CONTEXT) is False, bad

    # a clock that cannot answer is a refusal, never consent
    class Broken:
        def now(self) -> str:
            raise RuntimeError("synthetic clock outage")

    assert grant_storage_gate(case.grants, Broken())(ref, WORKER_CONTEXT) is False
    assert GRANT_EXPIRY > NOW


def test_worker_refuses_store_that_would_write_outside_the_grant_scope() -> None:
    """The gate only sees refs; the store's own write prefix must be the granted one."""
    plan = staged().scenario.plan

    def foreign_store(case: Staged, **overrides: Any) -> S3StagingStore:
        attempt = overrides.pop("attempt", ATTEMPT)
        return S3StagingStore(
            config(max_object_bytes=65536, transfer_chunk_bytes=64, **overrides),
            case.client,
            authorize=None,
            storage_reserved=grant_storage_gate(case.grants, StepClock()),
            clock=lambda: NOW,
            attempt_id=attempt,
        ).scoped_to(plan, attempt)

    for overrides in (
        {"prefix": "staging/elsewhere"},  # another configured prefix
        {"attempt": OTHER_ATTEMPT},  # a store bound to another attempt
        {"bucket": "synthetic-other-bucket"},  # another bucket
    ):
        case = staged()
        with pytest.raises(ContractError) as refused:
            case.run(foreign_store(case, **overrides), "nonce-a")
        assert refused.value.code == "forbidden", overrides
        assert case.calls() == [], overrides  # no lease, no read, no write

    # the matching store still runs, and its scope is exactly the granted one
    case = staged()
    store = case.worker()
    assert store.write_scope == case.grants.output_scope
    assert isinstance(case.run(store, "nonce-a"), ArtifactRef)


def test_worker_mode_requires_attempt_scope() -> None:
    client = FakeS3()

    def unauthenticated(**overrides: Any) -> S3StagingStore:
        return S3StagingStore(
            config(),
            client,
            authorize=None,
            storage_reserved=lambda _ref, _context: True,
            clock=lambda: NOW,
            **overrides,
        )

    with pytest.raises(ContractError) as unscoped:
        unauthenticated()
    assert unscoped.value.code == "invalid_schema"
    with pytest.raises(ContractError):
        unauthenticated(attempt_id=None)
    assert unauthenticated(attempt_id=ATTEMPT).attempt_id == ATTEMPT

    # an authorizer that is neither a callable nor absent is still refused
    with pytest.raises(ContractError):
        S3StagingStore(
            config(),
            client,
            authorize="allow",  # type: ignore[arg-type]
            storage_reserved=lambda _ref, _context: True,
            clock=lambda: NOW,
            attempt_id=ATTEMPT,
        )

    # worker mode still refuses a ref of another project before any request
    worker = unauthenticated(attempt_id=ATTEMPT)
    stranger = ref_for(b"x", "00000000-0000-0000-0000-0000000000f1")
    with pytest.raises(ContractError) as foreign:
        worker.put_verified(io.BytesIO(b"x"), stranger, CONTEXT)
    assert foreign.value.code == "forbidden"
    assert client.calls == []


def test_attempt_reader_sees_lease_and_pointer() -> None:
    case = staged()
    reader: AttemptStaging = case.control.attempt_reader(PROJECT, ATTEMPT)
    assert reader.lease_present() is False
    assert reader.result_pointer() is None

    winner = case.run(case.worker(), "nonce-a")

    assert isinstance(winner, ArtifactRef)
    assert reader.lease_present() is True
    assert reader.result_pointer() == winner
    # a reader never claims or publishes
    view = case.control.attempt_reader(PROJECT, ATTEMPT)
    with pytest.raises(ContractError) as read_only:
        view.claim_lease(ATTEMPT, "nonce-b")
    assert read_only.value.code == "forbidden"
    with pytest.raises(ContractError) as publishing:
        view.publish_result(ATTEMPT, winner)
    assert publishing.value.code == "forbidden"
    # another attempt id is not this store's to claim, and a nonce is a label, never a path
    with pytest.raises(ContractError) as foreign:
        case.worker().claim_lease(OTHER_ATTEMPT, "nonce-b")
    assert foreign.value.code == "forbidden"
    with pytest.raises(ContractError):
        case.worker().claim_lease(ATTEMPT, "../x")
