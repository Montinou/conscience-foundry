"""Synthetic local capacity and accounting boundaries."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import pytest

from conscience_foundry.contracts.common import ContractError, Ref
from conscience_foundry.execution.local_allocation import LocalAllocationPolicy, LocalAllocator

PROJECT = "00000000-0000-0000-0000-000000000001"
RUN_A = "00000000-0000-0000-0000-000000000002"
RUN_B = "00000000-0000-0000-0000-000000000003"
START = "2026-01-01T00:00:00.000Z"
NOW = "2026-01-02T00:00:00.000Z"
END = "2026-01-03T00:00:00.000Z"


def policy_ref() -> Ref:
    return Ref(
        schema_version="cf.artifact-ref.v1",
        project_id=PROJECT,
        digest="a" * 64,
        size_bytes=1,
        media_type="application/json",
        artifact_schema="cf.resource-policy.v1",
        locations=(),
    )


def policy(**changes: object) -> LocalAllocationPolicy:
    fields = {
        "attempt_price_usd": "1",
        "storage_price_usd": "1",
        "run_storage_capacity_bytes": 6,
        "operator_storage_capacity_bytes": 10,
        "resource_policy_ref": policy_ref(),
        "funded_from": START,
        "funded_until": END,
        "semantics": "cooperative",
    }
    return LocalAllocationPolicy(**(fields | changes))


@contextmanager
def authorized_closure(project_id, run_id):
    assert (project_id, run_id) == (PROJECT, RUN_A)
    yield lambda refs: refs == ()


def initialize(root: Path) -> None:
    operator_root = root / "operator"
    operator_root.mkdir(exist_ok=True)
    LocalAllocator.initialize(
        root,
        policy(),
        object(),
        lambda: NOW,
        operator_store_id="operator",
        operator_store_root=operator_root,
    )


def allocator(root: Path, clock=lambda: NOW, *, guard=authorized_closure) -> LocalAllocator:
    return LocalAllocator(
        root,
        policy(),
        object(),
        clock,
        operator_store_id="operator",
        operator_store_root=root / "operator",
        closure_guard=guard,
    )


def test_zero_funding_or_invalid_horizon_refused() -> None:
    for change in (
        {"attempt_price_usd": "0"},
        {"storage_price_usd": "0"},
        {"funded_until": START},
        {"semantics": "hard"},
    ):
        with pytest.raises((ContractError, ValueError)):
            policy(**change)


def test_capacity_survives_close_and_allocator_reconstruction(tmp_path: Path) -> None:
    initialize(tmp_path)
    first = allocator(tmp_path)
    first.reserve_storage_capacity(PROJECT, RUN_A, 6)
    first.reserve_storage_capacity(PROJECT, RUN_A, 6)
    first.close_storage(RUN_A, ())
    second = allocator(tmp_path)
    with pytest.raises(ContractError):
        second.reserve_storage_capacity(PROJECT, RUN_B, 6)


def test_operator_aggregate_capacity_serializes_concurrent_grants(tmp_path: Path) -> None:
    initialize(tmp_path)
    a, b = allocator(tmp_path), allocator(tmp_path)

    def reserve(item: tuple[LocalAllocator, str]) -> str:
        try:
            item[0].reserve_storage_capacity(PROJECT, item[1], 6)
            return "won"
        except ContractError:
            return "refused"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(reserve, [(a, RUN_A), (b, RUN_B)])) == ["refused", "won"]


def test_expired_horizon_never_grants_capacity(tmp_path: Path) -> None:
    initialize(tmp_path)
    value = allocator(tmp_path, lambda: END)
    with pytest.raises(ContractError):
        value.reserve_storage_capacity(PROJECT, RUN_A, 6)


def test_reopen_missing_or_changed_state_never_resets_quota(tmp_path: Path) -> None:
    with pytest.raises(ContractError):
        allocator(tmp_path)
    initialize(tmp_path)
    value = allocator(tmp_path)
    value.reserve_storage_capacity(PROJECT, RUN_A, 6)
    with pytest.raises(ContractError):
        initialize(tmp_path)
    with pytest.raises(ContractError):
        LocalAllocator(
            tmp_path,
            policy(operator_storage_capacity_bytes=100),
            object(),
            lambda: NOW,
            operator_store_id="operator",
            operator_store_root=tmp_path / "operator",
        )


def test_closure_requires_independent_verifier_and_refusal_keeps_open(tmp_path: Path) -> None:
    initialize(tmp_path)
    value = allocator(tmp_path, guard=None)
    value.reserve_storage_capacity(PROJECT, RUN_A, 6)
    with pytest.raises(ContractError):
        value.close_storage(RUN_A, ())
    reopened = allocator(tmp_path)
    reopened.close_storage(RUN_A, ())
    reopened.close_storage(RUN_A, ())


def test_corrupt_capacity_record_never_grants_more_storage(tmp_path: Path) -> None:
    import json

    initialize(tmp_path)
    value = allocator(tmp_path)
    value.reserve_storage_capacity(PROJECT, RUN_A, 6)
    state_path = tmp_path / "allocator.json"
    state = json.loads(state_path.read_bytes())
    state["runs"][RUN_A]["capacity"] = -100
    state_path.write_text(json.dumps(state))
    with pytest.raises(ContractError):
        allocator(tmp_path).reserve_storage_capacity(PROJECT, RUN_B, 6)


def test_unactivated_attempt_cannot_obtain_write_permit(tmp_path: Path) -> None:
    initialize(tmp_path)
    value = allocator(tmp_path)
    value.reserve_storage_capacity(PROJECT, RUN_A, 6)
    with pytest.raises(ContractError):
        value.activate_attempt(PROJECT, RUN_A, RUN_B)
    with pytest.raises(ContractError):
        with value.write_permit(PROJECT, RUN_A, RUN_B, policy_ref()):
            pass


def test_activation_requires_trusted_fact_and_root_scope(tmp_path: Path) -> None:
    import hashlib

    from conscience_foundry.execution.local_allocation import LocalActivationFacts
    from conscience_foundry.storage.local_attempt import local_output_scope

    initialize(tmp_path)
    attempt_root = tmp_path / "attempt-root"
    attempt_root.mkdir()
    source = Ref(
        schema_version="cf.artifact-ref.v1",
        project_id=PROJECT,
        digest=hashlib.sha256(b"input").hexdigest(),
        size_bytes=5,
        media_type="text/plain",
        artifact_schema="cf.raw-original.v1",
        locations=(),
    )
    scope = local_output_scope(
        attempt_root,
        destination_id="local",
        project_id=PROJECT,
        run_id=RUN_A,
        attempt_id=RUN_B,
        plan_digest=source.digest,
    )
    facts = LocalActivationFacts(
        project_id=PROJECT,
        run_id=RUN_A,
        attempt_id=RUN_B,
        reservation_id=RUN_A,
        storage_reservation_id=RUN_B,
        authorization_ref=source,
        plan_ref=source,
        config_ref=source,
        source_id=PROJECT,
        actor_id=RUN_A,
        input_refs=(source,),
        expires_at=END,
        attempt_root=attempt_root,
        output_scope=scope,
    )

    @contextmanager
    def permit(project_id, run_id, attempt_id):
        assert (project_id, run_id, attempt_id) == (PROJECT, RUN_A, RUN_B)
        yield facts

    value = LocalAllocator(
        tmp_path,
        policy(),
        object(),
        lambda: NOW,
        operator_store_id="operator",
        operator_store_root=tmp_path / "operator",
        activation_guard=permit,
        policy_reader=lambda *_: None,
    )
    value.activate_attempt(PROJECT, RUN_A, RUN_B)
    value.activate_attempt(PROJECT, RUN_A, RUN_B)
    with value.write_permit(PROJECT, RUN_A, RUN_B, source):
        value.revalidate_write(PROJECT, RUN_A, RUN_B, source)
    with pytest.raises(ContractError):
        value.activate_attempt(PROJECT, RUN_A, RUN_A)
    value.policy_reader = lambda *_: False
    with pytest.raises(ContractError):
        with value.write_permit(PROJECT, RUN_A, RUN_B, source):
            value.revalidate_write(PROJECT, RUN_A, RUN_B, source)
    value.policy_reader = lambda *_: None
    forged = source.model_copy(update={"size_bytes": -1})
    with pytest.raises(ContractError):
        with value.write_permit(PROJECT, RUN_A, RUN_B, forged):
            value.revalidate_write(PROJECT, RUN_A, RUN_B, forged)


def test_two_attempts_stage_separate_physical_copies_within_run_quota(tmp_path: Path) -> None:
    import hashlib
    import io

    from conscience_foundry.execution.local_allocation import LocalActivationFacts
    from conscience_foundry.execution.local_contracts import LocalWorkerGrant
    from conscience_foundry.policy.access import AccessContext
    from conscience_foundry.storage.local_attempt import LocalAttemptStore, local_output_scope

    initialize(tmp_path)
    attempt_root = tmp_path / "attempt-root"
    attempt_root.mkdir()
    payload = b"input"
    source = Ref(
        schema_version="cf.artifact-ref.v1",
        project_id=PROJECT,
        digest=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
        media_type="text/plain",
        artifact_schema="cf.raw-original.v1",
        locations=(),
    )
    attempts = (RUN_B, "00000000-0000-0000-0000-000000000004")
    storage_id = [RUN_B]

    def facts_for(attempt_id):
        scope = local_output_scope(
            attempt_root,
            destination_id="local",
            project_id=PROJECT,
            run_id=RUN_A,
            attempt_id=attempt_id,
            plan_digest=source.digest,
        )
        return LocalActivationFacts(
            PROJECT,
            RUN_A,
            attempt_id,
            RUN_A,
            storage_id[0],
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
    def activation(project_id, run_id, attempt_id):
        yield facts_for(attempt_id)

    reads_allowed = [True]

    class InputStore:
        def open_verified(self, ref, context):
            assert ref == source
            assert reads_allowed[0], "durable same-attempt replay must not create a duplicate copy"
            return io.BytesIO(payload)

    class Clock:
        def now(self):
            return NOW

    value = LocalAllocator(
        tmp_path,
        policy(),
        object(),
        lambda: NOW,
        operator_store_id="operator",
        operator_store_root=tmp_path / "operator",
        activation_guard=activation,
        policy_reader=lambda *_: None,
    )
    stores = []
    for attempt_id in attempts:
        if attempt_id == attempts[1]:
            storage_id[0] = RUN_A
            with pytest.raises(ContractError):
                value.activate_attempt(PROJECT, RUN_A, attempt_id)
            storage_id[0] = RUN_B
        value.activate_attempt(PROJECT, RUN_A, attempt_id)
        facts = facts_for(attempt_id)
        grant = LocalWorkerGrant(
            PROJECT, RUN_A, source.digest, attempt_id, "local", END, facts.output_scope, "nonce"
        )
        context = AccessContext(PROJECT, attempt_id, frozenset({"read", "extract"}))
        stores.append(
            (
                LocalAttemptStore(
                    attempt_root,
                    PROJECT,
                    attempt_id,
                    InputStore(),
                    (source,),
                    grant,
                    Clock(),
                    value,
                ),
                context,
            )
        )
    first, context = stores[0]
    assert first.stage_inputs(context) == (source,)
    reads_allowed[0] = False
    assert first.stage_inputs(context) == (source,)
    second, context = stores[1]
    with pytest.raises(ContractError, match="limit_exceeded"):
        second.stage_inputs(context)


def test_operator_copy_charged_but_verified_existing_copy_is_not(tmp_path: Path) -> None:
    import hashlib
    import io

    from conscience_foundry.contracts.common import ContractLimits
    from conscience_foundry.execution.local_allocation import LocalActivationFacts
    from conscience_foundry.policy.access import AccessContext
    from conscience_foundry.storage.local import LocalObjectStore
    from conscience_foundry.storage.local_attempt import local_output_scope
    from conscience_foundry.storage.locator import LocationRegistry

    initialize(tmp_path)
    attempt_root = tmp_path / "attempt-root"
    attempt_root.mkdir()
    payload = b"input"
    source = Ref(
        schema_version="cf.artifact-ref.v1",
        project_id=PROJECT,
        digest=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
        media_type="text/plain",
        artifact_schema="cf.raw-original.v1",
        locations=(),
    )
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
    def activation(*_):
        yield facts

    bounds = ContractLimits.model_validate(
        {
            "schemaVersion": "cf.contract-limits.v1",
            "version": "test",
            "maxJsonBytes": 4096,
            "maxStringScalars": 256,
            "maxArrayItems": 32,
            "maxDepth": 16,
            "maxManifestItems": 16,
            "maxSourceBytes": 1000,
            "maxOutputBytes": 1000,
            "maxErrorMessageScalars": 80,
        }
    )
    registry = LocationRegistry({"operator": tmp_path / "operator"}, bounds, lambda *_: None)
    store = LocalObjectStore("operator", registry)
    value = LocalAllocator(
        tmp_path,
        policy(),
        store,
        lambda: NOW,
        operator_store_id="operator",
        operator_store_root=tmp_path / "operator",
        activation_guard=activation,
        policy_reader=lambda *_: None,
    )
    try:
        value.activate_attempt(PROJECT, RUN_A, RUN_B)
        with value.write_permit(PROJECT, RUN_A, RUN_B, source):
            value.revalidate_write(PROJECT, RUN_A, RUN_B, source)
        access = AccessContext(PROJECT, RUN_A, frozenset({"read", "extract"}))
        writer = value.import_writer(PROJECT, RUN_A, RUN_B)
        with pytest.raises(ContractError, match="limit_exceeded"):
            writer.put_verified(io.BytesIO(payload), source, access)
        store.put_verified(io.BytesIO(payload), source, access)  # independent preexisting object
        assert writer.put_verified(io.BytesIO(payload), source, access) == source
        with pytest.raises(ContractError, match="hash_mismatch"):
            writer.put_verified(io.BytesIO(b"wrong"), source, access)

        class BrokenStream(io.BytesIO):
            def read(self, size=-1):
                raise RuntimeError("synthetic-private-path")

        with pytest.raises(ContractError) as error:
            writer.put_verified(BrokenStream(), source, access)
        assert error.value.code == "unavailable"
        assert "synthetic-private-path" not in str(error.value)

        class RefusingStream(io.BytesIO):
            def read(self, size=-1):
                raise ContractError("authorization_expired")

        with pytest.raises(ContractError) as error:
            writer.put_verified(RefusingStream(), source, access)
        assert error.value.code == "authorization_expired"
    finally:
        registry.close()


def test_corrupt_nested_copy_record_cannot_create_extra_capacity(tmp_path: Path) -> None:
    import json

    initialize(tmp_path)
    value = allocator(tmp_path)
    value.reserve_storage_capacity(PROJECT, RUN_A, 6)
    state_path = tmp_path / "allocator.json"
    state = json.loads(state_path.read_bytes())
    state["runs"][RUN_A]["refs"]["f" * 64] = {
        "identity": {"kind": "attempt"},
        "size": -5,
        "status": "durable",
    }
    state_path.write_text(json.dumps(state))
    with pytest.raises(ContractError):
        allocator(tmp_path)


def test_retention_release_requires_authorization_and_independent_removal(tmp_path: Path) -> None:
    initialize(tmp_path)
    marker = tmp_path / "operator" / "owned-copy"
    marker.write_text("synthetic")
    value = LocalAllocator(
        tmp_path,
        policy(),
        object(),
        lambda: NOW,
        operator_store_id="operator",
        operator_store_root=tmp_path / "operator",
        closure_guard=authorized_closure,
        retention_authorizer=lambda project, run, actor, proof: True,
        removal_verifier=lambda project, run: not marker.exists(),
    )
    value.reserve_storage_capacity(PROJECT, RUN_A, 6)
    value.close_storage(RUN_A, ())
    with pytest.raises(ContractError):
        allocator(tmp_path).release_retained_capacity(RUN_A, RUN_B, policy_ref())
    with pytest.raises(ContractError):
        value.release_retained_capacity(RUN_A, RUN_B, policy_ref())
    with pytest.raises(ContractError):
        value.reserve_storage_capacity(PROJECT, RUN_B, 6)
    marker.unlink()
    value.release_retained_capacity(RUN_A, RUN_B, policy_ref())
    value.reserve_storage_capacity(PROJECT, RUN_B, 6)
    with pytest.raises(ContractError):
        value.reserve_storage_capacity(PROJECT, RUN_A, 6)


def _capacity_process(root: Path, run_id: str, start, output) -> None:
    start.wait(5)
    try:
        allocator(root).reserve_storage_capacity(PROJECT, run_id, 6)
        output.put("won")
    except ContractError:
        output.put("refused")


def test_operator_capacity_is_atomic_across_processes(tmp_path: Path) -> None:
    import multiprocessing

    initialize(tmp_path)
    ctx = multiprocessing.get_context("fork")
    start, output = ctx.Event(), ctx.Queue()
    processes = [
        ctx.Process(target=_capacity_process, args=(tmp_path, run_id, start, output))
        for run_id in (RUN_A, RUN_B)
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(10)
        assert process.exitcode == 0
    assert sorted(output.get(timeout=2) for _ in processes) == ["refused", "won"]


def test_real_lease_and_result_pointer_payload_bytes_are_accounted(tmp_path: Path) -> None:
    import io
    import json
    import sys

    adapter_tests = str(Path(__file__).resolve().parents[1] / "adapters")
    if adapter_tests not in sys.path:
        sys.path.insert(0, adapter_tests)
    from test_modal import ATTEMPT, build, execute, read_manifest

    from conscience_foundry.execution.local_allocation import LocalActivationFacts
    from conscience_foundry.execution.local_contracts import LocalWorkerGrant
    from conscience_foundry.policy.access import AccessContext
    from conscience_foundry.storage.local_attempt import LocalAttemptStore, local_output_scope

    scenario = build()
    manifest_ref = execute(scenario)
    manifest = read_manifest(scenario, manifest_ref)
    attempt_root = tmp_path / "attempt-root"
    operator_root = tmp_path / "operator"
    attempt_root.mkdir()
    operator_root.mkdir()
    quota = policy(run_storage_capacity_bytes=100000, operator_storage_capacity_bytes=100000)
    LocalAllocator.initialize(
        tmp_path,
        quota,
        object(),
        lambda: NOW,
        operator_store_id="operator",
        operator_store_root=operator_root,
    )
    scope = local_output_scope(
        attempt_root,
        destination_id="local",
        project_id=PROJECT,
        run_id=RUN_A,
        attempt_id=ATTEMPT,
        plan_digest=manifest_ref.digest,
    )
    facts = LocalActivationFacts(
        PROJECT,
        RUN_A,
        ATTEMPT,
        RUN_A,
        RUN_B,
        manifest_ref,
        manifest_ref,
        manifest_ref,
        PROJECT,
        RUN_A,
        (),
        END,
        attempt_root,
        scope,
    )

    @contextmanager
    def activation(*_):
        yield facts

    class Clock:
        def now(self):
            return NOW

    value = LocalAllocator(
        tmp_path,
        quota,
        object(),
        lambda: NOW,
        operator_store_id="operator",
        operator_store_root=operator_root,
        activation_guard=activation,
        policy_reader=lambda *_: None,
    )
    value.activate_attempt(PROJECT, RUN_A, ATTEMPT)
    grant = LocalWorkerGrant(
        PROJECT, RUN_A, manifest_ref.digest, ATTEMPT, "local", END, scope, "nonce"
    )
    access = AccessContext(PROJECT, ATTEMPT, frozenset({"read", "extract"}))
    store = LocalAttemptStore(
        attempt_root, PROJECT, ATTEMPT, scenario.store, (), grant, Clock(), value
    )
    assert store.claim_lease(ATTEMPT, "nonce") == "won"
    for ref in (*manifest.outputs, manifest_ref):
        store.put_verified(io.BytesIO(scenario.store.objects[ref.digest]), ref, access)
    with pytest.raises(ContractError):
        store.put_verified(io.BytesIO(b"wrong stream"), manifest_ref, access)
    store.publish_result(ATTEMPT, manifest_ref)
    assert store.result_pointer() == manifest_ref
    physical = sum(
        p.stat().st_size for p in (attempt_root / PROJECT / ATTEMPT).iterdir() if p.is_file()
    )
    state = json.loads((tmp_path / "allocator.json").read_bytes())
    recorded = sum(x["size"] for x in state["runs"][RUN_A]["refs"].values())
    assert physical == recorded


@pytest.mark.parametrize("failure", ["policy", "expiry"])
def test_policy_revoked_during_operator_copy_refuses_publication(
    tmp_path: Path, monkeypatch, failure: str
) -> None:
    import hashlib
    import io

    from conscience_foundry.contracts.common import ContractLimits
    from conscience_foundry.execution.local_allocation import LocalActivationFacts
    from conscience_foundry.policy.access import AccessContext
    from conscience_foundry.storage.local import LocalObjectStore
    from conscience_foundry.storage.local_attempt import local_output_scope
    from conscience_foundry.storage.locator import LocationRegistry

    initialize(tmp_path)
    attempt_root = tmp_path / "attempt-root"
    attempt_root.mkdir()
    data = b"input"
    source = Ref(
        schema_version="cf.artifact-ref.v1",
        project_id=PROJECT,
        digest=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        media_type="text/plain",
        artifact_schema="cf.raw-original.v1",
        locations=(),
    )
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
    def activation(*_):
        yield facts

    permitted = [True]
    current_time = [NOW]

    def fresh_policy(*_):
        if not permitted[0]:
            raise ContractError("forbidden")

    class RevokingStream(io.BytesIO):
        def read(self, size=-1):
            result = super().read(size)
            if result:
                if failure == "policy":
                    permitted[0] = False
                else:
                    current_time[0] = END
            return result

    bounds = ContractLimits.model_validate(
        {
            "schemaVersion": "cf.contract-limits.v1",
            "version": "test",
            "maxJsonBytes": 4096,
            "maxStringScalars": 256,
            "maxArrayItems": 32,
            "maxDepth": 16,
            "maxManifestItems": 16,
            "maxSourceBytes": 1000,
            "maxOutputBytes": 1000,
            "maxErrorMessageScalars": 80,
        }
    )
    registry = LocationRegistry({"operator": tmp_path / "operator"}, bounds, lambda *_: None)
    store = LocalObjectStore("operator", registry)
    value = LocalAllocator(
        tmp_path,
        policy(),
        store,
        lambda: NOW,
        operator_store_id="operator",
        operator_store_root=tmp_path / "operator",
        activation_guard=activation,
        policy_reader=fresh_policy,
    )
    value.clock = lambda: current_time[0]
    access = AccessContext(PROJECT, RUN_A, frozenset({"read", "extract"}))
    try:
        value.activate_attempt(PROJECT, RUN_A, RUN_B)
        permitted[0] = False
        with monkeypatch.context() as scoped:
            scoped.setattr(
                registry, "_snapshot", lambda *_: pytest.fail("read before policy check")
            )
            with pytest.raises(ContractError, match="forbidden"):
                value.import_writer(PROJECT, RUN_A, RUN_B).put_verified(
                    io.BytesIO(data), source, access
                )
        permitted[0] = True
        reason = "forbidden" if failure == "policy" else "authorization_expired"
        with pytest.raises(ContractError, match=reason):
            value.import_writer(PROJECT, RUN_A, RUN_B).put_verified(
                RevokingStream(data), source, access
            )
        with pytest.raises(ContractError, match="artifact_missing"):
            store.open_verified(source, access)
        permitted[0] = True
        current_time[0] = NOW
        next_data = b"xx"
        next_ref = source.model_copy(
            update={"digest": hashlib.sha256(next_data).hexdigest(), "size_bytes": 2}
        )
        with pytest.raises(ContractError, match="limit_exceeded"):
            value.import_writer(PROJECT, RUN_A, RUN_B).put_verified(
                io.BytesIO(next_data), next_ref, access
            )
    finally:
        registry.close()


def test_closure_guard_holds_db_then_allocator_lock_and_waits_for_writer(tmp_path: Path) -> None:
    import fcntl
    import threading

    from conscience_foundry.execution.local_allocation import LocalActivationFacts
    from conscience_foundry.storage.local_attempt import local_output_scope

    initialize(tmp_path)
    attempt_root = tmp_path / "attempt-root"
    attempt_root.mkdir()
    source = policy_ref()
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
    db_lock = threading.RLock()
    writer_started, release_writer = threading.Event(), threading.Event()
    guard_entered, verifier_called = threading.Event(), threading.Event()

    @contextmanager
    def activation(*_):
        with db_lock:
            yield facts

    @contextmanager
    def closure(project, run):
        with db_lock:
            guard_entered.set()

            def verify(refs):
                assert db_lock._is_owned()  # synthetic equivalent of the held database guard
                with (tmp_path / "allocator.lock").open("rb+") as probe:
                    with pytest.raises(BlockingIOError):
                        fcntl.flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                verifier_called.set()
                return refs == (source,)

            yield verify

    value = LocalAllocator(
        tmp_path,
        policy(),
        object(),
        lambda: NOW,
        operator_store_id="operator",
        operator_store_root=tmp_path / "operator",
        activation_guard=activation,
        closure_guard=closure,
        policy_reader=lambda *_: None,
    )
    value.activate_attempt(PROJECT, RUN_A, RUN_B)

    def write():
        with value.write_permit(PROJECT, RUN_A, RUN_B, source):
            writer_started.set()
            assert release_writer.wait(5)
            value.revalidate_write(PROJECT, RUN_A, RUN_B, source)

    with ThreadPoolExecutor(max_workers=2) as pool:
        writing = pool.submit(write)
        assert writer_started.wait(5)
        closing = pool.submit(value.close_storage, RUN_A, (source,))
        assert guard_entered.wait(5)
        assert not verifier_called.is_set()
        release_writer.set()
        writing.result(timeout=5)
        closing.result(timeout=5)
    assert verifier_called.is_set()
    with pytest.raises(ContractError):
        value.activate_attempt(PROJECT, RUN_A, RUN_B)
    with pytest.raises(ContractError):
        with value.write_permit(PROJECT, RUN_A, RUN_B, source):
            pass


def test_closure_refuses_missing_retained_copy_even_if_guard_is_buggy(tmp_path: Path) -> None:
    from conscience_foundry.execution.local_allocation import LocalActivationFacts
    from conscience_foundry.storage.local_attempt import local_output_scope

    initialize(tmp_path)
    attempt_root = tmp_path / "attempt-root"
    attempt_root.mkdir()
    source = policy_ref()
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
    def activation(*_):
        yield facts

    @contextmanager
    def buggy_guard(*_):
        yield lambda _: True

    value = LocalAllocator(
        tmp_path,
        policy(),
        object(),
        lambda: NOW,
        operator_store_id="operator",
        operator_store_root=tmp_path / "operator",
        activation_guard=activation,
        closure_guard=buggy_guard,
        policy_reader=lambda *_: None,
    )
    value.activate_attempt(PROJECT, RUN_A, RUN_B)
    with value.write_permit(PROJECT, RUN_A, RUN_B, source):
        value.revalidate_write(PROJECT, RUN_A, RUN_B, source)
    with pytest.raises(ContractError):
        value.close_storage(RUN_A, ())
    second = source.model_copy(update={"digest": "b" * 64})
    with value.write_permit(PROJECT, RUN_A, RUN_B, second):
        value.revalidate_write(PROJECT, RUN_A, RUN_B, second)
    value.close_storage(RUN_A, (source, second))
    value.close_storage(RUN_A, (second, source))
    with pytest.raises(ContractError):
        value.close_storage(RUN_A, (source, source))


def test_reopen_rejects_corrupt_retention_release_proof(tmp_path: Path) -> None:
    import json

    initialize(tmp_path)
    value = LocalAllocator(
        tmp_path,
        policy(),
        object(),
        lambda: NOW,
        operator_store_id="operator",
        operator_store_root=tmp_path / "operator",
        closure_guard=authorized_closure,
        retention_authorizer=lambda *_: True,
        removal_verifier=lambda *_: True,
    )
    value.reserve_storage_capacity(PROJECT, RUN_A, 6)
    value.close_storage(RUN_A, ())
    value.release_retained_capacity(RUN_A, RUN_B, policy_ref())
    state_path = tmp_path / "allocator.json"
    state = json.loads(state_path.read_bytes())
    state["runs"][RUN_A]["release_proof"] = {"not_a_ref": True}
    state_path.write_text(json.dumps(state))
    with pytest.raises(ContractError):
        allocator(tmp_path)


def test_reopen_rejects_corrupt_attempt_root_binding(tmp_path: Path) -> None:
    import json

    from conscience_foundry.execution.local_allocation import LocalActivationFacts
    from conscience_foundry.storage.local_attempt import local_output_scope

    initialize(tmp_path)
    attempt_root = tmp_path / "attempt-root"
    attempt_root.mkdir()
    source = policy_ref()
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
    def activation(*_):
        yield facts

    value = LocalAllocator(
        tmp_path,
        policy(),
        object(),
        lambda: NOW,
        operator_store_id="operator",
        operator_store_root=tmp_path / "operator",
        activation_guard=activation,
        policy_reader=lambda *_: None,
    )
    value.activate_attempt(PROJECT, RUN_A, RUN_B)
    path = tmp_path / "allocator.json"
    state = json.loads(path.read_bytes())
    record = state["runs"][RUN_A]["attempts"][RUN_B]
    scope_data = json.loads(bytes.fromhex(record["output_scope"]))
    scope_data["inode"] = "0"
    record["output_scope"] = (
        json.dumps(scope_data, sort_keys=True, separators=(",", ":")).encode().hex()
    )
    path.write_text(json.dumps(state))
    with pytest.raises(ContractError):
        allocator(tmp_path)


def test_reopen_rejects_closed_refs_not_matching_retained_set(tmp_path: Path) -> None:
    import json

    initialize(tmp_path)
    value = allocator(tmp_path)
    value.reserve_storage_capacity(PROJECT, RUN_A, 6)
    value.close_storage(RUN_A, ())
    state_path = tmp_path / "allocator.json"
    state = json.loads(state_path.read_bytes())
    state["runs"][RUN_A]["closed_refs"] = [policy_ref().model_dump(mode="json", by_alias=True)]
    state_path.write_text(json.dumps(state))
    with pytest.raises(ContractError):
        allocator(tmp_path)
