"""Real filesystem boundaries for the local attempt staging store."""

import io
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace

import pytest
from test_modal import ATTEMPT, GRANT_EXPIRY, PROJECT, RUN, MemoryStore, StepClock, make_ref

from conscience_foundry.contracts.common import ContractError
from conscience_foundry.execution.local_contracts import LocalWorkerGrant
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.local_attempt import LocalAttemptStore, local_output_scope


class SyntheticAuthority:
    """Test-only permit; deliberately not a production allocator."""

    def __init__(self):
        self.local = threading.local()
        self.revoked = False
        self.revalidations = 0

    @contextmanager
    def write_permit(self, project_id, run_id, attempt_id, ref):
        assert not getattr(self.local, "active", False)
        self.local.active = True
        try:
            yield
        finally:
            self.local.active = False

    def revalidate_write(self, project_id, run_id, attempt_id, ref):
        assert self.local.active
        self.revalidations += 1
        if self.revoked:
            raise ContractError("forbidden")


@pytest.fixture
def setup(tmp_path):
    source = b"declared input"
    ref = make_ref(source, "cf.raw-original.v1", "text/plain")
    source_store = MemoryStore()
    source_store.objects[ref.digest] = source
    scope = local_output_scope(
        tmp_path,
        destination_id="local",
        project_id=PROJECT,
        run_id=RUN,
        attempt_id=ATTEMPT,
        plan_digest="a" * 64,
    )
    grant = LocalWorkerGrant(PROJECT, RUN, "a" * 64, ATTEMPT, "local", GRANT_EXPIRY, scope, "nonce")
    context = AccessContext(PROJECT, ATTEMPT, frozenset({"read", "extract"}))
    authority = SyntheticAuthority()
    store = LocalAttemptStore(
        tmp_path, PROJECT, ATTEMPT, source_store, (ref,), grant, StepClock(), authority
    )
    return store, source_store, ref, grant, context, authority


def test_exact_input_staged_and_output_idempotent(setup):
    store, _, ref, _, context, authority = setup
    assert store.stage_inputs(context) == (ref,)
    assert store.read_verified(ref, context, 100).data == b"declared input"
    output = make_ref(b"output", "cf.output.v1")
    assert store.put_verified(io.BytesIO(b"output"), output, context) == output
    assert store.put_verified(io.BytesIO(b"output"), output, context) == output
    assert store.read_verified(output, context, 100).data == b"output"
    assert authority.revalidations >= 2


def test_wrong_binding_and_undeclared_input_refuse(setup, tmp_path):
    store, source, ref, grant, context, authority = setup
    with pytest.raises(ContractError):
        LocalAttemptStore(tmp_path, "wrong", ATTEMPT, source, (ref,), grant, StepClock(), authority)
    with pytest.raises(ContractError):
        LocalAttemptStore(tmp_path, PROJECT, "wrong", source, (ref,), grant, StepClock(), authority)
    with pytest.raises(ContractError):
        store.claim_lease(ATTEMPT, "wrong nonce")
    with pytest.raises(ContractError):
        store.open_verified(make_ref(b"not declared", "cf.raw-original.v1"), context)
    with pytest.raises(ContractError):
        store.put_verified(
            io.BytesIO(b"x"),
            make_ref(b"x", "cf.output.v1"),
            AccessContext(PROJECT, RUN, frozenset({"read", "extract"})),
        )
    with pytest.raises(ContractError):
        LocalAttemptStore(
            tmp_path,
            PROJECT,
            ATTEMPT,
            source,
            (ref,),
            replace(grant, output_scope=b""),
            StepClock(),
            authority,
        )


def test_concurrent_lease_one_winner(setup):
    store, *_ = setup
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: store.claim_lease(ATTEMPT, "nonce"), range(2)))
    assert sorted(results) == ["lost", "won"]
    assert store.lease_present()


def test_revocation_and_expiry_refuse_before_publication(setup):
    store, _, _, _, context, authority = setup
    authority.revoked = True
    ref = make_ref(b"output", "cf.output.v1")
    with pytest.raises(ContractError):
        store.put_verified(io.BytesIO(b"output"), ref, context)
    with pytest.raises(ContractError):
        store.open_verified(ref, context)


def test_hash_drift_refuses_input_copy(setup):
    store, source, ref, _, context, _ = setup
    source.objects[ref.digest] = b"different bytes"
    with pytest.raises(ContractError):
        store.stage_inputs(context)


def test_publish_pointer_requires_durable_manifest(setup):
    store, _, _, _, _, _ = setup
    with pytest.raises(ContractError):
        store.publish_result(ATTEMPT, make_ref(b"missing", "cf.result.v1"))
    assert store.result_pointer() is None


def test_symlink_attempt_directory_refuses(tmp_path):
    source = MemoryStore()
    ref = make_ref(b"input", "cf.raw-original.v1")
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / PROJECT).symlink_to(outside, target_is_directory=True)
    scope = local_output_scope(
        tmp_path,
        destination_id="local",
        project_id=PROJECT,
        run_id=RUN,
        attempt_id=ATTEMPT,
        plan_digest="a" * 64,
    )
    grant = LocalWorkerGrant(PROJECT, RUN, "a" * 64, ATTEMPT, "local", GRANT_EXPIRY, scope, "nonce")
    with pytest.raises(ContractError):
        LocalAttemptStore(
            tmp_path, PROJECT, ATTEMPT, source, (ref,), grant, StepClock(), SyntheticAuthority()
        )


def test_failed_fsync_never_claims_success(setup, monkeypatch):
    store, _, _, _, context, _ = setup
    monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("fault")))
    with pytest.raises(ContractError):
        store.put_verified(io.BytesIO(b"output"), make_ref(b"output", "cf.output.v1"), context)


def test_fifo_and_symlink_output_never_read(setup, tmp_path):
    store, _, _, _, context, _ = setup
    ref = make_ref(b"payload", "cf.output.v1")
    entry = tmp_path / PROJECT / ATTEMPT / ("object-" + ref.digest)
    os.mkfifo(entry)
    with pytest.raises(ContractError):
        store.open_verified(ref, context)
    entry.unlink()
    entry.symlink_to(tmp_path / "absent")
    with pytest.raises(ContractError):
        store.open_verified(ref, context)


def test_wrong_root_scope_and_missing_authority_rejected(setup, tmp_path):
    _, source, ref, grant, _, authority = setup
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(ContractError):
        LocalAttemptStore(other, PROJECT, ATTEMPT, source, (ref,), grant, StepClock(), authority)
    with pytest.raises(ContractError):
        LocalAttemptStore(tmp_path, PROJECT, ATTEMPT, source, (ref,), grant, StepClock(), None)


def test_link_failure_is_unknown_and_not_published(setup, monkeypatch):
    store, _, _, _, context, _ = setup
    output = make_ref(b"output", "cf.output.v1")
    monkeypatch.setattr(os, "link", lambda *a, **k: (_ for _ in ()).throw(OSError("fault")))
    with pytest.raises(ContractError) as exc:
        store.put_verified(io.BytesIO(b"output"), output, context)
    assert exc.value.code == "dispatch_unknown"
    with pytest.raises(ContractError):
        store.open_verified(output, context)


def test_expiry_at_publication_blocks_output(setup):
    store, _, _, _, context, _ = setup
    store.clock = StepClock(expire_at_call=3)
    output = make_ref(b"output", "cf.output.v1")
    with pytest.raises(ContractError) as exc:
        store.put_verified(io.BytesIO(b"output"), output, context)
    assert exc.value.code == "authorization_expired"


def test_pointer_publication_requires_outputs_and_survives_link_failure(setup, monkeypatch):
    from test_modal import build, execute, read_manifest

    store, _, _, _, context, _ = setup
    scenario = build()
    manifest_ref = execute(scenario)
    manifest = read_manifest(scenario, manifest_ref)
    raw = scenario.store.objects[manifest_ref.digest]
    store.put_verified(io.BytesIO(raw), manifest_ref, context)
    with pytest.raises(ContractError):
        store.publish_result(ATTEMPT, manifest_ref)
    assert store.result_pointer() is None
    for ref in manifest.outputs:
        store.put_verified(io.BytesIO(scenario.store.objects[ref.digest]), ref, context)
    link = os.link

    def fail_pointer(source, destination, **kwargs):
        if destination == "result":
            raise OSError("fault")
        return link(source, destination, **kwargs)

    monkeypatch.setattr(os, "link", fail_pointer)
    with pytest.raises(ContractError):
        store.publish_result(ATTEMPT, manifest_ref)
    assert store.result_pointer() is None
    monkeypatch.setattr(os, "link", link)
    store.publish_result(ATTEMPT, manifest_ref)
    assert store.result_pointer() == manifest_ref
    store.publish_result(ATTEMPT, manifest_ref)


def test_post_link_fsync_failure_retains_published_object(setup, monkeypatch):
    store, _, _, _, context, _ = setup
    output = make_ref(b"output", "cf.output.v1")
    original = os.fsync
    calls = 0

    def fail_directory(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("post-link fault")
        original(fd)

    monkeypatch.setattr(os, "fsync", fail_directory)
    with pytest.raises(ContractError) as exc:
        store.put_verified(io.BytesIO(b"output"), output, context)
    assert exc.value.code == "dispatch_unknown"
    monkeypatch.setattr(os, "fsync", original)
    assert store.read_verified(output, context, 100).data == b"output"


def test_staging_reads_original_only_under_permit(setup):
    store, original, ref, _, context, authority = setup
    previous = original.open_verified

    def checked_open(item, access):
        assert authority.local.active
        return previous(item, access)

    original.open_verified = checked_open
    store.stage_inputs(context)
    original.open_verified = lambda *_: pytest.fail("worker re-read the source store")
    assert store.read_verified(ref, context, 100).data == b"declared input"


def test_verified_reads_do_not_create_unaccounted_disk_snapshot(setup, monkeypatch):
    import tempfile

    store, _, _, _, context, _ = setup
    output = make_ref(b"output", "cf.output.v1")
    store.put_verified(io.BytesIO(b"output"), output, context)
    monkeypatch.setattr(tempfile, "TemporaryFile", lambda **_: pytest.fail("unaccounted snapshot"))
    with store.open_verified(output, context) as source:
        assert source.read() == b"output"


def test_temp_entry_replacement_cannot_publish_unverified_bytes(setup, monkeypatch):
    store, _, _, _, context, _ = setup
    output = make_ref(b"output", "cf.output.v1")
    real_link = os.link

    def replace_before_link(source, destination, **kwargs):
        directory = kwargs["src_dir_fd"]
        os.unlink(source, dir_fd=directory)
        fd = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
        try:
            os.write(fd, b"forged")
        finally:
            os.close(fd)
        return real_link(source, destination, **kwargs)

    monkeypatch.setattr(os, "link", replace_before_link)
    with pytest.raises(ContractError):
        store.put_verified(io.BytesIO(b"output"), output, context)


def test_pointer_post_link_fsync_failure_retains_pointer(setup, monkeypatch):
    from test_modal import build, execute, read_manifest

    store, _, _, _, context, _ = setup
    scenario = build()
    manifest_ref = execute(scenario)
    manifest = read_manifest(scenario, manifest_ref)
    for ref in (*manifest.outputs, manifest_ref):
        store.put_verified(io.BytesIO(scenario.store.objects[ref.digest]), ref, context)
    original = os.fsync
    calls = 0

    def fail_post_link(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("pointer post-link fsync fault")
        original(fd)

    monkeypatch.setattr(os, "fsync", fail_post_link)
    with pytest.raises(ContractError) as exc:
        store.publish_result(ATTEMPT, manifest_ref)
    assert exc.value.code == "dispatch_unknown"
    monkeypatch.setattr(os, "fsync", original)
    assert store.result_pointer() == manifest_ref
