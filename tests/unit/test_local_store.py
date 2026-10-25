"""Synthetic filesystem faults exercise the actual local storage boundary."""

import errno
import hashlib
import io
import os
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

import pytest

from conscience_foundry.contracts.common import (
    ArtifactLocation,
    ArtifactRef,
    ContractError,
    ContractLimits,
)
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.local import LocalObjectStore, VerifiedBytes
from conscience_foundry.storage.locator import LocationRegistry

PROJECT = "00000000-0000-0000-0000-000000000001"
ACTOR = "00000000-0000-0000-0000-000000000002"
OTHER_PROJECT = "00000000-0000-0000-0000-000000000003"
CONTEXT = AccessContext(PROJECT, ACTOR, frozenset({"read", "extract"}))


def limits(**overrides: int) -> ContractLimits:
    return ContractLimits.model_validate(
        {
            "schemaVersion": "kf.contract-limits.v1",
            "version": "synthetic.storage-limits.v1",
            "maxJsonBytes": 4096,
            "maxStringScalars": 256,
            "maxArrayItems": 16,
            "maxDepth": 16,
            "maxManifestItems": 8,
            "maxSourceBytes": 128,
            "maxOutputBytes": 128,
            "maxErrorMessageScalars": 80,
        }
        | overrides
    )


def ref(data: bytes, *, locations: tuple[ArtifactLocation, ...] = ()) -> ArtifactRef:
    return ArtifactRef(
        schema_version="kf.artifact-ref.v1",
        project_id=PROJECT,
        digest=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        media_type="text/plain",
        artifact_schema="kf.raw-original.v1",
        locations=locations,
    )


def allow(_ref: ArtifactRef, _context: AccessContext, _effect: str) -> None:
    return None


def configured(
    roots: dict[str, Path],
    *,
    authorize: Callable[[ArtifactRef, AccessContext, str], None] = allow,
    bounds: ContractLimits | None = None,
) -> tuple[LocalObjectStore, LocationRegistry]:
    bounds = bounds or limits()
    registry = LocationRegistry(roots=roots, limits=bounds, authorize=authorize)
    return LocalObjectStore("primary", registry), registry


def test_partial_or_conflicting_write_never_replaces_blob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "store"
    root.mkdir()
    store, _ = configured({"primary": root})
    data = b"Synthetic immutable content"
    original = ref(data)
    assert store.put_verified(io.BytesIO(data), original, CONTEXT) == original
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}

    real_write = os.write
    calls = 0

    def disk_full(fd: int, payload: bytes) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(fd, payload[:1])
        raise OSError(errno.ENOSPC, "synthetic disk full")

    monkeypatch.setattr(os, "write", disk_full)
    with pytest.raises(ContractError) as exc:
        store.put_verified(io.BytesIO(b"different content"), ref(b"different content"), CONTEXT)
    assert exc.value.code == "storage_full"
    assert calls == 2
    monkeypatch.setattr(os, "write", real_write)
    assert {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()} == before
    assert store.read_verified(original, CONTEXT, 128).data == data

    installed = next(p for p in root.rglob("*") if p.is_file())
    installed.write_bytes(b"Corrupt existing bytes")
    with pytest.raises(ContractError) as exc:
        store.put_verified(io.BytesIO(data), original, CONTEXT)
    assert exc.value.code == "hash_mismatch"
    assert installed.read_bytes() == b"Corrupt existing bytes"


def test_bad_stream_never_installs_or_returns_unverified_bytes(tmp_path: Path) -> None:
    root = tmp_path / "store"
    root.mkdir()
    store, _ = configured({"primary": root})
    expected = ref(b"expected")
    for payload in (b"expecte", b"expected-extra", b"differen"):
        with pytest.raises(ContractError):
            store.put_verified(io.BytesIO(payload), expected, CONTEXT)
        assert not [p for p in root.rglob("*") if p.is_file()]
    with pytest.raises(ContractError) as exc:
        store.open_verified(expected, CONTEXT)
    assert exc.value.code == "artifact_missing"


def test_stream_byte_subclass_cannot_hide_installed_size(tmp_path: Path) -> None:
    class ShortBytes(bytes):
        def __len__(self) -> int:
            return 1

    class OversizedStream(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            # This untrusted stream returns more than requested.
            chunk = super().read()
            return ShortBytes(chunk) if chunk else b""

    root = tmp_path / "store"
    root.mkdir()
    store, registry = configured({"primary": root}, bounds=limits(maxSourceBytes=1))
    payload = b"oversized"
    expected = ArtifactRef.model_validate(ref(payload).model_dump() | {"size_bytes": 1})
    try:
        with pytest.raises(ContractError, match="invalid_schema"):
            store.put_verified(OversizedStream(payload), expected, CONTEXT)
        assert not [path for path in root.rglob("*") if path.is_file()]
    finally:
        registry.close()


def test_relocation_preserves_descriptor_digest(tmp_path: Path) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    data = b"Synthetic relocated bytes"
    original = ref(data)
    serialized = original.model_dump_json()
    store, registry = configured({"primary": first, "secondary": second})
    store.put_verified(io.BytesIO(data), original, CONTEXT)
    (second / "new-object").write_bytes(data)
    registry.register_location(original, "secondary", "new-object", CONTEXT)
    for p in first.rglob("*"):
        if p.is_file():
            p.unlink()
    assert store.read_verified(original, CONTEXT, 128).data == data
    assert original.model_dump_json() == serialized

    (second / "new-object").write_bytes(b"altered")
    with pytest.raises(ContractError):
        store.open_verified(original, CONTEXT)


def test_location_registration_requires_verified_bytes(tmp_path: Path) -> None:
    root = tmp_path / "store"
    root.mkdir()
    (root / "wrong").write_bytes(b"not expected")
    store, registry = configured({"primary": root})
    expected = ref(b"expected")
    with pytest.raises(ContractError):
        registry.register_location(expected, "primary", "wrong", CONTEXT)
    with pytest.raises(ContractError):
        store.open_verified(expected, CONTEXT)
    with pytest.raises(ContractError):
        registry.register_location(expected, "unknown", "wrong", CONTEXT)


def test_current_authority_checked_for_every_operation(tmp_path: Path) -> None:
    root = tmp_path / "store"
    root.mkdir()
    allowed = True
    effects: list[str] = []

    def authorize(value: ArtifactRef, context: AccessContext, effect: str) -> None:
        assert value.project_id == context.project_id
        effects.append(effect)
        if not allowed:
            raise ContractError("forbidden")

    store, registry = configured({"primary": root}, authorize=authorize)
    data = b"known bytes"
    expected = ref(data)
    store.put_verified(io.BytesIO(data), expected, CONTEXT)
    (root / "hint").write_bytes(data)
    registry.register_location(expected, "primary", "hint", CONTEXT)
    assert "register_location" in effects and "read" in effects
    allowed = False
    for action in (
        lambda: store.read_verified(expected, CONTEXT, 128),
        lambda: registry.register_location(expected, "primary", "hint", CONTEXT),
        lambda: store.put_verified(io.BytesIO(data), expected, CONTEXT),
    ):
        with pytest.raises(ContractError) as exc:
            action()
        assert exc.value.code == "forbidden"
    wrong_context = AccessContext(OTHER_PROJECT, ACTOR, frozenset({"read"}))
    with pytest.raises(ContractError):
        store.open_verified(expected, wrong_context)


def test_authority_unavailable_does_not_leak_private_errors(tmp_path: Path) -> None:
    root = tmp_path / "store"
    root.mkdir()

    def unavailable(_ref: ArtifactRef, _context: AccessContext, _effect: str) -> None:
        raise RuntimeError("private path /synthetic-secret and provider payload")

    store, _ = configured({"primary": root}, authorize=unavailable)
    with pytest.raises(ContractError) as exc:
        store.open_verified(ref(b"x"), CONTEXT)
    assert exc.value.code == "unavailable"
    assert "private" not in str(exc.value)


def test_safe_roots_and_symlink_components_never_escape(tmp_path: Path) -> None:
    root, outside = tmp_path / "store", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret").write_bytes(b"must remain untouched")
    (root / "escape").symlink_to(outside, target_is_directory=True)
    store, registry = configured({"primary": root})
    expected = ref(b"must remain untouched")
    with pytest.raises(ContractError) as exc:
        registry.register_location(expected, "primary", "escape/secret", CONTEXT)
    assert exc.value.code == "unsafe_path"
    assert (outside / "secret").read_bytes() == b"must remain untouched"
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(root, target_is_directory=True)
    with pytest.raises(ContractError):
        configured({"primary": linked_root})
    with pytest.raises(ContractError):
        store.read_verified(expected, CONTEXT, 128)


def test_streaming_bounds_and_private_verified_snapshot(tmp_path: Path) -> None:
    root = tmp_path / "store"
    root.mkdir()
    store, _ = configured({"primary": root}, bounds=limits(maxSourceBytes=8))
    reads: list[int] = []

    class BoundedStream(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            assert 0 < size <= 9
            reads.append(size)
            return super().read(size)

    data = b"12345678"
    expected = ref(data)
    store.put_verified(BoundedStream(data), expected, CONTEXT)
    assert reads
    with pytest.raises(ContractError) as exc:
        store.put_verified(io.BytesIO(b"123456789"), ref(b"123456789"), CONTEXT)
    assert exc.value.code == "limit_exceeded"
    with pytest.raises(ContractError):
        store.read_verified(expected, CONTEXT, 7)
    handle: BinaryIO = store.open_verified(expected, CONTEXT)
    try:
        installed = next(p for p in root.rglob("*") if p.is_file())
        installed.write_bytes(b"87654321")
        assert handle.read() == data
    finally:
        handle.close()


def test_verified_bytes_checks_its_own_content() -> None:
    data = b"synthetic"
    assert VerifiedBytes(data, hashlib.sha256(data).hexdigest()).data == data
    with pytest.raises(ContractError):
        VerifiedBytes(data, "0" * 64)


def test_fifo_is_rejected_without_a_blocking_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "store"
    root.mkdir()
    os.mkfifo(root / "fifo")
    store, registry = configured({"primary": root})
    real_open = os.open

    def guarded_open(path: str, flags: int, *args: object, **kwargs: object) -> int:
        if path == "fifo":
            assert flags & os.O_NONBLOCK, "nonregular candidates must not block before fstat"
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded_open)
    with pytest.raises(ContractError) as exc:
        registry.register_location(ref(b"x"), "primary", "fifo", CONTEXT)
    assert exc.value.code == "unsafe_path"
    with pytest.raises(ContractError):
        store.open_verified(ref(b"x"), CONTEXT)


def test_verified_hints_are_bounded_and_do_not_claim_restart_recovery(tmp_path: Path) -> None:
    root = tmp_path / "store"
    root.mkdir()
    data = b"synthetic"
    (root / "one").write_bytes(data)
    (root / "two").write_bytes(data)
    store, registry = configured({"primary": root}, bounds=limits(maxArrayItems=1))
    expected = ref(data)
    registry.register_location(expected, "primary", "one", CONTEXT)
    registry.register_location(expected, "primary", "one", CONTEXT)
    with pytest.raises(ContractError) as exc:
        registry.register_location(expected, "primary", "two", CONTEXT)
    assert exc.value.code == "limit_exceeded"
    assert store.read_verified(expected, CONTEXT, 128).data == data
    restarted, _ = configured({"primary": root})
    with pytest.raises(ContractError) as exc:
        restarted.open_verified(expected, CONTEXT)
    assert exc.value.code == "artifact_missing"


def test_installation_syncs_content_before_exclusive_link_and_directory_after(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "store"
    root.mkdir()
    store, _ = configured({"primary": root})
    events: list[str] = []
    real_sync, real_link = os.fsync, os.link

    def sync(fd: int) -> None:
        import stat

        events.append("file_sync" if stat.S_ISREG(os.fstat(fd).st_mode) else "directory_sync")
        real_sync(fd)

    def link(*args: object, **kwargs: object) -> None:
        assert events[-1] == "file_sync"
        assert kwargs["src_dir_fd"] == kwargs["dst_dir_fd"]
        assert kwargs["follow_symlinks"] is False
        real_link(*args, **kwargs)
        events.append("exclusive_install")

    monkeypatch.setattr(os, "fsync", sync)
    monkeypatch.setattr(os, "link", link)
    data = b"durable synthetic bytes"
    store.put_verified(io.BytesIO(data), ref(data), CONTEXT)
    assert events[-2:] == ["directory_sync", "directory_sync"]
    assert events.index("file_sync") < events.index("exclusive_install")


def test_read_allocation_is_bounded_by_artifact_not_large_caller_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "store"
    root.mkdir()
    store, _ = configured({"primary": root})
    data = b"small synthetic blob"
    expected = ref(data)
    store.put_verified(io.BytesIO(data), expected, CONTEXT)
    original_open = store.open_verified

    class GuardedReader(io.BufferedReader):
        def read(self, size: int = -1) -> bytes:
            assert 0 <= size <= len(data) + 1, "caller ceiling must not cause huge allocations"
            return super().read(size)

    def guarded_open(value: ArtifactRef, context: AccessContext) -> BinaryIO:
        return GuardedReader(original_open(value, context))

    monkeypatch.setattr(store, "open_verified", guarded_open)
    assert store.read_verified(expected, CONTEXT, 9007199254740991).data == data


def test_unexpected_stream_failure_is_redacted_and_cleans_partial_file(tmp_path: Path) -> None:
    root = tmp_path / "store"
    root.mkdir()
    store, _ = configured({"primary": root})

    class FailedStream(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            raise RuntimeError("private path /synthetic-secret")

    with pytest.raises(ContractError) as exc:
        store.put_verified(FailedStream(b"x"), ref(b"x"), CONTEXT)
    assert exc.value.code == "unavailable"
    assert "private" not in str(exc.value)
    assert not [p for p in root.rglob("*") if p.is_file()]
