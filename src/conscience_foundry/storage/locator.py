"""Configured safe local roots and verified, non-authoritative location hints."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import BinaryIO, Self

from pydantic import ValidationError

from conscience_foundry.contracts.common import (
    ArtifactLocation,
    ContractError,
    ContractLimits,
    Ref,
)
from conscience_foundry.policy.access import AccessContext

Authorizer = Callable[[Ref, AccessContext, str], None]
IO_CHUNK_BYTES = 64 * 1024


def _error(exc: OSError) -> ContractError:
    if exc.errno in {errno.ENOSPC, errno.EDQUOT}:
        return ContractError("storage_full")
    if exc.errno == errno.ENOENT:
        return ContractError("artifact_missing")
    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
        return ContractError("unsafe_path")
    return ContractError("unavailable")


def _parts(key: str) -> tuple[str, ...]:
    try:
        location = ArtifactLocation(store_id="local", object_key=key)
    except ValidationError:
        raise ContractError("unsafe_path") from None
    return tuple(location.object_key.split("/"))


def _open_root(path: Path) -> int:
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ContractError("unsafe_path")
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current
            )
            os.close(current)
            current = next_fd
        return current
    except OSError as exc:
        os.close(current)
        raise _error(exc) from None


def _copy_verified(source: BinaryIO, target_fd: int, expected: Ref, ceiling: int) -> None:
    if expected.size_bytes > ceiling:
        raise ContractError("limit_exceeded")
    total = 0
    digest = hashlib.sha256()
    while True:
        request_size = min(IO_CHUNK_BYTES, expected.size_bytes - total + 1)
        chunk = source.read(request_size)
        if not isinstance(chunk, bytes):
            raise ContractError("invalid_schema")
        if not chunk:
            break
        total += len(chunk)
        if total > expected.size_bytes or total > ceiling:
            raise ContractError("limit_exceeded")
        digest.update(chunk)
        remaining = memoryview(chunk)
        while remaining:
            written = os.write(target_fd, remaining)
            if written <= 0:
                raise ContractError("unavailable")
            remaining = remaining[written:]
    if total != expected.size_bytes or digest.hexdigest() != expected.digest:
        raise ContractError("hash_mismatch")


class LocationRegistry:
    """Pinned directory descriptors plus process-local hints, never access decisions.

    The injected authorizer is trusted control code. It must resolve the artifact's
    selected source/audit context and current policy for each operation; no grant is
    derived from possession of a digest. Loss of hints requires re-registration.
    Close this object (or use it as a context manager) to release its root handles.
    """

    def __init__(
        self, roots: Mapping[str, Path], limits: ContractLimits, authorize: Authorizer
    ) -> None:
        self._root_fds: dict[str, int] = {}
        self._hints: dict[tuple[str, str, int, str, str], tuple[ArtifactLocation, ...]] = {}
        if not roots or not callable(authorize) or not isinstance(limits, ContractLimits):
            raise ContractError("invalid_schema")
        self.limits = limits
        self._authorize_callback = authorize
        try:
            for store_id, root in roots.items():
                if not isinstance(store_id, str) or not store_id or not isinstance(root, Path):
                    raise ContractError("invalid_schema")
                self._root_fds[store_id] = _open_root(root)
        except Exception:
            self.close()
            raise

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        for fd in self._root_fds.values():
            os.close(fd)
        self._root_fds.clear()

    def _authorize(self, ref: Ref, context: AccessContext, effect: str) -> None:
        if ref.project_id != context.project_id:
            raise ContractError("forbidden")
        if effect not in {"read", "write", "register_location"}:
            raise ContractError("forbidden")
        try:
            result = self._authorize_callback(ref, context, effect)
            if result is not None:
                raise ContractError("forbidden")
        except ContractError:
            raise
        except Exception:
            raise ContractError("unavailable") from None

    def _ceiling(self, ref: Ref) -> int:
        if ref.artifact_schema == "kf.raw-original.v1":
            return self.limits.max_source_bytes
        return self.limits.max_output_bytes

    def _root_fd(self, store_id: str) -> int:
        try:
            return os.dup(self._root_fds[store_id])
        except KeyError:
            raise ContractError("unsafe_path") from None
        except OSError as exc:
            raise _error(exc) from None

    def _parent_fd(self, location: ArtifactLocation, *, create: bool = False) -> tuple[int, str]:
        parts = _parts(location.object_key)
        current = self._root_fd(location.store_id)
        try:
            for part in parts[:-1]:
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=current)
                    except FileExistsError:
                        pass
                    else:
                        os.fsync(current)
                next_fd = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current
                )
                os.close(current)
                current = next_fd
            return current, parts[-1]
        except OSError as exc:
            os.close(current)
            raise _error(exc) from None
        except Exception:
            os.close(current)
            raise

    def _snapshot(self, ref: Ref, location: ArtifactLocation, ceiling: int) -> BinaryIO:
        """Internal exact-location read; caller must already check current authority."""
        parent, name = self._parent_fd(location)
        source_fd = -1
        output: BinaryIO | None = None
        try:
            source_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            if not stat.S_ISREG(os.fstat(source_fd).st_mode):
                raise ContractError("unsafe_path")
            output = tempfile.TemporaryFile(mode="w+b")
            with os.fdopen(source_fd, "rb") as source:
                source_fd = -1
                _copy_verified(source, output.fileno(), ref, ceiling)
            output.seek(0)
            return output
        except OSError as exc:
            if output is not None:
                output.close()
            raise _error(exc) from None
        except Exception:
            if output is not None:
                output.close()
            raise
        finally:
            if source_fd >= 0:
                os.close(source_fd)
            os.close(parent)

    @staticmethod
    def _identity(ref: Ref) -> tuple[str, str, int, str, str]:
        return ref.project_id, ref.digest, ref.size_bytes, ref.media_type, ref.artifact_schema

    def _locations(self, ref: Ref) -> tuple[ArtifactLocation, ...]:
        return ref.locations + self._hints.get(self._identity(ref), ())

    def register_location(
        self, ref: Ref, store_id: str, object_key: str, context: AccessContext
    ) -> None:
        self._authorize(ref, context, "register_location")
        self._authorize(ref, context, "read")
        try:
            location = ArtifactLocation(store_id=store_id, object_key=object_key)
        except ValidationError:
            raise ContractError("unsafe_path") from None
        with self._snapshot(ref, location, self._ceiling(ref)):
            pass
        identity = self._identity(ref)
        existing = self._hints.get(identity, ())
        if location not in existing:
            if len(existing) >= self.limits.max_array_items:
                raise ContractError("limit_exceeded")
            self._hints[identity] = existing + (location,)
