"""Durable exclusive local blobs and bounded verified reads, without services."""

from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass
from typing import BinaryIO, Protocol

from conscience_foundry.contracts.common import (
    MAX_SAFE_INTEGER,
    ArtifactLocation,
    ContractError,
    Digest,
    Ref,
)
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.locator import LocationRegistry, _copy_verified, _error


@dataclass(frozen=True)
class VerifiedBytes:
    data: bytes
    digest: Digest

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes) or hashlib.sha256(self.data).hexdigest() != self.digest:
            raise ContractError("hash_mismatch")


class ObjectStore(Protocol):
    def put_verified(self, stream: BinaryIO, expected: Ref, context: AccessContext) -> Ref: ...

    def open_verified(self, ref: Ref, context: AccessContext) -> BinaryIO: ...

    def read_verified(self, ref: Ref, context: AccessContext, limit: int) -> VerifiedBytes: ...


class LocalObjectStore:
    """An explicitly selected store within one trusted root/limits/authority registry."""

    def __init__(self, store_id: str, locator: LocationRegistry) -> None:
        fd = locator._root_fd(store_id)
        os.close(fd)
        self.store_id = store_id
        self.locator = locator

    def _location(self, ref: Ref) -> ArtifactLocation:
        return ArtifactLocation(
            store_id=self.store_id, object_key=f"sha256/{ref.digest[:2]}/{ref.digest}"
        )

    def put_verified(self, stream: BinaryIO, expected: Ref, context: AccessContext) -> Ref:
        self.locator._authorize(expected, context, "write")
        ceiling = self.locator._ceiling(expected)
        if expected.size_bytes > ceiling:
            raise ContractError("limit_exceeded")
        location = self._location(expected)
        parent, name = self.locator._parent_fd(location, create=True)
        temporary = f".tmp-{uuid.uuid4().hex}"
        temporary_fd = -1
        created = False
        try:
            temporary_fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                mode=0o600,
                dir_fd=parent,
            )
            created = True
            _copy_verified(stream, temporary_fd, expected, ceiling)
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = -1
            try:
                os.link(
                    temporary,
                    name,
                    src_dir_fd=parent,
                    dst_dir_fd=parent,
                    follow_symlinks=False,
                )
            except FileExistsError:
                with self.locator._snapshot(expected, location, ceiling):
                    pass
            os.fsync(parent)
            return expected
        except ContractError:
            raise
        except OSError as exc:
            raise _error(exc) from None
        except Exception:
            raise ContractError("unavailable") from None
        finally:
            if temporary_fd >= 0:
                os.close(temporary_fd)
            try:
                if created:
                    try:
                        os.unlink(temporary, dir_fd=parent)
                        os.fsync(parent)
                    except OSError as exc:
                        raise _error(exc) from None
            finally:
                os.close(parent)

    def open_verified(self, ref: Ref, context: AccessContext) -> BinaryIO:
        """Return an independent private snapshot; caller owns closing the handle."""
        self.locator._authorize(ref, context, "read")
        ceiling = self.locator._ceiling(ref)
        if ref.size_bytes > ceiling:
            raise ContractError("limit_exceeded")
        locations = (self._location(ref),) + self.locator._locations(ref)
        seen: set[tuple[str, str]] = set()
        for location in locations:
            key = location.store_id, location.object_key
            if key in seen:
                continue
            seen.add(key)
            try:
                return self.locator._snapshot(ref, location, ceiling)
            except ContractError as exc:
                if exc.code != "artifact_missing":
                    raise
        raise ContractError("artifact_missing")

    def read_verified(self, ref: Ref, context: AccessContext, limit: int) -> VerifiedBytes:
        if type(limit) is not int or limit <= 0 or limit > MAX_SAFE_INTEGER:
            raise ContractError("invalid_schema")
        if ref.size_bytes > limit:
            raise ContractError("limit_exceeded")
        with self.open_verified(ref, context) as handle:
            data = handle.read(ref.size_bytes + 1)
        if len(data) > limit:
            raise ContractError("limit_exceeded")
        return VerifiedBytes(data, ref.digest)

    def register_location(
        self, ref: Ref, store_id: str, object_key: str, context: AccessContext
    ) -> None:
        self.locator.register_location(ref, store_id, object_key, context)
