"""Attempt-scoped, durable local staging for trusted cooperative workers."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext
from functools import partial
from pathlib import Path
from typing import BinaryIO, Literal

from pydantic import TypeAdapter

from conscience_foundry.contracts.common import MAX_SAFE_INTEGER, ContractError, Digest, Id, Ref
from conscience_foundry.contracts.execution import ResultManifest
from conscience_foundry.execution.local_contracts import LocalWorkerGrant, LocalWriteAuthority
from conscience_foundry.execution.worker import Clock
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.local import ObjectStore, VerifiedBytes
from conscience_foundry.storage.locator import IO_CHUNK_BYTES, _copy_verified
from conscience_foundry.storage.staging_s3 import _pointer_limits


def local_output_scope(
    root: Path,
    *,
    destination_id: str,
    project_id: Id,
    run_id: Id,
    attempt_id: Id,
    plan_digest: Digest,
) -> bytes:
    """Bind a private local scope to an operator-selected directory identity."""
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            held = os.fstat(fd)
            path = os.stat(root, follow_symlinks=False)
            if (held.st_dev, held.st_ino) != (path.st_dev, path.st_ino):
                raise ContractError("unsafe_path")
            return json.dumps(
                {
                    "destination_id": destination_id,
                    "project_id": project_id,
                    "run_id": run_id,
                    "attempt_id": attempt_id,
                    "plan_digest": plan_digest,
                    "device": str(held.st_dev),
                    "inode": str(held.st_ino),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        finally:
            os.close(fd)
    except ContractError:
        raise
    except OSError:
        raise ContractError("unsafe_path") from None


class LocalAttemptStore:
    """Immutable attempt artifacts; permits cover every persistent byte written."""

    def __init__(
        self,
        root: Path,
        project_id: Id,
        attempt_id: Id,
        input_store: ObjectStore,
        input_refs: tuple[Ref, ...],
        grant: LocalWorkerGrant,
        clock: Clock,
        write_authority: LocalWriteAuthority,
    ) -> None:
        try:
            TypeAdapter(Id).validate_python(project_id)
            TypeAdapter(Id).validate_python(attempt_id)
            if (
                not isinstance(root, Path)
                or type(grant) is not LocalWorkerGrant
                or grant.project_id != project_id
                or grant.attempt_id != attempt_id
                or not isinstance(input_refs, tuple)
                or any(type(r) is not Ref or r.project_id != project_id for r in input_refs)
                or type(grant.output_scope) is not bytes
                or not grant.output_scope
                or type(grant.nonce) is not str
                or not grant.nonce
                or not callable(getattr(write_authority, "write_permit", None))
                or not callable(getattr(write_authority, "revalidate_write", None))
            ):
                raise ContractError("forbidden")
        except ContractError:
            raise
        except Exception:
            raise ContractError("forbidden") from None
        if grant.output_scope != local_output_scope(
            root,
            destination_id=grant.destination_id,
            project_id=project_id,
            run_id=grant.run_id,
            attempt_id=attempt_id,
            plan_digest=grant.plan_digest,
        ):
            raise ContractError("forbidden")
        self.root, self.project_id, self.attempt_id = root, project_id, attempt_id
        self.input_store, self.input_refs, self.grant = input_store, input_refs, grant
        self.clock, self.authority = clock, write_authority
        with self._directory(create=True):
            pass

    @property
    def write_scope(self) -> bytes:
        return self.grant.output_scope

    def _live(self) -> None:
        try:
            if self.clock.now() >= self.grant.expires_at:
                raise ContractError("authorization_expired")
        except ContractError:
            raise
        except Exception:
            raise ContractError("forbidden") from None

    def _check(self, ref: Ref, context: AccessContext) -> None:
        if (
            type(ref) is not Ref
            or ref.project_id != self.project_id
            or type(context) is not AccessContext
            or context.project_id != self.project_id
            or context.actor_id != self.attempt_id
            or not {"read", "extract"} <= context.scopes
        ):
            raise ContractError("forbidden")
        self._live()

    @contextmanager
    def _directory(self, *, create: bool = False) -> Iterator[int]:
        if self.grant.output_scope != local_output_scope(
            self.root,
            destination_id=self.grant.destination_id,
            project_id=self.project_id,
            run_id=self.grant.run_id,
            attempt_id=self.attempt_id,
            plan_digest=self.grant.plan_digest,
        ):
            raise ContractError("unsafe_path")
        fds: list[int] = []
        links: list[tuple[int, str, int]] = []
        try:
            root = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fds.append(root)
            identity = json.loads(self.grant.output_scope)
            held_root = os.fstat(root)
            if (str(held_root.st_dev), str(held_root.st_ino)) != (
                identity["device"],
                identity["inode"],
            ):
                raise ContractError("unsafe_path")
            for name in (self.project_id, self.attempt_id):
                parent = fds[-1]
                if create:
                    try:
                        os.mkdir(name, mode=0o700, dir_fd=parent)
                        os.fsync(parent)
                    except FileExistsError:
                        pass
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                fds.append(fd)
                links.append((parent, name, fd))
            yield fds[-1]
            root_path = os.stat(self.root, follow_symlinks=False)
            if (root_path.st_dev, root_path.st_ino) != (
                os.fstat(root).st_dev,
                os.fstat(root).st_ino,
            ):
                raise ContractError("unsafe_path")
            for parent, name, fd in links:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                held = os.fstat(fd)
                if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (
                    held.st_dev,
                    held.st_ino,
                ):
                    raise ContractError("unsafe_path")
        except ContractError:
            raise
        except OSError:
            raise ContractError("unavailable") from None
        finally:
            for fd in reversed(fds):
                os.close(fd)

    def _read(self, directory: int, name: str, bound: int) -> bytes:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            raise ContractError("artifact_missing") from None
        except OSError:
            raise ContractError("unsafe_path") from None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ContractError("unsafe_path")
            with os.fdopen(fd, "rb") as stream:
                fd = -1
                data = stream.read(bound + 1)
            if len(data) > bound:
                raise ContractError("hash_mismatch")
            return data
        finally:
            if fd >= 0:
                os.close(fd)

    def _snapshot(self, directory: int, name: str, ref: Ref) -> BinaryIO:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            raise ContractError("artifact_missing") from None
        except OSError:
            raise ContractError("unsafe_path") from None
        output = io.BytesIO()
        try:
            held = os.fstat(fd)
            if not stat.S_ISREG(held.st_mode):
                raise ContractError("unsafe_path")
            with os.fdopen(fd, "rb") as source:
                fd = -1
                digest = hashlib.sha256()
                total = 0
                while True:
                    chunk = source.read(min(IO_CHUNK_BYTES, ref.size_bytes - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > ref.size_bytes:
                        raise ContractError("hash_mismatch")
                    digest.update(chunk)
                    output.write(chunk)
                if total != ref.size_bytes or digest.hexdigest() != ref.digest:
                    raise ContractError("hash_mismatch")
                after = os.fstat(source.fileno())
                path = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if (held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns, held.st_ctime_ns) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ) or (path.st_dev, path.st_ino) != (held.st_dev, held.st_ino):
                    raise ContractError("unsafe_path")
            output.seek(0)
            return output
        except BaseException:
            output.close()
            raise
        finally:
            if fd >= 0:
                os.close(fd)

    def _publish(
        self,
        name: str,
        stream: BinaryIO | Callable[[], BinaryIO],
        ref: Ref,
        *,
        exclusive: bool = False,
    ) -> bool:
        self._live()
        with (
            self.authority.write_permit(self.project_id, self.grant.run_id, self.attempt_id, ref),
            stream() if callable(stream) else nullcontext(stream) as source,
        ):
            with self._directory() as directory:
                temporary = ".tmp-" + uuid.uuid4().hex
                fd = -1
                try:
                    fd = os.open(
                        temporary,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=directory,
                    )
                    _copy_verified(source, fd, ref, ref.size_bytes)
                    os.fsync(fd)
                    self._live()
                    self.authority.revalidate_write(
                        self.project_id, self.grant.run_id, self.attempt_id, ref
                    )
                    held = os.fstat(fd)
                    candidate = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
                    if (candidate.st_dev, candidate.st_ino) != (held.st_dev, held.st_ino):
                        raise ContractError("dispatch_unknown")
                    try:
                        os.link(
                            temporary,
                            name,
                            src_dir_fd=directory,
                            dst_dir_fd=directory,
                            follow_symlinks=False,
                        )
                        published = os.stat(name, dir_fd=directory, follow_symlinks=False)
                        current = os.fstat(fd)
                        if (published.st_dev, published.st_ino) != (held.st_dev, held.st_ino) or (
                            current.st_dev,
                            current.st_ino,
                            current.st_size,
                            current.st_mtime_ns,
                        ) != (held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns):
                            raise ContractError("dispatch_unknown")
                    except FileExistsError:
                        if exclusive:
                            os.unlink(temporary, dir_fd=directory)
                            os.fsync(directory)
                            return False
                        with self._snapshot(directory, name, ref):
                            pass
                    os.fsync(directory)
                    os.unlink(temporary, dir_fd=directory)
                    os.fsync(directory)
                    return True
                except ContractError:
                    raise
                except OSError:
                    raise ContractError("dispatch_unknown") from None
                finally:
                    if fd >= 0:
                        os.close(fd)

    def put_verified(self, stream: BinaryIO, expected: Ref, context: AccessContext) -> Ref:
        self._check(expected, context)
        if expected in self.input_refs:
            raise ContractError("forbidden")
        self._publish("object-" + expected.digest, stream, expected)
        return expected

    def open_verified(self, ref: Ref, context: AccessContext) -> BinaryIO:
        self._check(ref, context)
        name = "object-" + ref.digest
        with self._directory() as directory:
            snapshot = self._snapshot(directory, name, ref)
        return snapshot

    def stage_inputs(self, context: AccessContext) -> tuple[Ref, ...]:
        for ref in self.input_refs:
            self._check(ref, context)
            self._publish(
                "object-" + ref.digest,
                partial(self.input_store.open_verified, ref, context),
                ref,
            )
        return self.input_refs

    def read_verified(self, ref: Ref, context: AccessContext, limit: int) -> VerifiedBytes:
        if type(limit) is not int or limit <= 0 or limit > MAX_SAFE_INTEGER:
            raise ContractError("invalid_schema")
        if ref.size_bytes > limit:
            raise ContractError("limit_exceeded")
        with self.open_verified(ref, context) as stream:
            return VerifiedBytes(stream.read(), ref.digest)

    def _control_ref(self, data: bytes) -> Ref:
        return Ref(
            schema_version="cf.artifact-ref.v1",
            project_id=self.project_id,
            digest=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
            media_type="application/json",
            artifact_schema="cf.local-control.v1",
            locations=(),
        )

    def claim_lease(self, attempt_id: Id, nonce: str) -> Literal["won", "lost"]:
        if attempt_id != self.attempt_id or nonce != self.grant.nonce:
            raise ContractError("forbidden")
        data = nonce.encode("utf-8")
        return (
            "won"
            if self._publish("lease", io.BytesIO(data), self._control_ref(data), exclusive=True)
            else "lost"
        )

    def lease_present(self) -> bool:
        with self._directory() as directory:
            try:
                self._read(directory, "lease", len(self.grant.nonce.encode("utf-8")))
            except ContractError as error:
                if error.code == "artifact_missing":
                    return False
                raise
        return True

    def publish_result(self, attempt_id: Id, manifest: Ref) -> None:
        if (
            attempt_id != self.attempt_id
            or type(manifest) is not Ref
            or manifest.project_id != self.project_id
        ):
            raise ContractError("forbidden")
        context = AccessContext(self.project_id, self.attempt_id, frozenset({"read", "extract"}))
        with self.open_verified(manifest, context) as stream:
            raw = stream.read()
        result = ResultManifest.from_wire(raw, _pointer_limits(max(len(raw), 1)))
        if result.project_id != self.project_id or result.attempt_id != self.attempt_id:
            raise ContractError("forbidden")
        for ref in result.outputs:
            if ref in self.input_refs:
                raise ContractError("forbidden")
            with self.open_verified(ref, context):
                pass
        pointer = manifest.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8")
        self._publish("result", io.BytesIO(pointer), self._control_ref(pointer))

    def result_pointer(self) -> Ref | None:
        with self._directory() as directory:
            try:
                data = self._read(directory, "result", 65536)
            except ContractError as error:
                if error.code == "artifact_missing":
                    return None
                raise
        ref = Ref.from_wire(data, _pointer_limits(max(len(data), 1)))
        if ref.project_id != self.project_id:
            raise ContractError("forbidden")
        return ref


def read_local_result(root: Path, grant: LocalWorkerGrant) -> tuple[ResultManifest, Ref] | None:
    """Reopen an existing attempt without creating directories or requesting write access."""
    if type(grant) is not LocalWorkerGrant:
        raise ContractError("forbidden")
    view = object.__new__(LocalAttemptStore)
    view.root, view.project_id, view.attempt_id, view.grant = (
        root,
        grant.project_id,
        grant.attempt_id,
        grant,
    )
    with view._directory() as directory:
        try:
            raw_pointer = view._read(directory, "result", 65536)
        except ContractError as error:
            if error.code == "artifact_missing":
                return None
            raise
        ref = Ref.from_wire(raw_pointer, _pointer_limits(max(len(raw_pointer), 1)))
        if ref.project_id != grant.project_id or ref.artifact_schema != "cf.result.v1":
            raise ContractError("forbidden")
        with view._snapshot(directory, "object-" + ref.digest, ref) as stream:
            raw = stream.read()
        result = ResultManifest.from_wire(raw, _pointer_limits(max(len(raw), 1)))
        if result.project_id != grant.project_id or result.attempt_id != grant.attempt_id:
            raise ContractError("forbidden")
        for output in result.outputs:
            if output.project_id != grant.project_id:
                raise ContractError("forbidden")
            with view._snapshot(directory, "object-" + output.digest, output):
                pass
        return result, ref
