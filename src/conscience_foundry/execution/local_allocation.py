"""Durable cooperative local storage-capacity allocation.

The allocator is operator-owned; it never substitutes for the ledger's budget authority.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, BinaryIO, Literal

from pydantic import TypeAdapter

from conscience_foundry.contracts.common import (
    MAX_SAFE_INTEGER,
    ContractError,
    Id,
    Instant,
    Money,
    PositiveInteger,
    Ref,
)
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.local import LocalObjectStore, ObjectStore, VerifiedBytes
from conscience_foundry.storage.locator import IO_CHUNK_BYTES, _error

_LOCK = "allocator.lock"
_STATE = "allocator.json"
_MAX_STATE_BYTES = 16 * 1024 * 1024


def _valid(adapter: Any, value: object) -> None:
    try:
        TypeAdapter(adapter).validate_python(value)
    except Exception:
        raise ContractError("invalid_schema") from None


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _checked_ref(ref: object, project_id: Id) -> None:
    if type(ref) is not Ref or ref.project_id != project_id:
        raise ContractError("forbidden")
    try:
        if Ref.model_validate(ref.model_dump()) != ref:
            raise ContractError("invalid_schema")
    except ContractError:
        raise
    except Exception:
        raise ContractError("invalid_schema") from None


@dataclass(frozen=True)
class LocalAllocationPolicy:
    attempt_price_usd: Money
    storage_price_usd: Money
    run_storage_capacity_bytes: PositiveInteger
    operator_storage_capacity_bytes: PositiveInteger
    resource_policy_ref: Ref
    funded_from: Instant
    funded_until: Instant
    semantics: Literal["cooperative"]

    def __post_init__(self) -> None:
        for value in (self.attempt_price_usd, self.storage_price_usd):
            _valid(Money, value)
            if Decimal(value) <= 0:
                raise ContractError("invalid_schema")
        for capacity in (self.run_storage_capacity_bytes, self.operator_storage_capacity_bytes):
            _valid(PositiveInteger, capacity)
        for value in (self.funded_from, self.funded_until):
            _valid(Instant, value)
        if (
            self.funded_from >= self.funded_until
            or self.run_storage_capacity_bytes > self.operator_storage_capacity_bytes
            or type(self.resource_policy_ref) is not Ref
            or self.semantics != "cooperative"
        ):
            raise ContractError("invalid_schema")
        try:
            Ref.model_validate(self.resource_policy_ref.model_dump())
        except Exception:
            raise ContractError("invalid_schema") from None

    def digest(self) -> str:
        return hashlib.sha256(
            _json(
                {
                    "attempt_price_usd": self.attempt_price_usd,
                    "storage_price_usd": self.storage_price_usd,
                    "run_storage_capacity_bytes": self.run_storage_capacity_bytes,
                    "operator_storage_capacity_bytes": self.operator_storage_capacity_bytes,
                    "resource_policy_ref": self.resource_policy_ref.model_dump(
                        mode="json", by_alias=True, exclude_none=True
                    ),
                    "funded_from": self.funded_from,
                    "funded_until": self.funded_until,
                    "semantics": self.semantics,
                }
            )
        ).hexdigest()


@dataclass(frozen=True)
class LocalActivationFacts:
    project_id: Id
    run_id: Id
    attempt_id: Id
    reservation_id: Id
    storage_reservation_id: Id
    authorization_ref: Ref
    plan_ref: Ref
    config_ref: Ref
    source_id: Id
    actor_id: Id
    input_refs: tuple[Ref, ...]
    expires_at: Instant
    attempt_root: Path
    output_scope: bytes


ActivationGuard = Callable[[Id, Id, Id], AbstractContextManager[LocalActivationFacts]]
ClosureGuard = Callable[[Id, Id], AbstractContextManager[Callable[[tuple[Ref, ...]], bool]]]
RetentionAuthorizer = Callable[[Id, Id, Id, Ref], bool]
RemovalVerifier = Callable[[Id, Id], bool]
PolicyReader = Callable[[Id, Id, Id], None]


def _directory(root: Path) -> int:
    if not isinstance(root, Path) or not root.is_absolute():
        raise ContractError("unsafe_path")
    try:
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise ContractError("unsafe_path") from None


def _read(fd: int, name: str) -> bytes:
    entry = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        if not stat.S_ISREG(os.fstat(entry).st_mode):
            raise ContractError("unsafe_path")
        with os.fdopen(entry, "rb", closefd=False) as stream:
            value = stream.read(_MAX_STATE_BYTES + 1)
        if len(value) > _MAX_STATE_BYTES:
            raise ContractError("limit_exceeded")
        return value
    finally:
        os.close(entry)


def _write_new(fd: int, name: str, raw: bytes) -> None:
    entry = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(entry, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
        os.fsync(entry)
    finally:
        os.close(entry)


class LocalAllocator:
    """An explicitly initialized journal; reopening absent state always refuses."""

    @classmethod
    def initialize(
        cls,
        root: Path,
        policy: LocalAllocationPolicy,
        store: ObjectStore,
        clock: Callable[[], Instant],
        *,
        operator_store_id: str,
        operator_store_root: Path,
        activation_guard: ActivationGuard | None = None,
        closure_guard: ClosureGuard | None = None,
        retention_authorizer: RetentionAuthorizer | None = None,
        removal_verifier: RemovalVerifier | None = None,
        policy_reader: PolicyReader | None = None,
    ) -> None:
        if type(policy) is not LocalAllocationPolicy:
            raise ContractError("invalid_schema")
        if type(operator_store_id) is not str or not operator_store_id:
            raise ContractError("invalid_schema")
        fd = _directory(root)
        try:
            operatorfd = _directory(operator_store_root)
        except Exception:
            os.close(fd)
            raise
        try:
            info = os.fstat(fd)
            operator_info = os.fstat(operatorfd)
            state = {
                "version": 1,
                "root_device": str(info.st_dev),
                "root_inode": str(info.st_ino),
                "policy_digest": policy.digest(),
                "operator_store_id": operator_store_id,
                "operator_device": str(operator_info.st_dev),
                "operator_inode": str(operator_info.st_ino),
                "runs": {},
            }
            _write_new(fd, _LOCK, b"")
            _write_new(fd, _STATE, _json(state))
            os.fsync(fd)
        except (OSError, ValueError):
            raise ContractError("dispatch_unknown") from None
        finally:
            os.close(operatorfd)
            os.close(fd)

    def __init__(
        self,
        root: Path,
        policy: LocalAllocationPolicy,
        store: ObjectStore,
        clock: Callable[[], Instant],
        *,
        operator_store_id: str,
        operator_store_root: Path,
        activation_guard: ActivationGuard | None = None,
        retention_authorizer: RetentionAuthorizer | None = None,
        removal_verifier: RemovalVerifier | None = None,
        policy_reader: PolicyReader | None = None,
        closure_guard: ClosureGuard | None = None,
    ) -> None:
        self.closure_guard = closure_guard
        self.activation_guard = activation_guard
        self.retention_authorizer = retention_authorizer
        self.removal_verifier = removal_verifier
        self.policy_reader = policy_reader
        self.operator_store_id = operator_store_id
        self.operator_store_root = operator_store_root
        if type(operator_store_id) is not str or not operator_store_id:
            raise ContractError("invalid_schema")
        if type(policy) is not LocalAllocationPolicy or not callable(clock):
            raise ContractError("invalid_schema")
        self.root, self.policy, self.store, self.clock = root, policy, store, clock
        self._local = threading.local()
        with self._locked() as (_, state):
            self._check(state)

    def _check(self, state: dict[str, Any], fd: int | None = None) -> None:
        own = fd is None
        rootfd = _directory(self.root) if own else fd
        assert rootfd is not None
        try:
            info = os.fstat(rootfd)
            operatorfd = _directory(self.operator_store_root)
            try:
                operator_info = os.fstat(operatorfd)
            finally:
                os.close(operatorfd)
            if (
                set(state)
                != {
                    "version",
                    "root_device",
                    "root_inode",
                    "policy_digest",
                    "operator_store_id",
                    "operator_device",
                    "operator_inode",
                    "runs",
                }
                or type(state["version"]) is not int
                or state["version"] != 1
                or state["root_device"] != str(info.st_dev)
                or state["root_inode"] != str(info.st_ino)
                or state["policy_digest"] != self.policy.digest()
                or state["operator_store_id"] != self.operator_store_id
                or state["operator_device"] != str(operator_info.st_dev)
                or state["operator_inode"] != str(operator_info.st_ino)
                or type(state["runs"]) is not dict
            ):
                raise ContractError("forbidden")
            for run_id, run in state["runs"].items():
                _valid(Id, run_id)
                if (
                    type(run) is not dict
                    or set(run)
                    != (
                        {"project_id", "capacity", "closed", "released", "attempts", "refs"}
                        | ({"closed_refs"} if run.get("closed") else set())
                        | ({"release_actor", "release_proof"} if run.get("released") else set())
                    )
                    or run["project_id"] != self.policy.resource_policy_ref.project_id
                    or type(run["capacity"]) is not int
                    or run["capacity"] != self.policy.run_storage_capacity_bytes
                    or type(run["closed"]) is not bool
                    or type(run["released"]) is not bool
                    or (run["released"] and not run["closed"])
                    or type(run["attempts"]) is not dict
                    or type(run["refs"]) is not dict
                    or (run["closed"] != ("closed_refs" in run))
                    or ("closed_refs" in run and type(run["closed_refs"]) is not list)
                ):
                    raise ContractError("forbidden")
                storage_ids = {
                    item.get("storage_reservation_id")
                    for item in run["attempts"].values()
                    if type(item) is dict
                }
                if len(storage_ids) > 1:
                    raise ContractError("forbidden")
                for attempt_id, item in run["attempts"].items():
                    _valid(Id, attempt_id)
                    fields = {
                        "project_id",
                        "run_id",
                        "attempt_id",
                        "reservation_id",
                        "storage_reservation_id",
                        "authorization_ref",
                        "plan_ref",
                        "config_ref",
                        "source_id",
                        "actor_id",
                        "input_refs",
                        "expires_at",
                        "attempt_root",
                        "output_scope",
                    }
                    if (
                        type(item) is not dict
                        or set(item) != fields
                        or (item["project_id"], item["run_id"], item["attempt_id"])
                        != (run["project_id"], run_id, attempt_id)
                        or type(item["input_refs"]) is not list
                        or type(item["attempt_root"]) is not str
                        or not Path(item["attempt_root"]).is_absolute()
                        or type(item["output_scope"]) is not str
                    ):
                        raise ContractError("forbidden")
                    for name in (
                        "reservation_id",
                        "storage_reservation_id",
                        "source_id",
                        "actor_id",
                    ):
                        _valid(Id, item[name])
                    _valid(Instant, item["expires_at"])
                    refs = [
                        item[name] for name in ("authorization_ref", "plan_ref", "config_ref")
                    ] + item["input_refs"]
                    for raw in refs:
                        try:
                            parsed_ref = Ref.model_validate(raw)
                        except Exception:
                            raise ContractError("invalid_schema") from None
                        if parsed_ref.project_id != run["project_id"]:
                            raise ContractError("forbidden")
                    try:
                        scope = json.loads(bytes.fromhex(item["output_scope"]))
                    except Exception:
                        raise ContractError("invalid_schema") from None
                    if (
                        type(scope) is not dict
                        or set(scope)
                        != {
                            "destination_id",
                            "project_id",
                            "run_id",
                            "attempt_id",
                            "plan_digest",
                            "device",
                            "inode",
                        }
                        or (
                            scope["project_id"],
                            scope["run_id"],
                            scope["attempt_id"],
                            scope["plan_digest"],
                        )
                        != (
                            run["project_id"],
                            run_id,
                            attempt_id,
                            Ref.model_validate(item["plan_ref"]).digest,
                        )
                    ):
                        raise ContractError("forbidden")
                    if (
                        type(scope["destination_id"]) is not str
                        or not scope["destination_id"]
                        or type(scope["device"]) is not str
                        or not scope["device"].isdigit()
                        or type(scope["inode"]) is not str
                        or not scope["inode"].isdigit()
                        or _json(scope) != bytes.fromhex(item["output_scope"])
                    ):
                        raise ContractError("forbidden")
                    if not run["closed"]:
                        from conscience_foundry.storage.local_attempt import local_output_scope

                        actual_scope = local_output_scope(
                            Path(item["attempt_root"]),
                            destination_id=scope["destination_id"],
                            project_id=run["project_id"],
                            run_id=run_id,
                            attempt_id=attempt_id,
                            plan_digest=scope["plan_digest"],
                        )
                        if actual_scope != bytes.fromhex(item["output_scope"]):
                            raise ContractError("forbidden")
                for key, item in run["refs"].items():
                    if (
                        type(key) is not str
                        or type(item) is not dict
                        or set(item) != {"identity", "size", "status"}
                        or type(item["size"]) is not int
                        or not 0 <= item["size"] <= MAX_SAFE_INTEGER
                        or item["status"] not in {"pending", "durable"}
                        or type(item["identity"]) is not dict
                    ):
                        raise ContractError("forbidden")
                    identity = item["identity"]
                    kind = identity.get("kind")
                    if (
                        (
                            kind == "attempt"
                            and (
                                set(identity) != {"kind", "attempt_id", "ref"}
                                or identity["attempt_id"] not in run["attempts"]
                            )
                        )
                        or (
                            kind == "operator"
                            and (
                                set(identity) != {"kind", "store_id", "ref"}
                                or identity["store_id"] != self.operator_store_id
                            )
                        )
                        or kind not in {"attempt", "operator"}
                    ):
                        raise ContractError("forbidden")
                    try:
                        ref = Ref.model_validate(identity["ref"])
                    except Exception:
                        raise ContractError("invalid_schema") from None
                    if (
                        ref.project_id != run["project_id"]
                        or ref.size_bytes != item["size"]
                        or hashlib.sha256(_json(identity)).hexdigest() != key
                    ):
                        raise ContractError("forbidden")
                if sum(item["size"] for item in run["refs"].values()) > run["capacity"]:
                    raise ContractError("forbidden")
                if run["closed"] and any(
                    item["status"] != "durable" for item in run["refs"].values()
                ):
                    raise ContractError("forbidden")
                if run["released"]:
                    _valid(Id, run["release_actor"])
                    try:
                        proof = Ref.model_validate(run["release_proof"])
                    except Exception:
                        raise ContractError("invalid_schema") from None
                    if proof.project_id != run["project_id"]:
                        raise ContractError("forbidden")
                if run["closed"]:
                    try:
                        closed = tuple(Ref.model_validate(raw) for raw in run["closed_refs"])
                    except Exception:
                        raise ContractError("invalid_schema") from None
                    if any(ref.project_id != run["project_id"] for ref in closed):
                        raise ContractError("forbidden")
                    closed_set = {
                        _json(ref.model_dump(mode="json", by_alias=True, exclude_none=True))
                        for ref in closed
                    }
                    retained = {_json(item["identity"]["ref"]) for item in run["refs"].values()}
                    if len(closed_set) != len(closed) or closed_set != retained:
                        raise ContractError("forbidden")
            if (
                sum(run["capacity"] for run in state["runs"].values() if not run["released"])
                > self.policy.operator_storage_capacity_bytes
            ):
                raise ContractError("forbidden")
        finally:
            if own:
                os.close(rootfd)

    @contextmanager
    def _locked(self) -> Iterator[tuple[int, dict[str, Any]]]:
        fd = _directory(self.root)
        lock = -1
        try:
            lock = os.open(_LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            if not stat.S_ISREG(os.fstat(lock).st_mode):
                raise ContractError("unsafe_path")
            fcntl.flock(lock, fcntl.LOCK_EX)
            parsed = json.loads(_read(fd, _STATE))
            if type(parsed) is not dict:
                raise ContractError("invalid_schema")
            self._check(parsed, fd)
            yield fd, parsed
        except ContractError:
            raise
        except (OSError, ValueError, TypeError):
            raise ContractError("dispatch_unknown") from None
        finally:
            if lock >= 0:
                fcntl.flock(lock, fcntl.LOCK_UN)
                os.close(lock)
            os.close(fd)

    def _save(self, fd: int, state: dict[str, Any]) -> None:
        raw = _json(state)
        if len(raw) > _MAX_STATE_BYTES:
            raise ContractError("limit_exceeded")
        name = ".allocator-" + uuid.uuid4().hex
        try:
            _write_new(fd, name, raw)
            os.replace(name, _STATE, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
        except OSError:
            raise ContractError("dispatch_unknown") from None

    def _funded(self) -> None:
        now = self.clock()
        _valid(Instant, now)
        if not self.policy.funded_from <= now < self.policy.funded_until:
            raise ContractError("authorization_expired")

    def reserve_storage_capacity(self, project_id: Id, run_id: Id, capacity_bytes: int) -> None:
        _valid(Id, project_id)
        _valid(Id, run_id)
        _valid(PositiveInteger, capacity_bytes)
        if (
            project_id != self.policy.resource_policy_ref.project_id
            or capacity_bytes != self.policy.run_storage_capacity_bytes
        ):
            raise ContractError("forbidden")
        with self._locked() as (fd, state):
            runs = state["runs"]
            existing = runs.get(run_id)
            if existing is not None:
                if existing["released"] or existing["closed"]:
                    raise ContractError("forbidden")
                if existing["project_id"] != project_id or existing["capacity"] != capacity_bytes:
                    raise ContractError("determinism_conflict")
                return
            self._funded()
            if sum(
                run["capacity"] for run in runs.values() if not run["released"]
            ) + capacity_bytes > (self.policy.operator_storage_capacity_bytes):
                raise ContractError("limit_exceeded")
            runs[run_id] = {
                "project_id": project_id,
                "capacity": capacity_bytes,
                "closed": False,
                "released": False,
                "attempts": {},
                "refs": {},
            }
            self._save(fd, state)

    def close_storage(self, run_id: Id, durable_refs: tuple[Ref, ...]) -> None:
        _valid(Id, run_id)
        if self.closure_guard is None or type(durable_refs) is not tuple:
            raise ContractError("forbidden")
        project_id = self.policy.resource_policy_ref.project_id
        for ref in durable_refs:
            _checked_ref(ref, project_id)
        raw_refs = [
            ref.model_dump(mode="json", by_alias=True, exclude_none=True) for ref in durable_refs
        ]
        if len({_json(ref) for ref in raw_refs}) != len(raw_refs):
            raise ContractError("invalid_schema")
        try:
            with self.closure_guard(project_id, run_id) as verify:
                with self._locked() as (fd, state):
                    run = state["runs"].get(run_id)
                    if run is None or run["project_id"] != project_id:
                        raise ContractError("forbidden")
                    if run["closed"]:
                        if {_json(ref) for ref in run["closed_refs"]} != {
                            _json(ref) for ref in raw_refs
                        }:
                            raise ContractError("determinism_conflict")
                        return
                    if any(item.get("status") != "durable" for item in run["refs"].values()):
                        raise ContractError("dispatch_unknown")
                    retained = {_json(item["identity"]["ref"]) for item in run["refs"].values()}
                    if retained != {_json(ref) for ref in raw_refs}:
                        raise ContractError("forbidden")
                    if not callable(verify) or verify(durable_refs) is not True:
                        raise ContractError("forbidden")
                    run["closed"], run["closed_refs"] = True, raw_refs
                    self._save(fd, state)
        except ContractError:
            raise
        except Exception:
            raise ContractError("forbidden") from None

    def _live_attempt(self, run: dict[str, Any], project_id: Id, attempt_id: Id) -> None:
        record = run["attempts"].get(attempt_id)
        if (
            run["closed"]
            or run["project_id"] != project_id
            or type(record) is not dict
            or not callable(self.policy_reader)
        ):
            raise ContractError("forbidden")
        self._funded()
        if self.clock() >= record["expires_at"]:
            raise ContractError("authorization_expired")
        if self.policy_reader(project_id, record["source_id"], record["actor_id"]) is not None:
            raise ContractError("forbidden")

    @contextmanager
    def _permit(
        self,
        project_id: Id,
        run_id: Id,
        attempt_id: Id,
        ref: Ref,
        kind: str,
        already_present: Callable[[], bool] | None = None,
    ) -> Iterator[bool]:
        for item in (project_id, run_id, attempt_id):
            _valid(Id, item)
        _checked_ref(ref, project_id)
        if getattr(self._local, "active", None) is not None:
            raise ContractError("forbidden")
        identity = {"kind": kind, "ref": ref.model_dump(mode="json", by_alias=True)}
        if kind == "attempt":
            identity["attempt_id"] = attempt_id
        else:
            identity["store_id"] = self.operator_store_id
        key = hashlib.sha256(_json(identity)).hexdigest()
        with self._locked() as (fd, state):
            run = state["runs"].get(run_id)
            if run is None:
                raise ContractError("forbidden")
            self._live_attempt(run, project_id, attempt_id)
            present = already_present() if already_present is not None else False
            prior = run["refs"].get(key)
            if prior is not None and (
                prior["identity"] != identity or prior["size"] != ref.size_bytes
            ):
                raise ContractError("determinism_conflict")
            if prior is not None and prior["status"] != "durable":
                raise ContractError("dispatch_unknown")
            new = prior is None and not present
            if new:
                if (
                    sum(item["size"] for item in run["refs"].values()) + ref.size_bytes
                    > run["capacity"]
                ):
                    raise ContractError("limit_exceeded")
                run["refs"][key] = {
                    "identity": identity,
                    "size": ref.size_bytes,
                    "status": "pending",
                }
                self._save(fd, state)
            self._local.active = (project_id, run_id, attempt_id, ref, run, False)
            try:
                yield present
                if not self._local.active[5]:
                    raise ContractError("forbidden")
                if new:
                    run["refs"][key]["status"] = "durable"
                    self._save(fd, state)
            finally:
                self._local.active = None

    @contextmanager
    def write_permit(self, project_id: Id, run_id: Id, attempt_id: Id, ref: Ref) -> Iterator[None]:
        with self._permit(project_id, run_id, attempt_id, ref, "attempt"):
            yield

    def revalidate_write(self, project_id: Id, run_id: Id, attempt_id: Id, ref: Ref) -> None:
        active = getattr(self._local, "active", None)
        if active is None or active[:4] != (project_id, run_id, attempt_id, ref):
            raise ContractError("forbidden")
        self._live_attempt(active[4], project_id, attempt_id)
        self._local.active = (*active[:5], True)

    def activate_attempt(self, project_id: Id, run_id: Id, attempt_id: Id) -> None:
        for value in (project_id, run_id, attempt_id):
            _valid(Id, value)
        if not callable(self.activation_guard):
            raise ContractError("forbidden")
        try:
            with self.activation_guard(project_id, run_id, attempt_id) as facts:
                if type(facts) is not LocalActivationFacts:
                    raise ContractError("forbidden")
                for value in (
                    facts.project_id,
                    facts.run_id,
                    facts.attempt_id,
                    facts.reservation_id,
                    facts.storage_reservation_id,
                    facts.source_id,
                    facts.actor_id,
                ):
                    _valid(Id, value)
                _valid(Instant, facts.expires_at)
                if (
                    (facts.project_id, facts.run_id, facts.attempt_id)
                    != (project_id, run_id, attempt_id)
                    or project_id != self.policy.resource_policy_ref.project_id
                    or type(facts.input_refs) is not tuple
                    or any(
                        type(ref) is not Ref or ref.project_id != project_id
                        for ref in (
                            facts.authorization_ref,
                            facts.plan_ref,
                            facts.config_ref,
                            *facts.input_refs,
                        )
                    )
                    or type(facts.output_scope) is not bytes
                    or not isinstance(facts.attempt_root, Path)
                ):
                    raise ContractError("forbidden")
                for ref in (
                    facts.authorization_ref,
                    facts.plan_ref,
                    facts.config_ref,
                    *facts.input_refs,
                ):
                    _checked_ref(ref, project_id)
                from conscience_foundry.storage.local_attempt import local_output_scope

                scope = json.loads(facts.output_scope)
                if (
                    type(scope) is not dict
                    or type(scope.get("destination_id")) is not str
                    or not scope["destination_id"]
                    or local_output_scope(
                        facts.attempt_root,
                        destination_id=scope["destination_id"],
                        project_id=project_id,
                        run_id=run_id,
                        attempt_id=attempt_id,
                        plan_digest=facts.plan_ref.digest,
                    )
                    != facts.output_scope
                ):
                    raise ContractError("forbidden")
                record = {
                    "project_id": project_id,
                    "run_id": run_id,
                    "attempt_id": attempt_id,
                    "reservation_id": facts.reservation_id,
                    "storage_reservation_id": facts.storage_reservation_id,
                    "authorization_ref": facts.authorization_ref.model_dump(
                        mode="json", by_alias=True
                    ),
                    "plan_ref": facts.plan_ref.model_dump(mode="json", by_alias=True),
                    "config_ref": facts.config_ref.model_dump(mode="json", by_alias=True),
                    "source_id": facts.source_id,
                    "actor_id": facts.actor_id,
                    "input_refs": [
                        ref.model_dump(mode="json", by_alias=True) for ref in facts.input_refs
                    ],
                    "expires_at": facts.expires_at,
                    "attempt_root": str(facts.attempt_root),
                    "output_scope": facts.output_scope.hex(),
                }
                with self._locked() as (fd, state):
                    self._funded()
                    if self.clock() >= facts.expires_at:
                        raise ContractError("authorization_expired")
                    runs = state["runs"]
                    run = runs.get(run_id)
                    if run is None:
                        capacity = self.policy.run_storage_capacity_bytes
                        if (
                            sum(item["capacity"] for item in runs.values() if not item["released"])
                            + capacity
                            > self.policy.operator_storage_capacity_bytes
                        ):
                            raise ContractError("limit_exceeded")
                        run = {
                            "project_id": project_id,
                            "capacity": capacity,
                            "closed": False,
                            "released": False,
                            "attempts": {},
                            "refs": {},
                        }
                        runs[run_id] = run
                    if run["project_id"] != project_id or run["closed"]:
                        raise ContractError("forbidden")
                    if any(
                        item["storage_reservation_id"] != facts.storage_reservation_id
                        for item in run["attempts"].values()
                    ):
                        raise ContractError("forbidden")
                    previous = run["attempts"].get(attempt_id)
                    if previous is not None and previous != record:
                        raise ContractError("determinism_conflict")
                    if previous is None:
                        run["attempts"][attempt_id] = record
                        self._save(fd, state)
        except ContractError:
            raise
        except Exception:
            raise ContractError("forbidden") from None

    def release_retained_capacity(self, run_id: Id, actor_id: Id, proof_ref: Ref) -> None:
        _valid(Id, run_id)
        _valid(Id, actor_id)
        project_id = self.policy.resource_policy_ref.project_id
        if (
            type(proof_ref) is not Ref
            or proof_ref.project_id != project_id
            or not callable(self.retention_authorizer)
            or not callable(self.removal_verifier)
        ):
            raise ContractError("forbidden")
        _checked_ref(proof_ref, project_id)
        try:
            if self.retention_authorizer(project_id, run_id, actor_id, proof_ref) is not True:
                raise ContractError("forbidden")
            with self._locked() as (fd, state):
                run = state["runs"].get(run_id)
                if run is None or not run["closed"]:
                    raise ContractError("forbidden")
                proof = proof_ref.model_dump(mode="json", by_alias=True)
                if run["released"]:
                    if run["release_actor"] != actor_id or run["release_proof"] != proof:
                        raise ContractError("determinism_conflict")
                    return
                if self.removal_verifier(project_id, run_id) is not True:
                    raise ContractError("forbidden")
                run["released"] = True
                run["release_actor"], run["release_proof"] = actor_id, proof
                self._save(fd, state)
        except ContractError:
            raise
        except Exception:
            raise ContractError("forbidden") from None

    def import_writer(self, project_id: Id, run_id: Id, attempt_id: Id) -> ObjectStore:
        for value in (project_id, run_id, attempt_id):
            _valid(Id, value)
        if (
            type(self.store) is not LocalObjectStore
            or self.store.store_id != self.operator_store_id
        ):
            raise ContractError("forbidden")
        rootfd = _directory(self.operator_store_root)
        try:
            actualfd = self.store.locator._root_fd(self.operator_store_id)
        except Exception:
            os.close(rootfd)
            raise
        try:
            root, actual = os.fstat(rootfd), os.fstat(actualfd)
            if (root.st_dev, root.st_ino) != (actual.st_dev, actual.st_ino):
                raise ContractError("forbidden")
        finally:
            os.close(actualfd)
            os.close(rootfd)
        return _ImportWriter(self, self.store, project_id, run_id, attempt_id)


class _ImportWriter:
    def __init__(
        self,
        allocator: LocalAllocator,
        store: LocalObjectStore,
        project_id: Id,
        run_id: Id,
        attempt_id: Id,
    ) -> None:
        self.allocator, self.store = allocator, store
        self.project_id, self.run_id, self.attempt_id = project_id, run_id, attempt_id

    def _exists(self, ref: Ref, context: AccessContext) -> bool:
        self.store.locator._authorize(ref, context, "read")
        ceiling = self.store.locator._ceiling(ref)
        try:
            with self.store.locator._snapshot(ref, self.store._location(ref), ceiling):
                pass
            return True
        except ContractError as exc:
            if exc.code == "artifact_missing":
                return False
            raise

    def put_verified(self, stream: BinaryIO, expected: Ref, context: AccessContext) -> Ref:
        _checked_ref(expected, self.project_id)
        with self.allocator._permit(
            self.project_id,
            self.run_id,
            self.attempt_id,
            expected,
            "operator",
            lambda: self._exists(expected, context),
        ) as present:
            if present:
                digest = hashlib.sha256()
                total = 0
                while True:
                    try:
                        chunk = stream.read(min(IO_CHUNK_BYTES, expected.size_bytes - total + 1))
                    except ContractError:
                        raise
                    except OSError as error:
                        raise _error(error) from None
                    except Exception:
                        raise ContractError("unavailable") from None
                    if type(chunk) is not bytes:
                        raise ContractError("invalid_schema")
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > expected.size_bytes:
                        raise ContractError("hash_mismatch")
                    digest.update(chunk)
                if total != expected.size_bytes or digest.hexdigest() != expected.digest:
                    raise ContractError("hash_mismatch")
                self.allocator.revalidate_write(
                    self.project_id, self.run_id, self.attempt_id, expected
                )
                return expected
            return self.store.put_verified(
                stream,
                expected,
                context,
                before_publish=lambda: self.allocator.revalidate_write(
                    self.project_id, self.run_id, self.attempt_id, expected
                ),
            )

    def open_verified(self, ref: Ref, context: AccessContext) -> BinaryIO:
        return self.store.open_verified(ref, context)

    def read_verified(self, ref: Ref, context: AccessContext, limit: int) -> VerifiedBytes:
        return self.store.read_verified(ref, context, limit)
