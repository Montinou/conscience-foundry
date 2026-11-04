"""Durable evidence for trusted cooperative local subprocesses, not an OS sandbox."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import signal
import stat
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil
from pydantic import TypeAdapter

from conscience_foundry.contracts.common import ContractError, Digest, Id, Instant, Ref
from conscience_foundry.contracts.execution import ExecutionPlan, StageAttempt
from conscience_foundry.execution import local_runtime
from conscience_foundry.execution.local_contracts import LocalWorkerGrant
from conscience_foundry.execution.local_runtime import verify_runtime
from conscience_foundry.execution.ports import ExecutionGrant, Observation, Submission
from conscience_foundry.execution.worker import Clock
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.local_attempt import LocalAttemptStore, read_local_result

_SCHEMA = "cf.local-process-observation.v1"
_MAX_RECORD = 1024 * 1024
LocalEvidenceSink = Callable[[StageAttempt, str, bytes], Ref]
_WORKER_BOOTSTRAP = """\
import importlib.util, pathlib, runpy, sys
spec = importlib.util.find_spec('conscience_foundry')
paths = None if spec is None else spec.submodule_search_locations
if (paths is None or len(paths) != 1
        or pathlib.Path(paths[0]).resolve() != pathlib.Path(sys.argv[1]).resolve()):
    raise SystemExit(3)
sys.argv = ['conscience_foundry.execution.local_worker', *sys.argv[2:]]
runpy.run_module('conscience_foundry.execution.local_worker', run_name='__main__')
"""


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _exclusive(directory: Path, name: str, value: object) -> None:
    """Persist a private immutable journal entry; an uncertain write stays claimed."""
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        try:
            raw = _json(value)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _read(directory: Path, name: str) -> dict[str, Any]:
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("not regular")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(_MAX_RECORD + 1)
            if len(raw) > _MAX_RECORD:
                raise ValueError("too large")
            data = json.loads(raw)
            if type(data) is not dict:
                raise ValueError("invalid record")
            return data
        finally:
            os.close(fd)
    finally:
        os.close(dfd)


def _grant_dict(grant: LocalWorkerGrant) -> dict[str, str]:
    return {
        "project_id": grant.project_id,
        "run_id": grant.run_id,
        "plan_digest": grant.plan_digest,
        "attempt_id": grant.attempt_id,
        "destination_id": grant.destination_id,
        "expires_at": grant.expires_at,
        "output_scope": base64.b64encode(grant.output_scope).decode("ascii"),
        "nonce": grant.nonce,
    }


def _grant(value: object) -> LocalWorkerGrant:
    if type(value) is not dict or set(value) != {
        "project_id",
        "run_id",
        "plan_digest",
        "attempt_id",
        "destination_id",
        "expires_at",
        "output_scope",
        "nonce",
    }:
        raise ValueError("bad grant")
    if any(type(v) is not str or not v for v in value.values()):
        raise ValueError("bad grant field")
    fields = dict(value)
    fields["output_scope"] = base64.b64decode(fields["output_scope"], validate=True)
    return LocalWorkerGrant(**fields)


def local_staged_refs(plan: ExecutionPlan) -> tuple[Ref, ...]:
    """The exact worker read closure, derived solely from its pinned plan."""
    refs: list[Ref] = []
    for ref in (
        plan.extraction_spec_ref,
        *plan.limits_refs,
        plan.admission_report_ref,
        *plan.input_refs,
    ):
        if ref.project_id != plan.project_id:
            raise ContractError("forbidden")
        if ref not in refs:
            refs.append(ref)
    return tuple(refs)


def _attempt_matches(intent: dict[str, Any], attempt: StageAttempt) -> bool:
    saved = StageAttempt.model_validate(intent["attempt"])
    return (
        saved.project_id,
        saved.plan_id,
        saved.operation_key,
        saved.attempt_id,
        saved.attempt_number,
        saved.reservation_id,
        saved.created_at,
    ) == (
        attempt.project_id,
        attempt.plan_id,
        attempt.operation_key,
        attempt.attempt_id,
        attempt.attempt_number,
        attempt.reservation_id,
        attempt.created_at,
    )


@dataclass(frozen=True)
class LocalInspection:
    state: str
    result_ref: Ref | None
    pid: str | None
    confirmed_termination: bool


class LocalExecutor:
    def __init__(
        self,
        journal_root: Path,
        destination_id: str,
        runtime_digest: Digest,
        clock: Clock,
        evidence: LocalEvidenceSink,
        store_factory: Callable[[StageAttempt, LocalWorkerGrant], LocalAttemptStore],
        *,
        bootstrap_path: Path | None = None,
        bootstrap_digest: Digest | None = None,
    ):
        if (bootstrap_path is None) != (bootstrap_digest is None):
            raise ContractError("forbidden")
        if bootstrap_path is not None:
            try:
                if not isinstance(bootstrap_path, Path) or not bootstrap_path.is_absolute():
                    raise ValueError("bootstrap path")
                TypeAdapter(Digest).validate_python(bootstrap_digest)
            except Exception:
                raise ContractError("forbidden") from None
        self.bootstrap_path, self.bootstrap_digest = bootstrap_path, bootstrap_digest
        self.journal_root = journal_root
        self.destination_id = destination_id
        self.runtime_digest = runtime_digest
        self.clock = clock
        self.evidence = evidence
        self.store_factory = store_factory
        self._waiters: dict[str, threading.Thread] = {}
        self._waiters_lock = threading.Lock()

    def submit(
        self, plan: ExecutionPlan, attempt: StageAttempt, grants: ExecutionGrant
    ) -> Submission:
        if (
            type(plan) is not ExecutionPlan
            or type(attempt) is not StageAttempt
            or type(grants) is not LocalWorkerGrant
        ):
            raise ContractError("forbidden")
        try:
            TypeAdapter(Id).validate_python(attempt.attempt_id)
        except Exception:
            raise ContractError("forbidden") from None
        plan_raw = plan.model_dump_json(by_alias=True, exclude_none=True).encode()
        if (
            grants.project_id != plan.project_id
            or grants.run_id != plan.run_id
            or grants.attempt_id != attempt.attempt_id
            or grants.destination_id != self.destination_id
            or grants.plan_digest != hashlib.sha256(plan_raw).hexdigest()
            or attempt.project_id != plan.project_id
            or attempt.plan_id != plan.plan_id
            or attempt.operation_key != plan.operation_key
            or attempt.state != "dispatching"
            or attempt.remote_call_id is not None
            or not grants.nonce
            or not grants.output_scope
        ):
            raise ContractError("forbidden")
        try:
            TypeAdapter(Instant).validate_python(grants.expires_at)
            if self.clock.now() >= min(grants.expires_at, plan.expires_at, plan.budget.valid_until):
                raise ContractError("authorization_expired")
            verify_runtime(self.runtime_digest)
            if self.clock.now() >= min(grants.expires_at, plan.expires_at, plan.budget.valid_until):
                raise ContractError("authorization_expired")
        except ContractError:
            raise
        except Exception:
            raise ContractError("unavailable") from None
        directory = self.journal_root / attempt.attempt_id
        try:
            rootfd = os.open(self.journal_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.mkdir(attempt.attempt_id, mode=0o700, dir_fd=rootfd)
                os.fsync(rootfd)
            finally:
                os.close(rootfd)
        except FileExistsError:
            raise ContractError("dispatch_unknown") from None
        except OSError:
            raise ContractError("dispatch_unknown") from None
        nonce = secrets.token_hex(32)
        try:
            store = self.store_factory(attempt, grants)
            root = Path(store.root)
            closure = local_staged_refs(plan)
            if store.input_refs != closure:
                raise ContractError("forbidden")
            intent = {
                "project_id": attempt.project_id,
                "attempt_id": attempt.attempt_id,
                "nonce": nonce,
                "plan_digest": grants.plan_digest,
                "config_digest": plan.execution_config_ref.digest,
                "runtime_digest": self.runtime_digest,
                "store_root": str(root),
                "grant": _grant_dict(grants),
                "staged_refs": [
                    r.model_dump(mode="json", by_alias=True, exclude_none=True) for r in closure
                ],
                "plan": plan.model_dump(mode="json", by_alias=True, exclude_none=True),
                "attempt": attempt.model_dump(mode="json", by_alias=True, exclude_none=True),
            }
            _exclusive(directory, "intent.json", intent)
            context = AccessContext(
                plan.project_id, attempt.attempt_id, frozenset({"read", "extract"})
            )
            if store.stage_inputs(context) != closure:
                raise ContractError("forbidden")
            job = {**intent, "journal_root": str(self.journal_root)}
            _exclusive(directory, "job.json", job)
            if self.clock.now() >= min(grants.expires_at, plan.expires_at, plan.budget.valid_until):
                raise ContractError("authorization_expired")
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    _WORKER_BOOTSTRAP,
                    str(Path(local_runtime.__file__).resolve().parent.parent),
                    str(directory / "job.json"),
                    *(
                        [str(self.bootstrap_path), str(self.bootstrap_digest)]
                        if self.bootstrap_path is not None
                        else []
                    ),
                ],
                env={"PATH": os.defpath, "PYTHONNOUSERSITE": "1"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
            created = psutil.Process(process.pid).create_time()
            _exclusive(
                directory,
                "process.json",
                {"pid": process.pid, "create_time": created, "nonce": nonce},
            )
            self._start_waiter(directory, attempt, process.wait)
            return Submission(str(process.pid), True)
        except Exception:
            # A spawn or journal write may have happened: no retry or invented no-effect.
            return Submission(None, None)

    def _start_waiter(
        self, directory: Path, attempt: StageAttempt, wait: Callable[[], int | None]
    ) -> None:
        """Record a real wait result while this controller owns a waitable process handle."""
        with self._waiters_lock:
            if attempt.attempt_id in self._waiters:
                return

            def watch() -> None:
                try:
                    code = wait()
                    if type(code) is not int:
                        return  # non-child wait reports no exit status
                    intent = _read(directory, "intent.json")
                    parent = _read(directory, "process.json")
                    child = _read(directory, "handshake.json")
                    if (
                        not _attempt_matches(intent, attempt)
                        or intent.get("project_id") != attempt.project_id
                        or intent.get("attempt_id") != attempt.attempt_id
                        or parent != child
                        or set(parent) != {"pid", "create_time", "nonce"}
                        or parent.get("nonce") != intent.get("nonce")
                        or type(parent.get("pid")) is not int
                        or type(parent.get("create_time")) not in (int, float)
                    ):
                        return
                    _exclusive(directory, "exit.json", {**parent, "exit_code": code})
                except Exception:
                    # Missing handshake, unavailable wait, or uncertain durable write is unknown.
                    return

            waiter = threading.Thread(target=watch, name="cf-local-waiter", daemon=True)
            self._waiters[attempt.attempt_id] = waiter
            waiter.start()

    def _identity(
        self, directory: Path, attempt: StageAttempt
    ) -> tuple[psutil.Process, dict[str, Any]]:
        intent = _read(directory, "intent.json")
        parent = _read(directory, "process.json")
        child = _read(directory, "handshake.json")
        if (
            intent.get("project_id") != attempt.project_id
            or intent.get("attempt_id") != attempt.attempt_id
            or not _attempt_matches(intent, attempt)
            or type(intent.get("nonce")) is not str
            or not intent["nonce"]
            or set(parent) != {"pid", "create_time", "nonce"}
            or parent != child
            or parent.get("nonce") != intent["nonce"]
            or type(parent.get("pid")) is not int
            or parent["pid"] <= 0
            or type(parent.get("create_time")) not in (int, float)
        ):
            raise ValueError("unverified identity")
        process = psutil.Process(parent["pid"])
        if process.create_time() != parent["create_time"] or not process.is_running():
            raise ValueError("pid reused or exited")
        return process, intent

    def _finish(
        self, attempt: StageAttempt, action: str, state: str, result: Ref | None = None
    ) -> Observation:
        data = _json(
            {
                "schemaVersion": _SCHEMA,
                "attemptId": attempt.attempt_id,
                "action": action,
                "observedState": state,
            }
        )
        try:
            ref = self.evidence(attempt, _SCHEMA, data)
            if type(ref) is not Ref:
                raise ValueError("invalid evidence")
            return Observation(state, result, None, ref)  # type: ignore[arg-type]
        except Exception:
            raise ContractError("unavailable") from None

    def observe(self, attempt: StageAttempt) -> Observation:
        inspection = self._inspect(attempt)
        return self._finish(attempt, "observe", inspection.state, inspection.result_ref)

    def _inspect(self, attempt: StageAttempt) -> LocalInspection:
        standing = attempt.state == "cancel_requested"
        try:
            TypeAdapter(Id).validate_python(attempt.attempt_id)
            directory = self.journal_root / attempt.attempt_id
            intent = _read(directory, "intent.json")
            if (
                intent.get("project_id") != attempt.project_id
                or intent.get("attempt_id") != attempt.attempt_id
                or not _attempt_matches(intent, attempt)
            ):
                raise ValueError("wrong attempt")
            grant = _grant(intent["grant"])
            plan = ExecutionPlan.model_validate(intent["plan"])
            saved_attempt = StageAttempt.model_validate(intent["attempt"])
            plan_digest = hashlib.sha256(
                plan.model_dump_json(by_alias=True, exclude_none=True).encode()
            ).hexdigest()
            if (
                grant.project_id != attempt.project_id
                or grant.attempt_id != attempt.attempt_id
                or grant.run_id != plan.run_id
                or grant.plan_digest != plan_digest
                or grant.destination_id != self.destination_id
                or intent.get("plan_digest") != plan_digest
                or intent.get("config_digest") != plan.execution_config_ref.digest
                or intent.get("runtime_digest") != self.runtime_digest
                or (
                    saved_attempt.project_id,
                    saved_attempt.plan_id,
                    saved_attempt.attempt_id,
                    saved_attempt.operation_key,
                )
                != (attempt.project_id, attempt.plan_id, attempt.attempt_id, attempt.operation_key)
                or (plan.project_id, plan.plan_id, plan.operation_key)
                != (attempt.project_id, attempt.plan_id, attempt.operation_key)
                or intent.get("staged_refs")
                != [
                    r.model_dump(mode="json", by_alias=True, exclude_none=True)
                    for r in local_staged_refs(plan)
                ]
            ):
                raise ValueError("wrong grant or pinned configuration")
            found = read_local_result(Path(intent["store_root"]), grant)
            if found is not None:
                result, ref = found
                if (result.project_id, result.plan_id, result.attempt_id, result.operation_key) != (
                    attempt.project_id,
                    attempt.plan_id,
                    attempt.attempt_id,
                    attempt.operation_key,
                ):
                    raise ValueError("wrong result")
            try:
                terminal = _read(directory, "exit.json")
            except FileNotFoundError:
                terminal = None
            if terminal is not None:
                parent = _read(directory, "process.json")
                child = _read(directory, "handshake.json")
                if (
                    parent != child
                    or parent.get("nonce") != intent.get("nonce")
                    or set(terminal) != {"pid", "create_time", "nonce", "exit_code"}
                    or {k: terminal[k] for k in ("pid", "create_time", "nonce")} != parent
                    or type(terminal["exit_code"]) is not int
                    or type(parent.get("pid")) is not int
                    or parent["pid"] <= 0
                    or type(parent.get("create_time")) not in (int, float)
                ):
                    raise ValueError("invalid exit evidence")
                if found is not None and terminal["exit_code"] == 0:
                    return LocalInspection(result.status, ref, str(parent["pid"]), True)
                if found is not None:
                    return LocalInspection("unknown_outcome", None, str(parent["pid"]), False)
                sent: dict[str, Any] | None
                request: dict[str, Any] | None
                try:
                    sent = _read(directory, "signal_sent.json")
                    request = _read(directory, "cancel.json")
                except FileNotFoundError:
                    sent = request = None
                if (
                    terminal["exit_code"] == -signal.SIGTERM
                    and sent == parent
                    and request == {"nonce": intent.get("nonce")}
                ):
                    return LocalInspection("cancelled", None, str(parent["pid"]), True)
                return LocalInspection("unknown_outcome", None, str(parent["pid"]), False)
            process, _ = self._identity(directory, attempt)
            return LocalInspection(
                "cancel_requested" if standing else "running", None, str(process.pid), False
            )
        except Exception:
            return LocalInspection(
                "cancel_requested" if standing else "unknown_outcome", None, None, False
            )

    def _historical_pid(self, attempt: StageAttempt) -> str | None:
        """Correlate the committed ID with the original launch record, without claiming liveness."""
        try:
            TypeAdapter(Id).validate_python(attempt.attempt_id)
            directory = self.journal_root / attempt.attempt_id
            intent = _read(directory, "intent.json")
            process = _read(directory, "process.json")
            if (
                intent.get("project_id") != attempt.project_id
                or intent.get("attempt_id") != attempt.attempt_id
                or not _attempt_matches(intent, attempt)
                or set(process) != {"pid", "create_time", "nonce"}
                or type(process.get("pid")) is not int
                or process["pid"] <= 0
                or type(process.get("create_time")) not in (int, float)
                or type(intent.get("nonce")) is not str
                or not intent["nonce"]
                or process.get("nonce") != intent["nonce"]
                or attempt.remote_call_id != str(process["pid"])
            ):
                return None
            return str(process["pid"])
        except Exception:
            return None

    def _inspect_cancel(self, attempt: StageAttempt) -> LocalInspection:
        try:
            TypeAdapter(Id).validate_python(attempt.attempt_id)
            directory = self.journal_root / attempt.attempt_id
            intent = _read(directory, "intent.json")
            parent = _read(directory, "process.json")
            child = _read(directory, "handshake.json")
            request = _read(directory, "cancel.json")
            sent = _read(directory, "signal_sent.json")
            if (
                intent.get("project_id") != attempt.project_id
                or intent.get("attempt_id") != attempt.attempt_id
                or not _attempt_matches(intent, attempt)
                or parent != child
                or sent != parent
                or set(parent) != {"pid", "create_time", "nonce"}
                or type(parent.get("pid")) is not int
                or parent["pid"] <= 0
                or type(parent.get("create_time")) not in (int, float)
                or type(intent.get("nonce")) is not str
                or not intent["nonce"]
                or parent.get("nonce") != intent["nonce"]
                or request != {"nonce": intent["nonce"]}
            ):
                raise ValueError("invalid cancellation evidence")
            return LocalInspection("cancel_requested", None, str(parent["pid"]), False)
        except Exception:
            return LocalInspection("unknown_outcome", None, None, False)

    def cancel(self, attempt: StageAttempt) -> Observation:
        try:
            TypeAdapter(Id).validate_python(attempt.attempt_id)
            directory = self.journal_root / attempt.attempt_id
            intent = _read(directory, "intent.json")
            if (
                intent.get("project_id") != attempt.project_id
                or intent.get("attempt_id") != attempt.attempt_id
                or not _attempt_matches(intent, attempt)
            ):
                raise ValueError("wrong attempt")
            try:
                _exclusive(directory, "cancel.json", {"nonce": intent["nonce"]})
            except FileExistsError:
                if _read(directory, "cancel.json") != {"nonce": intent["nonce"]}:
                    raise ValueError("conflicting cancellation") from None
            process, _ = self._identity(directory, attempt)
            identity = _read(directory, "process.json")
            try:
                sent = _read(directory, "signal_sent.json")
            except FileNotFoundError:
                sent = None
            if sent is None:
                process.terminate()  # psutil rechecks PID reuse before the signal.
                _exclusive(directory, "signal_sent.json", identity)
            elif sent != identity:
                raise ValueError("conflicting signal evidence")
            self._start_waiter(directory, attempt, process.wait)
            return self._finish(attempt, "cancel", "cancel_requested")
        except Exception:
            return self._finish(attempt, "cancel", "unknown_outcome")
