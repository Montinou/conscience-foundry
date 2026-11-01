"""Live Modal: the session that spawns and watches the one function, and the container's entry.

Trust model:

* ``modal`` and ``boto3`` are imported lazily, here and in ``storage.r2`` only: importing this
  module never loads an SDK, opens a connection or reads a credential. Offline tests inject a
  fake ``modal`` module through ``sys.modules``.
* ``LiveModalSession`` is the ``ModalSdk`` the executor drives. It opens one ephemeral app for
  the profile the operator named and stops it on every exit, an interrupt included. Before each
  spawn it reads the function's options back from the platform and refuses (``unsupported_
  capability``) unless they are exactly the ones the capability record relies on: no retries,
  non-preemptible, one container, the configured timeouts.
* SDK exceptions are never copied: each is mapped to a ``ModalPoll`` state, or to a stable
  ``ContractError`` code. Only an exception that proves the function itself ended without
  publishing a result (a remote error, or a worker ``ContractError`` whose code is in
  ``_PROVEN_NO_RESULT``) is a ``remote_error``; every other failure, the worker's ambiguous codes
  (``unavailable``, ``dispatch_unknown``) included, is unavailable, so the executor settles it as
  an unknown outcome and never as a failed one.
* ``poll_until_terminal`` waits at most until the deadline measured from the spawn, then hands
  the cancel to the caller's ``on_deadline`` callback (the control side's ``cancel_attempt``,
  holding the session's private ``DeadlineToken``) and makes sure the call and its containers are
  terminated. The session keeps a record of its own calls and serves no other.
* ``capability_record_from_live`` builds, offline, the capability record the executor's gate
  reads: only from the operator's configuration, the image and code digests, and evidence records
  of what was declared. It claims nothing the live preflight has not still to confirm.
* ``container_entry`` is the function the container runs. Its input is the plan, the attempt, the
  transient grants and the staging labels; the grants carry two temporary R2 credentials, one
  read-only and one scoped to the attempt prefix. The SDK loggers are quieted before any client is
  built, the store is the worker-mode staging store gated by what the grants cover, and the lease
  and the bound write scope are both required. It returns the manifest ``Ref`` JSON or exactly
  ``{"duplicate": true}``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType, TracebackType
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import TypeAdapter, ValidationError

from conscience_foundry.contracts.common import ContractError, Digest, Id, Instant, Ref
from conscience_foundry.contracts.execution import ExecutionPlan
from conscience_foundry.execution.capabilities import CapabilityRecord
from conscience_foundry.execution.modal_adapter import EvidenceSink, ModalPoll
from conscience_foundry.execution.ports import TransportGrants
from conscience_foundry.execution.worker import (
    Clock,
    DuplicateExecution,
    _bootstrap,
    _wire,
    run_worker,
)
from conscience_foundry.storage.r2 import SplitR2Client, r2_client
from conscience_foundry.storage.staging_s3 import (
    S3StagingStore,
    StagingConfig,
    credential_scopes,
    grant_storage_gate,
)

if TYPE_CHECKING:
    from conscience_foundry.cli.config import LiveSettings

R2_REGION = "auto"
"""R2 has one region name; it is part of the provider's contract, not an operator choice."""
MIN_SDK = (1, 2, 3)
STAGING_FIELDS = (
    "bucket",
    "prefix",
    "endpoint_id",
    "credential_source",
    "max_object_bytes",
    "transfer_chunk_bytes",
    "max_read_resumes",
    "max_parts",
    "grant_ttl_seconds",
    "checksum_mode",
)
"""The ``StagingConfig`` fields the operator sets; the rest come from the grants and R2 itself."""
SDK_LOGGERS = ("botocore", "boto3", "urllib3")
PACKAGE = "conscience_foundry"

_PAYLOAD_KEYS = frozenset({"plan", "attempt", "grants", "staging", "r2_account_id"})
_GRANT_KEYS = frozenset(
    {
        "project_id",
        "plan_digest",
        "attempt_id",
        "destination_id",
        "expires_at",
        "material",
        "output_scope",
    }
)
_CREDENTIAL_KEYS = frozenset({"accessKeyId", "secretAccessKey", "sessionToken"})
_ACCOUNT = re.compile(r"^[A-Za-z0-9-]{1,63}$")
_VERSION = re.compile(r"^([0-9]+)\.([0-9]+)\.([0-9]+)")
_TIMEOUT_OPTIONS = ("connect_timeout", "read_timeout")
DUPLICATE = json.dumps({"duplicate": True}).encode("utf-8")
_DIGEST = TypeAdapter(Digest)
_MINT = object()


# -- configuration helpers ----------------------------------------------------------------


def staging_config(fields: Mapping[str, Any], destination_id: str) -> StagingConfig:
    """The ``StagingConfig`` for the operator's staging fields and the grants' destination.

    The store id is the destination label and the region is R2's fixed ``auto``. Exactly the
    operator fields are accepted: a missing or extra one is ``invalid_schema``.
    """
    if not isinstance(fields, Mapping) or set(fields) != set(STAGING_FIELDS):
        raise ContractError("invalid_schema")
    return StagingConfig(
        destination_id=destination_id,
        store_id=destination_id,
        region=R2_REGION,
        **{name: fields[name] for name in STAGING_FIELDS},
    )


def live_payload_extras(settings: LiveSettings) -> Mapping[str, object]:
    """What the live wiring adds to the spawn payload: labels and bounds, never a secret.

    The parent key id and API token are named by environment variables the control side alone
    reads; neither the names nor the values ride along.
    """
    return {
        "staging": {name: getattr(settings.staging, name) for name in STAGING_FIELDS},
        "r2_account_id": settings.r2_account_id,
    }


@dataclass(frozen=True)
class LiveFunctionOptions:
    """The one function's options: the operator's bounds plus the fixed safety options.

    ``retries``, ``nonpreemptible`` and ``max_containers`` have one acceptable value each; a
    caller cannot loosen them.
    """

    app_name: str
    function_name: str
    python_version: str
    requirements_path: str
    cpu_milli: int
    memory_mib: int
    startup_timeout_seconds: int
    execution_timeout_seconds: int
    retries: int = 0
    nonpreemptible: bool = True
    max_containers: int = 1

    def __post_init__(self) -> None:
        if self.retries != 0 or self.nonpreemptible is not True or self.max_containers != 1:
            raise ContractError("unsupported_capability")
        for name in ("app_name", "function_name", "python_version", "requirements_path"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ContractError("invalid_schema")
        for name in (
            "cpu_milli",
            "memory_mib",
            "startup_timeout_seconds",
            "execution_timeout_seconds",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ContractError("invalid_schema")

    @classmethod
    def from_settings(cls, settings: LiveSettings) -> Self:
        return cls(
            app_name=settings.app_name,
            function_name=settings.function_name,
            python_version=settings.python_version,
            requirements_path=settings.requirements_path,
            cpu_milli=settings.cpu_milli,
            memory_mib=settings.memory_mib,
            startup_timeout_seconds=settings.startup_timeout_seconds,
            execution_timeout_seconds=settings.execution_timeout_seconds,
        )

    def function_kwargs(self) -> dict[str, Any]:
        """Exactly what is passed to ``app.function``."""
        return {
            "name": self.function_name,
            "serialized": True,
            "cpu": self.cpu_milli / 1000,
            "memory": self.memory_mib,
            "retries": self.retries,
            "nonpreemptible": self.nonpreemptible,
            "max_containers": self.max_containers,
            "timeout": self.execution_timeout_seconds,
            "startup_timeout": self.startup_timeout_seconds,
        }


LEASE_TEST_ID = "tests/adapters/test_lease.py::test_two_workers_one_executes"
"""The offline test that shows two workers on one attempt execute it once."""
CAPABILITY_SOURCE_SCHEMA = "cf.capability-source.v1"
RESTART_SEMANTICS = (
    "The function is registered with retries=0, nonpreemptible=True and max_containers=1, so the "
    "platform neither retries the call nor restarts its container after a crash or a preemption: "
    "max_platform_restarts is 0. The live session reads these options back from the platform "
    "before every spawn and refuses unless they are exactly these."
)


def requirements_sha256(path: str | Path) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        raise ContractError("config_invalid") from None


def image_spec(options: LiveFunctionOptions) -> dict[str, object]:
    """The image's identity: the builder, the Python version and the pinned requirements."""
    return {
        "builder": "debian_slim",
        "python_version": options.python_version,
        "requirements_sha256": requirements_sha256(options.requirements_path),
    }


def canonical_json(value: object) -> bytes:
    """Sorted keys, no whitespace, ASCII only: the same value is always the same bytes."""
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError):
        raise ContractError("invalid_schema") from None


def code_digest(root: str | Path | None = None) -> str:
    """SHA-256 over the sorted (path, bytes) pairs of every ``*.py`` under the package root.

    Each entry is the relative POSIX path, a NUL, the byte count and the bytes, so the boundary
    between a path and its content is part of the digest. A link is refused rather than followed.
    """
    base = Path(root) if root is not None else Path(__file__).resolve().parent.parent
    if not base.is_dir():
        raise ContractError("config_invalid")
    entries: list[tuple[str, Path]] = []
    for path in base.rglob("*.py"):
        if path.is_symlink():
            raise ContractError("unsafe_path")
        if path.is_file():
            entries.append((path.relative_to(base).as_posix(), path))
    if not entries:
        raise ContractError("config_invalid")
    digest = hashlib.sha256()
    for relative, path in sorted(entries):
        try:
            data = path.read_bytes()
        except OSError:
            raise ContractError("config_invalid") from None
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _instant(moment: datetime) -> Instant:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def capability_record_from_live(
    config: LiveSettings,
    project_id: Id,
    execution_config_ref: Ref,
    sdk_version: str,
    image_spec: Mapping[str, object],
    code_digest: Digest,
    now: Instant,
    evidence: EvidenceSink,
) -> CapabilityRecord:
    """The capability record for the ephemeral deployment the operator's config describes.

    Offline: nothing is read from the platform. The bounds are the configured ones (GPU and
    function retries are fixed at zero, platform restarts at zero because the function is
    non-preemptible with retries off), ``total_bound_seconds`` is the configured sum including the
    cancel margin, and the record is valid for ``capability_valid_seconds`` from ``now``. The
    image digest is the SHA-256 of the canonical image spec and the deployment version is derived
    from the code digest, so a record is evidence for exactly one image and one code tree.

    Three evidence records are stored through ``evidence`` and cited: the declared options, the
    restart-semantics statement and the id of the lease test. Whether the platform honors them is
    for the live preflight; this function never asserts it.
    """
    try:
        _DIGEST.validate_python(code_digest)
        valid_until = _instant(_parse(now) + timedelta(seconds=config.capability_valid_seconds))
        image_digest = hashlib.sha256(canonical_json(image_spec)).hexdigest()
        declared = {
            "kind": "declared_function_options",
            "sdkVersion": sdk_version,
            "retries": 0,
            "nonpreemptible": True,
            "maxContainers": 1,
            "cpuMilli": config.cpu_milli,
            "memoryMib": config.memory_mib,
            "schedulingTimeoutSeconds": config.scheduling_timeout_seconds,
            "startupTimeoutSeconds": config.startup_timeout_seconds,
            "executionTimeoutSeconds": config.execution_timeout_seconds,
            "cancelMarginSeconds": config.cancel_margin_seconds,
            "totalBoundSeconds": config.total_bound_seconds,
            "imageSpec": dict(image_spec),
            "codeDigest": code_digest,
        }
        statements = (
            declared,
            {"kind": "restart_semantics", "statement": RESTART_SEMANTICS},
            {"kind": "lease_test", "testId": LEASE_TEST_ID},
        )
    except ContractError:
        raise
    except Exception:
        raise ContractError("invalid_schema") from None
    refs: list[Ref] = []
    for statement in statements:
        try:
            ref = evidence(CAPABILITY_SOURCE_SCHEMA, canonical_json(statement))
        except Exception:
            raise ContractError("unavailable") from None
        if type(ref) is not Ref:
            raise ContractError("unavailable")
        refs.append(ref)
    try:
        return CapabilityRecord.model_validate(
            {
                "schema_version": "cf.modal-capability-record.v1",
                "project_id": project_id,
                "execution_config_ref": execution_config_ref,
                "sdk_version": sdk_version,
                "deployment_version": "ephemeral-" + code_digest[:16],
                "image_digest": image_digest,
                "code_digest": code_digest,
                "cpu_milli": config.cpu_milli,
                "memory_mib": config.memory_mib,
                "gpu_count": 0,
                "function_retries": 0,
                "startup_timeout_seconds": config.startup_timeout_seconds,
                "scheduling_timeout_seconds": config.scheduling_timeout_seconds,
                "execution_timeout_seconds": config.execution_timeout_seconds,
                "platform_restart_bound": "bounded",
                "max_platform_restarts": 0,
                "total_bound_seconds": config.total_bound_seconds,
                "cancellation": "terminates_containers",
                "deadline_enforcement": "entry_and_every_bounded_step",
                "valid_until": valid_until,
                "source_evidence_refs": tuple(refs),
            }
        )
    except (ValidationError, ValueError, TypeError):
        raise ContractError("invalid_schema") from None


# -- payload ------------------------------------------------------------------------------


def _b64(data: object) -> str:
    if type(data) is not bytes:
        raise ContractError("invalid_schema")
    return base64.b64encode(data).decode("ascii")


def encode_payload(payload: Mapping[str, object]) -> bytes:
    """The one function argument: JSON with the byte fields in base64.

    The keys are the executor's (``plan_bytes``, ``attempt_bytes``, ``grants``) plus the live
    extras (``staging``, ``r2_account_id``); any other shape is refused.
    """
    try:
        if not isinstance(payload, Mapping) or set(payload) != {
            "plan_bytes",
            "attempt_bytes",
            "grants",
            "staging",
            "r2_account_id",
        }:
            raise ContractError("invalid_schema")
        grants = payload["grants"]
        if not isinstance(grants, Mapping) or set(grants) != _GRANT_KEYS:
            raise ContractError("invalid_schema")
        material = grants["material"]
        if not isinstance(material, (list, tuple)):
            raise ContractError("invalid_schema")
        encoded_grants = {
            name: grants[name]
            for name in ("project_id", "plan_digest", "attempt_id", "destination_id", "expires_at")
        }
        encoded_grants["material"] = [_b64(piece) for piece in material]
        encoded_grants["output_scope"] = _b64(grants["output_scope"])
        document = {
            "plan": _b64(payload["plan_bytes"]),
            "attempt": _b64(payload["attempt_bytes"]),
            "grants": encoded_grants,
            "staging": dict(payload["staging"]),  # type: ignore[call-overload]
            "r2_account_id": payload["r2_account_id"],
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except ContractError:
        raise
    except Exception:
        raise ContractError("invalid_schema") from None


# -- the session --------------------------------------------------------------------------


def _parse(value: Instant) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def _sdk_version(version: object) -> tuple[int, ...] | None:
    found = _VERSION.match(version) if isinstance(version, str) else None
    return tuple(int(part) for part in found.groups()) if found else None


def _load_modal() -> Any:
    try:
        import modal
    except ImportError:
        raise ContractError("unsupported_capability") from None
    version = _sdk_version(getattr(modal, "__version__", None))
    if version is None or version < MIN_SDK:
        raise ContractError("unsupported_capability")
    return modal


@dataclass(frozen=True)
class CallRecord:
    """What this session has seen of one call it spawned; it never describes another's.

    ``completed``: the SDK returned a value. ``terminated``: a cancel that also terminates the
    containers was accepted. ``cancelled``: the SDK reported the call cancelled.
    """

    spawned_at: Instant
    completed: bool = False
    terminated: bool = False
    cancelled: bool = False


# Worker failures that are decided before or independently of any store answer: the result pointer
# was not published. Everything else (a put or claim whose answer was lost, ``unavailable``,
# ``dispatch_unknown``) may have landed and is an unknown outcome.
_PROVEN_NO_RESULT = frozenset(
    {"invalid_schema", "forbidden", "hash_mismatch", "limit_exceeded", "authorization_expired"}
)


class DeadlineToken:
    """The capability to cancel a call at its deadline; one per session, matched by identity.

    Only ``LiveModalSession`` makes one (the constructor takes a module-private mint), it has no
    value to copy, compare or serialize, and the control side accepts it only when it is the very
    object its context carries. It carries no secret: it proves who is asking, not what is allowed.
    """

    __slots__ = ()

    def __init__(self, mint: object) -> None:
        if mint is not _MINT:
            raise ContractError("forbidden")

    def __repr__(self) -> str:
        return "DeadlineToken()"

    def __copy__(self) -> Self:
        raise TypeError("a deadline token cannot be copied")

    def __deepcopy__(self, memo: object) -> Self:
        raise TypeError("a deadline token cannot be copied")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("a deadline token cannot be serialized")


class LiveModalSession:
    """An open ephemeral app for one profile, and the ``ModalSdk`` over its one function."""

    def __init__(
        self, profile: str, options: LiveFunctionOptions, deadline_seconds: int, clock: Clock
    ) -> None:
        if (
            type(profile) is not str
            or not profile
            or type(options) is not LiveFunctionOptions
            or type(deadline_seconds) is not int
            or deadline_seconds <= 0
            or not callable(getattr(clock, "now", None))
        ):
            raise ContractError("invalid_schema")
        self.profile = profile
        self.options = options
        self.deadline_seconds = deadline_seconds
        self._clock = clock
        self._deadline_token = DeadlineToken(_MINT)
        self._records: dict[str, CallRecord] = {}
        self._state: Literal["new", "open", "closed"] = "new"
        self._modal: Any = None
        self._client: Any = None
        self._function: Any = None
        self._run: Any = None

    def __repr__(self) -> str:
        return f"LiveModalSession(profile={self.profile!r}, state={self._state!r})"

    @property
    def deadline_token(self) -> DeadlineToken:
        """What the control side holds to cancel this session's calls at their deadline."""
        return self._deadline_token

    @property
    def records(self) -> Mapping[str, CallRecord]:
        return MappingProxyType(self._records)

    # -- lifecycle ------------------------------------------------------------------

    def __enter__(self) -> Self:
        if self._state != "new":
            raise ContractError("unavailable")
        self._state = "closed"  # until the app is really running
        modal = _load_modal()
        try:
            values = tuple(
                modal.config.config.get(key, profile=self.profile, use_env=False)
                for key in ("token_id", "token_secret")
            )
            if not all(type(value) is str and value for value in values):
                raise ContractError("credential_unavailable")
        except Exception:
            raise ContractError("credential_unavailable") from None
        try:
            client = modal.Client.from_credentials(*values)
            options = self.options
            image = (
                modal.Image.debian_slim(options.python_version)
                .pip_install_from_requirements(options.requirements_path)
                .add_local_python_source(PACKAGE)
            )
            app = modal.App(options.app_name, image=image)
            function = app.function(**options.function_kwargs())(container_entry)
            run = app.run(client=client)
            run.__enter__()
        except Exception:
            raise ContractError("unavailable") from None
        self._modal, self._client, self._function, self._run = modal, client, function, run
        self._state = "open"
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        run, self._run = self._run, None
        self._state = "closed"
        if run is None:
            return
        try:
            run.__exit__(exc_type, exc, traceback)
        except Exception:
            if exc is None:  # an interrupt in flight is the answer; otherwise say it did not stop
                raise ContractError("unavailable") from None

    def _require_open(self) -> None:
        if self._state != "open":
            raise ContractError("unavailable")

    def _now(self) -> Instant:
        try:
            now = self._clock.now()
            _parse(now)
        except Exception:
            raise ContractError("unavailable") from None
        return now

    # -- ModalSdk -------------------------------------------------------------------

    def _verify_options(self) -> None:
        """Read the function's options back; anything but exactly the configured ones refuses."""
        options = self.options
        wanted: dict[str, object] = {
            "timeout": options.execution_timeout_seconds,
            "startup_timeout": options.startup_timeout_seconds,
            "max_retries": options.retries,
            "nonpreemptible": options.nonpreemptible,
            "max_containers": options.max_containers,
            "cpu": options.cpu_milli / 1000,
            "memory_mib": options.memory_mib,
        }
        try:
            info = self._function.info(refresh=True)  # a method; refresh asks the server
            settings = self._function.autoscaler.settings()
            observed: dict[str, object] = {
                "timeout": info.timeout,
                "startup_timeout": info.startup_timeout,
                "max_retries": info.max_retries,
                "nonpreemptible": info.nonpreemptible,
                "max_containers": settings.max_containers,
                "cpu": info.cpu,
                "memory_mib": info.memory_mib,
            }
        except Exception:
            raise ContractError("unsupported_capability") from None
        for name, expected in wanted.items():
            got = observed[name]
            if isinstance(got, bool) != isinstance(expected, bool) or got != expected:
                raise ContractError("unsupported_capability")

    def spawn(self, function: str, payload: Mapping[str, object]) -> str:
        self._require_open()
        if function != self.options.function_name:
            raise ContractError("forbidden")
        encoded = encode_payload(payload)
        self._verify_options()
        spawned_at = self._now()  # before the call: the deadline is never later than the spawn
        try:
            call = self._function.spawn(encoded)
            call_id = call.object_id
        except Exception:
            raise ContractError("dispatch_unknown") from None  # it may have been delivered
        if type(call_id) is not str or not call_id or call_id in self._records:
            raise ContractError("dispatch_unknown")
        self._records[call_id] = CallRecord(spawned_at)
        return call_id

    def _own(self, call_id: str) -> CallRecord:
        self._require_open()
        record = self._records.get(call_id) if type(call_id) is str else None
        if record is None:
            raise ContractError("forbidden")
        return record

    def _update(self, call_id: str, **changes: Any) -> None:
        self._records[call_id] = replace(self._records[call_id], **changes)

    def _poll(self, call_id: str, wait: float) -> ModalPoll:
        errors = self._modal.exception
        try:
            call = self._modal.FunctionCall.from_id(call_id, client=self._client)
            value = call.get(timeout=wait)
        except errors.InputCancellation:
            self._update(call_id, cancelled=True)
            return ModalPoll("cancelled")
        except errors.OutputExpiredError:
            return ModalPoll("output_expired")
        except errors.FunctionTimeoutError:
            return ModalPoll("timed_out")
        except (TimeoutError, errors.TimeoutError):
            # ``FunctionCall.get(timeout=...)`` raises the built-in TimeoutError while the call
            # still runs; the SDK's own family (FunctionTimeoutError, OutputExpiredError) was
            # matched above, so what is left is "not finished yet".
            return ModalPoll("pending")
        except errors.RemoteError:
            return ModalPoll("remote_error")
        except ContractError as error:
            if error.code in _PROVEN_NO_RESULT:
                return ModalPoll("remote_error")
            # Anything else (a storage put that timed out, a lease that may be held) may have
            # published the result: unknown, never failed.
            raise ContractError("unavailable") from None
        except Exception:
            # Transport and platform failures prove nothing about the call: unknown, not failed.
            raise ContractError("unavailable") from None
        self._update(call_id, completed=True)
        return ModalPoll("completed", value if type(value) is bytes else None)

    def poll(self, call_id: str) -> ModalPoll:
        self._own(call_id)
        return self._poll(call_id, 0)

    def cancel(self, call_id: str) -> None:
        self._own(call_id)
        try:
            self._modal.FunctionCall.from_id(call_id, client=self._client).cancel(
                terminate_containers=True
            )
        except Exception:
            raise ContractError("dispatch_unknown") from None  # delivered or not: unknown
        self._update(call_id, terminated=True)

    def poll_until_terminal(
        self, call_id: str, on_deadline: Callable[[], None] | None = None
    ) -> ModalPoll:
        """Wait for the call to end; at its deadline cancel it and report what the SDK then says.

        Each wait is bounded by the time left, so there is no polling interval to configure. The
        deadline is ``deadline_seconds`` after the spawn. At the deadline ``on_deadline`` is called
        once: the control side passes a callback that runs ``cancel_attempt`` with this session's
        token, so the cancel is recorded in the ledger before it goes out (the executor's cancel
        then reaches ``cancel``). The session does not rely on it: a call it has not terminated by
        then is cancelled here, and a callback that failed is reported as ``unavailable`` after
        that. Without a callback the session cancels on its own. A cancel that cannot be delivered
        is ``dispatch_unknown``; a cancel that is still taking effect reports ``pending``.
        """
        record = self._own(call_id)
        deadline = _parse(record.spawned_at) + timedelta(seconds=self.deadline_seconds)
        while True:
            remaining = (deadline - _parse(self._now())).total_seconds()
            if remaining <= 0:
                failed = False
                if on_deadline is not None:
                    try:
                        on_deadline()
                    except Exception:
                        failed = True  # the SDK's answer, not the callback's message, is shown
                if not self._records[call_id].terminated:
                    self.cancel(call_id)
                outcome = self._poll(call_id, 0)
                if failed:
                    raise ContractError("unavailable")
                return outcome
            outcome = self._poll(call_id, remaining)
            if outcome.state != "pending":
                return outcome


# -- the container ------------------------------------------------------------------------


class _SystemClock:
    def now(self) -> Instant:
        moment = datetime.now(UTC)
        return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _container_clock() -> Clock:
    return _SystemClock()


def _nonce() -> str:
    return secrets.token_hex(16)


def _quiet_sdk_loggers() -> None:
    """Keep the SDK's DEBUG records, which can carry request headers and tokens, off every sink.

    A logger the process already set quieter than WARNING is left alone.
    """
    for name in SDK_LOGGERS:
        logger = logging.getLogger(name)
        if logger.level < logging.WARNING:  # NOTSET (0) inherits, so it counts as not quiet
            logger.setLevel(logging.WARNING)


def _unb64(value: object) -> bytes:
    if type(value) is not str:
        raise ContractError("invalid_schema")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ContractError("invalid_schema") from None


@dataclass(frozen=True)
class _Request:
    plan_bytes: bytes
    attempt_bytes: bytes
    grants: TransportGrants
    staging: Mapping[str, Any]
    account_id: str


def _decode(payload: bytes) -> _Request:
    try:
        if type(payload) is not bytes:
            raise ContractError("invalid_schema")
        document = json.loads(payload)
        if not isinstance(document, dict) or set(document) != _PAYLOAD_KEYS:
            raise ContractError("invalid_schema")
        raw = document["grants"]
        if not isinstance(raw, dict) or set(raw) != _GRANT_KEYS:
            raise ContractError("invalid_schema")
        material = raw["material"]
        if not isinstance(material, list) or len(material) != 2:
            raise ContractError("invalid_schema")  # exactly the read-only and the read-write piece
        texts = [
            raw[name] for name in ("project_id", "plan_digest", "attempt_id", "destination_id")
        ]
        if not all(type(text) is str for text in texts) or type(raw["expires_at"]) is not str:
            raise ContractError("invalid_schema")
        staging, account = document["staging"], document["r2_account_id"]
        if not isinstance(staging, dict) or type(account) is not str or not _ACCOUNT.match(account):
            raise ContractError("invalid_schema")
        grants = TransportGrants(
            project_id=raw["project_id"],
            plan_digest=raw["plan_digest"],
            attempt_id=raw["attempt_id"],
            destination_id=raw["destination_id"],
            expires_at=raw["expires_at"],
            material=tuple(_unb64(piece) for piece in material),
            output_scope=_unb64(raw["output_scope"]),
        )
        return _Request(
            _unb64(document["plan"]), _unb64(document["attempt"]), grants, staging, account
        )
    except ContractError:
        raise
    except Exception:
        raise ContractError("invalid_schema") from None


def _credential(piece: bytes) -> dict[str, str]:
    try:
        value = json.loads(piece)
    except Exception:
        raise ContractError("invalid_schema") from None
    if (
        not isinstance(value, dict)
        or set(value) != _CREDENTIAL_KEYS
        or not all(type(item) is str and item for item in value.values())
    ):
        raise ContractError("invalid_schema")
    return value


def _build_store(
    plan: ExecutionPlan,
    grants: TransportGrants,
    staging: Mapping[str, Any],
    account_id: str,
    clock: Clock,
) -> S3StagingStore:
    """The worker-mode staging store over the split client: no authorizer, writes gated by grants.

    Reads of the declared inputs go out with the read-only credential and everything under the
    attempt's prefix with the read-write one; a key in neither scope is refused before a request.
    """
    config = staging_config(staging, grants.destination_id)
    read_keys, write_prefix = credential_scopes(config.prefix, plan, grants.attempt_id)
    read_only, read_write = (_credential(piece) for piece in grants.material)
    timeouts = {
        name: value for name, value in config.client_options().items() if name in _TIMEOUT_OPTIONS
    }
    client = SplitR2Client(
        r2_client(account_id, read_only, options=timeouts),
        r2_client(account_id, read_write, options=timeouts),
        frozenset(read_keys),
        write_prefix,
    )
    return S3StagingStore(
        config,
        client,
        authorize=None,
        storage_reserved=grant_storage_gate(grants, clock),
        clock=clock.now,
        attempt_id=grants.attempt_id,
    ).scoped_to(plan, grants.attempt_id)


def _require_lease(store: object) -> None:
    if not all(callable(getattr(store, name, None)) for name in ("claim_lease", "publish_result")):
        raise ContractError("unsupported_capability")


def _require_bound(store: object, grants: TransportGrants) -> None:
    """The store must declare where it writes, and exactly where the grants allow.

    ``run_worker`` skips this comparison for a store that declares nothing, so the live entry
    does not let one through.
    """
    try:
        declared = getattr(store, "write_scope", None)
    except ContractError:
        raise
    except Exception:
        raise ContractError("forbidden") from None
    if type(declared) is not bytes or declared != grants.output_scope:
        raise ContractError("forbidden")


def container_entry(payload: bytes) -> bytes:
    """What the container runs: one attempt's worker under a lease, returning the claim as bytes."""
    _quiet_sdk_loggers()  # before any client exists
    request = _decode(payload)
    clock = _container_clock()
    plan = _wire(ExecutionPlan, request.plan_bytes, _bootstrap(len(request.plan_bytes)))
    store = _build_store(plan, request.grants, request.staging, request.account_id, clock)
    _require_lease(store)
    _require_bound(store, request.grants)
    outcome = run_worker(
        request.plan_bytes,
        request.attempt_bytes,
        request.grants,
        store,
        clock,
        lease=store,
        nonce=_nonce(),
    )
    if isinstance(outcome, DuplicateExecution):
        return DUPLICATE
    if type(outcome) is not Ref:
        raise ContractError("unavailable")
    return outcome.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8")
