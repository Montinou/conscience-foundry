"""Live Modal session and container entry, exercised offline through a fake ``modal`` module.

The ``modal`` module is always a fake injected through ``sys.modules``: no SDK call, network,
credential or deployment happens, and every identifier, key and token below is synthetic. What
the real platform does with these options is live preflight evidence, not asserted here.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import inspect
import json
import logging
import subprocess
import sys
import types
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from test_lease import ATTEMPT_PREFIX, LEASE_KEY, RESULT_KEY, Staged, staged
from test_modal import (
    ATTEMPT,
    DESTINATION,
    NOW,
    PROJECT,
    START,
    FakeModal,
    StepClock,
    build,
    make_executor,
    make_ref,
    running,
)
from test_staging_s3 import BUCKET, FakeS3

from conscience_foundry.contracts.common import ArtifactRef, ContractError, Instant
from conscience_foundry.execution import modal_live
from conscience_foundry.execution.capabilities import CapabilityRecord, validate_capabilities
from conscience_foundry.execution.modal_adapter import ModalPin, ModalPoll
from conscience_foundry.execution.modal_live import (
    DUPLICATE,
    CallRecord,
    DeadlineToken,
    LiveFunctionOptions,
    LiveModalSession,
    capability_record_from_live,
    code_digest,
    container_entry,
    encode_payload,
    image_spec,
    live_payload_extras,
    requirements_sha256,
    staging_config,
)
from conscience_foundry.execution.ports import TransportGrants
from conscience_foundry.execution.worker import DuplicateExecution
from conscience_foundry.policy.access import AccessContext

ACCOUNT = "synthetic-account-id"
PROFILE = "synthetic-profile"
TOKEN_ID = "synthetic-token-id-canary"
TOKEN_SECRET = "synthetic-token-secret-canary"
SDK_SECRET = "synthetic-sdk-message-canary"
ENV_VALUE_CANARY = "synthetic-env-value-canary"
NEVER_PRINT = (TOKEN_ID, TOKEN_SECRET, SDK_SECRET, ENV_VALUE_CANARY)
STAGING: dict[str, Any] = {
    "bucket": BUCKET,
    "prefix": "staging/f1",
    "endpoint_id": "synthetic-endpoint",
    "credential_source": "synthetic-source",
    "max_object_bytes": 65536,
    "transfer_chunk_bytes": 64,
    "max_read_resumes": 2,
    "max_parts": 4,
    "grant_ttl_seconds": 300,
    "checksum_mode": "sha256_header",
}


# -- the fake modal module ----------------------------------------------------------------


class Error(Exception):
    """Stands in for ``modal.exception.Error``."""


class ModalTimeoutError(Error):
    pass


class FunctionTimeoutError(ModalTimeoutError):
    pass


class OutputExpiredError(ModalTimeoutError):
    pass


class RemoteError(Error):
    pass


class InternalFailure(Error):
    pass


class InputCancellation(BaseException):
    pass


EXCEPTIONS = types.SimpleNamespace(
    Error=Error,
    TimeoutError=ModalTimeoutError,
    FunctionTimeoutError=FunctionTimeoutError,
    OutputExpiredError=OutputExpiredError,
    RemoteError=RemoteError,
    InternalFailure=InternalFailure,
    InputCancellation=InputCancellation,
)


class TickClock:
    """Moves forward by ``step`` seconds every time it is read."""

    def __init__(self, step: float = 10.0) -> None:
        self.step = step
        self.reads = 0

    def now(self) -> Instant:
        moment = START + timedelta(seconds=self.reads * self.step)
        self.reads += 1
        return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


class FakeCall:
    def __init__(self, world: World, object_id: str) -> None:
        self.world = world
        self.object_id = object_id

    def get(self, timeout: float | None = None, *, index: int = 0) -> Any:
        self.world.get_timeouts.append(timeout)
        if self.object_id in self.world.cancelled:
            raise InputCancellation()
        script = self.world.outcomes.get(self.object_id)
        if script:
            outcome = script.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome
        # the real SDK raises the built-in TimeoutError when ``get(timeout=...)`` expires
        raise TimeoutError(SDK_SECRET)

    def cancel(self, terminate_containers: bool = False) -> None:
        self.world.cancel_calls.append((self.object_id, terminate_containers))
        if self.world.cancel_error is not None:
            raise self.world.cancel_error
        self.world.cancelled.add(self.object_id)


class FakeFunction:
    def __init__(self, world: World, kwargs: dict[str, Any], entry: Callable[..., Any]) -> None:
        self.world = world
        self.entry = entry
        patch = world.readback_patch
        info = {
            "timeout": kwargs["timeout"],
            "startup_timeout": kwargs["startup_timeout"],
            "max_retries": kwargs["retries"],
            "nonpreemptible": kwargs["nonpreemptible"],
            "cpu": kwargs["cpu"],
            "memory_mib": kwargs["memory"],
        }
        settings = {"max_containers": kwargs["max_containers"]}
        self._info = types.SimpleNamespace(**{k: patch.get(k, v) for k, v in info.items()})
        self._settings = types.SimpleNamespace(**{k: patch.get(k, v) for k, v in settings.items()})

    def info(self, *, refresh: bool = False) -> Any:
        self.world.info_refresh.append(refresh)
        if self.world.readback_error is not None:
            raise self.world.readback_error
        return self._info

    @property
    def autoscaler(self) -> Any:
        return types.SimpleNamespace(settings=lambda: self._settings)

    def spawn(self, payload: bytes) -> FakeCall:
        if self.world.spawn_error is not None:
            raise self.world.spawn_error
        self.world.spawned.append(payload)
        return FakeCall(self.world, f"synthetic-call-{len(self.world.spawned)}")


class FakeRun:
    def __init__(self, world: World, kwargs: dict[str, Any]) -> None:
        self.world = world
        world.run_kwargs = kwargs

    def __enter__(self) -> FakeRun:
        self.world.entered += 1
        return self

    def __exit__(self, *exc: Any) -> None:
        self.world.exited.append(exc[0])


class FakeApp:
    def __init__(self, world: World, name: str, **kwargs: Any) -> None:
        self.world = world
        world.app_args = (name, kwargs)

    def function(self, **kwargs: Any) -> Callable[[Callable[..., Any]], FakeFunction]:
        self.world.function_kwargs = kwargs

        def register(entry: Callable[..., Any]) -> FakeFunction:
            self.world.registered = entry
            function = FakeFunction(self.world, kwargs, entry)
            self.world.function = function
            return function

        return register

    def run(self, **kwargs: Any) -> FakeRun:
        return FakeRun(self.world, kwargs)


class FakeImage:
    def __init__(self, world: World) -> None:
        self.world = world

    def pip_install_from_requirements(self, path: str, **kwargs: Any) -> FakeImage:
        self.world.image_calls.append(("pip_install_from_requirements", path))
        return self

    def add_local_python_source(self, *modules: str, **kwargs: Any) -> FakeImage:
        self.world.image_calls.append(("add_local_python_source", *modules))
        return self


@dataclass
class World:
    spawned: list[bytes] = field(default_factory=list)
    outcomes: dict[str, list[Any]] = field(default_factory=dict)
    get_timeouts: list[float | None] = field(default_factory=list)
    cancel_calls: list[tuple[str, bool]] = field(default_factory=list)
    cancelled: set[str] = field(default_factory=set)
    cancel_error: Exception | None = None
    spawn_error: Exception | None = None
    readback_error: Exception | None = None
    info_refresh: list[bool] = field(default_factory=list)
    readback_patch: dict[str, Any] = field(default_factory=dict)
    credentials_error: Exception | None = None
    config_reads: list[tuple[str, str | None, bool]] = field(default_factory=list)
    credentials_used: list[tuple[str, str]] = field(default_factory=list)
    image_calls: list[tuple[Any, ...]] = field(default_factory=list)
    function_kwargs: dict[str, Any] = field(default_factory=dict)
    app_args: tuple[Any, ...] = ()
    run_kwargs: dict[str, Any] = field(default_factory=dict)
    registered: Callable[..., Any] | None = None
    function: FakeFunction | None = None
    entered: int = 0
    exited: list[Any] = field(default_factory=list)
    client: Any = None
    from_id_clients: list[Any] = field(default_factory=list)
    python_versions: list[str] = field(default_factory=list)


def install(monkeypatch: pytest.MonkeyPatch, version: str = "1.6.3") -> tuple[World, Any]:
    world = World()
    world.client = types.SimpleNamespace(name="synthetic-client")
    module = types.ModuleType("modal")
    module.__version__ = version  # type: ignore[attr-defined]
    module.exception = EXCEPTIONS  # type: ignore[attr-defined]

    def read_config(key: str, *, profile: str | None = None, use_env: bool = True) -> str:
        world.config_reads.append((key, profile, use_env))
        return {"token_id": TOKEN_ID, "token_secret": TOKEN_SECRET}[key]

    module.config = types.SimpleNamespace(  # type: ignore[attr-defined]
        config=types.SimpleNamespace(get=read_config)
    )

    def from_credentials(token_id: str, token_secret: str) -> Any:
        if world.credentials_error is not None:
            raise world.credentials_error
        world.credentials_used.append((token_id, token_secret))
        return world.client

    module.Client = types.SimpleNamespace(from_credentials=from_credentials)  # type: ignore[attr-defined]

    def debian_slim(python_version: str | None = None) -> FakeImage:
        world.image_calls.append(("debian_slim", python_version))
        return FakeImage(world)

    module.Image = types.SimpleNamespace(debian_slim=debian_slim)  # type: ignore[attr-defined]
    module.App = lambda name, **kwargs: FakeApp(world, name, **kwargs)  # type: ignore[attr-defined]

    def from_id(call_id: str, client: Any = None) -> FakeCall:
        world.from_id_clients.append(client)
        return FakeCall(world, call_id)

    module.FunctionCall = types.SimpleNamespace(from_id=from_id)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "modal", module)
    return world, module


def make_options(**changes: Any) -> LiveFunctionOptions:
    values: dict[str, Any] = {
        "app_name": "synthetic-app",
        "function_name": "synthetic-worker",
        "python_version": "3.12",
        "requirements_path": "/synthetic/requirements.txt",
        "cpu_milli": 1000,
        "memory_mib": 512,
        "startup_timeout_seconds": 60,
        "execution_timeout_seconds": 300,
    } | changes
    return LiveFunctionOptions(**values)


def make_session(clock: Any = None, deadline: int = 480, **changes: Any) -> LiveModalSession:
    return LiveModalSession(PROFILE, make_options(**changes), deadline, clock or TickClock())


# -- options, image, settings -------------------------------------------------------------


def test_options_passed_exactly(monkeypatch: pytest.MonkeyPatch) -> None:
    world, _ = install(monkeypatch)
    options = make_options()
    with LiveModalSession(PROFILE, options, 480, TickClock()):
        pass

    assert world.function_kwargs == {
        "name": "synthetic-worker",
        "serialized": True,
        "cpu": 1.0,
        "memory": 512,
        "retries": 0,
        "nonpreemptible": True,
        "max_containers": 1,
        "timeout": 300,
        "startup_timeout": 60,
    }
    assert world.registered is container_entry
    assert world.image_calls == [
        ("debian_slim", "3.12"),
        ("pip_install_from_requirements", "/synthetic/requirements.txt"),
        ("add_local_python_source", "conscience_foundry"),
    ]
    name, kwargs = world.app_args
    assert name == "synthetic-app" and isinstance(kwargs["image"], FakeImage)
    # the profile selects the credentials; the environment never does
    assert world.config_reads == [("token_id", PROFILE, False), ("token_secret", PROFILE, False)]
    assert world.credentials_used == [(TOKEN_ID, TOKEN_SECRET)]
    assert world.run_kwargs == {"client": world.client}

    # the constraint values cannot be loosened by a caller
    for loosened in ({"retries": 1}, {"nonpreemptible": False}, {"max_containers": 2}):
        with pytest.raises(ContractError) as refused:
            make_options(**loosened)
        assert refused.value.code == "unsupported_capability"
    with pytest.raises(dataclasses.FrozenInstanceError):
        options.retries = 1  # type: ignore[misc]
    for bad in ({"execution_timeout_seconds": 0}, {"startup_timeout_seconds": -1}):
        with pytest.raises(ContractError):
            make_options(**bad)


def test_old_or_unreadable_sdk_version_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    for version in ("1.2.2", "0.64.1", "not-a-version", ""):
        install(monkeypatch, version)
        with pytest.raises(ContractError) as refused:
            make_session().__enter__()
        assert refused.value.code == "unsupported_capability"
    install(monkeypatch, "1.2.3")
    with make_session():
        pass


def test_missing_sdk_is_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "modal", None)  # an ImportError, as without the extra
    with pytest.raises(ContractError) as refused:
        make_session().__enter__()
    assert refused.value.code == "unsupported_capability"


def settings_document() -> dict[str, Any]:
    return {
        "modalProfile": PROFILE,
        "appName": "synthetic-app",
        "functionName": "synthetic-worker",
        "pythonVersion": "3.12",
        "requirementsPath": "/synthetic/requirements.txt",
        "cpuMilli": 1000,
        "memoryMib": 512,
        "schedulingTimeoutSeconds": 120,
        "startupTimeoutSeconds": 60,
        "executionTimeoutSeconds": 300,
        "cancelMarginSeconds": 30,
        "cloudflareTimeoutSeconds": 30,
        "capabilityValidSeconds": 3600,
        "r2AccountId": ACCOUNT,
        "parentAccessKeyIdEnv": "SYNTHETIC_PARENT_KEY_ID",
        "parentTokenEnv": "SYNTHETIC_PARENT_TOKEN",
        "staging": {
            "bucket": BUCKET,
            "prefix": "staging/f1",
            "endpointId": "synthetic-endpoint",
            "credentialSource": "synthetic-source",
            "maxObjectBytes": 65536,
            "transferChunkBytes": 64,
            "maxReadResumes": 2,
            "maxParts": 4,
            "grantTtlSeconds": 300,
            "checksumMode": "sha256_header",
        },
    }


def parse_live(document: dict[str, Any]) -> Any:
    from conscience_foundry.cli.config import LiveSettings, _bootstrap

    data = json.dumps(document).encode()
    return LiveSettings.from_wire(data, _bootstrap(len(data)))


def test_live_settings_reject_missing_field() -> None:
    from conscience_foundry.cli.config import RuntimeConfig

    settings = parse_live(settings_document())
    assert settings.staging.bucket == BUCKET
    assert settings.modal_profile == PROFILE
    assert settings.total_bound_seconds == 120 + 60 + 300 + 30

    document = settings_document()
    top = [name for name in document if name != "staging"]
    nested = list(document["staging"])
    assert len(top) == 16 and len(nested) == 10
    for name in top:
        broken = settings_document()
        del broken[name]
        with pytest.raises(ContractError) as missing:
            parse_live(broken)
        assert missing.value.code == "invalid_schema", name
    broken = settings_document()
    del broken["staging"]
    with pytest.raises(ContractError):
        parse_live(broken)
    for name in nested:
        broken = settings_document()
        del broken["staging"][name]
        with pytest.raises(ContractError) as missing:
            parse_live(broken)
        assert missing.value.code == "invalid_schema", name

    # strict: an unknown field, a wrong type and a non-positive bound are all refused
    for change in (
        lambda d: d.update(surprise=1),
        lambda d: d["staging"].update(surprise=1),
        lambda d: d.update(cpuMilli="1000"),
        lambda d: d.update(cancelMarginSeconds=0),
        lambda d: d["staging"].update(checksumMode="md5"),
        lambda d: d["staging"].update(prefix="/rooted"),
        lambda d: d["staging"].update(prefix="a/../b"),
        lambda d: d.update(requirementsPath="relative/requirements.txt"),
        lambda d: d.update(parentTokenEnv="SYNTHETIC_PARENT_KEY_ID"),
    ):
        broken = settings_document()
        change(broken)
        with pytest.raises(ContractError):
            parse_live(broken)

    field_info = RuntimeConfig.model_fields["live"]
    assert field_info.default is None


def test_staging_settings_map_one_to_one_onto_staging_config() -> None:
    settings = parse_live(settings_document())
    config = settings.staging.to_config(DESTINATION)
    assert (config.destination_id, config.store_id, config.region) == (
        DESTINATION,
        DESTINATION,
        "auto",
    )
    for name in STAGING:
        assert getattr(config, name) == STAGING[name]
    assert staging_config(STAGING, DESTINATION) == config
    for name in STAGING:
        partial = {key: value for key, value in STAGING.items() if key != name}
        with pytest.raises(ContractError) as refused:
            staging_config(partial, DESTINATION)
        assert refused.value.code == "invalid_schema"
    with pytest.raises(ContractError):
        staging_config(STAGING | {"request_timeout_seconds": 1}, DESTINATION)
    with pytest.raises(ContractError):
        staging_config(STAGING | {"checksum_mode": "md5"}, DESTINATION)


def test_payload_extras_carry_no_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYNTHETIC_PARENT_KEY_ID", ENV_VALUE_CANARY)
    monkeypatch.setenv("SYNTHETIC_PARENT_TOKEN", ENV_VALUE_CANARY)
    settings = parse_live(settings_document())
    extras = live_payload_extras(settings)

    assert set(extras) == {"staging", "r2_account_id"}
    assert extras["r2_account_id"] == ACCOUNT
    assert extras["staging"] == STAGING
    rendered = json.dumps(extras)
    assert ENV_VALUE_CANARY not in rendered
    assert "SYNTHETIC_PARENT" not in rendered  # not even the variable names ride along

    # the executor merges the extras into the spawn payload, and extras cannot replace core keys
    from test_modal import build

    scenario = build()
    sdk = FakeModal()
    executor = replace(make_executor(scenario, sdk), payload_extras=extras)
    assert executor.submit(scenario.plan, scenario.attempt, scenario.grants).remote_call_id
    ((_, payload),) = sdk.spawned
    assert set(payload) == {"plan_bytes", "attempt_bytes", "grants", "staging", "r2_account_id"}
    assert payload["staging"] == STAGING
    assert ENV_VALUE_CANARY not in repr(executor)

    clashing = replace(make_executor(scenario, FakeModal()), payload_extras={"grants": {}})
    with pytest.raises(ContractError) as refused:
        clashing.submit(scenario.plan, scenario.attempt, scenario.grants)
    assert refused.value.code == "invalid_schema"
    assert clashing.sdk.spawned == []  # type: ignore[attr-defined]
    # nothing was claimed: the attempt can still be submitted by a correct executor
    assert (
        make_executor(scenario, FakeModal())
        .submit(scenario.plan, scenario.attempt, scenario.grants)
        .remote_call_id
    )


def write_tree(root: Path, files: Mapping[str, bytes]) -> None:
    for relative, data in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def test_code_digest_is_stable_and_order_independent(tmp_path: Path) -> None:
    files = {
        "a.py": b"a = 1\n",
        "pkg/b.py": b"b = 2\n",
        "pkg/deep/c.py": b"c = 3\n",
        "README.md": b"not python\n",
        "pkg/data.json": b"{}",
    }
    first, second = tmp_path / "first", tmp_path / "second"
    write_tree(first, files)
    write_tree(second, dict(reversed(list(files.items()))))

    digest = code_digest(first)
    assert len(digest) == 64 and digest == code_digest(first) == code_digest(second)

    expected = hashlib.sha256()
    for relative, data in sorted((k, v) for k, v in files.items() if k.endswith(".py")):
        expected.update(relative.encode())
        expected.update(b"\0")
        expected.update(len(data).to_bytes(8, "big"))
        expected.update(data)
    assert digest == expected.hexdigest()

    # only python sources count; a content change, a rename or a new source changes it
    write_tree(second, {"README.md": b"changed\n", "pkg/data.json": b"[]"})
    assert code_digest(second) == digest
    write_tree(second, {"pkg/b.py": b"b = 3\n"})
    assert code_digest(second) != digest
    third = tmp_path / "third"
    write_tree(third, files | {"renamed.py": files["a.py"]} | {"a.py": b"a = 1\n"})
    assert code_digest(third) != digest
    # the boundary between a path and its bytes is part of the digest
    left, right = tmp_path / "left", tmp_path / "right"
    write_tree(left, {"a.py": b"xy", "b.py": b""})
    write_tree(right, {"a.py": b"x", "b.py": b"y"})
    assert code_digest(left) != code_digest(right)

    # the default is the installed package, and it is stable
    assert code_digest() == code_digest()
    with pytest.raises(ContractError):
        code_digest(tmp_path / "missing")


def test_image_spec_pins_the_requirements(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_bytes(b"pydantic==2.12.0\n")
    options = make_options(requirements_path=str(requirements))
    digest = hashlib.sha256(b"pydantic==2.12.0\n").hexdigest()
    assert requirements_sha256(requirements) == digest
    assert image_spec(options) == {
        "builder": "debian_slim",
        "python_version": "3.12",
        "requirements_sha256": digest,
    }
    with pytest.raises(ContractError):
        requirements_sha256(tmp_path / "missing.txt")


def test_importing_the_module_loads_no_sdk() -> None:
    probe = (
        "import sys, conscience_foundry.execution.modal_live;"
        "bad=[m for m in sys.modules if m.split('.')[0] in {'modal','boto3','botocore'}];"
        "print(','.join(sorted(bad)))"
    )
    loaded = subprocess.run(
        [sys.executable, "-I", "-c", probe], capture_output=True, text=True, check=True
    )
    assert loaded.stdout.strip() == ""


# -- the session --------------------------------------------------------------------------


def spawn_one(session: LiveModalSession, world: World) -> str:
    return session.spawn("synthetic-worker", sample_payload())


def sample_payload() -> dict[str, object]:
    return {
        "plan_bytes": b"plan",
        "attempt_bytes": b"attempt",
        "grants": {
            "project_id": PROJECT,
            "plan_digest": "a" * 64,
            "attempt_id": ATTEMPT,
            "destination_id": DESTINATION,
            "expires_at": NOW,
            "material": [b"one", b"two"],
            "output_scope": b"bucket/prefix/",
        },
        "staging": STAGING,
        "r2_account_id": ACCOUNT,
    }


def test_spawn_encodes_the_payload_and_keeps_a_record(monkeypatch: pytest.MonkeyPatch) -> None:
    world, _ = install(monkeypatch)
    with make_session() as session:
        call_id = spawn_one(session, world)
        assert call_id == "synthetic-call-1"
        assert world.info_refresh == [True]  # read back from the server, never a cached local copy
        decoded = json.loads(world.spawned[0])
        assert set(decoded) == {"plan", "attempt", "grants", "staging", "r2_account_id"}
        assert base64.b64decode(decoded["plan"]) == b"plan"
        assert base64.b64decode(decoded["grants"]["material"][1]) == b"two"
        assert decoded["staging"] == STAGING
        record = session.records[call_id]
        assert isinstance(record, CallRecord)
        assert (record.completed, record.terminated, record.cancelled) == (False, False, False)
        assert record.spawned_at.endswith("Z")
        with pytest.raises(TypeError):
            session.records[call_id] = record  # type: ignore[index]
        # only the pinned function may be spawned, and only known payload keys are encoded
        with pytest.raises(ContractError) as other:
            session.spawn("another-function", sample_payload())
        assert other.value.code == "forbidden"
        with pytest.raises(ContractError):
            session.spawn("synthetic-worker", sample_payload() | {"surprise": 1})
        assert len(world.spawned) == 1
    assert world.from_id_clients == []


@pytest.mark.parametrize(
    "mismatch",
    [
        {"timeout": 301},
        {"startup_timeout": 61},
        {"startup_timeout": None},
        {"max_retries": 1},
        {"max_retries": None},
        {"nonpreemptible": False},
        {"max_containers": 2},
        {"max_containers": None},
        {"cpu": 2.0},
        {"memory_mib": 1024},
    ],
)
def test_option_readback_mismatch_refuses(
    monkeypatch: pytest.MonkeyPatch, mismatch: dict[str, Any]
) -> None:
    world, _ = install(monkeypatch)
    world.readback_patch = mismatch
    with make_session() as session:
        with pytest.raises(ContractError) as refused:
            spawn_one(session, world)
        assert refused.value.code == "unsupported_capability"
        assert world.spawned == [] and session.records == {}

    # an unreadable answer cannot prove the options either
    world, _ = install(monkeypatch)
    world.readback_error = RuntimeError(SDK_SECRET)
    with make_session() as session:
        with pytest.raises(ContractError) as unreadable:
            spawn_one(session, world)
        assert unreadable.value.code == "unsupported_capability"
        assert SDK_SECRET not in str(unreadable.value) + repr(unreadable.value)
        assert world.spawned == []


def no_callback() -> None:  # a deadline callback that records nothing
    return None


def test_poll_until_terminal_requires_a_deadline_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without the control side's callback the session would cancel behind the ledger's back."""
    world, _ = install(monkeypatch)
    with make_session(clock=TickClock(step=10.0), deadline=5) as session:
        call_id = spawn_one(session, world)
        assert (
            inspect.signature(session.poll_until_terminal).parameters["on_deadline"].default
            is inspect.Parameter.empty
        )
        for missing in (None, "not-callable"):
            with pytest.raises(ContractError) as refused:
                session.poll_until_terminal(call_id, missing)  # type: ignore[arg-type]
            assert refused.value.code == "invalid_schema"
    assert world.get_timeouts == [] and world.cancel_calls == []  # nothing was waited or cancelled


def test_session_uses_an_injected_modal_module(monkeypatch: pytest.MonkeyPatch) -> None:
    world, module = install(monkeypatch)
    monkeypatch.delitem(sys.modules, "modal")  # only the injected module can be used
    session = LiveModalSession(PROFILE, make_options(), 480, TickClock(), modal=module)
    with session:
        spawn_one(session, world)
    assert world.entered == 1 and world.exited == [None]
    old = types.ModuleType("modal")
    old.__version__ = "1.2.2"  # type: ignore[attr-defined]
    with pytest.raises(ContractError) as refused:
        LiveModalSession(PROFILE, make_options(), 480, TickClock(), modal=old).__enter__()
    assert refused.value.code == "unsupported_capability"


def test_deadline_cancels_call(monkeypatch: pytest.MonkeyPatch) -> None:
    world, _ = install(monkeypatch)
    with make_session(clock=TickClock(step=10.0), deadline=25) as session:
        call_id = spawn_one(session, world)  # spawned at t=0, deadline at t=25
        poll = session.poll_until_terminal(call_id, no_callback)

    # each wait is bounded by what is left before the deadline, then the call is cancelled
    assert world.get_timeouts == [15.0, 5.0, 0]
    assert world.cancel_calls == [(call_id, True)]
    assert poll == ModalPoll("cancelled")
    record = session.records[call_id]
    assert (record.terminated, record.cancelled, record.completed) == (True, True, False)

    # a call that finishes in time is never cancelled
    world, _ = install(monkeypatch)
    with make_session(clock=TickClock(step=10.0), deadline=25) as session:
        call_id = spawn_one(session, world)
        world.outcomes[call_id] = [TimeoutError(), b"manifest-ref-json"]
        poll = session.poll_until_terminal(call_id, no_callback)
    assert poll == ModalPoll("completed", b"manifest-ref-json")
    assert world.cancel_calls == []
    assert session.records[call_id].completed is True

    # a cancel the SDK refuses is an unknown outcome, never a quiet success
    world, _ = install(monkeypatch)
    world.cancel_error = RuntimeError(SDK_SECRET)
    with make_session(clock=TickClock(step=10.0), deadline=5) as session:
        call_id = spawn_one(session, world)
        with pytest.raises(ContractError) as unknown:
            session.poll_until_terminal(call_id, no_callback)
    assert unknown.value.code == "dispatch_unknown"
    assert SDK_SECRET not in str(unknown.value)
    assert session.records[call_id].terminated is False


@pytest.mark.parametrize(
    ("raised", "state", "result"),
    [
        (b"payload", "completed", b"payload"),
        ("not-bytes", "completed", None),
        (TimeoutError(SDK_SECRET), "pending", None),
        (ModalTimeoutError(SDK_SECRET), "pending", None),
        (FunctionTimeoutError(SDK_SECRET), "timed_out", None),
        (OutputExpiredError(SDK_SECRET), "output_expired", None),
        (InputCancellation(), "cancelled", None),
        (RemoteError(SDK_SECRET), "remote_error", None),
        # the worker's own failures that prove nothing was published are failed, not unknown
        (ContractError("invalid_schema"), "remote_error", None),
        (ContractError("forbidden"), "remote_error", None),
        (ContractError("hash_mismatch"), "remote_error", None),
        (ContractError("limit_exceeded"), "remote_error", None),
        (ContractError("authorization_expired"), "remote_error", None),
    ],
)
def test_exception_mapping(
    monkeypatch: pytest.MonkeyPatch, raised: Any, state: str, result: bytes | None
) -> None:
    world, _ = install(monkeypatch)
    with make_session() as session:
        call_id = spawn_one(session, world)
        world.outcomes[call_id] = [raised]
        poll = session.poll(call_id)
        assert poll == ModalPoll(state, result)  # type: ignore[arg-type]
        assert world.get_timeouts == [0]
        assert SDK_SECRET not in repr(poll)
        record = session.records[call_id]
        assert record.completed is (state == "completed")
        assert record.cancelled is (state == "cancelled")


@pytest.mark.parametrize(
    "code",
    [
        "unavailable",  # a put of the result pointer that timed out may have landed
        "dispatch_unknown",  # the lease claim may have been taken
        "credential_unavailable",
        "config_invalid",
        "some_future_code",
    ],
)
def test_ambiguous_worker_failures_are_unknown_not_remote_errors(
    monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    world, _ = install(monkeypatch)
    with make_session() as session:
        call_id = spawn_one(session, world)
        world.outcomes[call_id] = [ContractError(code), ContractError(code)]
        with pytest.raises(ContractError) as unknown:
            session.poll(call_id)
        assert unknown.value.code == "unavailable"
        assert session.records[call_id].completed is False
        # waiting for the end reports it the same way: never a failed attempt
        with pytest.raises(ContractError) as waited:
            session.poll_until_terminal(call_id, no_callback)
        assert waited.value.code == "unavailable"


@pytest.mark.parametrize(
    "raised",
    [
        InternalFailure(SDK_SECRET),
        Error(SDK_SECRET),
        RuntimeError(SDK_SECRET),
        ConnectionError(SDK_SECRET),
        OSError(SDK_SECRET),
    ],
)
def test_unrecognized_sdk_failures_are_unknown_not_remote_errors(
    monkeypatch: pytest.MonkeyPatch, raised: Exception
) -> None:
    world, _ = install(monkeypatch)
    with make_session() as session:
        call_id = spawn_one(session, world)
        world.outcomes[call_id] = [raised]
        with pytest.raises(ContractError) as unknown:
            session.poll(call_id)
        assert unknown.value.code == "unavailable"
        assert SDK_SECRET not in str(unknown.value) + repr(unknown.value)
        assert unknown.value.__cause__ is None and unknown.value.__suppress_context__


def test_poll_and_cancel_only_serve_own_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    world, _ = install(monkeypatch)
    with make_session() as session:
        for action in (
            session.poll,
            session.cancel,
            lambda call: session.poll_until_terminal(call, no_callback),
        ):
            with pytest.raises(ContractError) as foreign:
                action("someone-elses-call")
            assert foreign.value.code == "forbidden"
        assert world.get_timeouts == [] and world.cancel_calls == []
        call_id = spawn_one(session, world)
        session.cancel(call_id)
        assert world.cancel_calls == [(call_id, True)]
        assert session.records[call_id].terminated is True
    with pytest.raises(ContractError) as closed:
        session.poll(call_id)
    assert closed.value.code == "unavailable"
    with pytest.raises(ContractError):
        spawn_one(session, world)


def test_keyboard_interrupt_during_a_wait_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    world, _ = install(monkeypatch)
    with pytest.raises(KeyboardInterrupt):
        with make_session() as session:
            call_id = spawn_one(session, world)
            world.outcomes[call_id] = [KeyboardInterrupt()]
            session.poll_until_terminal(call_id, no_callback)
    assert world.exited == [KeyboardInterrupt]


def test_session_exit_stops_app(monkeypatch: pytest.MonkeyPatch) -> None:
    world, _ = install(monkeypatch)
    session = make_session()
    with session:
        assert world.entered == 1 and world.exited == []
    assert world.exited == [None]
    session.__exit__(None, None, None)  # closing twice does not stop the app twice
    assert world.exited == [None]
    with pytest.raises(ContractError):
        with session:  # a session is single use
            pass
    assert world.entered == 1

    # a failure while opening never leaves a running app behind
    world, _ = install(monkeypatch)
    world.credentials_error = RuntimeError(SDK_SECRET)
    with pytest.raises(ContractError):
        make_session().__enter__()
    assert world.entered == 0


def test_keyboard_interrupt_tears_down_session(monkeypatch: pytest.MonkeyPatch) -> None:
    world, _ = install(monkeypatch)
    with pytest.raises(KeyboardInterrupt):
        with make_session() as session:
            spawn_one(session, world)
            raise KeyboardInterrupt
    assert world.exited == [KeyboardInterrupt]  # the app was stopped with the interrupt
    # the record of what was spawned survives the teardown
    assert list(session.records) == ["synthetic-call-1"]

    # the app's own failure to stop never replaces the interrupt
    world, _ = install(monkeypatch)

    class Broken(FakeRun):
        def __exit__(self, *exc: Any) -> None:
            super().__exit__(*exc)
            raise RuntimeError(SDK_SECRET)

    monkeypatch.setattr(sys.modules["modal"], "App", lambda name, **kw: BrokenApp(world, name))

    class BrokenApp(FakeApp):
        def run(self, **kwargs: Any) -> FakeRun:
            return Broken(self.world, kwargs)

    with pytest.raises(KeyboardInterrupt):
        with make_session():
            raise KeyboardInterrupt
    assert world.exited == [KeyboardInterrupt]


def test_sdk_errors_are_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    def assert_clean(error: BaseException) -> None:
        rendered = str(error) + repr(error) + repr(error.args)
        assert not any(secret in rendered for secret in NEVER_PRINT)
        assert error.__cause__ is None and error.__suppress_context__

    world, _ = install(monkeypatch)
    world.spawn_error = RuntimeError(SDK_SECRET)
    with make_session() as session:
        with pytest.raises(ContractError) as spawn_failed:
            spawn_one(session, world)
        assert spawn_failed.value.code == "dispatch_unknown"  # it may have been delivered
        assert_clean(spawn_failed.value)
        assert session.records == {}
        rendered = repr(session) + str(session)
        assert not any(secret in rendered for secret in NEVER_PRINT)

    world, _ = install(monkeypatch)
    world.credentials_error = RuntimeError(f"{SDK_SECRET} {TOKEN_SECRET}")
    with pytest.raises(ContractError) as credentials_failed:
        make_session().__enter__()
    assert_clean(credentials_failed.value)

    world, _ = install(monkeypatch)
    world.cancel_error = RuntimeError(SDK_SECRET)
    with make_session() as session:
        call_id = spawn_one(session, world)
        with pytest.raises(ContractError) as cancel_failed:
            session.cancel(call_id)
        assert cancel_failed.value.code == "dispatch_unknown"
        assert_clean(cancel_failed.value)

    # a missing token is a named credential error, not an SDK message
    world, module = install(monkeypatch)

    def missing(key: str, *, profile: str | None = None, use_env: bool = True) -> str:
        raise KeyError(f"{key} {SDK_SECRET}")

    module.config.config.get = missing
    with pytest.raises(ContractError) as unavailable:
        make_session().__enter__()
    assert unavailable.value.code == "credential_unavailable"
    assert_clean(unavailable.value)


# -- the executor drives the session through the same port --------------------------------


def test_session_is_a_modal_sdk_for_the_executor(monkeypatch: pytest.MonkeyPatch) -> None:
    from test_modal import build

    world, _ = install(monkeypatch)
    scenario = build()
    with make_session(clock=StepClock()) as session:
        executor = replace(
            make_executor(scenario, session), payload_extras=live_payload_extras_for(STAGING)
        )
        submission = executor.submit(scenario.plan, scenario.attempt, scenario.grants)
    assert submission.remote_call_id == "synthetic-call-1" and submission.accepted is True
    decoded = json.loads(world.spawned[0])
    assert base64.b64decode(decoded["plan"]) == scenario.plan_bytes
    assert decoded["r2_account_id"] == ACCOUNT


def live_payload_extras_for(staging: Mapping[str, Any]) -> dict[str, object]:
    return {"staging": dict(staging), "r2_account_id": ACCOUNT}


# -- container entry ----------------------------------------------------------------------


@dataclass
class Routed:
    """Records which credential each request went out with; delegates to one backing double."""

    tag: str
    backing: FakeS3
    log: list[tuple[str, str, str]]

    def _do(self, name: str, kwargs: dict[str, Any]) -> Any:
        self.log.append((self.tag, name, kwargs["Key"]))
        return getattr(self.backing, name)(**kwargs)

    def put_object(self, **kwargs: Any) -> Any:
        return self._do("put_object", kwargs)

    def head_object(self, **kwargs: Any) -> Any:
        return self._do("head_object", kwargs)

    def get_object(self, **kwargs: Any) -> Any:
        return self._do("get_object", kwargs)


@dataclass
class Container:
    case: Staged
    grants: TransportGrants
    routed: list[tuple[str, str, str]] = field(default_factory=list)
    built: list[tuple[str, dict[str, str], Mapping[str, int] | None]] = field(default_factory=list)
    logger_levels: list[dict[str, int]] = field(default_factory=list)
    stores: list[Any] = field(default_factory=list)
    gates: list[tuple[TransportGrants, Any]] = field(default_factory=list)
    nonces: list[str] = field(default_factory=list)

    def payload(self, **changes: Any) -> bytes:
        grants = self.grants
        document: dict[str, object] = {
            "plan_bytes": self.case.scenario.plan_bytes,
            "attempt_bytes": self.case.scenario.attempt_bytes,
            "grants": {
                "project_id": grants.project_id,
                "plan_digest": grants.plan_digest,
                "attempt_id": grants.attempt_id,
                "destination_id": grants.destination_id,
                "expires_at": grants.expires_at,
                "material": list(grants.material),
                "output_scope": grants.output_scope,
            },
            "staging": STAGING,
            "r2_account_id": ACCOUNT,
        }
        return encode_payload(document | changes)


READ_ONLY = {"accessKeyId": "ro-id", "secretAccessKey": "ro-secret", "sessionToken": "ro-token"}
READ_WRITE = {"accessKeyId": "rw-id", "secretAccessKey": "rw-secret", "sessionToken": "rw-token"}


def container(monkeypatch: pytest.MonkeyPatch) -> Container:
    case = staged()
    material = tuple(json.dumps(piece).encode() for piece in (READ_ONLY, READ_WRITE))
    grants = replace(case.grants, material=material)
    state = Container(case, grants)

    def fake_r2_client(
        account_id: str, credentials: Mapping[str, str], *, options: Mapping[str, int] | None = None
    ) -> Routed:
        state.logger_levels.append(
            {name: logging.getLogger(name).level for name in ("botocore", "boto3", "urllib3")}
        )
        tag = "ro" if credentials["accessKeyId"] == "ro-id" else "rw"
        state.built.append((account_id, dict(credentials), options))
        return Routed(tag, case.client, state.routed)

    real_gate = modal_live.grant_storage_gate

    def spy_gate(grants: TransportGrants, clock: Any) -> Any:
        gate = real_gate(grants, clock)
        state.gates.append((grants, gate))
        return gate

    real_build = modal_live._build_store

    def spy_build(*args: Any, **kwargs: Any) -> Any:
        store = real_build(*args, **kwargs)
        state.stores.append(store)
        return store

    def nonce() -> str:
        state.nonces.append(f"synthetic-nonce-{len(state.nonces) + 1}")
        return state.nonces[-1]

    monkeypatch.setattr(modal_live, "r2_client", fake_r2_client)
    monkeypatch.setattr(modal_live, "grant_storage_gate", spy_gate)
    monkeypatch.setattr(modal_live, "_build_store", spy_build)
    monkeypatch.setattr(modal_live, "_nonce", nonce)
    monkeypatch.setattr(modal_live, "_container_clock", StepClock)
    return state


@pytest.fixture
def sdk_loggers() -> Any:
    names = ("botocore", "boto3", "urllib3")
    before = {name: logging.getLogger(name).level for name in names}
    for name in names:
        logging.getLogger(name).setLevel(logging.DEBUG)
    yield names
    for name, level in before.items():
        logging.getLogger(name).setLevel(level)


def test_container_entry_runs_worker_with_lease(
    monkeypatch: pytest.MonkeyPatch, sdk_loggers: Any
) -> None:
    state = container(monkeypatch)
    result = container_entry(state.payload())

    # the return value is the manifest Ref JSON, and the pointer holds the same bytes
    pointer = state.case.client.objects[RESULT_KEY]
    assert result == pointer
    manifest = json.loads(result)
    assert manifest["artifactSchema"] == "cf.result.v1" and manifest["projectId"] == PROJECT
    assert state.case.client.objects[LEASE_KEY] == state.nonces[0].encode()
    assert len(state.nonces) == 1

    # two credentials, read-only first, built for the payload's account with bounded timeouts
    assert [(account, creds) for account, creds, _ in state.built] == [
        (ACCOUNT, READ_ONLY),
        (ACCOUNT, READ_WRITE),
    ]
    assert all(
        options == {"connect_timeout": 30, "read_timeout": 30} for *_, options in state.built
    )

    # routing: declared inputs are read with the read-only credential, everything else, and every
    # write, uses the read-write one and stays under the attempt's prefix
    routed = state.routed
    assert {tag for tag, op, _ in routed if op == "put_object"} == {"rw"}
    assert all(key.startswith(ATTEMPT_PREFIX) for tag, op, key in routed if tag == "rw")
    inputs = [key for tag, _op, key in routed if tag == "ro"]
    assert inputs and all("/attempts/" not in key for key in inputs)
    assert {op for tag, op, _ in routed if tag == "ro"} <= {"get_object"}

    # the worker store is the grants' own gate, never a blanket yes
    ((gated, gate),) = state.gates
    assert gated.output_scope == state.grants.output_scope
    (store,) = state.stores
    assert store.storage_reserved is gate
    assert store.authorize is None
    assert store.write_scope == state.grants.output_scope
    source = state.case.scenario.source_ref
    worker = AccessContext(PROJECT, ATTEMPT, frozenset({"read", "remoteTransfer"}))
    assert gate(source, worker) is True  # inside the grants' prefix, before they expire
    assert gate(source, replace(worker, actor_id="00000000-0000-0000-0000-0000000000f1")) is False
    assert gate(source, object()) is False  # type: ignore[arg-type]


def test_container_entry_duplicate_returns_sentinel(monkeypatch: pytest.MonkeyPatch) -> None:
    state = container(monkeypatch)
    state.case.client.objects[LEASE_KEY] = b"another-workers-nonce"
    before = len(state.case.client.calls)

    result = container_entry(state.payload())

    assert result == b'{"duplicate": true}'
    assert json.loads(result) == {"duplicate": True}
    later = state.case.client.calls[before:]
    assert [key for op, key in later if op == "put"] == [LEASE_KEY]  # only the refused claim
    assert state.case.client.objects[LEASE_KEY] == b"another-workers-nonce"

    # a loser that finds the winner's pointer returns that manifest instead
    winner = container(monkeypatch)
    first = container_entry(winner.payload())
    again = container_entry(winner.payload())
    assert again == first and again != b'{"duplicate": true}'


def test_container_entry_refuses_without_lease(monkeypatch: pytest.MonkeyPatch) -> None:
    state = container(monkeypatch)
    real_build = modal_live._build_store

    class NoLease:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def __getattr__(self, name: str) -> Any:
            if name in {"claim_lease", "publish_result"}:
                raise AttributeError(name)
            return getattr(self._inner, name)

    monkeypatch.setattr(modal_live, "_build_store", lambda *a, **k: NoLease(real_build(*a, **k)))
    before = len(state.case.client.calls)
    with pytest.raises(ContractError) as refused:
        container_entry(state.payload())
    assert refused.value.code == "unsupported_capability"
    assert state.case.client.calls[before:] == []  # nothing was read, claimed or written


def test_container_entry_requires_a_bound_write_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    state = container(monkeypatch)
    real_build = modal_live._build_store
    ran: list[str] = []
    real_run = modal_live.run_worker

    def watched(*args: Any, **kwargs: Any) -> Any:
        ran.append("run")
        return real_run(*args, **kwargs)

    monkeypatch.setattr(modal_live, "run_worker", watched)

    class Unbound:
        """A lease-capable store that declares no write scope: the worker would skip the check."""

        def __init__(self, inner: Any, scope: Any = ...) -> None:
            self._inner = inner
            self._scope = scope

        def __getattr__(self, name: str) -> Any:
            if name == "write_scope":
                if self._scope is ...:
                    raise AttributeError(name)
                return self._scope
            return getattr(self._inner, name)

    for scope in (..., None, b"synthetic-bucket/staging/elsewhere/", "text-not-bytes"):
        monkeypatch.setattr(
            modal_live,
            "_build_store",
            lambda *a, scope=scope, **k: Unbound(real_build(*a, **k), scope),
        )
        before = len(state.case.client.calls)
        with pytest.raises(ContractError) as refused:
            container_entry(state.payload())
        assert refused.value.code == "forbidden", scope
        assert state.case.client.calls[before:] == []
    assert ran == []  # the worker never started

    # the genuine store declares exactly the grants' scope and runs
    monkeypatch.setattr(modal_live, "_build_store", real_build)
    assert container_entry(state.payload())
    assert ran == ["run"]


def test_sdk_loggers_are_quiet_before_any_client_is_built(
    monkeypatch: pytest.MonkeyPatch, sdk_loggers: Any
) -> None:
    state = container(monkeypatch)
    for name in sdk_loggers:
        assert logging.getLogger(name).isEnabledFor(logging.DEBUG)

    container_entry(state.payload())

    # at the moment each client was built, and afterwards, DEBUG could not write a token
    assert len(state.logger_levels) == 2
    for levels in state.logger_levels:
        assert all(level >= logging.WARNING for level in levels.values()), levels
    for name in sdk_loggers:
        assert not logging.getLogger(name).isEnabledFor(logging.DEBUG)
        assert not logging.getLogger(f"{name}.credentials").isEnabledFor(logging.DEBUG)

    # a logger that was already quieter than WARNING is not made noisier
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    modal_live._quiet_sdk_loggers()
    assert logging.getLogger("urllib3").level == logging.ERROR


@pytest.mark.parametrize(
    "bad",
    [
        b"not json",
        b"[]",
        b'{"plan": "AA=="}',
        b"",
    ],
)
def test_container_entry_refuses_malformed_payloads(
    monkeypatch: pytest.MonkeyPatch, bad: bytes
) -> None:
    state = container(monkeypatch)
    with pytest.raises(ContractError) as refused:
        container_entry(bad)
    assert refused.value.code == "invalid_schema"
    assert state.built == []

    document = json.loads(state.payload())
    for change in (
        lambda d: d.update(surprise=1),
        lambda d: d["grants"].update(material=d["grants"]["material"][:1]),
        lambda d: d["grants"].update(material=d["grants"]["material"] * 2),
        lambda d: d["grants"].update(material=["***not base64***", "AA=="]),
        lambda d: d.update(r2_account_id="../evil"),
        lambda d: d.update(staging={**d["staging"], "surprise": 1}),
        lambda d: d["grants"].pop("output_scope"),
        lambda d: d["grants"].update(destination_id=7),
    ):
        broken = json.loads(json.dumps(document))
        change(broken)
        with pytest.raises(ContractError) as refused:
            container_entry(json.dumps(broken).encode())
        assert refused.value.code == "invalid_schema"
    assert state.built == []


def test_credential_pieces_that_are_not_credentials_are_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = container(monkeypatch)
    piece = json.dumps({"accessKeyId": "x"}).encode()
    grants = replace(state.grants, material=(piece, piece))
    state.grants = grants
    with pytest.raises(ContractError) as refused:
        container_entry(state.payload())
    assert refused.value.code == "invalid_schema"
    assert state.built == []


def test_r2_client_applies_explicit_timeouts() -> None:
    pytest.importorskip("boto3")
    from conscience_foundry.storage.r2 import r2_client

    credentials = {"accessKeyId": "a", "secretAccessKey": "b", "sessionToken": "c"}
    client = r2_client(
        "synthetic-account", credentials, options={"connect_timeout": 7, "read_timeout": 9}
    )
    assert client.meta.config.connect_timeout == 7  # type: ignore[attr-defined]
    assert client.meta.config.read_timeout == 9  # type: ignore[attr-defined]
    assert client.meta.config.retries["total_max_attempts"] == 1  # type: ignore[attr-defined]
    with pytest.raises(ContractError):
        r2_client("synthetic-account", credentials, options={"connect_timeout": 0})
    with pytest.raises(ContractError):
        r2_client("synthetic-account", credentials, options={"surprise": 1})


def test_default_clock_and_nonce_are_real_and_fresh() -> None:
    clock = modal_live._container_clock()
    moment = datetime.strptime(clock.now(), "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    assert abs((datetime.now(UTC) - moment).total_seconds()) < 5
    first, second = modal_live._nonce(), modal_live._nonce()
    assert first != second and len(first) >= 32
    assert DuplicateExecution() == DuplicateExecution()


# -- fidelity against the installed SDK (no network, no client) ---------------------------


@pytest.fixture
def isolated_modal_modules() -> Iterator[None]:
    """Keep the real SDK import from outliving the test.

    The core import-boundary test asserts that no ``modal`` module is loaded in the process; a
    real import here would leave the whole package family behind for every later test module.
    """

    def family() -> dict[str, Any]:
        return {
            name: module
            for name, module in sys.modules.items()
            if name == "modal" or name.startswith("modal.")
        }

    before = family()
    try:
        yield
    finally:
        for name in family():
            sys.modules.pop(name, None)
        sys.modules.update(before)


@pytest.mark.usefixtures("isolated_modal_modules")
def test_fake_matches_the_installed_modal_sdk() -> None:
    """What the session relies on exists in the real package, in the shape the fake imitates."""
    real = pytest.importorskip("modal")
    from modal import exception as real_exceptions

    # Function.info is a method taking ``refresh`` (not an attribute); FunctionCall.get takes
    # ``timeout``; the autoscaler namespace exposes ``settings``.
    assert callable(real.Function.info)
    assert "refresh" in inspect.signature(real.Function.info).parameters
    assert "timeout" in inspect.signature(real.FunctionCall.get).parameters
    assert callable(real.FunctionCall.from_id)
    assert callable(real.FunctionCall.cancel)
    assert "terminate_containers" in inspect.signature(real.FunctionCall.cancel).parameters
    assert isinstance(real.Function.autoscaler, property)

    # FunctionInfo and FunctionAutoscalerSettings carry the fields the option readback compares.
    from modal.types import FunctionAutoscalerSettings, FunctionInfo

    info_fields = {item.name for item in dataclasses.fields(FunctionInfo)}
    assert {"timeout", "startup_timeout", "max_retries", "nonpreemptible", "cpu", "memory_mib"} <= (
        info_fields
    )
    assert "max_containers" in {
        item.name for item in dataclasses.fields(FunctionAutoscalerSettings)
    }

    # The exceptions the mapping names exist, and the SDK's own TimeoutError family is not the
    # built-in one: ``get(timeout=...)`` raises the built-in, which only the session's own clause
    # for it recognizes.
    for name in ("RemoteError", "FunctionTimeoutError", "OutputExpiredError", "InputCancellation"):
        assert hasattr(real_exceptions, name)
    assert not issubclass(real_exceptions.TimeoutError, TimeoutError)
    assert issubclass(real_exceptions.FunctionTimeoutError, real_exceptions.TimeoutError)
    assert issubclass(real_exceptions.OutputExpiredError, real_exceptions.TimeoutError)
    from modal import _functions

    assert "raise TimeoutError(" in inspect.getsource(_functions._Invocation.poll_function)


# -- the capability record ----------------------------------------------------------------

CODE_DIGEST = "c" * 64
IMAGE_SPEC: dict[str, object] = {
    "builder": "debian_slim",
    "python_version": "3.12",
    "requirements_sha256": "d" * 64,
}


def build_record(
    scenario: Any, document: dict[str, Any] | None = None
) -> tuple[CapabilityRecord, list[tuple[str, bytes]]]:
    log: list[tuple[str, bytes]] = []

    def sink(schema: str, data: bytes) -> ArtifactRef:
        log.append((schema, data))
        return make_ref(data, schema)

    record = capability_record_from_live(
        parse_live(document or settings_document()),
        PROJECT,
        scenario.plan.execution_config_ref,
        "1.6.3",
        IMAGE_SPEC,
        CODE_DIGEST,
        NOW,
        sink,
    )
    return record, log


def test_record_validates_against_plan() -> None:
    scenario = build()
    record, log = build_record(scenario)

    validate_capabilities(record, scenario.plan)
    canonical = json.dumps(IMAGE_SPEC, sort_keys=True, separators=(",", ":")).encode()
    assert record.image_digest == hashlib.sha256(canonical).hexdigest()
    assert (record.cpu_milli, record.memory_mib, record.gpu_count) == (1000, 512, 0)
    assert (record.function_retries, record.platform_restart_bound) == (0, "bounded")
    assert record.max_platform_restarts == 0
    assert record.cancellation == "terminates_containers"
    assert record.deadline_enforcement == "entry_and_every_bounded_step"
    assert record.deployment_version == "ephemeral-" + CODE_DIGEST[:16]
    assert (record.project_id, record.sdk_version, record.code_digest) == (
        PROJECT,
        "1.6.3",
        CODE_DIGEST,
    )
    assert record.execution_config_ref == scenario.plan.execution_config_ref
    assert (
        record.scheduling_timeout_seconds,
        record.startup_timeout_seconds,
        record.execution_timeout_seconds,
    ) == (120, 60, 300)
    assert record.total_bound_seconds == 120 + 60 + 300 + 30
    assert record.valid_until == "2030-01-01T01:00:00.000Z"  # now + capabilityValidSeconds

    # three evidence records: the declared options, the restart semantics and the lease test
    assert len(log) == 3 == len(record.source_evidence_refs)
    assert [ref.digest for ref in record.source_evidence_refs] == [
        hashlib.sha256(data).hexdigest() for _, data in log
    ]
    kinds = {json.loads(data)["kind"] for _, data in log}
    assert kinds == {"declared_function_options", "restart_semantics", "lease_test"}
    texts = [data.decode() for _, data in log]
    assert any("test_lease.py::test_two_workers_one_executes" in text for text in texts)
    assert not any(TOKEN_SECRET in text or "SYNTHETIC_PARENT" in text for text in texts)

    # the executor accepts the built record for exactly the deployment it describes
    pin = ModalPin(
        "synthetic-app",
        "synthetic-worker",
        record.deployment_version,
        record.image_digest,
        CODE_DIGEST,
        "1.6.3",
        DESTINATION,
    )
    sdk = FakeModal()
    executor = make_executor(scenario, sdk, record=record, pin=pin)
    assert executor.submit(scenario.plan, scenario.attempt, scenario.grants).remote_call_id
    # the record is built from the image and code it names: another spec is another digest
    other, _ = build_record(scenario)
    assert other == record
    assert (
        capability_record_from_live(
            parse_live(settings_document()),
            PROJECT,
            scenario.plan.execution_config_ref,
            "1.6.3",
            IMAGE_SPEC | {"python_version": "3.13"},
            CODE_DIGEST,
            NOW,
            lambda schema, data: make_ref(data, schema),
        ).image_digest
        != record.image_digest
    )


def test_record_refuses_unusable_inputs() -> None:
    scenario = build()
    config = parse_live(settings_document())
    ref = scenario.plan.execution_config_ref

    def sink(schema: str, data: bytes) -> ArtifactRef:
        return make_ref(data, schema)

    def broken(_schema: str, _data: bytes) -> ArtifactRef:
        raise OSError(SDK_SECRET)

    with pytest.raises(ContractError) as outage:
        capability_record_from_live(
            config, PROJECT, ref, "1.6.3", IMAGE_SPEC, CODE_DIGEST, NOW, broken
        )
    assert outage.value.code == "unavailable" and SDK_SECRET not in str(outage.value)
    with pytest.raises(ContractError) as untyped:
        capability_record_from_live(
            config,
            PROJECT,
            ref,
            "1.6.3",
            IMAGE_SPEC,
            CODE_DIGEST,
            NOW,
            lambda *_: b"x",  # type: ignore[arg-type]
        )
    assert untyped.value.code == "unavailable"
    for bad_digest in ("short", "C" * 64):
        with pytest.raises(ContractError) as invalid:
            capability_record_from_live(
                config, PROJECT, ref, "1.6.3", IMAGE_SPEC, bad_digest, NOW, sink
            )
        assert invalid.value.code == "invalid_schema"
    with pytest.raises(ContractError):
        capability_record_from_live(
            config, PROJECT, ref, "1.6.3", IMAGE_SPEC, CODE_DIGEST, "soon", sink
        )


def test_record_rejected_when_total_exceeds_max_wall() -> None:
    # the record's total (scheduling + startup + execution + cancel margin) is 510 s
    fits = build(resources={"max_wall_seconds": 510})
    record, _ = build_record(fits)
    assert record.total_bound_seconds == 510
    validate_capabilities(record, fits.plan)

    tight = build(resources={"max_wall_seconds": 509})
    with pytest.raises(ContractError) as over:
        validate_capabilities(record, tight.plan)
    assert over.value.code == "limit_exceeded"
    sdk = FakeModal()
    pin = ModalPin(
        "synthetic-app",
        "synthetic-worker",
        record.deployment_version,
        record.image_digest,
        CODE_DIGEST,
        "1.6.3",
        DESTINATION,
    )
    executor = make_executor(tight, sdk, record=record, pin=pin)
    with pytest.raises(ContractError) as refused:
        executor.submit(tight.plan, tight.attempt, tight.grants)
    assert refused.value.code == "limit_exceeded"
    assert sdk.spawned == []


def test_restart_gate_closes_for_built_record() -> None:
    scenario = build()
    record, _ = build_record(scenario)
    validate_capabilities(record, scenario.plan)

    def changed(**changes: Any) -> CapabilityRecord:
        value = record.model_dump(exclude_none=True) | changes
        return CapabilityRecord.model_validate(value)

    # one platform restart repeats startup and execution: the built total no longer covers it
    with pytest.raises(ContractError) as restarts:
        validate_capabilities(changed(max_platform_restarts=1), scenario.plan)
    assert restarts.value.code == "unsupported_capability"
    # without an evidenced bound the gate stays shut
    for unproven in ("unknown", "unbounded"):
        value = record.model_dump(exclude_none=True) | {"platform_restart_bound": unproven}
        value.pop("max_platform_restarts")
        with pytest.raises(ContractError) as blocked:
            validate_capabilities(CapabilityRecord.model_validate(value), scenario.plan)
        assert blocked.value.code == "unsupported_capability"
    # the built record is the only shape the live path produces: no retries, no gpu
    assert record.function_retries == 0 and record.gpu_count == 0
    with pytest.raises(ContractError):
        validate_capabilities(changed(function_retries=1), scenario.plan)


# -- duplicate and remote error with a lease -----------------------------------------------


def lease_executor(
    reader: Any, *polls: ModalPoll | Exception, scenario: Any = None
) -> tuple[Any, Any, list[tuple[str, bytes]]]:
    case = scenario or build()
    sdk = FakeModal()
    sdk.polls = list(polls)
    log: list[tuple[str, bytes]] = []
    executor = make_executor(case, sdk, evidence=log, reader_for=lambda _p, _a: reader)
    return executor, case, log


def test_duplicate_maps_to_unknown_outcome() -> None:
    case = staged()
    assert case.worker().claim_lease(ATTEMPT, "nonce-a") == "won"
    reader = case.control.attempt_reader(PROJECT, ATTEMPT)
    # the container returned exactly {"duplicate": true}: it lost to a worker that holds the lease
    assert DUPLICATE == json.dumps({"duplicate": True}).encode()
    executor, scenario, log = lease_executor(
        reader, ModalPoll("completed", DUPLICATE), scenario=case.scenario
    )
    observed = executor.observe(running(scenario))
    assert (observed.state, observed.result_ref) == ("unknown_outcome", None)
    assert json.loads(log[-1][1])["sdkState"] == "duplicate"

    # a standing cancel stays on record; it is never settled by a duplicate
    standing = replace_state(running(scenario), "cancel_requested")
    executor, _, _ = lease_executor(
        reader, ModalPoll("completed", DUPLICATE), scenario=case.scenario
    )
    assert executor.observe(standing).state == "cancel_requested"

    # a duplicate whose lease cannot be seen is no more certain
    bare = staged()
    executor, scenario, _ = lease_executor(
        bare.control.attempt_reader(PROJECT, ATTEMPT),
        ModalPoll("completed", DUPLICATE),
        scenario=bare.scenario,
    )
    assert executor.observe(running(scenario)).state == "unknown_outcome"

    # only the exact sentinel is a duplicate: anything else stays an unverified result
    for lookalike in (b'{"duplicate": 1}', b'{"duplicate": true, "x": 1}', b'["duplicate"]'):
        executor, scenario, log = lease_executor(
            reader, ModalPoll("completed", lookalike), scenario=case.scenario
        )
        assert executor.observe(running(scenario)).state == "unknown_outcome"
        assert json.loads(log[-1][1])["sdkState"] == "result_unverified"

    # a loser that found the winner's pointer returns the manifest Ref: mapped as in F1
    decided = staged()
    winner = decided.run(decided.worker(), "nonce-a")
    assert isinstance(winner, ArtifactRef)
    assert decided.run(decided.worker(), "nonce-b") == winner  # the loser found the pointer
    wire = winner.model_dump_json(by_alias=True, exclude_none=True).encode()
    executor, scenario, _ = lease_executor(
        decided.control.attempt_reader(PROJECT, ATTEMPT),
        ModalPoll("completed", wire),
        scenario=decided.scenario,
    )
    done = executor.observe(running(scenario))
    assert (done.state, done.result_ref) == ("succeeded", winner)


def replace_state(attempt: Any, state: str) -> Any:
    return type(attempt).model_validate(
        attempt.model_dump(by_alias=True, exclude_none=True) | {"state": state}
    )


def test_remote_error_with_lease_is_unknown_not_failed() -> None:
    case = staged()
    assert case.worker().claim_lease(ATTEMPT, "nonce-a") == "won"
    leased = case.control.attempt_reader(PROJECT, ATTEMPT)
    executor, scenario, log = lease_executor(
        leased, ModalPoll("remote_error"), scenario=case.scenario
    )
    observed = executor.observe(running(scenario))
    assert (observed.state, observed.result_ref) == ("unknown_outcome", None)
    assert json.loads(log[-1][1])["sdkState"] == "remote_error"

    # no lease anywhere: the function ended before claiming the attempt, so it is a failure
    unclaimed = staged()
    executor, scenario, _ = lease_executor(
        unclaimed.control.attempt_reader(PROJECT, ATTEMPT),
        ModalPoll("remote_error"),
        scenario=unclaimed.scenario,
    )
    assert executor.observe(running(scenario)).state == "failed"

    # a lease that cannot be read is not "no lease"
    class Unreadable:
        def lease_present(self) -> bool:
            raise ContractError("dispatch_unknown")

    executor, scenario, _ = lease_executor(Unreadable(), ModalPoll("remote_error"))
    assert executor.observe(running(scenario)).state == "unknown_outcome"

    # a standing cancel is kept rather than settled as failed
    executor, scenario, _ = lease_executor(
        leased, ModalPoll("remote_error"), scenario=case.scenario
    )
    assert (
        executor.observe(replace_state(running(case.scenario), "cancel_requested")).state
        == "cancel_requested"
    )


# -- the deadline token -------------------------------------------------------------------


def test_deadline_token_is_private_to_the_session(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch)
    first, second = make_session(), make_session()
    assert isinstance(first.deadline_token, DeadlineToken)
    assert first.deadline_token is first.deadline_token
    assert first.deadline_token is not second.deadline_token
    assert repr(first.deadline_token) == "DeadlineToken()"
    with pytest.raises(ContractError) as forged:
        DeadlineToken(object())
    assert forged.value.code == "forbidden"
    import copy
    import pickle

    for duplicate in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            duplicate(first.deadline_token)


def test_deadline_callback_runs_at_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    world, _ = install(monkeypatch)
    with make_session(clock=TickClock(step=10.0), deadline=25) as session:
        call_id = spawn_one(session, world)
        fired: list[int] = []

        def on_deadline() -> None:
            fired.append(len(world.get_timeouts))
            session.cancel(call_id)  # what the control side's cancel_attempt does via the executor

        poll = session.poll_until_terminal(call_id, on_deadline)

    assert fired == [2]  # only after the two bounded waits
    assert world.cancel_calls == [(call_id, True)]  # the callback cancelled; no second cancel
    assert poll == ModalPoll("cancelled")

    # a callback that did not cancel is backed up by the session: nothing outlives its deadline
    world, _ = install(monkeypatch)
    with make_session(clock=TickClock(step=10.0), deadline=25) as session:
        call_id = spawn_one(session, world)
        poll = session.poll_until_terminal(call_id, lambda: None)
    assert world.cancel_calls == [(call_id, True)]
    assert poll == ModalPoll("cancelled")

    # a callback that fails is reported, after the backstop cancel went out
    world, _ = install(monkeypatch)
    with make_session(clock=TickClock(step=10.0), deadline=25) as session:
        call_id = spawn_one(session, world)

        def failing() -> None:
            raise RuntimeError(SDK_SECRET)

        with pytest.raises(ContractError) as unknown:
            session.poll_until_terminal(call_id, failing)
    assert unknown.value.code == "unavailable" and SDK_SECRET not in str(unknown.value)
    assert world.cancel_calls == [(call_id, True)]

    # a call that finishes in time never fires it
    world, _ = install(monkeypatch)
    with make_session(clock=TickClock(step=10.0), deadline=25) as session:
        call_id = spawn_one(session, world)
        world.outcomes[call_id] = [b"manifest-ref-json"]

        def never() -> None:
            raise AssertionError("fired before the deadline")

        assert session.poll_until_terminal(call_id, never) == ModalPoll(
            "completed", b"manifest-ref-json"
        )
