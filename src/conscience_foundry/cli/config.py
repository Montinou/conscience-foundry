"""Private operator configuration and trusted adapters for the explicit CLI.

Everything here is operator-owned: the strictly parsed config file names the project, the one
acting operator, the separate grants, the registered stores/roots and the *reference* to the
ledger credential. Nothing is discovered from the environment, defaulted, or read from a request
document. Authenticated adapters (evidence, release approval, remote executor, transport scope)
are supplied by trusted code through `TrustedServices`; there is no default adapter and no plugin
loader, so a deployment without one cannot spend, approve, publish or activate anything.
"""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Literal, Self, cast

import psycopg
from psycopg.conninfo import conninfo_to_dict
from pydantic import AfterValidator, BeforeValidator, Field, StringConstraints, model_validator
from pydantic.json_schema import SkipJsonSchema

from conscience_foundry.contracts.codec import load_json
from conscience_foundry.contracts.common import (
    ContractError,
    ContractLimits,
    Digest,
    Id,
    Instant,
    PositiveInteger,
    ScalarString,
    WireModel,
)
from conscience_foundry.contracts.project import EFFECT_NAMES, PolicyArtifact
from conscience_foundry.execution.ports import (
    ControlContext,
    EvidenceAuthority,
    Executor,
    TransportGrants,
)
from conscience_foundry.ledger.db import Connection, Ledger
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.release.context import ReleaseAuthority, ReleaseContext, TrustedReleasePin
from conscience_foundry.storage.local import LocalObjectStore
from conscience_foundry.storage.locator import LocationRegistry

CONFIG_MAX_BYTES = 1 << 20
"""Syntax ceiling for the operator's own config/limits/policy files, before limits are known."""
LAYOUT = "cfoundry.cli-config.v1"

GRANT_COMMANDS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "admission": frozenset({"admit"}),
        "execution": frozenset(
            {"prepare-run", "authorize-run", "dispatch", "reconcile", "cancel", "pause", "resume"}
        ),
        "review": frozenset({"review"}),
        "release": frozenset({"build-release", "import-release"}),
        "publication": frozenset({"publish"}),
        "activation": frozenset({"activate"}),
        "read": frozenset({"read-span"}),
    }
)
"""Each effect class has its own grant list; one never implies another."""

# Library control actions (including budget-evidence purposes) and the only CLI commands whose
# grant may perform them. Cancellation observes and settles through the reconcile path, so it may
# perform those internal actions. Nothing else is reachable: storage reservations, billing
# corrections, manual unknown-outcome marks, budget reconciliation and control reads have no CLI
# command in this task, so no grant can authorize them here.
_SETTLEMENT = frozenset({"reconcile", "cancel"})
ACTION_COMMANDS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "install_run_authorization": frozenset({"authorize-run"}),
        "dispatch": frozenset({"dispatch"}),
        "reserve_attempt": frozenset({"dispatch"}),
        "reserve": frozenset({"dispatch"}),
        "manual_retry": frozenset({"dispatch"}),
        "reconcile": _SETTLEMENT,
        "apply_budget_event": _SETTLEMENT,
        "record_usage": _SETTLEMENT,
        "final_billing": _SETTLEMENT,
        "release_unspent": _SETTLEMENT,
        "final_no_effect": _SETTLEMENT,
        "cancel_attempt": frozenset({"cancel"}),
        "pause": frozenset({"pause"}),
        "resume": frozenset({"resume"}),
    }
)


def _array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _absolute(value: str) -> str:
    if not os.path.isabs(value) or "\x00" in value:
        raise ValueError("an absolute path is required")
    return value


Name = Annotated[ScalarString, StringConstraints(min_length=1)]
AbsolutePath = Annotated[ScalarString, AfterValidator(_absolute)]
EnvName = Annotated[str, StringConstraints(strict=True, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")]
SchemaName = Annotated[str, StringConstraints(strict=True, pattern=r"^[a-z][a-z0-9_]{0,62}$")]


class LedgerSettings(WireModel):
    """A reference to the ledger credential, never the credential itself."""

    schema_name: SchemaName
    dsn_env: EnvName | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    dsn_file: AbsolutePath | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    connect_timeout_seconds: PositiveInteger | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def one_credential_reference(self) -> Self:
        if (self.dsn_env is None) == (self.dsn_file is None):
            raise ValueError("exactly one credential reference is required")
        return self


class StoreSettings(WireModel):
    store_id: Name
    root_path: AbsolutePath
    limits: ContractLimits


class InputRoot(WireModel):
    root_id: Name
    path: AbsolutePath


class AdmissionSettings(WireModel):
    project_config_path: AbsolutePath
    profile_path: AbsolutePath
    contract_set_path: AbsolutePath
    input_roots: Annotated[tuple[InputRoot, ...], BeforeValidator(_array), Field(min_length=1)]

    @model_validator(mode="after")
    def unique_roots(self) -> Self:
        if len({root.root_id for root in self.input_roots}) != len(self.input_roots):
            raise ValueError("duplicate input root")
        return self


class Grants(WireModel):
    admission: Annotated[tuple[Name, ...], BeforeValidator(_array)] = ()
    execution: Annotated[tuple[Name, ...], BeforeValidator(_array)] = ()
    review: Annotated[tuple[Name, ...], BeforeValidator(_array)] = ()
    release: Annotated[tuple[Name, ...], BeforeValidator(_array)] = ()
    publication: Annotated[tuple[Name, ...], BeforeValidator(_array)] = ()
    activation: Annotated[tuple[Name, ...], BeforeValidator(_array)] = ()
    read: Annotated[tuple[Name, ...], BeforeValidator(_array)] = ()

    @model_validator(mode="after")
    def commands_in_their_own_category(self) -> Self:
        for category, commands in GRANT_COMMANDS.items():
            if not set(getattr(self, category)) <= commands:
                raise ValueError("command granted under the wrong category")
        return self

    def allows(self, command: str) -> bool:
        return any(
            command in getattr(self, category)
            for category, commands in GRANT_COMMANDS.items()
            if command in commands
        )


class OperatorSettings(WireModel):
    actor_id: Id
    scopes: Annotated[tuple[Name, ...], BeforeValidator(_array)]
    grants: Grants

    @model_validator(mode="after")
    def known_scopes(self) -> Self:
        if not set(self.scopes) <= EFFECT_NAMES or len(set(self.scopes)) != len(self.scopes):
            raise ValueError("unknown or duplicate scope")
        return self


class PinSettings(WireModel):
    release_digest: Digest
    store_id: Name
    consumer_contract: Name
    capabilities: Annotated[tuple[Name, ...], BeforeValidator(_array)]


class RuntimeConfig(WireModel):
    schema_version: Literal["cfoundry.cli-config.v1"]
    project_id: Id
    operator: OperatorSettings
    ledger: LedgerSettings
    object_store: StoreSettings
    limits_path: AbsolutePath
    policy_path: AbsolutePath
    transport_limits: ContractLimits
    admission: AdmissionSettings | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    release_pins: Annotated[tuple[PinSettings, ...], BeforeValidator(_array)] = ()


@dataclass(frozen=True)
class TrustedServices:
    """Authenticated adapters supplied by deployment code, never by config or documents.

    A missing adapter blocks the commands that need it; nothing substitutes for it.
    """

    evidence_authority: EvidenceAuthority | None = None
    release_authority: ReleaseAuthority | None = None
    executor: Executor | None = None
    transport_grants: Callable[[Any, Any], TransportGrants] | None = None
    connect: Callable[[str], Connection] | None = None
    clock: Callable[[], Instant] | None = None


class _Refusing:
    """Fail-closed stand-in used only where a library port is structurally required."""

    decoders: Mapping[str, Callable[[bytes, ContractLimits], object]] = MappingProxyType({})

    def _refuse(self, *_args: object) -> Any:
        raise ContractError("unavailable")

    budget = observation = control = transport = approve = _refuse


def _bootstrap(size: int) -> ContractLimits:
    """Syntax-only limits for operator files whose real limits are not yet known."""
    bound = max(size, 1)
    return ContractLimits.model_validate(
        {
            "schemaVersion": "kf.contract-limits.v1",
            "version": "cli.bootstrap.v1",
            "maxJsonBytes": bound,
            "maxStringScalars": bound,
            "maxArrayItems": bound,
            "maxDepth": bound,
            "maxManifestItems": bound,
            "maxSourceBytes": bound,
            "maxOutputBytes": bound,
            "maxErrorMessageScalars": bound,
        }
    )


def _open_regular(path: str | Path, code: str, link: str) -> tuple[int, os.stat_result]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise ContractError(link if error.errno == errno.ELOOP else code) from None
    try:
        information = os.fstat(fd)
        if not stat.S_ISREG(information.st_mode):
            raise ContractError(code)
    except BaseException:
        os.close(fd)
        raise
    return fd, information


def _read_fd(fd: int, limit: int) -> bytes:
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ContractError("limit_exceeded")
    return data


def inside_repository(path: Path) -> bool:
    return any((parent / ".git").exists() for parent in (path.parent, *path.parent.parents))


def read_trusted(path: str | Path, limit: int, *, missing: str = "config_invalid") -> bytes:
    """Read an operator-owned file: regular, not a link, owned by us, not writable by others."""
    fd, information = _open_regular(path, missing, "config_insecure")
    if information.st_uid != os.geteuid() or information.st_mode & 0o022:
        os.close(fd)
        raise ContractError("config_insecure")
    return _read_fd(fd, limit)


def read_input(path: str | Path, limit: int) -> bytes:
    """Read a request document under the caller-declared byte ceiling; it grants nothing."""
    fd, _ = _open_regular(path, "input_unreadable", "input_unreadable")
    return _read_fd(fd, limit)


def load_config(path: str | Path) -> RuntimeConfig:
    location = Path(path)
    if inside_repository(location.absolute()):
        raise ContractError("config_in_repository")
    data = read_trusted(location, CONFIG_MAX_BYTES)
    try:
        return RuntimeConfig.from_wire(data, _bootstrap(len(data)))
    except Exception:
        raise ContractError("config_invalid") from None


def load_limits(path: str | Path) -> dict[str, ContractLimits]:
    data = read_trusted(path, CONFIG_MAX_BYTES)
    try:
        document = load_json(data, _bootstrap(len(data)))
        return {
            key: ContractLimits.model_validate(value, by_alias=True, by_name=False)
            for key, value in document.items()
        }
    except Exception:
        raise ContractError("config_invalid") from None


def resolve_dsn(settings: LedgerSettings) -> str:
    """Resolve the explicitly referenced credential; never discovered, defaulted or printed."""
    if settings.dsn_env is not None:
        value = os.environ.get(settings.dsn_env, "")
        if not value:
            raise ContractError("credential_unavailable")
    else:
        assert settings.dsn_file is not None
        location = Path(settings.dsn_file)
        if inside_repository(location):
            raise ContractError("config_in_repository")
        try:
            value = read_trusted(location, CONFIG_MAX_BYTES).decode("utf-8").strip()
        except ContractError:
            raise ContractError("credential_unavailable") from None
        except UnicodeError:
            raise ContractError("credential_invalid") from None
        if not value:
            raise ContractError("credential_unavailable")
    if any(
        option.envvar is not None and option.envvar.decode("ascii") in os.environ
        for option in psycopg.pq.Conninfo.get_defaults()
    ):
        raise ContractError("credential_invalid")  # ambient libpq routing is never trusted
    try:
        options = conninfo_to_dict(value)
    except psycopg.Error:
        raise ContractError("credential_invalid") from None
    if not options.get("host") or not options.get("dbname"):
        raise ContractError("credential_invalid")  # the target must be named, not discovered
    return value


def now() -> Instant:
    moment = datetime.now(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


class Runtime:
    """Lazy, per-invocation wiring of trusted ports from config; closed when the command ends."""

    def __init__(self, config: RuntimeConfig, services: TrustedServices, command: str) -> None:
        self.config = config
        self.services = services
        self.command = command
        self._stack = ExitStack()
        self._limits: dict[str, ContractLimits] | None = None
        self._store: LocalObjectStore | None = None
        self._ledger: Ledger | None = None
        self.access = AccessContext(
            config.project_id, config.operator.actor_id, frozenset(config.operator.scopes)
        )

    def close(self) -> None:
        self._stack.close()

    @property
    def limits(self) -> dict[str, ContractLimits]:
        if self._limits is None:
            self._limits = load_limits(self.config.limits_path)
        return self._limits

    def limit(self, schema: str) -> ContractLimits:
        found = self.limits.get(schema)
        if found is None:
            raise ContractError("limits_missing")
        return found

    def clock(self) -> Instant:
        return (self.services.clock or now)()

    def read_policy_bytes(self) -> bytes:
        return read_trusted(self.config.policy_path, self.limit("kf.policy.v1").max_json_bytes)

    def current_policy(self, project: Id) -> PolicyArtifact:
        """Re-read on every call so each effect boundary sees the policy as it is now."""
        return PolicyArtifact.from_wire(self.read_policy_bytes(), self.limit("kf.policy.v1"))

    @property
    def store(self) -> LocalObjectStore:
        if self._store is None:
            settings = self.config.object_store
            project, access = self.config.project_id, self.access

            def authority(ref: Any, context: AccessContext, effect: str) -> None:
                if ref.project_id != project or context != access:
                    raise ContractError("forbidden")

            registry = LocationRegistry(
                {settings.store_id: Path(settings.root_path)}, settings.limits, authority
            )
            self._stack.callback(registry.close)
            self._store = LocalObjectStore(settings.store_id, registry)
        return self._store

    @property
    def ledger(self) -> Ledger:
        if self._ledger is None:
            dsn = resolve_dsn(self.config.ledger)
            connect = self.services.connect
            timeout = self.config.ledger.connect_timeout_seconds

            def factory() -> Connection:
                if connect is not None:
                    return connect(dsn)
                if timeout is not None:
                    return cast(Connection, psycopg.connect(dsn, connect_timeout=timeout))
                return cast(Connection, psycopg.connect(dsn))

            self._ledger = Ledger(factory, schema=self.config.ledger.schema_name)
        return self._ledger

    def authorize(self, action: str, project: str, run: str | None, actor: str) -> bool:
        """Library control actions are allowed only for this command, this project and actor."""
        return (
            project == self.config.project_id
            and actor == self.config.operator.actor_id
            and self.command in ACTION_COMMANDS.get(action, frozenset())
            and self.config.operator.grants.allows(self.command)
        )

    @property
    def control(self) -> ControlContext:
        settings = self.config.object_store
        return ControlContext(
            access=self.access,
            clock=self.clock,
            limits_by_schema=self.limits,
            current_policy=self.current_policy,
            authorize=self.authorize,
            evidence_authority=self.services.evidence_authority or cast(Any, _Refusing()),
            output_store_id=settings.store_id,
            store=self.store,
            transport_limits=self.config.transport_limits,
        )

    @property
    def release(self) -> ReleaseContext:
        settings = self.config.object_store
        return ReleaseContext(
            self.access,
            self.store,
            self.clock,
            self.limits,
            settings.store_id,
            self.current_policy,
            self.services.release_authority or cast(Any, _Refusing()),
        )

    def pin(self, release_digest: str) -> TrustedReleasePin:
        for pin in self.config.release_pins:
            if pin.release_digest == release_digest:
                return TrustedReleasePin(
                    self.config.project_id,
                    pin.release_digest,
                    pin.store_id,
                    pin.consumer_contract,
                    tuple(pin.capabilities),
                )
        raise ContractError("pin_missing")
