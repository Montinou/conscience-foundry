"""Explicit operator CLI: gates, redaction and the same ledger-backed flow on synthetic data.

No live service is contacted. Operator authority comes only from a private test config and from
test-owned independent adapters; nothing a request document says can grant anything.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import tomllib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import psycopg
import pytest
from conftest import approved_database_dsn
from psycopg import sql
from test_execution_control import Case, Executor
from test_import_publication import (
    Library,
    activation,
    active_digest,
    build_library,
    events,
    operator,
    publication,
    record_bytes,
    span_of,
)
from test_ledger_db import (
    ACTOR,
    ASSET,
    BATCH,
    PROJECT,
    RUN,
    TIME,
    admission,
    encoded,
    limits,
    reference,
)
from test_release_build import ReleaseCase, make_case, produced_revision

from conscience_foundry.cli.config import TrustedServices
from conscience_foundry.cli.main import main
from conscience_foundry.contracts.canonical import RevisionReview
from conscience_foundry.contracts.common import Reason, Ref
from conscience_foundry.contracts.project import ProfileDescriptor, ProjectConfig
from conscience_foundry.contracts.registry import (
    export_schemas,
    registered_schema_ids,
    technical_metadata_binding,
)
from conscience_foundry.contracts.release import ReleaseSource
from conscience_foundry.execution.ports import Observation
from conscience_foundry.ledger.db import Ledger, register_admission

SECRET = "SECRETMARK"
ATTEMPT = "00000000-0000-0000-0000-0000000000a1"
DIGEST = "d" * 64
DSN_ENV = "CF_CLI_TEST_DSN"
STORE_ID = "synthetic"
ALL_GRANTS: dict[str, list[str]] = {
    "admission": ["admit"],
    "execution": [
        "prepare-run",
        "authorize-run",
        "dispatch",
        "reconcile",
        "cancel",
        "pause",
        "resume",
    ],
    "review": ["review"],
    "release": ["build-release", "import-release"],
    "publication": ["publish"],
    "activation": ["activate"],
    "read": ["read-span"],
}
EFFECT_ARGS: dict[str, list[str]] = {
    "admit": ["--manifest", "manifest.json"],
    "prepare-run": ["--plan", "plan.json"],
    "authorize-run": ["--authorization", "authorization.json"],
    "dispatch": [
        "--plan-ref",
        "plan-ref.json",
        "--authorization-ref",
        "authorization-ref.json",
        "--evidence-ref",
        "evidence-ref.json",
        "--asset-id",
        ASSET,
    ],
    "reconcile": ["--attempt-id", ATTEMPT],
    "cancel": [
        "--attempt-id",
        ATTEMPT,
        "--reason-code",
        "unavailable",
        "--reason-message",
        "operator stop",
        "--evidence-ref",
        "evidence-ref.json",
    ],
    "pause": [
        "--scope",
        "project",
        "--expected-version",
        "0",
        "--reason-code",
        "unavailable",
        "--reason-message",
        "operator stop",
        "--evidence-ref",
        "evidence-ref.json",
    ],
    "resume": [
        "--scope",
        "project",
        "--expected-version",
        "1",
        "--reason-code",
        "unavailable",
        "--reason-message",
        "operator resume",
        "--evidence-ref",
        "evidence-ref.json",
    ],
    "review": [
        "--review",
        "review.json",
        "--operation-key",
        DIGEST,
        "--revision-ref",
        "revision-ref.json",
        "--evidence-ref",
        "evidence-ref.json",
    ],
    "build-release": ["--selection", "selection.json"],
    "import-release": ["--release-ref", "release-ref.json"],
    "publish": ["--record", "record.json"],
    "activate": ["--record", "record.json"],
}


class Spy:
    """A trusted adapter stand-in that fails the test when anything touches it."""

    def __init__(self, name: str, calls: list[str]) -> None:
        self.name, self.calls = name, calls

    def __getattr__(self, attribute: str) -> Any:
        self.calls.append(f"{self.name}.{attribute}")
        raise AssertionError(f"{self.name}.{attribute} used outside an executed command")


@dataclass
class Result:
    exit: int
    raw: str
    payload: dict[str, Any] = field(default_factory=dict)

    @property
    def code(self) -> str | None:
        value = self.payload.get("code")
        return value if isinstance(value, str) else None


class NetworkProbe:
    def __init__(self) -> None:
        self.attempts = 0


@pytest.fixture
def network(monkeypatch: pytest.MonkeyPatch) -> NetworkProbe:
    probe = NetworkProbe()
    denied_connect = socket.socket.connect
    denied_create = socket.create_connection
    denied_resolve = socket.getaddrinfo

    def connect(sock: socket.socket, address: object) -> None:
        probe.attempts += 1
        denied_connect(sock, address)

    def create(*args: Any, **kwargs: Any) -> Any:
        probe.attempts += 1
        return denied_create(*args, **kwargs)

    def resolve(*args: Any, **kwargs: Any) -> Any:
        probe.attempts += 1
        return denied_resolve(*args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "create_connection", create)
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    return probe


def write_private(path: Path, data: bytes | str, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    path.chmod(mode)
    return path


def ref_json(schema: str, payload: bytes = b"synthetic") -> str:
    from conscience_foundry.contracts.common import Ref

    return Ref(
        schema_version="kf.artifact-ref.v1",
        project_id=PROJECT,
        digest=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
        media_type="application/json",
        artifact_schema=schema,
        locations=(),
    ).model_dump_json(by_alias=True)


def file_names(root: Path) -> list[str]:
    return sorted(str(path.relative_to(root)) for path in root.rglob("*") if path.is_file())


class Env:
    """A private operator configuration plus an in-process invocation of the real CLI."""

    def __init__(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        grants: dict[str, list[str]] | None = None,
        scopes: frozenset[str] = frozenset(
            {"read", "extract", "remoteTransfer", "auditMetadataRead"}
        ),
        policy: Callable[[], Any] | None = None,
        schemas: dict[str, Any] | None = None,
        bound: Any = None,
        pins: list[dict[str, Any]] | None = None,
        dsn: str | None = None,
        schema_name: str = "cf_cli_test",
    ) -> None:
        tmp_path.mkdir(parents=True, exist_ok=True)
        self.tmp = tmp_path
        self.monkeypatch = monkeypatch
        self.bound = bound if bound is not None else limits()
        self.private = tmp_path / "operator"
        self.private.mkdir(mode=0o700)
        self.objects = tmp_path / "objects"
        self.objects.mkdir(exist_ok=True)
        self.inputs = tmp_path / "inputs"
        self.inputs.mkdir()
        self.scopes = scopes
        self.grants = ALL_GRANTS if grants is None else grants
        self.pins = pins or []
        self.schema_name = schema_name
        self.policy = policy if policy is not None else (lambda: admission().evidence.pinned_policy)
        self.schemas = (
            schemas if schemas is not None else dict.fromkeys(registered_schema_ids(), self.bound)
        )
        self.limits_path = self.private / "limits.json"
        self.policy_path = self.private / "policy.json"
        self.config_path = self.private / "config.json"
        self.connects: list[str] = []
        self.extra: dict[str, Any] = {}
        monkeypatch.setenv(
            DSN_ENV,
            dsn
            if dsn is not None
            else f"host={tmp_path}/{SECRET} dbname=cf_{SECRET.lower()}_test user={SECRET}",
        )
        self.write_config()

    def config(self) -> dict[str, Any]:
        bound = self.bound.model_dump(by_alias=True)
        value: dict[str, Any] = {
            "schemaVersion": "cfoundry.cli-config.v1",
            "projectId": PROJECT,
            "operator": {
                "actorId": ACTOR,
                "scopes": sorted(self.scopes),
                "grants": self.grants,
            },
            "ledger": {"schemaName": self.schema_name, "dsnEnv": DSN_ENV},
            "objectStore": {"storeId": STORE_ID, "rootPath": str(self.objects), "limits": bound},
            "limitsPath": str(self.limits_path),
            "policyPath": str(self.policy_path),
            "transportLimits": bound,
            "releasePins": self.pins,
        }
        value.update(self.extra)
        return value

    def write_config(self) -> None:
        write_private(
            self.limits_path,
            json.dumps({k: v.model_dump(by_alias=True) for k, v in self.schemas.items()}),
        )
        self.sync_policy()
        write_private(self.config_path, json.dumps(self.config()))

    def sync_policy(self) -> None:
        write_private(self.policy_path, self.policy().model_dump_json(by_alias=True))

    def input(self, name: str, data: bytes | str) -> str:
        return str(write_private(self.inputs / name, data, 0o644))

    def connect(self, dsn: str) -> Any:
        self.connects.append("connect")
        raise psycopg.OperationalError(f"password={SECRET} unreachable")

    def invoke(
        self,
        *argv: str,
        services: TrustedServices | None = None,
        config: bool = True,
    ) -> Result:
        out = io.StringIO()
        prefix = ["--config", str(self.config_path)] if config else []
        self.sync_policy()
        chosen = services if services is not None else TrustedServices(connect=self.connect)
        code = main([*prefix, *argv], services=chosen, out=out)
        raw = out.getvalue()
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = {}
        return Result(code, raw, payload if isinstance(payload, dict) else {})

    def assert_redacted(self, result: Result) -> None:
        for marker in (SECRET, str(self.tmp), "Traceback", "password"):
            assert marker not in result.raw


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    return Env(tmp_path, monkeypatch)


def spy_services(calls: list[str], env: Env) -> TrustedServices:
    return TrustedServices(
        evidence_authority=Spy("evidence", calls),
        release_authority=Spy("release", calls),
        executor=Spy("executor", calls),
        transport_grants=lambda *args: calls.append("transport") or Spy("grants", calls),
        connect=env.connect,
        clock=lambda: calls.append("clock") or TIME,
    )


def test_help_and_dry_run_have_no_external_effect(env: Env, network: NetworkProbe) -> None:
    helped = io.StringIO()
    assert main(["--help"], out=helped) == 0
    for command in (*EFFECT_ARGS, "validate", "read-span"):
        assert command in helped.getvalue()
    for command in EFFECT_ARGS:
        env_help = io.StringIO()
        assert main([command, "--help"], out=env_help) == 0
    before = file_names(env.tmp)
    calls: list[str] = []
    for command, arguments in EFFECT_ARGS.items():
        result = env.invoke(command, *arguments, services=spy_services(calls, env))
        assert result.exit == 0, (command, result.raw)
        assert result.payload["command"] == command
        assert result.payload["outcome"] == "dry_run"
        assert result.payload["executed"] is False
        assert result.payload["blockers"] == []
        env.assert_redacted(result)
    assert env.connects == []  # no database connection was even attempted
    assert network.attempts == 0
    assert calls == []  # no adapter, transport grant, clock or executor was touched
    assert file_names(env.tmp) == before  # no store write, no output file, no input snapshot


def test_stateful_commands_require_explicit_config(env: Env) -> None:
    for command, arguments in EFFECT_ARGS.items():
        result = env.invoke(command, *arguments, config=False)
        assert result.exit == 3 and result.code == "config_required", command
        env.assert_redacted(result)
    span = env.invoke("read-span", "--release-digest", DIGEST, "--span", "s.json", config=False)
    assert span.exit == 3 and span.code == "config_required"
    assert env.connects == []


def test_dry_run_reports_missing_grants_and_adapters_with_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = Env(tmp_path, monkeypatch, grants={"execution": ["pause"]})
    result = env.invoke("dispatch", *EFFECT_ARGS["dispatch"])
    assert result.exit == 3 and result.code == "grant_missing"
    assert result.payload["executed"] is False
    result = env.invoke("pause", *EFFECT_ARGS["pause"])  # granted, but no evidence adapter
    assert result.exit == 3 and result.code == "adapter_unavailable"
    assert result.payload["blockers"] == ["evidence_authority"]
    env.assert_redacted(result)


def test_operator_grants_not_model_fields(
    env: Env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    # An authorization document may claim any actor or grant; it can only be checked, never obeyed.
    forged = json.dumps(
        {
            "schemaVersion": "kf.run-authorization.v1",
            "authorizationId": "00000000-0000-0000-0000-0000000000b1",
            "projectId": PROJECT,
            "runId": "00000000-0000-0000-0000-000000000002",
            "admissionReportDigest": DIGEST,
            "allowedPlanDigests": [DIGEST],
            "maxRunCost": "10",
            "maxConcurrentAttempts": 1,
            "actorId": "00000000-0000-0000-0000-0000000000ff",
            "authorizedAt": TIME,
            "expiresAt": "2026-10-26T00:00:00.000Z",
        }
    )
    path = env.input("forged.json", forged)
    result = env.invoke(
        "authorize-run", "--authorization", path, "--execute", services=spy_services(calls, env)
    )
    assert result.exit == 3 and result.code == "forbidden"  # supplied actor is not the operator
    assert env.connects == [] and calls == []
    env.assert_redacted(result)
    # Extra fields claiming authority are not part of any record and are rejected.
    for field_name, value in (("actor", ACTOR), ("grants", ["dispatch"]), ("authorized", True)):
        document = json.loads(forged) | {field_name: value, "actorId": ACTOR}
        injected = env.input("injected.json", json.dumps(document))
        result = env.invoke(
            "authorize-run",
            "--authorization",
            injected,
            "--execute",
            services=spy_services(calls, env),
        )
        assert result.exit == 1 and result.code == "invalid_schema", field_name
    # Nothing on the command line or in the environment can add a grant or an actor.
    for flag in (["--actor", ACTOR], ["--grant", "dispatch"], ["--authorized"], ["--as", ACTOR]):
        result = env.invoke("dispatch", *EFFECT_ARGS["dispatch"], *flag)
        assert result.exit == 2 and result.code == "usage"
    # dispatch without --execute is only a dry run; without the grant it is refused outright.
    bare = Env(tmp_path / "bare", monkeypatch, grants={})
    for extra in ([], ["--execute"]):
        result = bare.invoke("dispatch", *EFFECT_ARGS["dispatch"], *extra)
        assert result.exit == 3 and result.code == "grant_missing"
    assert bare.connects == []


def test_each_grant_is_separate_and_local_commands_do_not_imply_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    local = {"release": ["build-release", "import-release"], "read": ["read-span"]}
    env = Env(tmp_path, monkeypatch, grants=local)
    for command in ("publish", "activate", "dispatch", "admit", "review"):
        result = env.invoke(command, *EFFECT_ARGS[command], "--execute")
        assert result.exit == 3 and result.code == "grant_missing", command
    # A grant for one command never covers a sibling command of the same category.
    narrow = Env(tmp_path / "n", monkeypatch, grants={"execution": ["pause"]})
    for command in ("resume", "cancel", "reconcile", "authorize-run", "prepare-run"):
        result = narrow.invoke(command, *EFFECT_ARGS[command], "--execute")
        assert result.exit == 3 and result.code == "grant_missing", command
    # A command listed under the wrong category is not a grant.
    wrong = Env(tmp_path / "w", monkeypatch, grants={"release": ["publish"]})
    assert wrong.invoke("publish", *EFFECT_ARGS["publish"]).code in {"config_invalid"}


def test_config_is_strict_private_and_has_no_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = Env(tmp_path, monkeypatch)
    base = env.config()
    arguments = EFFECT_ARGS["pause"]

    def attempt(config: dict[str, Any], mode: int = 0o600) -> Result:
        write_private(env.config_path, json.dumps(config), mode)
        return env.invoke("pause", *arguments)

    for broken in (
        base | {"surprise": 1},
        base | {"ledger": {"schemaName": "cf_x"}},  # no credential reference: no default DSN
        base | {"ledger": {"schemaName": "cf_x", "dsnEnv": DSN_ENV, "dsnFile": "/x"}},
        {k: v for k, v in base.items() if k != "transportLimits"},  # no default limits
        {k: v for k, v in base.items() if k != "objectStore"},  # no default root
        base | {"limitsPath": "relative/limits.json"},
        base | {"operator": base["operator"] | {"scopes": ["root"]}},
        base | {"operator": base["operator"] | {"grants": {"execution": ["publish"]}}},
        base | {"projectId": "not-an-id"},
    ):
        result = attempt(broken)
        assert result.exit == 3 and result.code == "config_invalid", broken
        env.assert_redacted(result)
    assert attempt(base, 0o666).code == "config_insecure"
    write_private(env.config_path, b"{not json")
    assert env.invoke("pause", *arguments).code == "config_invalid"
    duplicate = json.dumps(base)[:-1] + ',"projectId":"' + PROJECT + '"}'
    write_private(env.config_path, duplicate)
    assert env.invoke("pause", *arguments).code == "config_invalid"
    link = env.private / "link.json"
    write_private(env.config_path, json.dumps(base))
    link.symlink_to(env.config_path)
    out = io.StringIO()
    assert main(["--config", str(link), "pause", *arguments], out=out) == 3
    assert json.loads(out.getvalue())["code"] == "config_insecure"
    missing = io.StringIO()
    assert main(["--config", str(tmp_path / "absent.json"), "pause", *arguments], out=missing) == 3
    assert json.loads(missing.getvalue())["code"] == "config_invalid"
    assert str(tmp_path) not in missing.getvalue()


FIFO_PROBE = """
import sys
from conscience_foundry.cli.config import (
    LedgerSettings,
    load_config,
    read_input,
    read_trusted,
    resolve_dsn,
)
from conscience_foundry.contracts.common import ContractError

path = sys.argv[1]
codes = []
for attempt in (
    lambda: read_input(path, 1024),
    lambda: read_trusted(path, 1024),
    lambda: load_config(path),
    lambda: resolve_dsn(LedgerSettings(schema_name="cf_x", dsn_file=path)),
):
    try:
        attempt()
    except ContractError as error:
        codes.append(error.code)
print(",".join(codes))
"""


def test_a_fifo_is_refused_without_blocking(tmp_path: Path) -> None:
    """Config, DSN and input paths are opened without waiting for a writer to appear."""
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    # A child process, so a blocked open() cannot hang the suite: it is killed at the timeout.
    done = subprocess.run(
        [sys.executable, "-I", "-c", FIFO_PROBE, str(fifo)],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    expected = "input_unreadable,config_invalid,config_invalid,credential_unavailable"
    assert done.stdout.strip() == expected


def test_config_inside_a_repository_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = Env(tmp_path, monkeypatch)
    (env.private / ".git").mkdir()
    result = env.invoke("pause", *EFFECT_ARGS["pause"])
    assert result.exit == 3 and result.code == "config_in_repository"
    env.assert_redacted(result)


def test_database_credential_reference_is_explicit_and_never_printed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = Env(tmp_path, monkeypatch)
    services = TrustedServices(evidence_authority=Spy("evidence", []), connect=env.connect)
    monkeypatch.delenv(DSN_ENV)
    result = env.invoke("pause", *EFFECT_ARGS["pause"], services=services)
    assert result.exit == 3 and result.code == "credential_unavailable"  # dry run reports it
    result = env.invoke("pause", *EFFECT_ARGS["pause"], "--execute", services=services)
    assert result.exit == 3 and result.code == "credential_unavailable"
    # A DSN that leans on ambient libpq routing is refused rather than discovered.
    monkeypatch.setenv(DSN_ENV, "dbname=cf_x")
    result = env.invoke("pause", *EFFECT_ARGS["pause"], "--execute", services=services)
    assert result.code == "credential_invalid"
    monkeypatch.setenv(DSN_ENV, f"host=/x dbname=cf_{SECRET.lower()}")
    monkeypatch.setenv("PGHOST", "elsewhere")
    result = env.invoke("pause", *EFFECT_ARGS["pause"], "--execute", services=services)
    assert result.code == "credential_invalid"
    env.assert_redacted(result)
    monkeypatch.delenv("PGHOST")
    # A real connection failure surfaces only a stable code, never the driver message.
    evidence = env.input("evidence.json", ref_json("kf.control-evidence.v1"))
    arguments = [
        evidence if value == "evidence-ref.json" else value for value in EFFECT_ARGS["pause"]
    ]
    result = env.invoke("pause", *arguments, "--execute", services=services)
    assert result.exit == 1 and result.code == "unavailable"
    assert env.connects == ["connect"]
    env.assert_redacted(result)


def test_validate_checks_registered_schemas_offline(env: Env, network: NetworkProbe) -> None:
    good = env.input("policy.json", admission().evidence.policy_bytes)
    result = env.invoke(
        "validate",
        "--schema",
        "kf.policy.v1",
        "--input",
        good,
        "--limits",
        str(env.limits_path),
        config=False,
    )
    assert result.exit == 0 and result.payload["outcome"] == "ok"
    assert result.payload["schema"] == "kf.policy.v1" and result.payload["valid"] is True
    bad = env.input("bad.json", json.dumps({"schemaVersion": "kf.policy.v1", "extra": 1}))
    result = env.invoke(
        "validate",
        "--schema",
        "kf.policy.v1",
        "--input",
        bad,
        "--limits",
        str(env.limits_path),
        config=False,
    )
    assert result.exit == 1 and result.code == "invalid_schema"
    unknown = env.invoke(
        "validate",
        "--schema",
        "not.registered.v1",
        "--input",
        good,
        "--limits",
        str(env.limits_path),
        config=False,
    )
    assert unknown.exit == 3 and unknown.code == "unsupported_schema"
    for shown in (result, unknown):
        env.assert_redacted(shown)
    assert network.attempts == 0 and env.connects == []


def test_usage_errors_are_redacted_and_nonzero(env: Env) -> None:
    for argv in (
        ["no-such-command", "--secret-path", f"/{SECRET}"],
        ["dispatch", "--unknown", SECRET],
        ["pause", "--scope", "galaxy"],
        [],
    ):
        result = env.invoke(*argv, config=False)
        assert result.exit == 2 and result.code == "usage", argv
        assert SECRET not in result.raw


def test_control_actions_follow_only_the_running_and_granted_command(
    env: Env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from conscience_foundry.cli.commands import COMMANDS
    from conscience_foundry.cli.config import Runtime, load_config

    def allowed(
        config_path: Path, command: str, action: str, *, actor: str = ACTOR, project: str = PROJECT
    ) -> bool:
        runtime = Runtime(load_config(config_path), TrustedServices(), command)
        return runtime.authorize(action, project, RUN, actor)

    path = env.config_path
    assert allowed(path, "dispatch", "dispatch") and allowed(path, "dispatch", "manual_retry")
    assert allowed(path, "dispatch", "reserve_attempt") and allowed(path, "dispatch", "reserve")
    assert allowed(path, "authorize-run", "install_run_authorization")
    assert allowed(path, "reconcile", "record_usage") and allowed(path, "cancel", "reconcile")
    assert allowed(path, "pause", "pause") and allowed(path, "resume", "resume")
    assert not allowed(path, "pause", "reserve_attempt")
    assert not allowed(path, "reconcile", "reserve_attempt")
    assert not allowed(path, "dispatch", "record_usage")
    assert not allowed(path, "reconcile", "cancel_attempt")
    assert not allowed(path, "resume", "pause") and not allowed(path, "pause", "resume")
    for action in (
        "reserve_storage",
        "mark_unknown_outcome",
        "reconcile_budget",
        "control_read",
        "apply_billing_adjustment",
        "billing_adjustment",
        "anything_else",
    ):
        assert not any(allowed(path, command.name, action) for command in COMMANDS)
    assert not allowed(path, "dispatch", "dispatch", actor="00000000-0000-0000-0000-0000000000ff")
    assert not allowed(path, "dispatch", "dispatch", project="00000000-0000-0000-0000-0000000000ff")
    narrow = Env(tmp_path / "narrow", monkeypatch, grants={"execution": ["pause"]})
    assert allowed(narrow.config_path, "pause", "pause")
    assert not allowed(narrow.config_path, "dispatch", "dispatch")  # not granted, so no action


def test_console_script_is_registered() -> None:
    root = Path(__file__).resolve().parents[2]
    project = tomllib.loads((root / "pyproject.toml").read_text())
    assert project["project"]["scripts"]["cfoundry"] == "conscience_foundry.cli.main:run"


@pytest.fixture(autouse=True)
def clean_libpq_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for option in psycopg.pq.Conninfo.get_defaults():
        if option.envvar is not None:
            monkeypatch.delenv(option.envvar.decode("ascii"), raising=False)
    yield


# --- ledger-backed flow: the CLI drives the real T11/T12/T13 functions ---------------------------


ADMIT_ASSET_B = "00000000-0000-0000-0000-000000000009"
ADMIT_SOURCE_B = "00000000-0000-0000-0000-000000000008"
SOURCE_A = "00000000-0000-0000-0000-000000000005"


def count(ledger: Ledger, table: str, where: str = "true", params: tuple[Any, ...] = ()) -> int:
    with ledger.transaction() as tx:
        row = tx.connection.execute(
            sql.SQL("SELECT count(*) FROM {} WHERE " + where).format(tx.table(table)), params
        ).fetchone()
    assert row is not None
    return int(row[0])


def database_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ledger: Ledger, case: Case, **overrides: Any
) -> Env:
    return Env(
        tmp_path,
        monkeypatch,
        schemas=case.schemas,
        bound=case.bound,
        policy=lambda: case.policy,
        scopes=case.access.scopes,
        dsn=approved_database_dsn(),
        schema_name=ledger.schema,
        **overrides,
    )


def case_services(
    case: Case, executor: Executor, minted: list[str] | None = None
) -> TrustedServices:
    def grants(plan: Any, attempt: Any, plan_ref: Any) -> Any:
        assert attempt.state == "dispatching"  # asked only for the claimed, durable attempt
        if minted is not None:
            minted.append(plan_ref.digest)
        return case.grants(attempt_id=attempt.attempt_id)

    return TrustedServices(
        evidence_authority=case.authority,
        executor=executor,
        transport_grants=grants,
        clock=lambda: TIME,
    )


def register(case: Case, ledger: Ledger) -> None:
    with ledger.transaction() as tx:
        register_admission(
            case.data.manifest_ref,
            case.data.report,
            case.data.report_ref,
            tx,
            evidence=case.data.evidence,
        )


def ref_file(env: Env, name: str, ref: Any) -> str:
    return env.input(name, ref.model_dump_json(by_alias=True))


class Prepared:
    """A case driven through prepare-run and authorize-run by the CLI itself."""

    def __init__(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ledger: Ledger, *, lost: bool = False
    ) -> None:
        self.ledger = ledger
        self.case = Case(tmp_path)
        self.executor = Executor(self.case, lost=lost)
        self.minted: list[str] = []
        self.env = database_env(tmp_path, monkeypatch, ledger, self.case)
        self.services = case_services(self.case, self.executor, self.minted)
        register(self.case, ledger)
        plan = self.env.input("plan.json", encoded(self.case.plan))
        auth = self.env.input("authorization.json", encoded(self.case.auth))
        assert self.run("prepare-run", "--plan", plan, "--execute").exit == 0
        assert self.run("authorize-run", "--authorization", auth, "--execute").exit == 0
        self.dispatch_args = [
            "--plan-ref",
            ref_file(self.env, "plan-ref.json", self.case.plan_ref),
            "--authorization-ref",
            ref_file(self.env, "authorization-ref.json", self.case.auth_ref),
            "--evidence-ref",
            ref_file(self.env, "estimate.json", self.case.estimate),
            "--asset-id",
            ASSET,
        ]

    def run(self, *argv: str) -> Result:
        return self.env.invoke(*argv, services=self.services)

    def dispatch(self) -> Result:
        return self.run("dispatch", *self.dispatch_args, "--execute")

    def control_args(self, action: str, *, scope: str = "project", version: int = 0) -> list[str]:
        proof = self.case.proof()
        self.case.authority.controls[proof.digest] = (action, None, (), False, False)
        extra = ["--run-id", RUN] if scope == "run" else []
        return [
            "--scope",
            scope,
            *extra,
            "--expected-version",
            str(version),
            "--reason-code",
            "unavailable",
            "--reason-message",
            "operator decision",
            "--evidence-ref",
            ref_file(self.env, f"{action}-{version}.json", proof),
        ]

    def attempt(self, result: Result) -> SimpleNamespace:
        found = result.payload["attempt"]
        return SimpleNamespace(
            attempt_id=found["attemptId"], remote_call_id=found.get("remoteCallId")
        )


@pytest.mark.database
def test_prepare_run_needs_a_registered_admission_report(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    env = database_env(tmp_path, monkeypatch, ledger, case)
    plan = env.input("plan.json", encoded(case.plan))
    services = case_services(case, Executor(case))
    result = env.invoke("prepare-run", "--plan", plan, "--execute", services=services)
    assert result.exit == 3 and result.code == "forbidden"  # the report is not registered
    assert count(ledger, "runs") == 0
    register(case, ledger)
    result = env.invoke("prepare-run", "--plan", plan, "--execute", services=services)
    assert result.exit == 0 and result.payload["runId"] == RUN
    assert result.payload["planRef"]["digest"] == case.plan_ref.digest
    assert count(ledger, "runs") == 1
    assert count(ledger, "attempts") == 0  # preparing a run reserves and spends nothing
    again = env.invoke("prepare-run", "--plan", plan, "--execute", services=services)
    assert again.exit == 0 and count(ledger, "runs") == 1  # idempotent
    env.assert_redacted(again)


@pytest.mark.database
def test_prepare_run_rejects_a_plan_file_that_is_not_in_canonical_form(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    register(case, ledger)
    env = database_env(tmp_path, monkeypatch, ledger, case)
    services = case_services(case, Executor(case))
    pretty = json.dumps(json.loads(encoded(case.plan)), indent=2, sort_keys=True)
    plan = env.input("plan.json", pretty)
    result = env.invoke("prepare-run", "--plan", plan, "--execute", services=services)
    # Digests bind the stored bytes everywhere, so only the canonical serialization is accepted.
    assert result.exit == 1 and result.code == "invalid_schema"
    assert count(ledger, "runs") == 0


@pytest.mark.database
def test_prepare_run_rejects_a_plan_that_does_not_match_the_registered_admission(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    register(case, ledger)
    env = database_env(tmp_path, monkeypatch, ledger, case)
    services = case_services(case, Executor(case))
    mismatched = case.plan.model_copy(update={"operation_key": "e" * 64})
    plan = env.input("plan.json", encoded(mismatched))
    result = env.invoke("prepare-run", "--plan", plan, "--execute", services=services)
    assert result.exit == 3 and result.code == "forbidden"
    assert count(ledger, "runs") == 0  # the run opened for the check was rolled back


@pytest.mark.database
def test_authorization_needs_the_independent_authority_not_the_cli_flags(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    register(case, ledger)
    env = database_env(tmp_path, monkeypatch, ledger, case)
    services = case_services(case, Executor(case))
    plan = env.input("plan.json", encoded(case.plan))
    auth = env.input("authorization.json", encoded(case.auth))
    assert env.invoke("prepare-run", "--plan", plan, "--execute", services=services).exit == 0
    del case.authority.grants[case.auth_ref.digest]  # the authority never approved this grant
    result = env.invoke("authorize-run", "--authorization", auth, "--execute", services=services)
    assert result.exit != 0 and result.code is not None
    assert count(ledger, "authorizations") == 0
    case.authority.grants[case.auth_ref.digest] = case.auth_ref.digest, None
    ok = env.invoke("authorize-run", "--authorization", auth, "--execute", services=services)
    assert ok.exit == 0 and ok.payload["authorizationId"] == case.auth.authorization_id
    assert count(ledger, "authorizations") == 1
    assert count(ledger, "attempts") == 0


@pytest.mark.database
def test_dispatch_and_reconcile_use_the_ledger_and_never_trust_a_submit(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Prepared(tmp_path, monkeypatch, ledger)
    dry = run.run("dispatch", *run.dispatch_args)
    assert dry.payload["outcome"] == "dry_run" and run.executor.calls == 0
    assert run.minted == [] and count(ledger, "attempts") == 0
    first = run.dispatch()
    assert first.exit == 0 and first.payload["attempt"]["state"] == "running"
    assert run.executor.calls == 1 and run.minted == [run.case.plan_ref.digest]
    assert count(ledger, "attempts") == 1 and count(ledger, "reservations") == 1
    attempt = run.attempt(first)
    # A worker that has not finished cannot be reported as a result.
    run.executor.next = Observation("running", None, None, run.case.proof())
    run.case.authority.observations[run.executor.next.evidence.digest] = (
        attempt.remote_call_id,
        "running",
        None,
        False,
        False,
    )
    running = run.run("reconcile", "--attempt-id", attempt.attempt_id, "--execute")
    assert running.exit == 0 and running.payload["attempt"]["state"] == "running"
    assert running.payload["selection"] is None and count(ledger, "operation_results") == 0
    run.executor.success(attempt)
    done = run.run("reconcile", "--attempt-id", attempt.attempt_id, "--execute")
    assert done.exit == 0 and done.payload["attempt"]["state"] == "succeeded"
    assert done.payload["selection"]["outcome"] == "selected"
    assert count(ledger, "operation_results") == 1 and run.executor.calls == 1
    run.env.assert_redacted(done)


@pytest.mark.database
def test_dispatch_reads_current_policy_before_any_transport_scope_is_minted(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Prepared(tmp_path, monkeypatch, ledger)
    current = run.case.policy
    run.env.policy = lambda: current.model_copy(update={"effective_at": "2026-10-25T12:00:00.000Z"})
    blocked = run.dispatch()  # a policy that is not yet effective is not current permission
    assert blocked.exit == 3 and blocked.code == "permission_unknown"
    assert run.minted == [] and run.executor.calls == 0 and count(ledger, "attempts") == 0
    run.env.policy = lambda: current
    assert run.dispatch().exit == 0 and run.executor.calls == 1


@pytest.mark.database
def test_unknown_outcome_is_failure_and_blocks_a_second_claim(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Prepared(tmp_path, monkeypatch, ledger, lost=True)
    first = run.dispatch()
    assert first.exit == 1 and first.code == "unknown_outcome"
    assert first.payload["attempt"]["state"] == "unknown_outcome"
    assert run.executor.calls == 1
    second = run.dispatch()  # the unresolved attempt keeps its reservation and blocks new work
    assert second.exit == 3 and second.code == "dispatch_unknown"
    assert run.executor.calls == 1 and count(ledger, "attempts") == 1
    assert len(run.minted) == 1  # the refused second dispatch minted nothing


@pytest.mark.database
def test_durable_pause_stops_dispatch_before_any_transport_scope_is_minted(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Prepared(tmp_path, monkeypatch, ledger)
    paused = run.run("pause", *run.control_args("pause"), "--execute")
    assert paused.exit == 0 and paused.payload["pause"]["paused"] is True
    assert paused.payload["pause"]["version"] == 1
    blocked = run.dispatch()
    assert blocked.exit == 3 and blocked.code == "paused"
    assert run.minted == [] and run.executor.calls == 0 and count(ledger, "attempts") == 0
    stale = run.run("pause", *run.control_args("pause", version=0), "--execute")
    assert stale.exit == 3 and stale.code == "activation_conflict"
    # Resume is its own grant and its own command; a pause grant cannot resume.
    run.env.grants = {"execution": [name for name in ALL_GRANTS["execution"] if name != "resume"]}
    run.env.write_config()
    refused = run.run("resume", *run.control_args("resume", version=1), "--execute")
    assert refused.exit == 3 and refused.code == "grant_missing"
    run.env.grants = ALL_GRANTS
    run.env.write_config()
    resumed = run.run("resume", *run.control_args("resume", version=1), "--execute")
    assert resumed.exit == 0 and resumed.payload["pause"]["paused"] is False
    assert run.dispatch().exit == 0 and run.executor.calls == 1


@pytest.mark.database
def test_cancel_requires_confirmed_termination_through_the_same_ledger(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Prepared(tmp_path, monkeypatch, ledger)
    attempt = run.attempt(run.dispatch())
    arguments = run.control_args("cancel_attempt")
    observed = run.case.proof()
    run.executor.next = Observation("cancelled", None, None, observed)
    run.case.authority.observations[observed.digest] = (
        attempt.remote_call_id,
        "cancelled",
        None,
        False,
        False,
    )
    command = ["cancel", "--attempt-id", attempt.attempt_id, *arguments[-6:], "--execute"]
    unconfirmed = run.run(*command)
    assert unconfirmed.exit != 0  # the provider has not proved termination
    run.case.authority.observations[observed.digest] = (
        attempt.remote_call_id,
        "cancelled",
        None,
        False,
        True,
    )
    confirmed = run.run(*command)
    assert confirmed.exit == 0 and confirmed.payload["attempt"]["state"] == "cancelled"
    run.env.assert_redacted(confirmed)
    unrelated = run.run("reconcile", "--attempt-id", attempt.attempt_id)
    assert unrelated.payload["outcome"] == "dry_run"  # reconcile stays a dry run without --execute


def admit_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ledger: Ledger
) -> tuple[Env, Path]:
    bound = limits()
    schemas = dict.fromkeys(registered_schema_ids(), bound)
    policy = admission().evidence.pinned_policy
    policy_bytes = policy.model_dump_json(by_alias=True).encode()
    policy_ref = reference(policy_bytes, "kf.policy.v1")
    bundle = export_schemas(
        tmp_path / "schemas",
        project_id=PROJECT,
        store_id=STORE_ID,
        version="synthetic.contract-set.v1",
        limits_by_schema=schemas,
    )
    binding = technical_metadata_binding(bundle, project_id=PROJECT, limits_by_schema=schemas)
    profile = ProfileDescriptor(
        schema_version="kf.profile.v1",
        profile_id="technical_minimal",
        version="synthetic.profile.v1",
        metadata_schema_ref=binding.expected_schema_ref,
        allowed_processor_ids=("text.utf8.v1",),
        extension_schema_refs=(),
        export_adapters=(),
    )
    project = ProjectConfig(
        schema_version="kf.project.v1",
        project_id=PROJECT,
        profile_id="technical_minimal",
        profile_version="synthetic.profile.v1",
        policy_ref=policy_ref,
        limits_refs=(reference(b"{}", "kf.contract-limits.v1"),),
        contract_set_ref=reference(encoded(bundle), "kf.contract-set.v1"),
        storage_config_ref=reference(b"{}", "kf.storage-config.v1"),
        execution_config_ref=reference(b"{}", "kf.execution-config.v1"),
    )
    env = Env(
        tmp_path,
        monkeypatch,
        schemas=schemas,
        bound=bound,
        dsn=approved_database_dsn(),
        schema_name=ledger.schema,
        scopes=frozenset({"read", "extract", "auditMetadataRead"}),
    )
    root = tmp_path / "custody"
    root.mkdir()
    for name, value in (
        ("project.json", project.model_dump_json(by_alias=True)),
        ("profile.json", profile.model_dump_json(by_alias=True)),
        ("contract-set.json", bundle.model_dump_json(by_alias=True)),
    ):
        write_private(env.private / name, value)
    env.extra["admission"] = {
        "projectConfigPath": str(env.private / "project.json"),
        "profilePath": str(env.private / "profile.json"),
        "contractSetPath": str(env.private / "contract-set.json"),
        "inputRoots": [{"rootId": "synthetic-input", "path": str(root)}],
    }
    env.write_config()
    return env, root


def intake(policy_ref: Any, files: list[tuple[str, str, str]]) -> str:
    return json.dumps(
        {
            "schemaVersion": "kf.intake.v1",
            "projectId": PROJECT,
            "batchId": BATCH,
            "profileId": "technical_minimal",
            "profileVersion": "synthetic.profile.v1",
            "policyRef": json.loads(policy_ref.model_dump_json(by_alias=True)),
            "createdAt": TIME,
            "items": [
                {
                    "assetId": asset,
                    "sourceId": source,
                    "originalDigest": hashlib.sha256(name.encode()).hexdigest(),
                    "sizeBytes": len(name),
                    "mediaType": "text/plain",
                    "custodyRef": {"rootId": "synthetic-input", "relativePath": name},
                    "metadata": {"title": "Synthetic manual"},
                }
                for asset, source, name in files
            ],
        }
    )


@pytest.mark.database
def test_admit_snapshots_registers_and_preserves_every_row(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env, root = admit_environment(tmp_path, monkeypatch, ledger)
    (root / "a.txt").write_bytes(b"a.txt")
    (root / "b.txt").write_bytes(b"b.txt")
    policy_bytes = admission().evidence.pinned_policy.model_dump_json(by_alias=True).encode()
    policy_ref = reference(policy_bytes, "kf.policy.v1")
    services = TrustedServices(clock=lambda: TIME)
    manifest = env.input(
        "manifest.json",
        intake(policy_ref, [(ASSET, SOURCE_A, "a.txt"), (ADMIT_ASSET_B, ADMIT_SOURCE_B, "b.txt")]),
    )
    before = file_names(env.objects)
    assert env.invoke("admit", "--manifest", manifest, services=services).exit == 0
    assert file_names(env.objects) == before and count(ledger, "admission_reports") == 0
    result = env.invoke("admit", "--manifest", manifest, "--execute", services=services)
    assert result.exit == 0, result.raw
    assert [row["status"] for row in result.payload["entries"]] == ["admitted", "admitted"]
    assert count(ledger, "admission_reports") == 1 and count(ledger, "admission_entries") == 2
    assert count(ledger, "assets") == 2 and count(ledger, "batches") == 1
    assert len(file_names(env.objects)) > len(before)  # immutable snapshots exist in the store
    env.assert_redacted(result)
    # Admission opens no run, authorization or attempt: it spends nothing and dispatches nothing.
    assert count(ledger, "runs") == 0 and count(ledger, "attempts") == 0


@pytest.mark.database
def test_admit_with_a_missing_source_reports_blocked_but_keeps_the_row(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env, root = admit_environment(tmp_path, monkeypatch, ledger)
    (root / "a.txt").write_bytes(b"a.txt")
    policy_bytes = admission().evidence.pinned_policy.model_dump_json(by_alias=True).encode()
    policy_ref = reference(policy_bytes, "kf.policy.v1")
    manifest = env.input(
        "manifest.json",
        intake(
            policy_ref, [(ASSET, SOURCE_A, "a.txt"), (ADMIT_ASSET_B, ADMIT_SOURCE_B, "gone.txt")]
        ),
    )
    result = env.invoke(
        "admit", "--manifest", manifest, "--execute", services=TrustedServices(clock=lambda: TIME)
    )
    assert result.exit == 3 and result.code == "admission_blocked"
    assert result.payload["registered"] is True
    statuses = {row["assetId"]: row["status"] for row in result.payload["entries"]}
    assert statuses == {ASSET: "admitted", ADMIT_ASSET_B: "blocked"}
    assert count(ledger, "admission_entries") == 2  # no admission row is dropped
    assert "gone.txt" not in result.raw and str(root) not in result.raw


# --- private release lifecycle: review, build, import, publish, activate, read ------------------


@pytest.fixture
def release_case(ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReleaseCase:
    return make_case(ledger, tmp_path, monkeypatch, b"Synthetic text")


@pytest.fixture
def library(ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Library:
    return build_library(
        make_case(ledger, tmp_path, monkeypatch, b"Synthetic text"), tmp_path / "objects"
    )


def release_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ledger: Ledger,
    case: Case,
    authority: Any,
    *,
    scopes: frozenset[str],
    pins: list[dict[str, Any]] | None = None,
    **overrides: Any,
) -> tuple[Env, TrustedServices]:
    env = database_env(tmp_path, monkeypatch, ledger, case, pins=pins, **overrides)
    env.scopes = scopes
    env.write_config()
    return env, TrustedServices(release_authority=authority, clock=lambda: TIME)


@pytest.mark.database
def test_review_and_build_release_are_private_local_steps(
    release_case: ReleaseCase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = release_case
    env, services = release_env(
        tmp_path,
        monkeypatch,
        value.ledger,
        value.case,
        value.authority,
        scopes=value.case.access.scopes,
    )
    revision_ref = produced_revision(value)
    logical = json.loads(value.read(revision_ref, value.case.access, 65536).data)["revisionId"]
    review = RevisionReview(
        schema_version="kf.revision-review.v1",
        project_id=PROJECT,
        revision_id=logical,
        decision="accepted",
        actor_id=ACTOR,
        policy_version=value.case.policy.policy_version,
        reviewed_at=TIME,
        reason=Reason(code="unavailable", message="Synthetic operator decision"),
    )
    raw = encoded(review)
    arguments = [
        "--review",
        env.input("review.json", raw),
        "--operation-key",
        value.case.plan.operation_key,
        "--revision-ref",
        ref_file(env, "revision-ref.json", revision_ref),
        "--evidence-ref",
        ref_file(env, "report-ref.json", value.case.data.report_ref),
    ]
    refused = env.invoke("review", *arguments, "--execute", services=services)
    assert refused.exit != 0 and value.count("reviews") == 0  # the authority approved nothing yet
    forged = review.model_copy(update={"actor_id": "00000000-0000-0000-0000-0000000000ff"})
    other = env.input("forged-review.json", encoded(forged))
    forged_arguments = [other if item.endswith("review.json") else item for item in arguments]
    value.authority.allowed.add(("record_review", encoded(forged)))
    result = env.invoke("review", *forged_arguments, "--execute", services=services)
    assert result.exit == 3 and result.code == "forbidden" and value.count("reviews") == 0
    value.authority.allowed.add(("record_review", raw))
    reviewed = env.invoke("review", *arguments, "--execute", services=services)
    assert reviewed.exit == 0 and value.count("reviews") == 1, reviewed.raw
    review_ref = Ref.model_validate(reviewed.payload["reviewRef"])
    source = ReleaseSource(
        source_id=value.case.data.report.entries[0].source_id,
        revision_ref=revision_ref,
        review_ref=review_ref,
    )
    selection = {
        "schemaVersion": "cfoundry.release-selection.v1",
        "sources": [json.loads(source.model_dump_json(by_alias=True))],
        "admissionReportRefs": [
            json.loads(value.case.data.report_ref.model_dump_json(by_alias=True))
        ],
    }
    path = env.input("selection.json", json.dumps(selection))
    unapproved = env.invoke("build-release", "--selection", path, "--execute", services=services)
    assert unapproved.exit != 0 and value.count("releases") == 0
    value.allow_build((source,))
    built = env.invoke("build-release", "--selection", path, "--execute", services=services)
    assert built.exit == 0 and built.payload["published"] is False, built.raw
    assert value.count("releases") == 1
    # Building a release publishes nothing and activates nothing.
    assert value.count("publications") == 0 and value.count("active_releases") == 0
    env.assert_redacted(built)


def run_events(
    env: Env, lib: Library, services: TrustedServices, record: Any, *, stage: str
) -> Result:
    operator(lib.value).operations.add(("append_publication", record_bytes(record)))
    path = env.input(f"{stage}.json", record_bytes(record))
    return env.invoke("publish", "--record", path, "--execute", services=services)


@pytest.mark.database
def test_import_publish_activate_and_read_each_need_their_own_grant(
    library: Library, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lib = library
    pin = lib.pin
    env, services = release_env(
        tmp_path,
        monkeypatch,
        lib.ledger,
        lib.value.case,
        lib.value.authority,
        scopes=lib.access.scopes,
        pins=[
            {
                "releaseDigest": pin.release_digest,
                "storeId": pin.store_id,
                "consumerContract": pin.consumer_contract,
                "capabilities": list(pin.capabilities),
            }
        ],
        grants={"release": ["import-release"], "read": ["read-span"]},
    )
    release_ref = ref_file(env, "release.json", lib.ref)
    unimported = env.invoke(
        "read-span",
        "--release-digest",
        lib.digest,
        "--span",
        env.input("span.json", span_of(lib, 0, 9).model_dump_json(by_alias=True)),
        services=services,
    )
    assert unimported.exit != 0 and "Synthetic" not in unimported.raw
    # Import is local verification only: no publication row appears and publishing is refused.
    unapproved = env.invoke(
        "import-release", "--release-ref", release_ref, "--execute", services=services
    )
    assert unapproved.exit != 0 and lib.row()[0] is False
    lib.allow_import()
    imported_ = env.invoke(
        "import-release", "--release-ref", release_ref, "--execute", services=services
    )
    assert imported_.exit == 0 and imported_.payload["receipt"]["status"] == "local_verified"
    assert imported_.payload["published"] is False and lib.row()[0] is True
    candidate = publication(lib, "candidate", None)
    assert run_events(env, lib, services, candidate, stage="candidate").code == "grant_missing"
    assert events(lib) == []
    # With the publication grant the chain is appended through the same stage-ordered ledger.
    env.grants = {**ALL_GRANTS, "activation": []}
    env.write_config()
    previous = None
    for stage in ("candidate", "validated", "transferred", "local_verified", "published"):
        record = publication(lib, stage, previous)
        done = run_events(env, lib, services, record, stage=stage)
        assert done.exit == 0 and done.payload["stage"] == stage, done.raw
        previous = record.event_id
    assert [event[1] for event in events(lib)][-1] == "published"
    # Publication is not activation: the pointer needs its own grant, record and approval.
    move = activation(lib, lib.digest, None)
    operator(lib.value).operations.add(("activate_release", record_bytes(move)))
    path = env.input("activation.json", record_bytes(move))
    denied = env.invoke("activate", "--record", path, "--execute", services=services)
    assert denied.exit == 3 and denied.code == "grant_missing" and active_digest(lib) is None
    env.grants = ALL_GRANTS
    env.write_config()
    dry = env.invoke("activate", "--record", path, services=services)
    assert dry.payload["outcome"] == "dry_run" and active_digest(lib) is None
    moved = env.invoke("activate", "--record", path, "--execute", services=services)
    assert moved.exit == 0 and active_digest(lib) == lib.digest
    stale = env.invoke("activate", "--record", path, "--execute", services=services)
    assert stale.exit == 3 and stale.code == "activation_conflict"
    # Reading returns metadata on stdout and the text only into a new private file.
    span_path = env.input("span.json", span_of(lib, 0, 9).model_dump_json(by_alias=True))
    target = tmp_path / "slice.txt"
    read = env.invoke(
        "read-span",
        "--release-digest",
        lib.digest,
        "--span",
        span_path,
        "--output",
        str(target),
        services=services,
    )
    assert read.exit == 0 and read.payload["textWritten"] is True, read.raw
    assert target.read_bytes() == b"Synthetic" and oct(target.stat().st_mode & 0o777) == "0o600"
    assert read.payload["independentlyVerified"] is False
    assert "Synthetic" not in read.raw and str(tmp_path) not in read.raw
    again = env.invoke(
        "read-span",
        "--release-digest",
        lib.digest,
        "--span",
        span_path,
        "--output",
        str(target),
        services=services,
    )
    assert again.exit != 0  # never overwrites an existing file
    # A release without an operator pin cannot be read, whatever its digest.
    env.pins = []
    env.write_config()
    unpinned = env.invoke(
        "read-span", "--release-digest", lib.digest, "--span", span_path, services=services
    )
    assert unpinned.exit == 3 and unpinned.code == "pin_missing"
