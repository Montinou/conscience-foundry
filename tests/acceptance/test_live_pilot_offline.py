"""The live composition root under ``run-pilot``, offline: fake ``modal``, FakeS3, fake Cloudflare.

The ``modal`` module is the fake of ``tests/adapters/test_modal_live.py`` injected through
``sys.modules``; its function really runs ``container_entry`` in-process against a FakeS3 that the
control side stages into, so the worker, the lease, the staged import and the ledger checks are the
production code. The Cloudflare API is a fake callable and the R2 clients are FakeS3. Nothing here
reaches a network, a provider or a paid service, and every identifier and token is synthetic.
"""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from psycopg import sql
from pydantic import ValidationError

for _sibling in ("integration", "adapters"):
    _path = str(Path(__file__).resolve().parents[1] / _sibling)
    if _path not in sys.path:
        sys.path.append(_path)

import test_cli as cli_case  # noqa: E402
import test_import_publication as import_case  # noqa: E402
import test_modal_live as fake_modal  # noqa: E402
import test_preflight as preflight_case  # noqa: E402
from test_execution_control import Case  # noqa: E402
from test_ledger_db import ACTOR, ASSET, PROJECT, RUN, TIME, encoded  # noqa: E402
from test_staging_s3 import BUCKET, FakeS3  # noqa: E402

from conscience_foundry.cli import live  # noqa: E402
from conscience_foundry.cli import preflight as pilot_cli  # noqa: E402
from conscience_foundry.cli.commands import Outcome  # noqa: E402
from conscience_foundry.cli.config import RuntimeConfig, TrustedServices, load_config  # noqa: E402
from conscience_foundry.contracts.canonical import RevisionReview  # noqa: E402
from conscience_foundry.contracts.common import ContractError, Reason, Ref  # noqa: E402
from conscience_foundry.contracts.execution import ResultManifest  # noqa: E402
from conscience_foundry.contracts.release import ReleaseSource  # noqa: E402
from conscience_foundry.execution import modal_live  # noqa: E402
from conscience_foundry.execution.modal_live import (  # noqa: E402
    LiveFunctionOptions,
    capability_record_from_live,
    code_digest,
    image_spec,
)
from conscience_foundry.ledger.db import Ledger  # noqa: E402
from conscience_foundry.policy.access import AccessContext  # noqa: E402

SCOPES = frozenset({"read", "extract", "remoteTransfer", "auditMetadataRead", "publish"})
PILOT_GRANTS = {**cli_case.ALL_GRANTS, "pilot": ["preflight", "run-pilot"]}
PACKET_EXPIRY = "2026-10-26T00:00:00.000Z"  # the plan's own expiry
GRANT_EXPIRY = "2026-10-25T06:00:00.000Z"
KEY_ID_ENV = "SYNTHETIC_PARENT_KEY_ID"
TOKEN_ENV = "SYNTHETIC_PARENT_TOKEN"
KEY_ID = "synthetic-parent-key-id"
TOKEN = "synthetic-parent-token-canary"
STEPS = ("prepare-run", "authorize-run", "reserve-storage", "dispatch", "reconcile")
SDK_VERSION = "1.6.3"
EVIDENCE_SCHEMAS = ("cfoundry.cost-estimate.v1", live.OBSERVATION_SCHEMA, live.STOP_SCHEMA)


def live_document(requirements: Path, **changes: Any) -> dict[str, Any]:
    """Every live value, synthetic and explicit; the total bound fits the plan's 10 s wall."""
    document: dict[str, Any] = {
        "modalProfile": "synthetic-profile",
        "appName": "synthetic-app",
        "functionName": "synthetic-worker",
        "pythonVersion": "3.12",
        "requirementsPath": str(requirements),
        "cpuMilli": 100,
        "memoryMib": 64,
        "schedulingTimeoutSeconds": 2,
        "startupTimeoutSeconds": 2,
        "executionTimeoutSeconds": 4,
        "cancelMarginSeconds": 2,
        "cloudflareTimeoutSeconds": 7,
        "capabilityValidSeconds": 172800,
        "r2AccountId": "synthetic-account-id",
        "parentAccessKeyIdEnv": KEY_ID_ENV,
        "parentTokenEnv": TOKEN_ENV,
        "staging": {
            "bucket": BUCKET,
            "prefix": "staging/f1",
            "endpointId": "synthetic-endpoint",
            "credentialSource": "synthetic-source",
            "maxObjectBytes": 65536,
            "transferChunkBytes": 4096,
            "maxReadResumes": 2,
            "maxParts": 8,
            "grantTtlSeconds": 300,
            "checksumMode": "sha256_header",
        },
    }
    return document | changes


class Clock:
    """The one controllable clock of the control side, the session and the container."""

    def __init__(self, start: str = TIME) -> None:
        self.moment = datetime.strptime(start, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)

    def instant(self) -> str:
        moment = self.moment
        return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"

    def now(self) -> str:
        return self.instant()

    def advance(self, seconds: float) -> None:
        self.moment += timedelta(seconds=seconds)


class Cloudflare:
    """The Cloudflare API double: answers each temp-credential request with a synthetic key."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, Mapping[str, Any]]] = []

    def __call__(self, path: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self.requests.append((path, request))
        n = len(self.requests)
        return {
            "success": True,
            "result": {
                "accessKeyId": f"synthetic-temp-key-{n}",
                "secretAccessKey": f"synthetic-temp-secret-{n}",
                "sessionToken": f"synthetic-temp-session-{n}",
            },
        }


def wire(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def ref_wire(data: bytes, schema: str) -> dict[str, Any]:
    return {
        "schemaVersion": "cf.artifact-ref.v1",
        "projectId": PROJECT,
        "digest": hashlib.sha256(data).hexdigest(),
        "sizeBytes": len(data),
        "mediaType": "application/json",
        "artifactSchema": schema,
        "locations": [],
    }


class Pilot:
    """One live-configured operator directory, a ledger, the packet, its grant and its steps."""

    def __init__(
        self,
        ledger: Ledger,
        tmp: Path,
        mp: pytest.MonkeyPatch,
        *,
        run_entry: bool = True,
    ) -> None:
        self.ledger, self.tmp, self.mp = ledger, tmp, mp
        self.clock = Clock()
        mp.setattr(live, "now", self.clock.instant)
        mp.setattr(modal_live, "_container_clock", lambda: self.clock)
        case = Case(tmp)
        case.access = AccessContext(PROJECT, ACTOR, SCOPES)
        case.control = dataclasses.replace(case.control, access=case.access)
        for schema in EVIDENCE_SCHEMAS:
            case.schemas[schema] = case.bound
        self.case = case
        cli_case.register(case, ledger)
        self.s3 = FakeS3()
        self.cloudflare = Cloudflare()
        self.world, self.module = fake_modal.install(mp, SDK_VERSION)
        self.run_entry = run_entry
        self.results: dict[str, bytes] = {}
        self._fake_running_function()
        mp.setattr(live, "r2_static_client", self._control_client)
        mp.setattr(modal_live, "r2_client", self._worker_client)
        mp.setenv(KEY_ID_ENV, KEY_ID)
        mp.setenv(TOKEN_ENV, TOKEN)
        self.requirements = tmp / "requirements.txt"
        self.requirements.write_text("synthetic==1.0\n")
        self.env = cli_case.database_env(tmp, mp, ledger, case, grants=PILOT_GRANTS)
        self.env.extra = {
            "projectMaxLiveAttempts": 1,
            "live": live_document(self.requirements),
        }
        self.env.write_config()
        self.control_clients: list[tuple[str, str, str]] = []
        self._documents()

    # -- fakes -----------------------------------------------------------------------

    def _control_client(self, account: str, key_id: str, secret: str) -> FakeS3:
        self.control_clients.append((account, key_id, secret))
        return self.s3

    def _worker_client(
        self, account: str, credentials: Mapping[str, str], *, options: Any = None
    ) -> FakeS3:
        return self.s3

    def _fake_running_function(self) -> None:
        """The fake function runs the registered entry when spawned; like the real SDK, every
        later ``get`` returns the same result until the call is cancelled."""
        pilot = self

        def spawn(function: Any, payload: bytes) -> Any:
            world = function.world
            if world.spawn_error is not None:
                raise world.spawn_error
            world.spawned.append(payload)
            call_id = f"synthetic-call-{len(world.spawned)}"
            if pilot.run_entry:
                value = function.entry(payload)
                pilot.results[call_id] = value
                world.outcomes[call_id] = [value] * 16
            return fake_modal.FakeCall(world, call_id)

        self.mp.setattr(fake_modal.FakeFunction, "spawn", spawn)

    # -- documents -------------------------------------------------------------------

    def _documents(self) -> None:
        c = self.case
        config = load_config(self.env.config_path)
        settings = config.live
        assert settings is not None
        self.settings = settings
        options = LiveFunctionOptions.from_settings(settings)

        def sink(schema: str, data: bytes) -> Ref:
            ref = Ref.model_validate(ref_wire(data, schema))
            return c.store.put_verified(io.BytesIO(data), ref, c.access)

        record = capability_record_from_live(
            settings,
            PROJECT,
            c.config_ref,
            SDK_VERSION,
            image_spec(options),
            code_digest(),
            TIME,
            sink,
        )
        self.record = record
        self.auth = c.auth.model_copy(update={"expires_at": PACKET_EXPIRY})
        self.auth_bytes = encoded(self.auth)
        self.plan_bytes = encoded(c.plan)
        manifest_bytes = c.data.evidence.manifest_bytes
        policy_ref = json.loads(manifest_bytes)["policyRef"]
        tariff = json.loads(c.config.tariff_ref.model_dump_json(by_alias=True))
        estimate = {
            "schemaVersion": "cfoundry.cost-estimate.v1",
            "projectId": PROJECT,
            "currency": "USD",
            "tariffRef": tariff,
            "maxAttemptUsd": "4",
            "runStorageUsd": "0.40",
            "lines": [
                {
                    "category": category,
                    "scope": scope,
                    "status": "estimated",
                    "amountUsd": amount,
                    "tariffRef": tariff,
                    "basis": f"synthetic basis for {category}",
                }
                for category, scope, amount in (
                    ("compute", "attempt", "2.5"),
                    ("startup", "attempt", "0.5"),
                    ("restart", "attempt", "0.5"),
                    ("transfer", "attempt", "0.5"),
                    ("storage", "run_storage", "0.40"),
                )
            ],
            "reviewedBy": ACTOR,
            "reviewedAt": TIME,
            "validUntil": PACKET_EXPIRY,
        }
        backup = {
            "schemaVersion": "cfoundry.backup-evidence.v1",
            "projectId": PROJECT,
            "backupStoreId": "synthetic-backup",
            "independence": "verified",
            "restoreEvidenceRef": ref_wire(b"synthetic restore", "cf.restore-evidence.v1"),
            "validUntil": PACKET_EXPIRY,
        }
        self.estimate_bytes = wire(estimate)
        self.estimate_ref = ref_wire(self.estimate_bytes, "cfoundry.cost-estimate.v1")
        capabilities = record.model_dump_json(by_alias=True, exclude_none=True).encode()
        backup_bytes = wire(backup)
        plan_wire = json.loads(self.plan_bytes)
        self.packet_wire: dict[str, Any] = {
            "schemaVersion": "cfoundry.preflight-packet.v1",
            "projectId": PROJECT,
            "manifestDigest": hashlib.sha256(manifest_bytes).hexdigest(),
            "planDigest": hashlib.sha256(self.plan_bytes).hexdigest(),
            "provider": "synthetic-provider",
            "region": "synthetic-region-1",
            "deploymentVersion": record.deployment_version,
            "imageDigest": record.image_digest,
            "dependencyLockDigest": hashlib.sha256(b"synthetic lock").hexdigest(),
            "capabilitiesRef": ref_wire(capabilities, "cf.modal-capability-record.v1"),
            "tariffRef": tariff,
            "estimateRef": self.estimate_ref,
            "policyRef": policy_ref,
            "destinationRef": ref_wire(b"synthetic destination", "cf.destination.v1"),
            "backupRef": ref_wire(backup_bytes, "cfoundry.backup-evidence.v1"),
            "contractLimits": json.loads(c.bound.model_dump_json(by_alias=True)),
            "resources": plan_wire["resources"],
            "maxRunUsd": plan_wire["budget"]["maxRunCost"],
            "maxAttemptUsd": plan_wire["budget"]["maxAttemptCost"],
            "retention": {
                "schemaVersion": "cf.retention.v1",
                "policyVersion": "synthetic.v1",
                "minStagingAgeSeconds": 60,
                "fundedStagingHorizonSeconds": 86400,
                "escalationLeadSeconds": 3600,
                "backupRequired": True,
                "auditRetentionSeconds": 604800,
            },
            "expiresAt": PACKET_EXPIRY,
        }
        private = self.env.private
        write = cli_case.write_private
        self.files = {
            "packet": write(private / "packet.json", wire(self.packet_wire)),
            "manifest": write(private / "manifest.json", manifest_bytes),
            "plan": write(private / "plan.json", self.plan_bytes),
            "capabilities": write(private / "capabilities.json", capabilities),
            "estimate": write(private / "estimate.json", self.estimate_bytes),
            "backup": write(private / "backup.json", backup_bytes),
            "authorization": write(private / "authorization.json", self.auth_bytes),
            "plan-ref": write(
                private / "plan-ref.json", wire(ref_wire(self.plan_bytes, "cf.execution-plan.v1"))
            ),
            "authorization-ref": write(
                private / "authorization-ref.json",
                wire(ref_wire(self.auth_bytes, "cf.run-authorization.v1")),
            ),
            "estimate-ref": write(private / "estimate-ref.json", wire(self.estimate_ref)),
        }  # fmt: skip

    def services(self, **changes: Any) -> TrustedServices:
        built = live.build_services(load_config(self.env.config_path), http=self.cloudflare)
        return dataclasses.replace(built, **changes) if changes else built

    def step_documents(self) -> list[dict[str, Any]]:
        f = self.files
        argv = {
            "prepare-run": ["--plan", str(f["plan"])],
            "authorize-run": ["--authorization", str(f["authorization"])],
            "reserve-storage": [
                "--run-id", RUN, "--amount", "0.40", "--evidence", str(f["estimate-ref"]),
            ],
            "dispatch": [
                "--plan-ref", str(f["plan-ref"]),
                "--authorization-ref", str(f["authorization-ref"]),
                "--evidence-ref", str(f["estimate-ref"]),
                "--asset-id", ASSET,
            ],
            "reconcile": ["--attempt-id", "@dispatch"],
        }  # fmt: skip
        return [{"command": name, "argv": argv[name]} for name in STEPS]

    def grant(self) -> Path:
        packet = preflight_case.PreflightPacket.model_validate(self.packet_wire)
        grant = {
            "schemaVersion": "cfoundry.live-grant.v1",
            "grantId": "00000000-0000-0000-0000-0000000000c1",
            "projectId": PROJECT,
            "packetDigest": preflight_case.packet_digest(packet),
            "actorId": ACTOR,
            "commands": list(STEPS),
            "grantedAt": TIME,
            "expiresAt": GRANT_EXPIRY,
        }
        return cli_case.write_private(self.env.private / "grant.json", wire(grant))

    def evidence_args(self) -> list[str]:
        f = self.files
        return [
            "--packet", str(f["packet"]),
            "--manifest", str(f["manifest"]),
            "--plan", str(f["plan"]),
            "--capabilities", str(f["capabilities"]),
            "--estimate", str(f["estimate"]),
            "--backup-evidence", str(f["backup"]),
        ]  # fmt: skip

    def run_pilot(self, services: TrustedServices | None = None) -> cli_case.Result:
        steps = {"schemaVersion": "cfoundry.pilot-steps.v1", "steps": self.step_documents()}
        path = cli_case.write_private(self.env.private / "steps.json", wire(steps))
        argv = [
            "run-pilot", *self.evidence_args(), "--grant", str(self.grant()),
            "--steps", str(path), "--execute",
        ]  # fmt: skip
        return self.env.invoke(*argv, services=services or self.services())

    def attempts(self) -> list[tuple[str, str, str | None]]:
        with self.ledger.transaction() as tx:
            rows = tx.connection.execute(
                sql.SQL(
                    "SELECT attempt_id::text,state,remote_call_id FROM {} ORDER BY created_at"
                ).format(tx.table("attempts"))
            ).fetchall()
        return [(str(a), str(s), None if r is None else str(r)) for a, s, r in rows]

    def decisions(self) -> list[str]:
        with self.ledger.transaction() as tx:
            rows = tx.connection.execute(
                sql.SQL("SELECT action FROM {} ORDER BY decided_at").format(
                    tx.table("control_decisions")
                )
            ).fetchall()
        return [str(row[0]) for row in rows]

    def read(self, ref: Ref) -> bytes:
        return self.case.store.read_verified(ref, self.case.access, 65536).data


def assert_clean(pilot: Pilot, result: cli_case.Result) -> None:
    pilot.env.assert_redacted(result)
    for marker in (TOKEN, KEY_ID, "synthetic-temp-secret", "synthetic-temp-session"):
        assert marker not in result.raw


# -- the configuration --------------------------------------------------------------------------


def config_document(tmp_path: Path, **changes: Any) -> dict[str, Any]:
    root = tmp_path / "objects"
    root.mkdir(exist_ok=True)
    bound = json.loads(cli_case.limits().model_dump_json(by_alias=True))
    document: dict[str, Any] = {
        "schemaVersion": "cfoundry.cli-config.v1",
        "projectId": PROJECT,
        "operator": {"actorId": ACTOR, "scopes": sorted(SCOPES), "grants": PILOT_GRANTS},
        "ledger": {"schemaName": "cf_live_test", "dsnEnv": cli_case.DSN_ENV},
        "objectStore": {"storeId": "synthetic", "rootPath": str(root), "limits": bound},
        "limitsPath": str(tmp_path / "limits.json"),
        "policyPath": str(tmp_path / "policy.json"),
        "transportLimits": bound,
        "projectMaxLiveAttempts": 1,
        "live": live_document(tmp_path / "requirements.txt"),
    }
    return document | changes


def parse_config(document: dict[str, Any]) -> RuntimeConfig:
    data = json.dumps(document).encode()
    return RuntimeConfig.from_wire(data, pilot_cli._bootstrap(len(data)))


def test_live_section_requires_project_cap(tmp_path: Path) -> None:
    assert parse_config(config_document(tmp_path)).project_max_live_attempts == 1
    without = config_document(tmp_path)
    del without["projectMaxLiveAttempts"]
    with pytest.raises(ContractError) as refused:
        parse_config(without)
    assert refused.value.code == "invalid_schema"
    # without a live section the cap stays optional, as in F1
    offline = config_document(tmp_path)
    del offline["projectMaxLiveAttempts"], offline["live"]
    assert parse_config(offline).project_max_live_attempts is None


def test_missing_live_field_blocks_named(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = cli_case.Env(tmp_path, monkeypatch, grants=PILOT_GRANTS)
    for name in ("modalProfile", "cloudflareTimeoutSeconds"):
        env.extra = {"projectMaxLiveAttempts": 1, "live": live_document(tmp_path / "req.txt")}
        del env.extra["live"][name]
        env.write_config()
        result = env.invoke("dispatch", *cli_case.EFFECT_ARGS["dispatch"], "--execute")
        assert result.exit == 3 and result.code == "config_invalid", (name, result.raw)

    # a live value read from the environment has no default either: the variable is named only
    env.extra = {"projectMaxLiveAttempts": 1, "live": live_document(tmp_path / "req.txt")}
    env.write_config()
    monkeypatch.delenv(KEY_ID_ENV, raising=False)
    monkeypatch.setattr(sys, "argv", ["cfoundry", "--config", str(env.config_path), "reconcile",
                                      "--attempt-id", cli_case.ATTEMPT, "--execute"])  # fmt: skip
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    from conscience_foundry.cli import main as main_module

    with pytest.raises(SystemExit) as stopped:
        main_module.run()
    assert stopped.value.code == 3
    record = json.loads(out.getvalue())
    assert record["outcome"] == "blocked" and record["code"] == "credential_unavailable"
    assert KEY_ID not in out.getvalue()


def test_no_live_section_keeps_empty_services(tmp_path: Path) -> None:
    offline = config_document(tmp_path)
    del offline["projectMaxLiveAttempts"], offline["live"]
    assert live.build_services(parse_config(offline)) == TrustedServices()


def test_run_builds_services_from_the_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = cli_case.Env(tmp_path, monkeypatch, grants=PILOT_GRANTS)
    seen: list[RuntimeConfig] = []

    def spy(config: RuntimeConfig, **kwargs: Any) -> TrustedServices:
        seen.append(config)
        return TrustedServices()

    from conscience_foundry.cli import main as main_module

    monkeypatch.setattr(main_module, "build_services", spy)
    monkeypatch.setattr(sys, "argv", ["cfoundry", "--config", str(env.config_path), "reconcile",
                                      "--attempt-id", cli_case.ATTEMPT])  # fmt: skip
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    with pytest.raises(SystemExit):
        main_module.run()
    assert [config.project_id for config in seen] == [PROJECT]


def live_services(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[TrustedServices, Any]:
    monkeypatch.setenv(KEY_ID_ENV, KEY_ID)
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    document = config_document(tmp_path)
    policy = cli_case.admission().evidence.pinned_policy
    cli_case.write_private(tmp_path / "policy.json", policy.model_dump_json(by_alias=True))
    cli_case.write_private(
        tmp_path / "limits.json",
        json.dumps({"cf.policy.v1": cli_case.limits().model_dump(by_alias=True)}),
    )
    http = Cloudflare()
    return live.build_services(parse_config(document), http=http), http


def test_standalone_dispatch_refuses_live(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = cli_case.Env(tmp_path / "operator-root", monkeypatch, grants=PILOT_GRANTS)
    services, http = live_services(tmp_path, monkeypatch)
    for name, value in cli_case.EFFECT_ARGS.items():
        if name == "dispatch":
            for argument in value[1::2]:
                if argument.endswith(".json"):
                    env.input(argument, cli_case.ref_json("cf.artifact-ref.v1"))
    argv = [part if not part.endswith(".json") else str(env.inputs / part)
            for part in cli_case.EFFECT_ARGS["dispatch"]]  # fmt: skip
    result = env.invoke("dispatch", *argv, "--execute", services=services)
    assert result.exit == 3 and result.code == "live_requires_pilot", result.raw
    assert env.connects == [] and http.requests == []  # refused before any ledger or mint


def test_one_issuer_backs_scopes_and_minting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    services, http = live_services(tmp_path, monkeypatch)
    wiring = services.live
    assert wiring is not None
    issuer = wiring.issuer
    scopes = services.issuer_scopes
    assert getattr(scopes, "__self__", None) is issuer  # the very issuer that mints
    assert issuer.prefix == wiring.config.live.staging.prefix  # type: ignore[union-attr]
    assert pilot_cli.attested_gates(services, PROJECT) == preflight_case.CLOSED
    assert http.requests == []  # probing the scopes mints nothing
    # an issuer configured for another prefix or bucket is refused at wiring time
    for change in ({"prefix": "staging/other"}, {"bucket": "synthetic-other"}):
        other = dataclasses.replace(issuer, **change)
        with pytest.raises(ContractError) as refused:
            live.require_bound_issuer(other, wiring.config.live.staging)  # type: ignore[union-attr]
        assert refused.value.code == "config_invalid"
    live.require_bound_issuer(issuer, wiring.config.live.staging)  # type: ignore[union-attr]
    assert TOKEN not in repr(services) and KEY_ID not in repr(services)


def test_release_authority_is_pinned_to_the_current_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from conscience_foundry.cli.authorities import LocalReleaseAuthority
    from conscience_foundry.release.context import ReleaseProof

    services, _ = live_services(tmp_path, monkeypatch)
    authority = services.release_authority
    assert isinstance(authority, LocalReleaseAuthority)
    assert authority.project_id == PROJECT
    request = b'{"synthetic":"request"}'
    proof = ReleaseProof(
        project_id=PROJECT,
        actor_id=ACTOR,
        action="record_review",
        request_digest=hashlib.sha256(request).hexdigest(),
        request_bytes=request,
        state_digest="e" * 64,
        evidence_ref=None,
        evidence_bytes=None,
        revision_ref=None,
        now=TIME,
    )
    assert authority.approve(proof).project_id == PROJECT
    # the policy now in force changed: nothing is approved under the old pin
    policy = cli_case.admission().evidence.pinned_policy
    changed = policy.model_copy(update={"policy_version": "synthetic.changed"})
    cli_case.write_private(tmp_path / "policy.json", changed.model_dump_json(by_alias=True))
    with pytest.raises(ContractError) as refused:
        authority.approve(proof)
    assert refused.value.code == "forbidden"
    with pytest.raises(ContractError):
        authority.approve(dataclasses.replace(proof, project_id=preflight_case.OTHER))


# -- the attempt binding and the report (orchestration only) ------------------------------------


def recorded_pilot(cli: Any, steps: list[dict[str, Any]], recorder: Any) -> cli_case.Result:
    commands = tuple(step["command"] for step in steps)
    argv = preflight_case.bound_argv(
        cli, steps, preflight_case.grant_for(cli.case, commands=commands)
    )
    return cli.env.invoke(*argv, services=cli.services())


def dispatch_then_reconcile(cli: Any) -> list[dict[str, Any]]:
    steps = cli.bound_steps()
    return [*steps, {"command": "reconcile", "argv": ["--attempt-id", "@dispatch"]}]


DISPATCHED = "00000000-0000-0000-0000-0000000000d1"


def test_pilot_binds_dispatch_attempt_id_to_reconcile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cli = preflight_case.Cli(tmp_path, monkeypatch)
    recorder = preflight_case.Recorder(
        {"dispatch": Outcome("ok", None, {"attempt": {"attemptId": DISPATCHED}})}
    )
    monkeypatch.setattr(pilot_cli, "run_command", recorder)
    result = recorded_pilot(cli, dispatch_then_reconcile(cli), recorder)
    assert result.exit == 0, result.raw
    assert [name for name, *_ in recorder.ran] == [*preflight_case.BOUND_COMMANDS, "reconcile"]
    assert recorder.ran[-1][3]["attempt_id"] == DISPATCHED


def test_attempt_token_without_prior_dispatch_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cli = preflight_case.Cli(tmp_path, monkeypatch)
    recorder = preflight_case.Recorder()
    monkeypatch.setattr(pilot_cli, "run_command", recorder)
    plan = cli.bound_steps()[0]
    for steps in (
        [plan, {"command": "reconcile", "argv": ["--attempt-id", "@dispatch"]}],
        [{"command": "reconcile", "argv": ["--attempt-id", "@dispatch"]}, *cli.bound_steps()],
    ):
        result = recorded_pilot(cli, steps, recorder)
        assert result.exit == 3 and result.code == "forbidden", result.raw
    assert recorder.ran == []
    # a dispatch whose outcome names no attempt cannot feed the token either
    silent = preflight_case.Recorder({"dispatch": Outcome("ok", None, {})})
    monkeypatch.setattr(pilot_cli, "run_command", silent)
    halted = recorded_pilot(cli, dispatch_then_reconcile(cli), silent)
    assert halted.exit == 3 and halted.code == "forbidden", halted.raw
    assert [name for name, *_ in silent.ran] == list(preflight_case.BOUND_COMMANDS)


RISKS = {
    "controller death leaves unknown_outcome",
    "a crash before publish_result loses a paid result",
    "costs stay estimated until billed",
}


def test_pilot_report_lists_residual_risks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cli = preflight_case.Cli(tmp_path, monkeypatch)
    monkeypatch.setattr(pilot_cli, "run_command", preflight_case.Recorder())
    finished = preflight_case.pilot(cli)
    assert finished.exit == 0 and set(finished.payload["residual_risks"]) == RISKS
    halted_by = preflight_case.Recorder({"backup": Outcome("blocked", "adapter_unavailable")})
    monkeypatch.setattr(pilot_cli, "run_command", halted_by)
    halted = preflight_case.pilot(cli)
    assert halted.exit == 3 and set(halted.payload["residual_risks"]) == RISKS
    unready = preflight_case.pilot(cli, closed=frozenset())
    assert unready.exit == 3 and set(unready.payload["residual_risks"]) == RISKS


# -- the live pilot against the real ledger ------------------------------------------------------


@pytest.mark.database
def test_pilot_offline_end_to_end(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pilot = Pilot(ledger, tmp_path, monkeypatch)
    result = pilot.run_pilot()
    assert result.exit == 0, result.raw
    assert [step["outcome"] for step in result.payload["steps"]] == ["ok"] * len(STEPS)
    assert result.payload["paidPilotAcceptance"] == "not_established"
    assert set(result.payload["residual_risks"]) == RISKS
    assert_clean(pilot, result)

    # one call, spawned once, inside one ephemeral app that was exited after reconcile
    assert len(pilot.world.spawned) == 1 and pilot.world.entered == 1
    assert pilot.world.exited == [None]
    ((attempt_id, state, call_id),) = pilot.attempts()
    assert state == "succeeded" and call_id == "synthetic-call-1"
    # the inputs were staged to the shared keys, the worker wrote under its attempt prefix only
    keys = set(pilot.s3.objects)
    assert any(f"{PROJECT}/sha256/" in key and "/attempts/" not in key for key in keys)
    assert f"staging/f1/{PROJECT}/attempts/{attempt_id}/lease" in keys
    assert f"staging/f1/{PROJECT}/attempts/{attempt_id}/result" in keys
    # two temporary credentials per attempt, minted by the one configured issuer
    assert [body["body"]["permission"] for _, body in pilot.cloudflare.requests] == [
        "object-read-only",
        "object-read-write",
    ]
    assert all(request["tokenEnv"] == TOKEN_ENV for _, request in pilot.cloudflare.requests)

    # review -> build-release -> import-release under their own grants: local_verified
    manifest_ref = Ref.model_validate(json.loads(pilot.results[call_id]))
    manifest = ResultManifest.from_wire(pilot.read(manifest_ref), pilot.case.bound)
    revision_ref = manifest.document_revision_ref
    assert revision_ref is not None
    services = pilot.services()
    revision = json.loads(pilot.read(revision_ref))
    review = RevisionReview(
        schema_version="cf.revision-review.v1",
        project_id=PROJECT,
        revision_id=revision["revisionId"],
        decision="accepted",
        actor_id=ACTOR,
        policy_version=pilot.case.policy.policy_version,
        reviewed_at=TIME,
        reason=Reason(code="unavailable", message="Synthetic operator decision"),
    )
    env = pilot.env
    reviewed = env.invoke(
        "review",
        "--review", env.input("review.json", encoded(review)),
        "--operation-key", pilot.case.plan.operation_key,
        "--revision-ref", cli_case.ref_file(env, "revision-ref.json", revision_ref),
        "--evidence-ref", cli_case.ref_file(env, "report-ref.json", pilot.case.data.report_ref),
        "--execute",
        services=services,
    )  # fmt: skip
    assert reviewed.exit == 0, reviewed.raw
    source = ReleaseSource(
        source_id=pilot.case.data.report.entries[0].source_id,
        revision_ref=revision_ref,
        review_ref=Ref.model_validate(reviewed.payload["reviewRef"]),
    )
    selection = {
        "schemaVersion": "cfoundry.release-selection.v1",
        "sources": [json.loads(source.model_dump_json(by_alias=True))],
        "admissionReportRefs": [
            json.loads(pilot.case.data.report_ref.model_dump_json(by_alias=True))
        ],
    }
    built = env.invoke(
        "build-release", "--selection", env.input("selection.json", json.dumps(selection)),
        "--execute", services=services,
    )  # fmt: skip
    assert built.exit == 0, built.raw
    release_ref = Ref.model_validate(built.payload["releaseRef"])
    env.pins = [
        {
            "releaseDigest": release_ref.digest,
            "storeId": cli_case.STORE_ID,
            "consumerContract": import_case.CONSUMER,
            "capabilities": ["canonical_text"],
        }
    ]
    env.write_config()
    imported = env.invoke(
        "import-release", "--release-ref", cli_case.ref_file(env, "release.json", release_ref),
        "--execute", services=pilot.services(),
    )  # fmt: skip
    assert imported.exit == 0, imported.raw
    assert imported.payload["receipt"]["status"] == "local_verified"


def interrupt_get(pilot: Pilot) -> None:
    """The operator presses Ctrl-C while the reconcile step waits on the call."""
    real = fake_modal.FakeCall.get

    def get(call: Any, timeout: float | None = None, *, index: int = 0) -> Any:
        if timeout and call.object_id not in call.world.cancelled:
            raise KeyboardInterrupt
        return real(call, timeout, index=index)

    pilot.mp.setattr(fake_modal.FakeCall, "get", get)


def interrupt_spawn(pilot: Pilot) -> None:
    """The operator presses Ctrl-C while the dispatch step submits the call."""
    pilot.world.spawn_error = KeyboardInterrupt()  # type: ignore[assignment]


@pytest.mark.database
@pytest.mark.parametrize("interrupt", [interrupt_get, interrupt_spawn], ids=["poll", "spawn"])
def test_interrupt_leaves_attempt_not_running(
    ledger: Ledger,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupt: Callable[[Pilot], None],
) -> None:
    pilot = Pilot(ledger, tmp_path, monkeypatch, run_entry=False)
    interrupt(pilot)
    result = pilot.run_pilot()
    assert result.exit == 130, result.raw
    assert result.payload["outcome"] == "interrupted"
    assert set(result.payload["residual_risks"]) == RISKS
    ((_, state, _),) = pilot.attempts()
    assert state in {"cancel_requested", "cancelled", "unknown_outcome"}, state
    assert pilot.world.exited and pilot.world.exited[-1] is KeyboardInterrupt  # app exited
    assert all(terminate for _, terminate in pilot.world.cancel_calls)
    assert "cancel_attempt" in pilot.decisions()
    assert_clean(pilot, result)


@pytest.mark.database
def test_deadline_cancel_goes_through_the_ledger_with_the_token(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pilot = Pilot(ledger, tmp_path, monkeypatch, run_entry=False)
    real = fake_modal.FakeCall.get

    def get(call: Any, timeout: float | None = None, *, index: int = 0) -> Any:
        if timeout:
            pilot.clock.advance(timeout)  # the call never finishes: time runs out
        return real(call, timeout, index=index)

    monkeypatch.setattr(fake_modal.FakeCall, "get", get)
    result = pilot.run_pilot()
    ((_, state, call_id),) = pilot.attempts()
    # cancelled by the reconcile step's own deadline callback, recorded before it went out
    assert state in {"cancel_requested", "cancelled"}, (state, result.raw)
    assert pilot.world.cancel_calls == [(call_id, True)]
    assert pilot.decisions().count("cancel_attempt") == 1
    assert result.payload["steps"][-1]["command"] == "reconcile"
    assert_clean(pilot, result)


def test_cloudflare_http_sends_the_token_only_as_a_header(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.request

    sent: list[Any] = []

    class Response(io.BytesIO):
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

    def urlopen(request: Any, timeout: float) -> Response:
        sent.append((request, timeout))
        return Response(b'{"success": true, "result": {}}')

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    body = {"bucket": BUCKET, "ttlSeconds": 70}
    path = "/accounts/synthetic-account-id/r2/temp-access-credentials"
    http = live.cloudflare_http(7)
    answer = http(path, {"tokenEnv": TOKEN_ENV, "body": body})
    assert answer == {"success": True, "result": {}}
    ((request, timeout),) = sent
    assert request.full_url == live.CLOUDFLARE_API + path and request.get_method() == "POST"
    assert request.get_header("Authorization") == f"Bearer {TOKEN}"
    assert json.loads(request.data) == body and TOKEN.encode() not in request.data
    assert timeout == 7  # the operator's configured timeout, never a default
    monkeypatch.delenv(TOKEN_ENV)
    with pytest.raises(ContractError) as missing:
        http(path, {"tokenEnv": TOKEN_ENV, "body": body})
    assert missing.value.code == "credential_unavailable" and len(sent) == 1


# -- fix round 1 -----------------------------------------------------------------------------------


def test_build_services_uses_the_configured_cloudflare_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[int] = []
    monkeypatch.setattr(
        live, "cloudflare_http", lambda timeout: seen.append(timeout) or Cloudflare()
    )
    monkeypatch.setenv(KEY_ID_ENV, KEY_ID)
    policy = cli_case.admission().evidence.pinned_policy
    cli_case.write_private(tmp_path / "policy.json", policy.model_dump_json(by_alias=True))
    cli_case.write_private(
        tmp_path / "limits.json",
        json.dumps({"cf.policy.v1": cli_case.limits().model_dump(by_alias=True)}),
    )
    live.build_services(parse_config(config_document(tmp_path)))
    assert seen == [7]


def test_dry_run_pilot_report_lists_residual_risks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cli = preflight_case.Cli(tmp_path, monkeypatch)
    dry = preflight_case.pilot(cli, execute=False)
    assert dry.payload["outcome"] == "dry_run" and set(dry.payload["residual_risks"]) == RISKS
    unconfigured = cli.env.invoke("run-pilot", "--packet", "p", "--steps", "s", config=False)
    assert unconfigured.code == "config_required"
    assert set(unconfigured.payload["residual_risks"]) == RISKS


def billing_record(pilot: Pilot, attempt_id: str, **changes: Any) -> Ref:
    """The operator's billing document for the attempt, installed in the local store."""
    document = {
        "schemaVersion": "cfoundry.billing-record.v1",
        "projectId": PROJECT,
        "attemptId": attempt_id,
        "currency": "USD",
        "costStatus": "actual",
        "amountUsd": "0.12",
        "source": "synthetic-billing-export",
        "recordedBy": ACTOR,
        "recordedAt": TIME,
    } | changes
    data = wire(document)
    ref = Ref.model_validate(ref_wire(data, "cfoundry.billing-record.v1"))
    return pilot.case.store.put_verified(io.BytesIO(data), ref, pilot.case.access)


def settlements(pilot: Pilot) -> list[tuple[str, str]]:
    with pilot.ledger.transaction() as tx:
        rows = tx.connection.execute(
            sql.SQL("SELECT record_bytes FROM {}").format(tx.table("budget_events"))
        ).fetchall()
    events = [json.loads(bytes(row[0])) for row in rows]
    return [(e["costStatus"], e["amountUsd"]) for e in events if e["eventType"] == "settle"]


@pytest.mark.database
def test_live_record_billing_settles_from_the_billing_document(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pilot = Pilot(ledger, tmp_path, monkeypatch)
    pilot.env.schemas["cfoundry.billing-record.v1"] = pilot.case.bound
    pilot.env.write_config()
    assert pilot.run_pilot().exit == 0
    ((attempt_id, state, _),) = pilot.attempts()
    assert state == "succeeded"
    env = pilot.env

    def bill(ref: Ref, amount: str = "0.12") -> cli_case.Result:
        return env.invoke(
            "record-billing", "--attempt-id", attempt_id, "--amount", amount,
            "--evidence", cli_case.ref_file(env, f"bill-{ref.digest[:8]}-{amount}.json", ref),
            "--execute", services=pilot.services(),
        )  # fmt: skip

    # nothing becomes actual without the very billing document for this attempt and amount
    refused = [
        bill(billing_record(pilot, attempt_id), "0.13"),  # the request is not what was billed
        bill(billing_record(pilot, preflight_case.OTHER)),  # another attempt's bill
        bill(billing_record(pilot, attempt_id, costStatus="estimated")),  # not a bill
        bill(billing_record(pilot, attempt_id, projectId=preflight_case.OTHER)),
        bill(Ref.model_validate(ref_wire(b"never stored", "cfoundry.billing-record.v1"))),
    ]
    for result in refused:
        assert result.exit != 0 and result.payload["outcome"] in {"blocked", "failed"}, result.raw
    assert settlements(pilot) == []
    settled = bill(billing_record(pilot, attempt_id))
    assert settled.exit == 0, settled.raw
    assert settled.payload["costStatus"] == "actual" and settled.payload["amountUsd"] == "0.12"
    assert settlements(pilot) == [("actual", "0.12")]
    assert_clean(pilot, settled)
    # every other standalone live command still refuses to attest anything
    authority: Any = pilot.services().evidence_authority
    for attest in (authority.control, authority.observation, authority.transport):
        with pytest.raises(ContractError) as still:
            attest(None)
        assert still.value.code == "live_requires_pilot"


@pytest.mark.database
def test_interrupt_falls_back_to_unknown_outcome_when_cancel_fails(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pilot = Pilot(ledger, tmp_path, monkeypatch, run_entry=False)
    interrupt_get(pilot)

    def broken(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("synthetic cancel failure")

    monkeypatch.setattr(live, "cancel_attempt", broken)
    result = pilot.run_pilot()
    assert result.exit == 130, result.raw
    ((_, state, call_id),) = pilot.attempts()
    assert state == "unknown_outcome"  # never left running
    assert pilot.world.cancel_calls == [(call_id, True)]  # the backstop still terminated it
    assert_clean(pilot, result)


# -- the evidence label ----------------------------------------------------------------------------

LIVE_STEPS = {"dispatch", "reconcile"}
"""The pilot steps that run while the live session is open."""


def stored_records(pilot: Pilot, schema: str) -> list[dict[str, Any]]:
    """Every JSON record of one schema in the local object store (the control side's records)."""
    found: list[dict[str, Any]] = []
    for path in sorted(pilot.env.objects.rglob("*")):
        if not path.is_file():
            continue
        try:
            value = json.loads(path.read_bytes())
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("schemaVersion") == schema:
            found.append(value)
    return found


def test_offline_pilot_labels_synthetic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cli = preflight_case.Cli(tmp_path, monkeypatch)
    monkeypatch.setattr(pilot_cli, "run_command", preflight_case.Recorder())
    finished = preflight_case.pilot(cli)
    assert finished.exit == 0, finished.raw
    assert finished.payload["evidenceLabel"] == "synthetic_offline"
    steps = finished.payload["steps"]
    assert steps and {step["evidenceLabel"] for step in steps} == {"synthetic_offline"}
    # a halted pilot and one refused before any step say the same: nothing live was open
    halted_by = preflight_case.Recorder({"backup": Outcome("blocked", "adapter_unavailable")})
    monkeypatch.setattr(pilot_cli, "run_command", halted_by)
    halted = preflight_case.pilot(cli)
    assert halted.payload["evidenceLabel"] == "synthetic_offline"
    assert {step["evidenceLabel"] for step in halted.payload["steps"]} == {"synthetic_offline"}
    unready = preflight_case.pilot(cli, closed=frozenset())
    assert unready.payload["evidenceLabel"] == "synthetic_offline"


@pytest.mark.database
def test_live_session_labels_live(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pilot = Pilot(ledger, tmp_path, monkeypatch)
    result = pilot.run_pilot()
    assert result.exit == 0, result.raw
    labels = {step["command"]: step["evidenceLabel"] for step in result.payload["steps"]}
    # exactly the steps that ran while the session was open are live; the rest are not
    assert labels == {name: "live" if name in LIVE_STEPS else "synthetic_offline" for name in STEPS}
    assert result.payload["evidenceLabel"] == "live"
    # the control side's own record of the observation was written under the open session
    records = stored_records(pilot, live.OBSERVATION_SCHEMA)
    assert records and {record["evidenceLabel"] for record in records} == {"live"}
    assert_clean(pilot, result)


@pytest.mark.database
def test_deadline_stop_record_is_labelled_live(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pilot = Pilot(ledger, tmp_path, monkeypatch, run_entry=False)
    real = fake_modal.FakeCall.get

    def get(call: Any, timeout: float | None = None, *, index: int = 0) -> Any:
        if timeout:
            pilot.clock.advance(timeout)
        return real(call, timeout, index=index)

    monkeypatch.setattr(fake_modal.FakeCall, "get", get)
    result = pilot.run_pilot()
    stops = stored_records(pilot, live.STOP_SCHEMA)
    assert len(stops) == 1 and stops[0]["evidenceLabel"] == "live", result.raw
    assert result.payload["evidenceLabel"] == "live"


def exit_fails(pilot: Pilot) -> None:
    """The ephemeral app cannot be stopped when the session closes."""

    def broken(run: Any, *exc: Any) -> None:
        run.world.exited.append(exc[0])
        raise RuntimeError("synthetic app stop failure")

    pilot.mp.setattr(fake_modal.FakeRun, "__exit__", broken)


def spawn_fails(pilot: Pilot) -> None:
    """The dispatch step halts inside the session, which then also cannot be stopped."""
    exit_fails(pilot)
    pilot.world.spawn_error = RuntimeError("synthetic spawn failure")


@pytest.mark.database
@pytest.mark.parametrize("fault", [exit_fails, spawn_fails], ids=["closing", "halted-then-closing"])
def test_session_that_fails_to_close_is_still_labelled_live(
    ledger: Ledger,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: Callable[[Pilot], None],
) -> None:
    pilot = Pilot(ledger, tmp_path, monkeypatch)
    fault(pilot)
    result = pilot.run_pilot()
    # a paid dispatch was made under the open session: the refusal never reports it as synthetic
    assert result.exit != 0, result.raw
    assert result.payload["code"] == "unavailable", result.raw
    assert result.payload["evidenceLabel"] == "live", result.raw
    assert set(result.payload["residual_risks"]) == RISKS
    steps = result.payload["steps"]  # what ran before the failure is still reported
    assert steps and steps[-1]["command"] in LIVE_STEPS
    assert {step["evidenceLabel"] for step in steps if step["command"] in LIVE_STEPS} == {"live"}
    assert pilot.world.exited, "the app stop was attempted"


def test_document_cannot_set_label(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # no operator document has a label field: the strict models refuse one
    cli = preflight_case.Cli(tmp_path, monkeypatch)
    for model, document in (
        (preflight_case.PreflightPacket, cli.case.packet_wire),
        (live.BillingRecord, {
            "schemaVersion": "cfoundry.billing-record.v1", "projectId": PROJECT,
            "attemptId": preflight_case.OTHER, "currency": "USD", "costStatus": "actual",
            "amountUsd": "0.12", "source": "synthetic-billing-export", "recordedBy": ACTOR,
            "recordedAt": TIME,
        }),
    ):  # fmt: skip
        for value in ("live", "synthetic_offline"):
            with pytest.raises(ValidationError) as refused:
                model.model_validate({**document, "evidenceLabel": value})
            assert [(e["type"], e["loc"]) for e in refused.value.errors()] == [
                ("extra_forbidden", ("evidenceLabel",))
            ]
    # a record that already names a label is never stamped: the trusted side alone decides
    with pytest.raises(ContractError) as forged:
        live.stamp_label(b'{"evidenceLabel":"live","schemaVersion":"x"}', "synthetic_offline")
    assert forged.value.code == "invalid_schema"
    stamped = json.loads(live.stamp_label(b'{"schemaVersion":"x"}', "synthetic_offline"))
    assert stamped == {"schemaVersion": "x", "evidenceLabel": "synthetic_offline"}
    # the control-side record decoders accept the two labels and nothing else
    limits = cli_case.limits()
    for schema, base in (
        (live.STOP_SCHEMA, {"attemptId": "a", "recordedAt": TIME, "remoteCallId": None,
                            "trigger": "deadline"}),
        (live.OBSERVATION_SCHEMA, {"action": "reconcile", "attemptId": "a", "observedState": "x",
                                   "remoteCallId": None, "sdkState": "y"}),
    ):  # fmt: skip
        decode = live.LIVE_DECODERS[schema]
        record = {"schemaVersion": schema, **base}
        for good in ("live", "synthetic_offline"):
            decode(wire({**record, "evidenceLabel": good}), limits)
        for bad in ("document", "", None):
            with pytest.raises(ContractError):
                decode(wire({**record, "evidenceLabel": bad}), limits)
        with pytest.raises(ContractError):
            decode(wire(record), limits)  # unlabelled records are not accepted either
