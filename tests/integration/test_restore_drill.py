"""The restore drill: a separate, fresh recovery target and the evidence preflight trusts.

Everything runs against the authorized temporary PostgreSQL (one extra schema per drill) and the
offline R2 fake; nothing reaches a network. Each drill restores into a schema and an object
directory named after a fresh drill id, so the live ledger is never opened and repeated drills
never meet the restore's refusal of an already-populated target.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from psycopg import sql
from test_cli import Env, approved_database_dsn
from test_preflight import build as build_packet
from test_recovery import (
    FakeS3,
    cli_env,
    pause_rows,
    r2_cli,
    row_count,
    verified,
)
from test_recovery import library as library_fixture

from conscience_foundry.cli.config import TrustedServices
from conscience_foundry.ledger.allowance import install_allowance_schema
from conscience_foundry.ledger.db import Ledger
from conscience_foundry.operator.packet import BackupEvidence

pytestmark = pytest.mark.database

CLOCK = "2030-01-01T00:00:00.000Z"
VALID_FOR = 7200
VALID_UNTIL = "2030-01-01T02:00:00.000Z"
SERVICES = TrustedServices(clock=lambda: CLOCK)
GRANTS_KEY = "recovery"
DRILL_GRANTS = [
    "backup",
    "restore",
    "retention-report",
    "restore-drill",
]
REPORT_SCHEMA = "cfoundry.restore-drill-report.v1"


@pytest.fixture
def library(ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """The recovery tests' release library (imported fixtures would be shadowed by parameters)."""
    return library_fixture.__wrapped__(ledger, tmp_path, monkeypatch)


@dataclass
class Drill:
    base: str
    config: Env
    ledger: Ledger

    def targets(self) -> list[str]:
        with self.ledger.transaction() as tx:
            rows = tx.connection.execute(
                "SELECT nspname FROM pg_catalog.pg_namespace WHERE nspname LIKE %s ORDER BY 1",
                (self.base.replace("_", r"\_") + r"\_%",),
            ).fetchall()
        return [row[0] for row in rows]

    def ledger_of(self, drill_id: str) -> Ledger:
        return Ledger(self.ledger.connection_factory, schema=f"{self.base}_{drill_id}")

    def object_dirs(self) -> list[str]:
        return sorted(path.name for path in self.config.objects.iterdir())


def new_drill(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lib: Any,
    ledger: Ledger,
    base: str | None = None,
) -> Drill:
    case = lib.value.case
    name = base if base is not None else "cf_drill_" + uuid4().hex[:8]
    config = Env(
        tmp_path / "drill",
        monkeypatch,
        schemas=case.schemas,
        bound=case.bound,
        policy=lambda: case.policy,
        scopes=case.access.scopes,
        dsn=approved_database_dsn(),
        schema_name=name,
        grants={"recovery": DRILL_GRANTS},
    )
    return Drill(name, config, ledger)


def drop_targets(drill: Drill) -> None:
    with drill.ledger.connection_factory() as connection:
        for name in drill.targets():
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(name)))


@pytest.fixture
def drills(ledger: Ledger) -> Iterator[list[Drill]]:
    created: list[Drill] = []
    try:
        yield created
    finally:
        for drill in created:
            drop_targets(drill)


def with_grants(env: Env) -> Env:
    env.grants = {**env.grants, GRANTS_KEY: DRILL_GRANTS}
    env.write_config()
    return env


def take_local_backup(
    lib: Any, ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Env, Path]:
    live = with_grants(cli_env(tmp_path, monkeypatch, lib, ledger, tmp_path / "cli-backup"))
    manifest = tmp_path / "recovery.json"
    done = live.invoke("backup", "--manifest-output", str(manifest), "--execute", services=SERVICES)
    assert done.exit == 0, done.raw
    return live, manifest


def take_r2_backup(
    lib: Any, ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake: FakeS3
) -> tuple[Env, Path]:
    live, _ = r2_cli(lib, ledger, tmp_path, monkeypatch, fake)
    with_grants(live)
    manifest = tmp_path / "recovery.json"
    done = live.invoke("backup", "--manifest-output", str(manifest), "--execute", services=SERVICES)
    assert done.exit == 0, done.raw
    return live, manifest


def drill_argv(
    drill: Drill, manifest: Path, evidence: Path, *extra: str, seconds: int = VALID_FOR
) -> list[str]:
    return [
        "restore-drill",
        "--manifest",
        str(manifest),
        "--drill-config",
        str(drill.config.config_path),
        "--evidence-output",
        str(evidence),
        "--valid-for-seconds",
        str(seconds),
        *extra,
    ]


def read_evidence(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_bytes())
    assert isinstance(loaded, dict)
    return loaded


def test_drill_leaves_live_ledger_unpaused_and_verified(
    library: Any,
    ledger: Ledger,
    drills: list[Drill],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lib = library
    verified(lib)
    live, manifest = take_local_backup(lib, ledger, tmp_path, monkeypatch)
    drill = new_drill(tmp_path, monkeypatch, lib, ledger)
    drills.append(drill)
    # The command's own config points at a ledger schema that does not exist: if the drill
    # opened the live ledger at all it could not succeed.
    live.schema_name = "cf_live_ledger_never_opened"
    live.write_config()
    assert pause_rows(ledger) == [] and lib.row()[0] is True
    evidence = tmp_path / "evidence.json"

    done = live.invoke(*drill_argv(drill, manifest, evidence, "--execute"), services=SERVICES)

    assert done.exit == 0, done.raw
    assert pause_rows(ledger) == [] and lib.row()[0] is True  # live: unpaused, still verified
    drill_id = done.payload["drillId"]
    assert re.fullmatch(r"[0-9a-f]{12}", drill_id)
    restored = drill.ledger_of(drill_id)
    assert row_count(restored, "projects") == 1
    assert [(paused, reason) for paused, _, reason in pause_rows(restored)] == [
        (True, "restore_barrier")
    ]
    assert done.payload["dispatchBlocked"] is True
    live.assert_redacted(done)


def test_drill_verified_only_for_r2_with_attestation(
    library: Any,
    ledger: Ledger,
    drills: list[Drill],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lib = library
    verified(lib)
    fake = FakeS3()
    live, manifest = take_r2_backup(lib, ledger, tmp_path, monkeypatch, fake)
    drill = new_drill(tmp_path, monkeypatch, lib, ledger)
    drills.append(drill)

    attested = tmp_path / "attested.json"
    done = live.invoke(
        *drill_argv(drill, manifest, attested, "--attest-independent", "--execute"),
        services=SERVICES,
    )
    assert done.exit == 0, done.raw
    proof = read_evidence(attested)
    assert proof["independence"] == "verified" and done.payload["independence"] == "verified"
    assert proof["backupStoreId"] == "backup" and proof["validUntil"] == VALID_UNTIL
    assert BackupEvidence.model_validate(proof).independence == "verified"

    plain = tmp_path / "plain.json"
    unattested = live.invoke(*drill_argv(drill, manifest, plain, "--execute"), services=SERVICES)
    assert unattested.exit == 0, unattested.raw
    assert read_evidence(plain)["independence"] == "unverified"
    assert unattested.payload["independence"] == "unverified"
    live.assert_redacted(done)


def test_drill_unverified_for_local_backup(
    library: Any,
    ledger: Ledger,
    drills: list[Drill],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lib = library
    verified(lib)
    live, manifest = take_local_backup(lib, ledger, tmp_path, monkeypatch)
    drill = new_drill(tmp_path, monkeypatch, lib, ledger)
    drills.append(drill)
    evidence = tmp_path / "evidence.json"

    done = live.invoke(
        *drill_argv(drill, manifest, evidence, "--attest-independent", "--execute"),
        services=SERVICES,
    )

    assert done.exit == 0, done.raw
    assert read_evidence(evidence)["independence"] == "unverified"  # an attestation is not enough
    assert done.payload["independence"] == "unverified"


def test_drill_dry_run_writes_nothing(
    library: Any,
    ledger: Ledger,
    drills: list[Drill],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lib = library
    verified(lib)
    live, manifest = take_local_backup(lib, ledger, tmp_path, monkeypatch)
    drill = new_drill(tmp_path, monkeypatch, lib, ledger)
    drills.append(drill)
    evidence = tmp_path / "evidence.json"
    calls: list[str] = []

    def connect(dsn: str) -> Any:
        calls.append("connect")
        raise AssertionError("a dry run must not open a database")

    def clock() -> str:
        calls.append("clock")
        return CLOCK

    services = TrustedServices(clock=clock, connect=connect)

    dry = live.invoke(*drill_argv(drill, manifest, evidence), services=services)

    assert dry.exit == 0 and dry.payload["outcome"] == "dry_run"
    assert dry.payload["executed"] is False and calls == []
    assert not evidence.exists()
    assert drill.targets() == [] and drill.object_dirs() == []


def test_preflight_accepts_drill_evidence(
    library: Any,
    ledger: Ledger,
    drills: list[Drill],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lib = library
    verified(lib)
    live, manifest = take_r2_backup(lib, ledger, tmp_path, monkeypatch, FakeS3())
    drill = new_drill(tmp_path, monkeypatch, lib, ledger)
    drills.append(drill)
    evidence = tmp_path / "evidence.json"
    done = live.invoke(
        *drill_argv(drill, manifest, evidence, "--attest-independent", "--execute"),
        services=SERVICES,
    )
    assert done.exit == 0, done.raw
    proof = read_evidence(evidence)

    def adopt(wire_backup: dict[str, Any]) -> None:
        wire_backup.clear()
        wire_backup.update(proof)

    report = build_packet(backup=adopt).run()  # the packet binds the exact drill evidence bytes

    assert report.ready and report.blockers == ()
    # The reference names the drill report, which really is in the drill's own object store.
    ref = proof["restoreEvidenceRef"]
    assert ref["artifactSchema"] == REPORT_SCHEMA
    stored = drill.config.objects / done.payload["drillId"] / "sha256" / ref["digest"][:2]
    assert (stored / ref["digest"]).read_bytes()
    report_document = json.loads((stored / ref["digest"]).read_bytes())
    assert report_document["drillId"] == done.payload["drillId"]


def test_second_drill_uses_fresh_target(
    library: Any,
    ledger: Ledger,
    drills: list[Drill],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lib = library
    verified(lib)
    live, manifest = take_local_backup(lib, ledger, tmp_path, monkeypatch)
    drill = new_drill(tmp_path, monkeypatch, lib, ledger)
    drills.append(drill)

    first = live.invoke(
        *drill_argv(drill, manifest, tmp_path / "one.json", "--execute"), services=SERVICES
    )
    second = live.invoke(
        *drill_argv(drill, manifest, tmp_path / "two.json", "--execute"), services=SERVICES
    )

    assert first.exit == 0 and second.exit == 0, (first.raw, second.raw)
    ids = {first.payload["drillId"], second.payload["drillId"]}
    assert len(ids) == 2
    assert drill.targets() == sorted(f"{drill.base}_{drill_id}" for drill_id in ids)
    assert drill.object_dirs() == sorted(ids)
    for drill_id in ids:
        assert row_count(drill.ledger_of(drill_id), "projects") == 1


def test_drill_schema_name_is_valid_and_bounded(
    library: Any,
    ledger: Ledger,
    drills: list[Drill],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lib = library
    verified(lib)
    live, manifest = take_local_backup(lib, ledger, tmp_path, monkeypatch)
    longest = "cf_" + "d" * 47  # 50 characters: the longest base the drill accepts
    assert len(longest) == 50
    drill = new_drill(tmp_path, monkeypatch, lib, ledger, base=longest)
    drills.append(drill)
    done = live.invoke(
        *drill_argv(drill, manifest, tmp_path / "ok.json", "--execute"), services=SERVICES
    )
    assert done.exit == 0, done.raw
    (name,) = drill.targets()
    assert re.fullmatch(r"[a-z][a-z0-9_]{0,62}", name) and len(name) == 63

    too_long = new_drill(tmp_path / "long", monkeypatch, lib, ledger, base=longest + "d")
    drills.append(too_long)
    refused_output = tmp_path / "refused.json"
    refused = live.invoke(
        *drill_argv(too_long, manifest, refused_output, "--execute"), services=SERVICES
    )
    assert refused.exit == 3 and refused.code == "config_invalid"
    assert not refused_output.exists()
    assert too_long.targets() == [] and too_long.object_dirs() == []


def test_drill_needs_its_own_grant_and_a_matching_operator(
    library: Any,
    ledger: Ledger,
    drills: list[Drill],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lib = library
    verified(lib)
    live, manifest = take_local_backup(lib, ledger, tmp_path, monkeypatch)
    drill = new_drill(tmp_path, monkeypatch, lib, ledger)
    drills.append(drill)
    evidence = tmp_path / "evidence.json"

    live.grants = {**live.grants, GRANTS_KEY: ["backup", "restore", "retention-report"]}
    live.write_config()  # restore does not imply restore-drill
    refused = live.invoke(*drill_argv(drill, manifest, evidence, "--execute"), services=SERVICES)
    assert refused.exit == 3 and refused.code == "grant_missing"
    assert not evidence.exists() and drill.targets() == []

    with_grants(live)
    drill.config.scopes = frozenset({"read"})  # a different operator than the live config
    drill.config.write_config()
    other = live.invoke(*drill_argv(drill, manifest, evidence, "--execute"), services=SERVICES)
    assert other.exit == 3 and other.code == "forbidden"
    assert not evidence.exists() and drill.targets() == [] and drill.object_dirs() == []


def test_incomplete_recovery_writes_no_evidence(
    library: Any,
    ledger: Ledger,
    drills: list[Drill],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lib = library
    verified(lib)
    live, manifest = take_local_backup(lib, ledger, tmp_path, monkeypatch)
    drill = new_drill(tmp_path, monkeypatch, lib, ledger)
    drills.append(drill)
    document = json.loads(manifest.read_bytes())
    victim = document["contentRefs"][0]["digest"]
    stored = tmp_path / "cli-backup" / "sha256" / victim[:2] / victim
    stored.unlink()  # a backup object that is gone: the recovery is incomplete
    evidence = tmp_path / "evidence.json"

    failed = live.invoke(*drill_argv(drill, manifest, evidence, "--execute"), services=SERVICES)

    assert failed.exit == 1 and failed.code == "artifact_missing"
    assert not evidence.exists()  # never evidence of a recovery that did not complete


def test_existing_evidence_file_is_refused_before_anything_is_restored(
    library: Any,
    ledger: Ledger,
    drills: list[Drill],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lib = library
    verified(lib)
    live, manifest = take_local_backup(lib, ledger, tmp_path, monkeypatch)
    drill = new_drill(tmp_path, monkeypatch, lib, ledger)
    drills.append(drill)
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(b"keep")

    refused = live.invoke(*drill_argv(drill, manifest, evidence, "--execute"), services=SERVICES)

    assert refused.code == "unavailable" and evidence.read_bytes() == b"keep"
    assert drill.targets() == [] and drill.object_dirs() == []


def test_drill_installs_allowance_tables_when_the_snapshot_has_them(
    library: Any,
    ledger: Ledger,
    drills: list[Drill],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lib = library
    install_allowance_schema(ledger)
    verified(lib)
    live, manifest = take_local_backup(lib, ledger, tmp_path, monkeypatch)
    drill = new_drill(tmp_path, monkeypatch, lib, ledger)
    drills.append(drill)

    done = live.invoke(
        *drill_argv(drill, manifest, tmp_path / "evidence.json", "--execute"), services=SERVICES
    )

    assert done.exit == 0, done.raw
    restored = drill.ledger_of(done.payload["drillId"])
    with restored.transaction() as tx:
        tables = {
            row[0]
            for row in tx.connection.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema=%s",
                (restored.schema,),
            ).fetchall()
        }
    assert {"call_allowance_scopes", "call_allowance_events"} <= tables
