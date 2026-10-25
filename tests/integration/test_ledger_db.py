"""Real, explicitly approved disposable PostgreSQL transaction tests."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from threading import Barrier
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import psycopg
import pytest
from conftest import approved_database_dsn
from conftest import ledger as ledger_fixture
from psycopg import sql
from psycopg.types.json import Jsonb

from conscience_foundry.contracts.accounting import BudgetEvent
from conscience_foundry.contracts.admission import AdmissionReport, IntakeManifest
from conscience_foundry.contracts.common import ArtifactRef, ContractError, ContractLimits
from conscience_foundry.contracts.project import PolicyArtifact
from conscience_foundry.ledger.db import (
    AdmissionRegistrationEvidence,
    Ledger,
    register_admission,
)

PROJECT = "00000000-0000-0000-0000-000000000001"
RUN = "00000000-0000-0000-0000-000000000002"
ACTOR = "00000000-0000-0000-0000-000000000003"
ASSET = "00000000-0000-0000-0000-000000000004"
SOURCE = "00000000-0000-0000-0000-000000000005"
BATCH = "00000000-0000-0000-0000-000000000006"
RESERVATION = "00000000-0000-0000-0000-000000000007"
TIME = "2026-10-25T00:00:00.000Z"


def limits() -> ContractLimits:
    return ContractLimits(
        schema_version="kf.contract-limits.v1",
        version="synthetic.v1",
        max_json_bytes=65536,
        max_string_scalars=1024,
        max_array_items=64,
        max_depth=16,
        max_manifest_items=8,
        max_source_bytes=4096,
        max_output_bytes=65536,
        max_error_message_scalars=80,
    )


def encoded(value: Any) -> bytes:
    if hasattr(value, "model_dump_json"):
        return value.model_dump_json(by_alias=True).encode()
    return json.dumps(value, separators=(",", ":")).encode()


def reference(data: bytes, schema: str) -> ArtifactRef:
    return ArtifactRef(
        schema_version="kf.artifact-ref.v1",
        project_id=PROJECT,
        digest=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        media_type="application/json",
        artifact_schema=schema,
        locations=(),
    )


@dataclass(frozen=True)
class Admission:
    manifest_ref: ArtifactRef
    report: AdmissionReport
    report_ref: ArtifactRef
    evidence: AdmissionRegistrationEvidence


def admission(*, title: str = "Synthetic manual", extra_asset: bool = False) -> Admission:
    policy = PolicyArtifact.model_validate(
        {
            "schemaVersion": "kf.policy.v1",
            "projectId": PROJECT,
            "allowedRemoteDestinations": [],
            "effectiveAt": TIME,
            "policyVersion": "synthetic.v1",
            "sources": [
                {
                    "sourceId": source,
                    **{
                        effect: "allow"
                        for effect in (
                            "read",
                            "extract",
                            "auditMetadataRead",
                            "remoteTransfer",
                            "enrich",
                            "embed",
                            "train",
                            "publish",
                        )
                    },
                }
                for source in (SOURCE, "00000000-0000-0000-0000-000000000008")
            ],
        }
    )
    policy_bytes = encoded(policy)
    payload = b"Synthetic text"
    items = [
        {
            "assetId": ASSET,
            "sourceId": SOURCE,
            "originalDigest": hashlib.sha256(payload).hexdigest(),
            "sizeBytes": len(payload),
            "mediaType": "text/plain",
            "custodyRef": {"rootId": "synthetic", "relativePath": "a.txt"},
            "metadata": {"title": title},
        }
    ]
    if extra_asset:
        items.append(
            items[0]
            | {
                "assetId": "00000000-0000-0000-0000-000000000009",
                "sourceId": "00000000-0000-0000-0000-000000000008",
            }
        )
    manifest = IntakeManifest.model_validate(
        {
            "schemaVersion": "kf.intake.v1",
            "projectId": PROJECT,
            "batchId": BATCH,
            "profileId": "technical_minimal",
            "profileVersion": "synthetic.v1",
            "policyRef": reference(policy_bytes, "kf.policy.v1"),
            "createdAt": TIME,
            "items": items,
        }
    )
    manifest_bytes = encoded(manifest)
    snapshot = reference(payload, "kf.raw-original.v1").model_copy(
        update={"media_type": "text/plain"}
    )
    report = AdmissionReport.model_validate(
        {
            "schemaVersion": "kf.admission-report.v1",
            "projectId": PROJECT,
            "batchId": BATCH,
            "manifestDigest": hashlib.sha256(manifest_bytes).hexdigest(),
            "policyVersion": policy.policy_version,
            "checkedAt": TIME,
            "entries": [
                {
                    "assetId": item["assetId"],
                    "sourceId": item["sourceId"],
                    "status": "admitted",
                    "reasons": [],
                    "snapshotRef": snapshot,
                }
                for item in items
            ],
        }
    )
    report_bytes = encoded(report)
    return Admission(
        reference(manifest_bytes, "kf.intake.v1"),
        report,
        reference(report_bytes, "kf.admission-report.v1"),
        AdmissionRegistrationEvidence(
            manifest_bytes=manifest_bytes,
            report_bytes=report_bytes,
            policy_bytes=policy_bytes,
            pinned_policy=policy,
            limits_by_schema={
                schema: limits()
                for schema in (
                    "kf.intake.v1",
                    "kf.admission-report.v1",
                    "kf.policy.v1",
                )
            },
        ),
    )


def register(ledger: Ledger, data: Admission) -> None:
    with ledger.transaction() as tx:
        register_admission(
            data.manifest_ref, data.report, data.report_ref, tx, evidence=data.evidence
        )


def test_test_database_guard(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    monkeypatch.delenv("CF_TEST_POSTGRES_DSN", raising=False)
    monkeypatch.delenv("CF_TEST_POSTGRES_APPROVED_DSN", raising=False)
    with pytest.raises(ValueError, match="authorization"):
        approved_database_dsn()
    monkeypatch.setenv("CF_TEST_POSTGRES_DSN", "dbname=postgres host=localhost")
    monkeypatch.setenv("CF_TEST_POSTGRES_APPROVED_DSN", "different")
    with pytest.raises(ValueError, match="authorization"):
        approved_database_dsn()
    for dsn in ("dbname=postgres host=localhost", "dbname=cf_test host=127.0.0.1"):
        monkeypatch.setenv("CF_TEST_POSTGRES_DSN", dsn)
        monkeypatch.setenv("CF_TEST_POSTGRES_APPROVED_DSN", dsn)
        with pytest.raises(ValueError, match="disposable|socket"):
            approved_database_dsn()
    # Guard-unit tests use no server: a private local socket directory is enough.
    tmp_path.chmod(0o700)
    dsn = f"dbname=cf_test_guard user=synthetic host={tmp_path}"
    monkeypatch.setenv("CF_TEST_POSTGRES_DSN", dsn)
    monkeypatch.setenv("CF_TEST_POSTGRES_APPROVED_DSN", dsn)
    assert approved_database_dsn() == dsn


def test_guard_rejects_ambient_libpq_routing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    tmp_path.chmod(0o700)
    dsn = f"dbname=cf_test_guard user=synthetic host={tmp_path}"
    monkeypatch.setenv("CF_TEST_POSTGRES_DSN", dsn)
    monkeypatch.setenv("CF_TEST_POSTGRES_APPROVED_DSN", dsn)
    monkeypatch.setenv("PGHOSTADDR", "192.0.2.1")
    with pytest.raises(ValueError, match="ambient"):
        approved_database_dsn()


def test_missing_database_is_failure_not_skip(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    tmp_path.chmod(0o700)
    dsn = f"dbname=cf_test_guard user=synthetic host={tmp_path}"
    monkeypatch.setenv("CF_TEST_POSTGRES_DSN", dsn)
    monkeypatch.setenv("CF_TEST_POSTGRES_APPROVED_DSN", dsn)
    calls: list[str] = []

    def unavailable(target: str, **options: object) -> None:
        calls.append(target)
        raise psycopg.OperationalError("Synthetic unavailable endpoint")

    monkeypatch.setattr(psycopg, "connect", unavailable)
    request = SimpleNamespace(node=SimpleNamespace(get_closest_marker=lambda name: object()))
    generator = ledger_fixture.__wrapped__(request)
    with pytest.raises(pytest.fail.Exception, match="unavailable"):
        next(generator)
    assert calls == [dsn]


@pytest.mark.database
def test_migration_is_explicit_and_rejects_unrelated_schema(ledger: Ledger) -> None:
    with ledger.transaction() as tx:
        assert tx.connection.execute(
            sql.SQL("SELECT version FROM {}.schema_version").format(sql.Identifier(ledger.schema))
        ).fetchone() == (1,)
    with pytest.raises(ContractError, match="schema_incompatible"):
        ledger.migrate()
    with pytest.raises(ContractError, match="invalid_schema"):
        Ledger(ledger.connection_factory, schema="public")
    name = "cf_test_" + uuid4().hex
    with ledger.connection_factory() as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(name)))
        connection.execute(
            sql.SQL("CREATE TABLE {}.unrelated (n integer)").format(sql.Identifier(name))
        )
    try:
        with pytest.raises(ContractError, match="schema_incompatible"):
            Ledger(ledger.connection_factory, schema=name).migrate()
        with ledger.connection_factory() as connection:
            assert (
                connection.execute("SELECT to_regclass(%s)", (name + ".unrelated",)).fetchone()[0]
                is not None
            )
    finally:
        with ledger.connection_factory() as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(name)))


@pytest.mark.database
def test_migration_rejects_schema_owned_collation_without_modifying_it(ledger: Ledger) -> None:
    name = "cf_test_" + uuid4().hex
    with ledger.connection_factory() as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(name)))
        connection.execute(
            sql.SQL('CREATE COLLATION {}.unrelated FROM pg_catalog."C"').format(
                sql.Identifier(name)
            )
        )
    try:
        with pytest.raises(ContractError, match="schema_incompatible"):
            Ledger(ledger.connection_factory, schema=name).migrate()
        with ledger.connection_factory() as connection:
            assert connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_collation c "
                "JOIN pg_catalog.pg_namespace n ON n.oid=c.collnamespace WHERE n.nspname=%s",
                (name,),
            ).fetchone() == (1,)
            assert connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s",
                (name,),
            ).fetchone() == (0,)
    finally:
        with ledger.connection_factory() as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(name)))


@pytest.mark.database
@pytest.mark.parametrize("exposure", ["schema_usage", "default_table_select"])
def test_migration_rejects_public_namespace_privileges(ledger: Ledger, exposure: str) -> None:
    name = "cf_test_" + uuid4().hex
    with ledger.connection_factory() as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(name)))
        if exposure == "schema_usage":
            statement = sql.SQL("GRANT USAGE ON SCHEMA {} TO PUBLIC")
        else:
            statement = sql.SQL(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT SELECT ON TABLES TO PUBLIC"
            )
        connection.execute(statement.format(sql.Identifier(name)))
    try:
        with pytest.raises(ContractError):
            Ledger(ledger.connection_factory, schema=name).migrate()
        with ledger.connection_factory() as connection:
            assert connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s",
                (name,),
            ).fetchone() == (0,)
    finally:
        with ledger.connection_factory() as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(name)))


@pytest.mark.database
def test_transaction_rollback_and_unique_event(ledger: Ledger) -> None:
    with pytest.raises(RuntimeError, match="rollback"):
        with ledger.transaction() as tx:
            tx.create_project(PROJECT)
            raise RuntimeError("rollback")
    with ledger.transaction() as tx:
        assert tx.connection.execute(
            sql.SQL("SELECT count(*) FROM {}.projects").format(sql.Identifier(ledger.schema))
        ).fetchone() == (0,)
    data = admission()
    register(ledger, data)
    evidence = reference(b"synthetic evidence", "synthetic.evidence.v1")
    event = BudgetEvent(
        schema_version="kf.budget-event.v1",
        project_id=PROJECT,
        run_id=RUN,
        reservation_id=RESERVATION,
        scope="run_storage",
        event_id=str(uuid4()),
        event_type="reserve",
        amount_usd="4",
        cost_status="estimated",
        evidence_ref=evidence,
        created_at=TIME,
    )
    with ledger.transaction() as tx:
        tx.create_run(PROJECT, RUN, data.report_ref.digest)
        authorization_id = str(uuid4())
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,authorization_id,run_id,authorization_ref,"
                "allowed_plan_digests,max_run_cost,max_concurrent_attempts,actor_id,authorized_at,"
                "expires_at) VALUES (%s,%s,%s,%s,%s,10,1,%s,%s,%s)"
            ).format(tx.table("authorizations")),
            (
                PROJECT,
                authorization_id,
                RUN,
                Jsonb({"synthetic": True}),
                ["c" * 64],
                ACTOR,
                TIME,
                "2026-10-25T01:00:00.000Z",
            ),
        )
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,reservation_id,run_id,scope,reserved_usd,"
                "outstanding_usd,settled_usd,authorization_id) "
                "VALUES (%s,%s,%s,'run_storage',4,4,0,%s)"
            ).format(tx.table("reservations")),
            (PROJECT, RESERVATION, RUN, authorization_id),
        )
        assert tx.append_budget_event(event, event_bytes=encoded(event), limits=limits()) is True
    with ledger.transaction() as tx:
        assert tx.append_budget_event(event, event_bytes=encoded(event), limits=limits()) is False
    changed = event.model_copy(update={"amount_usd": "5"})
    with pytest.raises(ContractError, match="determinism_conflict"):
        with ledger.transaction() as tx:
            tx.append_budget_event(changed, event_bytes=encoded(changed), limits=limits())


@pytest.mark.database
def test_registration_verifies_raw_pins_before_writing(ledger: Ledger) -> None:
    data = admission()
    bad = AdmissionRegistrationEvidence(
        manifest_bytes=data.evidence.manifest_bytes + b" ",
        report_bytes=data.evidence.report_bytes,
        policy_bytes=data.evidence.policy_bytes,
        pinned_policy=data.evidence.pinned_policy,
        limits_by_schema=data.evidence.limits_by_schema,
    )
    with pytest.raises(ContractError, match="hash_mismatch"):
        with ledger.transaction() as tx:
            register_admission(data.manifest_ref, data.report, data.report_ref, tx, evidence=bad)
    with ledger.transaction() as tx:
        assert tx.connection.execute(
            sql.SQL("SELECT count(*) FROM {}").format(tx.table("batches"))
        ).fetchone() == (0,)
    register(ledger, data)
    register(ledger, data)
    with ledger.transaction() as tx:
        assert tx.connection.execute(
            sql.SQL("SELECT count(*) FROM {}").format(tx.table("admission_reports"))
        ).fetchone() == (1,)


@pytest.mark.database
def test_two_sessions_race_batch_binding_and_restart(ledger: Ledger) -> None:
    first, second = admission(title="A"), admission(title="B")
    barrier = Barrier(2)

    def compete(data: Admission) -> str:
        barrier.wait(timeout=5)
        try:
            register(ledger, data)
            return data.manifest_ref.digest
        except ContractError as error:
            assert error.code == "determinism_conflict"
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(compete, (first, second)))
    assert results.count("conflict") == 1
    winner = first if first.manifest_ref.digest in results else second
    loser = second if winner is first else first
    restarted = Ledger(ledger.connection_factory, schema=ledger.schema)
    register(restarted, winner)
    with pytest.raises(ContractError, match="determinism_conflict"):
        register(restarted, loser)
    with pytest.raises(ContractError, match="forbidden"):
        with restarted.transaction() as tx:
            tx.create_run(PROJECT, RUN, loser.report_ref.digest)


@pytest.mark.database
def test_identical_blob_does_not_merge_sources_or_assets(ledger: Ledger) -> None:
    data = admission(extra_asset=True)
    register(ledger, data)
    with ledger.transaction() as tx:
        rows = tx.connection.execute(
            sql.SQL("SELECT asset_id,source_id,original_digest FROM {} ORDER BY asset_id").format(
                tx.table("assets")
            )
        ).fetchall()
    assert len(rows) == 2
    assert rows[0][0] != rows[1][0] and rows[0][1] != rows[1][1]
    assert rows[0][2] == rows[1][2]


@pytest.mark.database
def test_pause_history_and_optimistic_version(ledger: Ledger) -> None:
    data = admission()
    register(ledger, data)
    with ledger.transaction() as tx:
        tx.create_run(PROJECT, RUN, data.report_ref.digest)
        paused = tx.record_pause(
            "run",
            PROJECT,
            RUN,
            True,
            expected_version=0,
            actor_id=ACTOR,
            reason="synthetic_pause",
            decided_at=TIME,
            decision_id=str(uuid4()),
        )
        assert paused.paused and paused.version == 1
    with pytest.raises(ContractError, match="activation_conflict"):
        with ledger.transaction() as tx:
            tx.record_pause(
                "run",
                PROJECT,
                RUN,
                False,
                expected_version=0,
                actor_id=ACTOR,
                reason="synthetic_resume",
                decided_at=TIME,
                decision_id=str(uuid4()),
            )
    with ledger.transaction() as tx:
        assert tx.get_pause("run", PROJECT, RUN).paused
        assert tx.connection.execute(
            sql.SQL("SELECT count(*) FROM {}").format(tx.table("pause_history"))
        ).fetchone() == (1,)


@pytest.mark.database
def test_foreign_keys_keep_project_and_run_consistent(ledger: Ledger) -> None:
    data = admission()
    register(ledger, data)
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with ledger.transaction() as tx:
            tx.create_project(ACTOR)
            tx.connection.execute(
                sql.SQL(
                    "INSERT INTO {} (project_id,run_id,admission_report_digest) VALUES (%s,%s,%s)"
                ).format(tx.table("runs")),
                (ACTOR, RUN, data.report_ref.digest),
            )


@pytest.mark.database
def test_attempt_cannot_mix_plan_and_reservation_operations(ledger: Ledger) -> None:
    """Raw rows isolate SQL invariants; these are not dispatch authorization."""
    data = admission()
    register(ledger, data)
    authorization_id, plan_id = str(uuid4()), str(uuid4())
    first, second = "a" * 64, "b" * 64
    with ledger.transaction() as tx:
        tx.create_run(PROJECT, RUN, data.report_ref.digest)
        for operation in (first, second):
            tx.connection.execute(
                sql.SQL(
                    "INSERT INTO {} (project_id,operation_key,asset_id) VALUES (%s,%s,%s)"
                ).format(tx.table("operations")),
                (PROJECT, operation, ASSET),
            )
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,authorization_id,run_id,authorization_ref,"
                "allowed_plan_digests,max_run_cost,max_concurrent_attempts,actor_id,authorized_at,"
                "expires_at) VALUES (%s,%s,%s,%s,%s,10,1,%s,%s,%s)"
            ).format(tx.table("authorizations")),
            (
                PROJECT,
                authorization_id,
                RUN,
                Jsonb({"synthetic": True}),
                ["c" * 64],
                ACTOR,
                TIME,
                "2026-10-25T01:00:00.000Z",
            ),
        )
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,plan_id,run_id,plan_digest,plan_ref,authorization_id,"
                "operation_key) VALUES (%s,%s,%s,%s,%s,%s,%s)"
            ).format(tx.table("plans")),
            (
                PROJECT,
                plan_id,
                RUN,
                "c" * 64,
                Jsonb({"synthetic": True}),
                authorization_id,
                first,
            ),
        )
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,reservation_id,run_id,operation_key,scope,reserved_usd,"
                "outstanding_usd,settled_usd,authorization_id) "
                "VALUES (%s,%s,%s,%s,'attempt',4,4,0,%s)"
            ).format(tx.table("reservations")),
            (PROJECT, RESERVATION, RUN, second, authorization_id),
        )
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with ledger.transaction() as tx:
            tx.connection.execute(
                sql.SQL(
                    "INSERT INTO {} (project_id,attempt_id,run_id,plan_id,operation_key,"
                    "attempt_number,reservation_id,state,created_at) "
                    "VALUES (%s,%s,%s,%s,%s,1,%s,'reserved',%s)"
                ).format(tx.table("attempts")),
                (
                    PROJECT,
                    str(uuid4()),
                    RUN,
                    plan_id,
                    first,
                    RESERVATION,
                    TIME,
                ),
            )


@pytest.mark.database
def test_registration_rejects_incomplete_policy_universe(ledger: Ledger) -> None:
    data = admission()
    policy = data.evidence.pinned_policy.model_copy(update={"sources": ()})
    policy_bytes = encoded(policy)
    manifest = IntakeManifest.from_wire(data.evidence.manifest_bytes, limits()).model_copy(
        update={"policy_ref": reference(policy_bytes, "kf.policy.v1")}
    )
    manifest_bytes = encoded(manifest)
    report = data.report.model_copy(
        update={"manifest_digest": hashlib.sha256(manifest_bytes).hexdigest()}
    )
    report_bytes = encoded(report)
    evidence = AdmissionRegistrationEvidence(
        manifest_bytes=manifest_bytes,
        report_bytes=report_bytes,
        policy_bytes=policy_bytes,
        pinned_policy=policy,
        limits_by_schema=data.evidence.limits_by_schema,
    )
    with pytest.raises(ContractError, match="forbidden"):
        with ledger.transaction() as tx:
            register_admission(
                reference(manifest_bytes, "kf.intake.v1"),
                report,
                reference(report_bytes, "kf.admission-report.v1"),
                tx,
                evidence=evidence,
            )


@pytest.mark.database
def test_transaction_is_atomic_with_autocommit_factory(ledger: Ledger) -> None:
    def connection() -> psycopg.Connection[tuple[Any, ...]]:
        result = ledger.connection_factory()
        result.autocommit = True
        return result

    database = Ledger(connection, schema=ledger.schema)
    with pytest.raises(RuntimeError, match="rollback"):
        with database.transaction() as tx:
            tx.create_project(PROJECT)
            raise RuntimeError("rollback")
    with database.transaction() as tx:
        assert tx.connection.execute(
            sql.SQL("SELECT count(*) FROM {}").format(tx.table("projects"))
        ).fetchone() == (0,)


@pytest.mark.database
def test_registration_conflict_caught_by_caller_leaves_no_partial_rows(ledger: Ledger) -> None:
    data = admission()
    register(ledger, data)
    manifest = IntakeManifest.from_wire(data.evidence.manifest_bytes, limits())
    source = "00000000-0000-0000-0000-000000000008"
    manifest = manifest.model_copy(
        update={
            "batch_id": str(uuid4()),
            "items": (manifest.items[0].model_copy(update={"source_id": source}),),
        }
    )
    manifest_bytes = encoded(manifest)
    report = data.report.model_copy(
        update={
            "batch_id": manifest.batch_id,
            "manifest_digest": hashlib.sha256(manifest_bytes).hexdigest(),
            "entries": (data.report.entries[0].model_copy(update={"source_id": source}),),
        }
    )
    report_bytes = encoded(report)
    evidence = AdmissionRegistrationEvidence(
        manifest_bytes=manifest_bytes,
        report_bytes=report_bytes,
        policy_bytes=data.evidence.policy_bytes,
        pinned_policy=data.evidence.pinned_policy,
        limits_by_schema=data.evidence.limits_by_schema,
    )
    with ledger.transaction() as tx:
        with pytest.raises(ContractError, match="determinism_conflict"):
            register_admission(
                reference(manifest_bytes, "kf.intake.v1"),
                report,
                reference(report_bytes, "kf.admission-report.v1"),
                tx,
                evidence=evidence,
            )
        assert tx.connection.execute(
            sql.SQL("SELECT count(*) FROM {}").format(tx.table("batches"))
        ).fetchone() == (1,)
        assert tx.connection.execute(
            sql.SQL("SELECT count(*) FROM {}").format(tx.table("admission_reports"))
        ).fetchone() == (1,)
