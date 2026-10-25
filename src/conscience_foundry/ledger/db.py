"""Explicit PostgreSQL namespace and control-only transactional primitives.

This module establishes historical registrations and stores operational state.
It does not authenticate callers, authorize dispatch or prove object durability.
Only trusted control code may construct its connection factory and use a txn.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from importlib.resources import files
from typing import Any, Literal

import psycopg
from psycopg import sql
from psycopg.pq import TransactionStatus
from psycopg.rows import tuple_row
from psycopg.types.json import Jsonb
from pydantic import TypeAdapter, ValidationError

from conscience_foundry.contracts.accounting import BudgetEvent
from conscience_foundry.contracts.admission import AdmissionReport, IntakeManifest
from conscience_foundry.contracts.common import (
    ContractError,
    ContractLimits,
    Digest,
    Id,
    Instant,
    Ref,
)
from conscience_foundry.contracts.project import PolicyArtifact

Connection = psycopg.Connection[tuple[Any, ...]]
ConnectionFactory = Callable[[], Connection]
PauseScope = Literal["project", "run"]
TABLES = frozenset(
    {
        "schema_version",
        "projects",
        "batches",
        "admission_reports",
        "assets",
        "admission_entries",
        "runs",
        "authorizations",
        "plans",
        "operations",
        "reservations",
        "attempts",
        "dispatch_claims",
        "budget_events",
        "billing_adjustments",
        "operation_results",
        "integrity_holds",
        "attempt_observations",
        "control_decisions",
        "reviews",
        "releases",
        "publications",
        "active_releases",
        "pause_state",
        "pause_history",
    }
)


def _id(value: str) -> None:
    try:
        TypeAdapter(Id).validate_python(value)
    except ValidationError:
        raise ContractError("invalid_schema") from None


def _digest(value: str) -> None:
    try:
        TypeAdapter(Digest).validate_python(value)
    except ValidationError:
        raise ContractError("invalid_schema") from None


def _instant(value: str) -> None:
    try:
        TypeAdapter(Instant).validate_python(value)
    except ValidationError:
        raise ContractError("invalid_schema") from None


def _ref_json(reference: Ref) -> Jsonb:
    return Jsonb(reference.model_dump(by_alias=True, exclude_none=True))


@dataclass(frozen=True)
class AdmissionRegistrationEvidence:
    """Transient exact bytes; caller has already durably installed all artifacts.

    This is input evidence, not a transferable capability or authentication token.
    The SQL ledger retains references/identities, never these artifact bodies.
    """

    manifest_bytes: bytes = field(repr=False)
    report_bytes: bytes = field(repr=False)
    policy_bytes: bytes = field(repr=False)
    pinned_policy: PolicyArtifact = field(repr=False)
    limits_by_schema: Mapping[str, ContractLimits] = field(repr=False)


@dataclass(frozen=True)
class PauseState:
    scope: PauseScope
    project_id: Id
    run_id: Id | None
    paused: bool
    version: int


class Ledger:
    """A fresh connection per transaction, with no ambient/default SQL namespace."""

    def __init__(self, connection_factory: ConnectionFactory, *, schema: str) -> None:
        if (
            type(schema) is not str
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema)
            or schema in {"public", "information_schema"}
            or schema.startswith("pg_")
            or not callable(connection_factory)
        ):
            raise ContractError("invalid_schema")
        self.connection_factory = connection_factory
        self.schema = schema
        self._migration = (
            files("conscience_foundry.ledger")
            .joinpath("migrations/001_initial.sql")
            .read_text(encoding="utf-8")
        )
        self._migration_digest = hashlib.sha256(self._migration.encode("utf-8")).hexdigest()

    def _connection(self) -> Connection:
        connection = self.connection_factory()
        if connection.info.transaction_status != TransactionStatus.IDLE:
            connection.close()
            raise ContractError("unavailable")
        connection.row_factory = tuple_row
        return connection

    def migrate(self) -> None:
        """Install only into an absent or empty, caller-owned explicit namespace.

        Re-running on a populated namespace is intentionally rejected; opening a
        ledger never migrates, adopts or modifies an existing consumer schema.
        """
        with self._connection() as connection, connection.transaction():
            connection.execute(
                "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(%s,0))",
                ("conscience-foundry:migrate:" + self.schema,),
            )
            namespace = connection.execute(
                "SELECT n.oid, n.nspowner = r.oid FROM pg_catalog.pg_namespace n "
                "JOIN pg_catalog.pg_roles r ON r.rolname = current_user WHERE n.nspname = %s",
                (self.schema,),
            ).fetchone()
            if namespace is None:
                connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
            else:
                if not namespace[1]:
                    raise ContractError("forbidden")
                populated = connection.execute(
                    "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_depend "
                    "WHERE refclassid='pg_catalog.pg_namespace'::pg_catalog.regclass "
                    "AND refobjid=%s)",
                    (namespace[0],),
                ).fetchone()
                if populated is None or populated[0]:
                    raise ContractError("schema_incompatible")
            shared_namespace = connection.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n, "
                "LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl, "
                "pg_catalog.acldefault('n',n.nspowner))) a "
                "WHERE n.nspname=%s AND a.grantee<>n.nspowner)",
                (self.schema,),
            ).fetchone()
            if shared_namespace is None or shared_namespace[0]:
                raise ContractError("forbidden")
            connection.execute(sql.SQL(self._migration).format(schema=sql.Identifier(self.schema)))
            # Effective ACLs include global defaults inherited by newly created
            # tables. Reject exposure atomically rather than alter role defaults.
            shared_tables = connection.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace, "
                "LATERAL pg_catalog.aclexplode(COALESCE(c.relacl, "
                "pg_catalog.acldefault('r',c.relowner))) a "
                "WHERE n.nspname=%s AND a.grantee<>c.relowner)",
                (self.schema,),
            ).fetchone()
            if shared_tables is None or shared_tables[0]:
                raise ContractError("forbidden")
            connection.execute(
                sql.SQL(
                    "INSERT INTO {}.schema_version (version,migration_digest) VALUES (1,%s)"
                ).format(sql.Identifier(self.schema)),
                (self._migration_digest,),
            )

    @contextmanager
    def transaction(self) -> Iterator[LedgerTxn]:
        with self._connection() as connection, connection.transaction():
            try:
                version = connection.execute(
                    sql.SQL("SELECT version,migration_digest FROM {}.schema_version").format(
                        sql.Identifier(self.schema)
                    )
                ).fetchall()
            except (psycopg.errors.UndefinedTable, psycopg.errors.InvalidSchemaName):
                raise ContractError("schema_incompatible") from None
            if version != [(1, self._migration_digest)]:
                raise ContractError("schema_incompatible")
            transaction = LedgerTxn(connection, self.schema)
            try:
                yield transaction
            finally:
                transaction._active = False


class LedgerTxn:
    """Trusted control transaction; all table identifiers are explicitly qualified.

    SQL writes exposed here are historical/control primitives. Later control
    ports must authenticate actors and resolve current policy before using them.
    Locks always acquire project, then run, then operation; project serialization
    keeps absent-row creation and cross-run operation counters safe in F1.
    """

    def __init__(self, connection: Connection, schema: str) -> None:
        self.connection = connection
        self.schema = schema
        self._active = True
        self._locked_project: str | None = None

    def table(self, name: str) -> sql.Identifier:
        if not self._active or name not in TABLES:
            raise ContractError("invalid_schema")
        return sql.Identifier(self.schema, name)

    def create_project(self, project_id: Id) -> None:
        _id(project_id)
        self.connection.execute(
            sql.SQL("INSERT INTO {} (project_id) VALUES (%s) ON CONFLICT DO NOTHING").format(
                self.table("projects")
            ),
            (project_id,),
        )

    def lock(
        self, project_id: Id, run_id: Id | None = None, operation_key: Digest | None = None
    ) -> None:
        _id(project_id)
        if self._locked_project is not None and self._locked_project != project_id:
            raise ContractError("forbidden")
        if (
            self.connection.execute(
                sql.SQL("SELECT project_id FROM {} WHERE project_id=%s FOR UPDATE").format(
                    self.table("projects")
                ),
                (project_id,),
            ).fetchone()
            is None
        ):
            raise ContractError("forbidden")
        self._locked_project = project_id
        if run_id is not None:
            _id(run_id)
            if (
                self.connection.execute(
                    sql.SQL(
                        "SELECT run_id FROM {} WHERE project_id=%s AND run_id=%s FOR UPDATE"
                    ).format(self.table("runs")),
                    (project_id, run_id),
                ).fetchone()
                is None
            ):
                raise ContractError("forbidden")
        if operation_key is not None:
            _digest(operation_key)
            if (
                self.connection.execute(
                    sql.SQL(
                        "SELECT operation_key FROM {} WHERE project_id=%s AND operation_key=%s "
                        "FOR UPDATE"
                    ).format(self.table("operations")),
                    (project_id, operation_key),
                ).fetchone()
                is None
            ):
                raise ContractError("forbidden")

    def create_run(self, project_id: Id, run_id: Id, admission_report_digest: Digest) -> None:
        _id(run_id)
        _digest(admission_report_digest)
        self.lock(project_id)
        if (
            self.connection.execute(
                sql.SQL("SELECT 1 FROM {} WHERE project_id=%s AND report_digest=%s").format(
                    self.table("admission_reports")
                ),
                (project_id, admission_report_digest),
            ).fetchone()
            is None
        ):
            raise ContractError("forbidden")
        self.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,run_id,admission_report_digest) VALUES (%s,%s,%s) "
                "ON CONFLICT DO NOTHING"
            ).format(self.table("runs")),
            (project_id, run_id, admission_report_digest),
        )
        existing = self.connection.execute(
            sql.SQL(
                "SELECT admission_report_digest FROM {} WHERE project_id=%s AND run_id=%s"
            ).format(self.table("runs")),
            (project_id, run_id),
        ).fetchone()
        if existing != (admission_report_digest,):
            raise ContractError("determinism_conflict")

    def append_budget_event(
        self, event: BudgetEvent, *, event_bytes: bytes, limits: ContractLimits
    ) -> bool:
        """Append exact immutable control bytes; arithmetic belongs to T12."""
        if BudgetEvent.from_wire(event_bytes, limits) != event:
            raise ContractError("hash_mismatch")
        self.lock(event.project_id, event.run_id)
        digest = hashlib.sha256(event_bytes).hexdigest()
        previous = self.connection.execute(
            sql.SQL("SELECT record_bytes FROM {} WHERE project_id=%s AND event_id=%s").format(
                self.table("budget_events")
            ),
            (event.project_id, event.event_id),
        ).fetchone()
        if previous is not None:
            if bytes(previous[0]) != event_bytes:
                raise ContractError("determinism_conflict")
            return False
        self.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,event_id,run_id,reservation_id,schema_version,"
                "record_digest,record_bytes) VALUES (%s,%s,%s,%s,%s,%s,%s)"
            ).format(self.table("budget_events")),
            (
                event.project_id,
                event.event_id,
                event.run_id,
                event.reservation_id,
                event.schema_version,
                digest,
                event_bytes,
            ),
        )
        return True

    def _pause_key(self, scope: PauseScope, project_id: Id, run_id: Id | None) -> str:
        if scope not in {"project", "run"} or (scope == "run") != (run_id is not None):
            raise ContractError("invalid_schema")
        self.lock(project_id, run_id)
        return run_id if run_id is not None else project_id

    def get_pause(self, scope: PauseScope, project_id: Id, run_id: Id | None) -> PauseState:
        key = self._pause_key(scope, project_id, run_id)
        row = self.connection.execute(
            sql.SQL(
                "SELECT paused,version FROM {} WHERE project_id=%s AND scope=%s AND scope_id=%s"
            ).format(self.table("pause_state")),
            (project_id, scope, key),
        ).fetchone()
        return PauseState(scope, project_id, run_id, row[0] if row else False, row[1] if row else 0)

    def record_pause(
        self,
        scope: PauseScope,
        project_id: Id,
        run_id: Id | None,
        paused: bool,
        *,
        expected_version: int,
        actor_id: Id,
        reason: str,
        decided_at: Instant,
        decision_id: Id,
    ) -> PauseState:
        """CAS/history primitive; authenticated current operator authority is caller-owned."""
        _id(actor_id)
        _id(decision_id)
        _instant(decided_at)
        if (
            type(paused) is not bool
            or type(expected_version) is not int
            or not 0 <= expected_version < 9007199254740991
            or type(reason) is not str
            or not re.fullmatch(r"[a-z][a-z0-9_]*", reason)
        ):
            raise ContractError("invalid_schema")
        old = self.get_pause(scope, project_id, run_id)
        if old.version != expected_version:
            raise ContractError("activation_conflict")
        key = run_id if run_id is not None else project_id
        version = old.version + 1
        self.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,scope,scope_id,run_id,paused,version) "
                "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (project_id,scope,scope_id) "
                "DO UPDATE SET paused=EXCLUDED.paused,version=EXCLUDED.version"
            ).format(self.table("pause_state")),
            (project_id, scope, key, run_id, paused, version),
        )
        self.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,decision_id,scope,scope_id,version,paused,"
                "actor_id,reason,decided_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            ).format(self.table("pause_history")),
            (project_id, decision_id, scope, key, version, paused, actor_id, reason, decided_at),
        )
        return PauseState(scope, project_id, run_id, paused, version)


def _limits(evidence: AdmissionRegistrationEvidence, schema: str) -> ContractLimits:
    value = evidence.limits_by_schema.get(schema)
    if not isinstance(value, ContractLimits) or value.schema_version != "kf.contract-limits.v1":
        raise ContractError("limits_missing")
    return value


def _verify_ref(data: bytes, reference: Ref, schema: str, project_id: Id) -> None:
    if (
        reference.schema_version != "kf.artifact-ref.v1"
        or reference.project_id != project_id
        or reference.artifact_schema != schema
        or reference.media_type != "application/json"
    ):
        raise ContractError("invalid_schema")
    if reference.size_bytes != len(data) or reference.digest != hashlib.sha256(data).hexdigest():
        raise ContractError("hash_mismatch")


def register_admission(
    manifest_ref: Ref,
    report: AdmissionReport,
    report_ref: Ref,
    tx: LedgerTxn,
    *,
    evidence: AdmissionRegistrationEvidence,
) -> None:
    """Bind historical verified evidence; no dispatch/custody/current-access grant.

    The trusted caller must durably install all referenced artifacts first.
    Their raw bytes are verified here, retained transiently, and never persisted.
    """
    # A caught domain conflict must not commit a half-registered admission.
    with tx.connection.transaction():
        manifest = IntakeManifest.from_wire(
            evidence.manifest_bytes, _limits(evidence, "kf.intake.v1")
        )
        parsed_report = AdmissionReport.from_wire(
            evidence.report_bytes, _limits(evidence, "kf.admission-report.v1")
        )
        policy = PolicyArtifact.from_wire(evidence.policy_bytes, _limits(evidence, "kf.policy.v1"))
        if parsed_report != report or policy != evidence.pinned_policy:
            raise ContractError("hash_mismatch")
        _verify_ref(evidence.manifest_bytes, manifest_ref, "kf.intake.v1", manifest.project_id)
        _verify_ref(
            evidence.report_bytes, report_ref, "kf.admission-report.v1", manifest.project_id
        )
        _verify_ref(evidence.policy_bytes, manifest.policy_ref, "kf.policy.v1", manifest.project_id)
        if report.manifest_digest != manifest_ref.digest:
            raise ContractError("hash_mismatch")
        report.validate_manifest(manifest, policy)
        if not {item.source_id for item in manifest.items} <= {
            source.source_id for source in policy.sources
        }:
            raise ContractError("forbidden")
        tx.create_project(manifest.project_id)
        tx.lock(manifest.project_id)
        existing = tx.connection.execute(
            sql.SQL("SELECT manifest_digest FROM {} WHERE project_id=%s AND batch_id=%s").format(
                tx.table("batches")
            ),
            (manifest.project_id, manifest.batch_id),
        ).fetchone()
        if existing is not None and existing != (manifest_ref.digest,):
            raise ContractError("determinism_conflict")
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,batch_id,manifest_digest,manifest_ref) "
                "VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING"
            ).format(tx.table("batches")),
            (manifest.project_id, manifest.batch_id, manifest_ref.digest, _ref_json(manifest_ref)),
        )
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,report_digest,batch_id,manifest_digest,report_ref,"
                "policy_ref,policy_version,checked_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT DO NOTHING"
            ).format(tx.table("admission_reports")),
            (
                manifest.project_id,
                report_ref.digest,
                manifest.batch_id,
                manifest_ref.digest,
                _ref_json(report_ref),
                _ref_json(manifest.policy_ref),
                report.policy_version,
                report.checked_at,
            ),
        )
        entries = {entry.asset_id: entry for entry in report.entries}
        for item in manifest.items:
            original = tx.connection.execute(
                sql.SQL(
                    "SELECT source_id::text,original_digest,size_bytes FROM {} "
                    "WHERE project_id=%s AND asset_id=%s"
                ).format(tx.table("assets")),
                (manifest.project_id, item.asset_id),
            ).fetchone()
            if original is not None and original != (
                item.source_id,
                item.original_digest,
                item.size_bytes,
            ):
                raise ContractError("determinism_conflict")
            tx.connection.execute(
                sql.SQL(
                    "INSERT INTO {} (project_id,asset_id,source_id,original_digest,size_bytes) "
                    "VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING"
                ).format(tx.table("assets")),
                (
                    manifest.project_id,
                    item.asset_id,
                    item.source_id,
                    item.original_digest,
                    item.size_bytes,
                ),
            )
            entry = entries[item.asset_id]
            tx.connection.execute(
                sql.SQL(
                    "INSERT INTO {} (project_id,report_digest,asset_id,source_id,status,"
                    "snapshot_ref,reason_codes) VALUES (%s,%s,%s,%s,%s,%s,%s) "
                    "ON CONFLICT DO NOTHING"
                ).format(tx.table("admission_entries")),
                (
                    manifest.project_id,
                    report_ref.digest,
                    item.asset_id,
                    item.source_id,
                    entry.status,
                    _ref_json(entry.snapshot_ref) if entry.snapshot_ref is not None else None,
                    [reason.code for reason in entry.reasons],
                ),
            )
