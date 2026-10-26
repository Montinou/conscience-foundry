"""PostgreSQL persistence for the shared call allowance: scope state and idempotent events.

Only trusted control code (the execution allowance mechanism) calls these primitives inside a
`LedgerTxn` that already holds the project, run and operation locks. Nothing here decides
policy, contacts a provider or touches monetary accounting; reservations are only read.

The migration is additive: it never alters 001 objects and is applied explicitly after the
base ledger exists. Its identity is pinned by a digest stored as a table comment, because the
base `schema_version` row is intentionally a single immutable version-1 record.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from typing import Any

from psycopg import sql
from psycopg.types.json import Jsonb

from conscience_foundry.contracts.common import ContractError, Digest, Id, Instant
from conscience_foundry.ledger.db import Ledger, LedgerTxn

MIGRATION_NAME = "002_call_allowance.sql"
SCOPES = "call_allowance_scopes"
EVENTS = "call_allowance_events"
SUBMISSION_KINDS = ("request", "repair", "transport")
# Attempt states in which a billable submission may still be reserved.
ACTIVE_ATTEMPT_STATES = frozenset({"reserved", "dispatching", "running"})
UNRESOLVED_ATTEMPT_STATES = frozenset({"unknown_outcome", "cancel_requested"})


def migration_text() -> str:
    return files("conscience_foundry.ledger").joinpath("migrations/" + MIGRATION_NAME).read_text(
        encoding="utf-8"
    )


def migration_digest() -> str:
    return hashlib.sha256(migration_text().encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ScopeRow:
    limits: dict[str, Any]
    requests: int
    repairs: int
    transports: int
    transitions: int
    input_tokens: int
    output_tokens: int
    peak_context: int
    retries_consumed: int
    version: int
    exhausted: bool


@dataclass(frozen=True)
class EventRow:
    event_id: Id
    call_id: Id
    run_id: Id
    attempt_id: Id
    reservation_id: Id
    request_digest: Digest
    kind: str
    outcome: str
    external_request_id: str | None
    reserved_input_tokens: int
    reserved_output_tokens: int
    context_scalars: int
    event_digest: Digest
    sequence: int


def _table(tx: LedgerTxn, name: str) -> sql.Identifier:
    if not tx._active or name not in {SCOPES, EVENTS}:
        raise ContractError("invalid_schema")
    return sql.Identifier(tx.schema, name)


def _installed_comment(tx: LedgerTxn) -> str | None:
    """None when absent; the pinned digest comment when present; partial installs are unsafe."""
    rows = tx.connection.execute(
        "SELECT c.relname, pg_catalog.obj_description(c.oid,'pg_class') "
        "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=%s AND c.relname IN (%s,%s) AND c.relkind='r'",
        (tx.schema, SCOPES, EVENTS),
    ).fetchall()
    if not rows:
        return None
    names = {row[0]: row[1] for row in rows}
    if set(names) != {SCOPES, EVENTS}:
        raise ContractError("schema_incompatible")
    return str(names[SCOPES]) if names[SCOPES] is not None else ""


def install_allowance_schema(ledger: Ledger) -> None:
    """Apply 002 once, additively, to an already migrated ledger namespace; idempotent."""
    text = migration_text()
    digest = migration_digest()
    with ledger.transaction() as tx:
        tx.connection.execute(
            "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(%s,0))",
            ("conscience-foundry:migrate-allowance:" + tx.schema,),
        )
        present = _installed_comment(tx)
        if present is not None:
            if present != digest:
                raise ContractError("schema_incompatible")
            return
        tx.connection.execute(sql.SQL(text).format(schema=sql.Identifier(tx.schema)))
        tx.connection.execute(
            sql.SQL("COMMENT ON TABLE {} IS {}").format(_table(tx, SCOPES), sql.Literal(digest))
        )
        # Effective ACLs include inherited defaults; refuse exposure rather than alter them.
        shared = tx.connection.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace, "
            "LATERAL pg_catalog.aclexplode(COALESCE(c.relacl, "
            "pg_catalog.acldefault('r',c.relowner))) a "
            "WHERE n.nspname=%s AND c.relname IN (%s,%s) AND a.grantee<>c.relowner)",
            (tx.schema, SCOPES, EVENTS),
        ).fetchone()
        if shared is None or shared[0]:
            raise ContractError("forbidden")


def require_installed(tx: LedgerTxn) -> None:
    if _installed_comment(tx) != migration_digest():
        raise ContractError("schema_incompatible")


def load_scope(tx: LedgerTxn, project: Id, operation_key: Digest) -> ScopeRow | None:
    row = tx.connection.execute(
        sql.SQL(
            "SELECT limits,requests,repairs,transports,transitions,input_tokens,output_tokens,"
            "peak_context,retries_consumed,version,exhausted FROM {} "
            "WHERE project_id=%s AND operation_key=%s"
        ).format(_table(tx, SCOPES)),
        (project, operation_key),
    ).fetchone()
    if row is None:
        return None
    return ScopeRow(
        dict(row[0]),
        int(row[1]),
        int(row[2]),
        int(row[3]),
        int(row[4]),
        int(row[5]),
        int(row[6]),
        int(row[7]),
        int(row[8]),
        int(row[9]),
        bool(row[10]),
    )


def insert_scope(tx: LedgerTxn, project: Id, operation_key: Digest, limits: dict[str, Any]) -> None:
    tx.connection.execute(
        sql.SQL("INSERT INTO {} (project_id,operation_key,limits) VALUES (%s,%s,%s)").format(
            _table(tx, SCOPES)
        ),
        (project, operation_key, Jsonb(limits)),
    )


_EVENT_COLUMNS = (
    "event_id::text,call_id::text,run_id::text,attempt_id::text,reservation_id::text,"
    "request_digest,kind,outcome,external_request_id,reserved_input_tokens,"
    "reserved_output_tokens,context_scalars,event_digest,sequence"
)


def _event(row: tuple[Any, ...]) -> EventRow:
    return EventRow(
        row[0],
        row[1],
        row[2],
        row[3],
        row[4],
        row[5],
        row[6],
        row[7],
        row[8],
        int(row[9]),
        int(row[10]),
        int(row[11]),
        row[12],
        int(row[13]),
    )


def load_event(tx: LedgerTxn, project: Id, event_id: Id) -> EventRow | None:
    row = tx.connection.execute(
        sql.SQL("SELECT " + _EVENT_COLUMNS + " FROM {} WHERE project_id=%s AND event_id=%s").format(
            _table(tx, EVENTS)
        ),
        (project, event_id),
    ).fetchone()
    return _event(row) if row is not None else None


def load_events(tx: LedgerTxn, project: Id, operation_key: Digest) -> list[EventRow]:
    rows = tx.connection.execute(
        sql.SQL(
            "SELECT " + _EVENT_COLUMNS + " FROM {} WHERE project_id=%s AND operation_key=%s "
            "ORDER BY sequence"
        ).format(_table(tx, EVENTS)),
        (project, operation_key),
    ).fetchall()
    return [_event(row) for row in rows]


def call_submitted(tx: LedgerTxn, project: Id, call_id: Id) -> bool:
    """True when this local call identity is already a submission or transition anywhere."""
    row = tx.connection.execute(
        sql.SQL(
            "SELECT 1 FROM {} WHERE project_id=%s AND call_id=%s AND kind<>'outcome'"
        ).format(_table(tx, EVENTS)),
        (project, call_id),
    ).fetchone()
    return row is not None


def bind_scope(
    tx: LedgerTxn,
    project: Id,
    run: Id,
    operation_key: Digest,
    attempt: Id,
    reservation: Id,
) -> str:
    """Return the existing admitted attempt's state, or fail closed.

    The attempt, its D05 attempt-scope reservation, the run and the operation must already exist
    and agree. Nothing is created here, so a caller cannot invent allowance scope.
    """
    row = tx.connection.execute(
        sql.SQL(
            "SELECT a.state FROM {} a JOIN {} r ON "
            "(a.project_id,a.run_id,a.reservation_id)=(r.project_id,r.run_id,r.reservation_id) "
            "WHERE a.project_id=%s AND a.attempt_id=%s AND a.run_id=%s AND a.operation_key=%s "
            "AND a.reservation_id=%s AND r.operation_key=%s AND r.scope='attempt'"
        ).format(tx.table("attempts"), tx.table("reservations")),
        (project, attempt, run, operation_key, reservation, operation_key),
    ).fetchone()
    if row is None:
        raise ContractError("forbidden")
    return str(row[0])


def run_frozen(tx: LedgerTxn, project: Id, run: Id) -> bool:
    row = tx.connection.execute(
        sql.SQL("SELECT frozen FROM {} WHERE project_id=%s AND run_id=%s").format(
            tx.table("runs")
        ),
        (project, run),
    ).fetchone()
    if row is None:
        raise ContractError("forbidden")
    return bool(row[0])


def manual_retry_decisions(tx: LedgerTxn, project: Id, operation_key: Digest) -> int:
    """Count D05 manual-retry decisions that still authorize the current unresolved episode.

    A decision counts only when it was decided strictly after the latest event that left a call
    unresolved (a pending submission or an unknown outcome with no later settlement), and each
    submission recorded after that event spends one. A decision recorded earlier, or one whose
    episode was reconciled, authorizes nothing for a later unknown call. Read only.
    """
    events = _table(tx, EVENTS)
    submissions = list(SUBMISSION_KINDS)
    row = tx.connection.execute(
        sql.SQL(
            "SELECT e.sequence, e.recorded_at FROM {ev} e WHERE e.project_id=%s "
            "AND e.operation_key=%s AND NOT EXISTS (SELECT 1 FROM {ev} k WHERE "
            "k.project_id=e.project_id AND k.operation_key=e.operation_key "
            "AND k.call_id=e.call_id AND k.kind='outcome' "
            "AND (e.kind <> 'outcome' OR k.outcome='known')) "
            "AND ((e.kind='outcome' AND e.outcome='unknown') OR e.kind = ANY(%s)) "
            "ORDER BY e.sequence DESC LIMIT 1"
        ).format(ev=events),
        (project, operation_key, submissions),
    ).fetchone()
    if row is None:
        return 0
    marker, since = row
    decisions = tx.connection.execute(
        sql.SQL(
            "SELECT count(*) FROM {} WHERE project_id=%s AND operation_key=%s "
            "AND action='manual_retry' AND decided_at > %s"
        ).format(tx.table("control_decisions")),
        (project, operation_key, since),
    ).fetchone()
    spent = tx.connection.execute(
        sql.SQL(
            "SELECT count(*) FROM {} WHERE project_id=%s AND operation_key=%s "
            "AND kind = ANY(%s) AND sequence > %s"
        ).format(events),
        (project, operation_key, submissions, marker),
    ).fetchone()
    assert decisions is not None and spent is not None
    return max(int(decisions[0]) - int(spent[0]), 0)


def append_event(
    tx: LedgerTxn,
    project: Id,
    operation_key: Digest,
    event: EventRow,
    *,
    recorded_at: Instant,
    scope: ScopeRow,
) -> None:
    """Insert one immutable event and CAS-advance to `scope` (the new state) under held locks."""
    if event.sequence != scope.version:
        raise ContractError("determinism_conflict")
    tx.connection.execute(
        sql.SQL(
            "INSERT INTO {} (project_id,event_id,call_id,operation_key,run_id,attempt_id,"
            "reservation_id,request_digest,kind,outcome,external_request_id,"
            "reserved_input_tokens,reserved_output_tokens,context_scalars,event_digest,"
            "sequence,recorded_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        ).format(_table(tx, EVENTS)),
        (
            project,
            event.event_id,
            event.call_id,
            operation_key,
            event.run_id,
            event.attempt_id,
            event.reservation_id,
            event.request_digest,
            event.kind,
            event.outcome,
            event.external_request_id,
            event.reserved_input_tokens,
            event.reserved_output_tokens,
            event.context_scalars,
            event.event_digest,
            event.sequence,
            datetime.fromisoformat(recorded_at),
        ),
    )
    updated = tx.connection.execute(
        sql.SQL(
            "UPDATE {} SET requests=%s,repairs=%s,transports=%s,transitions=%s,input_tokens=%s,"
            "output_tokens=%s,peak_context=%s,retries_consumed=%s,version=%s,exhausted=%s "
            "WHERE project_id=%s AND operation_key=%s AND version=%s"
        ).format(_table(tx, SCOPES)),
        (
            scope.requests,
            scope.repairs,
            scope.transports,
            scope.transitions,
            scope.input_tokens,
            scope.output_tokens,
            scope.peak_context,
            scope.retries_consumed,
            event.sequence,
            scope.exhausted,
            project,
            operation_key,
            event.sequence - 1,
        ),
    )
    if updated.rowcount != 1:
        raise ContractError("determinism_conflict")
