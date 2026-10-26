"""Ledger rows for release verification, publication chains and the active pointer.

These primitives persist trusted control decisions; they never authenticate
actors, resolve current policy or prove that the referenced bytes are durable.
Callers hold the project lock and store verified bytes before recording a ref.
"""

from __future__ import annotations

from dataclasses import dataclass

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

from conscience_foundry.contracts.common import ContractError, Id, Ref
from conscience_foundry.contracts.release import ActivationRecord, PublicationRecord
from conscience_foundry.ledger.db import LedgerTxn

# Registered C07 order; a successor is always the next entry, never a skip.
STAGES = ("candidate", "validated", "transferred", "local_verified", "published", "retired")
POINTER_ID = "active"


def _json(ref: Ref) -> Jsonb:
    return Jsonb(ref.model_dump(by_alias=True, exclude_none=True))


@dataclass(frozen=True)
class ReleaseRow:
    release_ref: Ref
    selection_digest: str
    local_verified: bool
    import_receipt_ref: Ref | None


def load_release(tx: LedgerTxn, project_id: Id, release_digest: str) -> ReleaseRow | None:
    found = tx.connection.execute(
        sql.SQL(
            "SELECT release_ref,selection_digest,local_verified,import_receipt_ref "
            "FROM {} WHERE project_id=%s AND release_digest=%s"
        ).format(tx.table("releases")),
        (project_id, release_digest),
    ).fetchone()
    if found is None:
        return None
    receipt = Ref.model_validate(found[3]) if found[3] is not None else None
    return ReleaseRow(Ref.model_validate(found[0]), found[1], found[2], receipt)


def mark_local_verified(tx: LedgerTxn, project_id: Id, release_digest: str, receipt: Ref) -> None:
    """First verified import only; a stored receipt is never replaced or reverted."""
    changed = tx.connection.execute(
        sql.SQL(
            "UPDATE {} SET import_receipt_ref=%s,local_verified=true WHERE "
            "project_id=%s AND release_digest=%s AND import_receipt_ref IS NULL "
            "AND NOT local_verified"
        ).format(tx.table("releases")),
        (_json(receipt), project_id, release_digest),
    ).rowcount
    if changed != 1:
        raise ContractError("determinism_conflict")


@dataclass(frozen=True)
class PublicationEvent:
    event_id: str
    release_digest: str
    stage: str
    record_ref: Ref


def _event(row: tuple[object, ...]) -> PublicationEvent:
    return PublicationEvent(str(row[0]), str(row[1]), str(row[2]), Ref.model_validate(row[3]))


_EVENT_COLUMNS = "event_id::text,release_digest,stage,publication_ref"


def publication_event(tx: LedgerTxn, project_id: Id, event_id: str) -> PublicationEvent | None:
    found = tx.connection.execute(
        sql.SQL("SELECT " + _EVENT_COLUMNS + " FROM {} WHERE project_id=%s AND event_id=%s").format(
            tx.table("publications")
        ),
        (project_id, event_id),
    ).fetchone()
    return None if found is None else _event(found)


def publication_tail(tx: LedgerTxn, project_id: Id, release_digest: str) -> PublicationEvent | None:
    """The unique event without a successor; uniqueness is enforced by the schema."""
    found = tx.connection.execute(
        sql.SQL(
            "SELECT " + _EVENT_COLUMNS + " FROM {0} p WHERE p.project_id=%s AND "
            "p.release_digest=%s AND NOT EXISTS (SELECT 1 FROM {0} n WHERE "
            "n.project_id=p.project_id AND n.release_digest=p.release_digest "
            "AND n.previous_event_id=p.event_id)"
        ).format(tx.table("publications")),
        (project_id, release_digest),
    ).fetchall()
    if len(found) > 1:
        raise ContractError("determinism_conflict")
    return _event(found[0]) if found else None


def insert_publication(tx: LedgerTxn, record: PublicationRecord, ref: Ref) -> None:
    """Append one verified event; unique/foreign keys backstop the caller's CAS."""
    try:
        with tx.connection.transaction():
            tx.connection.execute(
                sql.SQL(
                    "INSERT INTO {} (project_id,event_id,release_digest,previous_event_id,"
                    "stage,publication_ref,actor_id,recorded_at) VALUES "
                    "(%s,%s,%s,%s,%s,%s,%s,%s)"
                ).format(tx.table("publications")),
                (
                    record.project_id,
                    record.event_id,
                    record.release_digest,
                    record.previous_event_id,
                    record.stage,
                    _json(ref),
                    record.actor_id,
                    record.recorded_at,
                ),
            )
    except psycopg.errors.IntegrityError:
        raise ContractError("activation_conflict") from None


@dataclass(frozen=True)
class ActivePointer:
    release_digest: str
    version: int


def active_pointer(tx: LedgerTxn, project_id: Id) -> ActivePointer | None:
    found = tx.connection.execute(
        sql.SQL(
            "SELECT release_digest,version FROM {} WHERE project_id=%s AND pointer_id=%s"
        ).format(tx.table("active_releases")),
        (project_id, POINTER_ID),
    ).fetchone()
    return None if found is None else ActivePointer(str(found[0]), int(found[1]))


def move_pointer(
    tx: LedgerTxn,
    record: ActivationRecord,
    ref: Ref,
    current: ActivePointer | None,
) -> None:
    """Compare-and-swap against `current`, appending every activation to the history."""
    version = 1 if current is None else current.version + 1
    try:
        with tx.connection.transaction():
            if current is None:
                tx.connection.execute(
                    sql.SQL(
                        "INSERT INTO {} (project_id,pointer_id,release_digest,version) "
                        "VALUES (%s,%s,%s,%s)"
                    ).format(tx.table("active_releases")),
                    (record.project_id, POINTER_ID, record.next_release_digest, version),
                )
            else:
                changed = tx.connection.execute(
                    sql.SQL(
                        "UPDATE {} SET release_digest=%s,version=%s WHERE project_id=%s "
                        "AND pointer_id=%s AND release_digest=%s AND version=%s"
                    ).format(tx.table("active_releases")),
                    (
                        record.next_release_digest,
                        version,
                        record.project_id,
                        POINTER_ID,
                        current.release_digest,
                        current.version,
                    ),
                ).rowcount
                if changed != 1:
                    raise ContractError("activation_conflict")
            tx.connection.execute(
                sql.SQL(
                    "INSERT INTO {} (project_id,pointer_id,version,"
                    "expected_previous_release_digest,release_digest,activation_ref,"
                    "actor_id,activated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)"
                ).format(tx.table("activation_history")),
                (
                    record.project_id,
                    POINTER_ID,
                    version,
                    record.expected_previous_release_digest,
                    record.next_release_digest,
                    _json(ref),
                    record.actor_id,
                    record.activated_at,
                ),
            )
    except psycopg.errors.IntegrityError:
        raise ContractError("activation_conflict") from None
