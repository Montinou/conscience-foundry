"""Restore barrier: recover a backup into an empty project and keep it fenced.

A restored ledger is a past view. Work submitted after the recovery point is not in it, and an
attempt that was unresolved then may have finished, been billed or still be running. So the same
transaction that brings the ledger back also writes a durable project pause: dispatch stays fenced
until an operator reconciles and resumes through the normal pause control. An allow recorded in the
snapshot never re-enables a read either: every release's local verification is cleared, and the
next read needs a fresh import under the policy as it is now. Nothing here deletes anything.
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass
from uuid import UUID, uuid5

import psycopg
from psycopg import sql

from conscience_foundry.contracts.common import ContractError, Reason, Ref
from conscience_foundry.ledger.db import Ledger, LedgerTxn
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.recovery.backup import (
    OPTIONAL_TABLES,
    SNAPSHOT_SCHEMA,
    SNAPSHOT_TABLES,
    RecoveryManifest,
    binding_digest,
    copy_object,
    database_instant,
    optional_tables,
    pending_attempts,
    require_recovery_scopes,
)
from conscience_foundry.storage.local import ObjectStore

BARRIER_REASON = "restore_barrier"
BARRIER_NAMESPACE = UUID("6f1c3a0e-5d0b-4c7e-9a59-2f3b8c1d7e44")
# Columns that point at a row inserted later in the same restore; set once everything exists.
DEFERRED_COLUMNS = {"runs": "current_authorization_id", "operations": "latest_event_id"}
DENIED = frozenset({"forbidden", "permission_unknown"})
ABSENT = frozenset({"artifact_missing", "hash_mismatch", "unsafe_path", "limit_exceeded"})


@dataclass(frozen=True)
class RecoveryReport:
    verified_refs: tuple[Ref, ...]
    missing_refs: tuple[Ref, ...]
    dispatch_blocked: bool
    access_blocked: bool
    reasons: tuple[Reason, ...]


def barrier_decision_id(snapshot_digest: str) -> str:
    """One deterministic barrier per recovered snapshot, so a repeated restore is recognised."""
    return str(uuid5(BARRIER_NAMESPACE, snapshot_digest))


def _read_snapshot(
    manifest: RecoveryManifest,
    context: AccessContext,
    source: ObjectStore,
) -> bytes:
    snapshot_ref = manifest.ledger_snapshot_ref
    # The reader checks size and digest; a missing or altered snapshot is no recovery at all.
    return source.read_verified(snapshot_ref, context, snapshot_ref.size_bytes).data


def _split_tables(tx: LedgerTxn, document: bytes, manifest: RecoveryManifest) -> dict[str, str]:
    """Let PostgreSQL split the JSON so numerics and timestamps are never rounded in Python."""
    text = document.decode("utf-8")
    header = tx.connection.execute(
        "SELECT d->>'schemaVersion', d->>'projectId', d->>'recoveryPoint' "
        "FROM (SELECT %s::jsonb AS d) x",
        (text,),
    ).fetchone()
    if header != (SNAPSHOT_SCHEMA, manifest.project_id, manifest.recovery_point):
        raise ContractError("hash_mismatch")
    rows = tx.connection.execute(
        "SELECT key, value::text FROM jsonb_each((%s::jsonb)->'tables')", (text,)
    ).fetchall()
    tables = {key: value for key, value in rows}
    expected = set(SNAPSHOT_TABLES)
    if set(tables) not in (expected, expected | set(OPTIONAL_TABLES)):
        raise ContractError("invalid_schema")
    return tables


def _insert(tx: LedgerTxn, name: str, rows: str, project_id: str) -> None:
    table = sql.Identifier(tx.schema, name)
    foreign = tx.connection.execute(
        "SELECT count(*) FROM jsonb_array_elements(%s::jsonb) e "
        "WHERE e->>'project_id' IS DISTINCT FROM %s",
        (rows, project_id),
    ).fetchone()
    if foreign is None or foreign[0]:
        raise ContractError("hash_mismatch")
    deferred = DEFERRED_COLUMNS.get(name)
    source = (
        sql.SQL(
            "(SELECT coalesce(jsonb_agg(e - %s::text), '[]'::jsonb) "
            "FROM jsonb_array_elements(%s::jsonb) e)"
        )
        if deferred
        else sql.SQL("%s::jsonb")
    )
    params: tuple[str, ...] = (deferred, rows) if deferred else (rows,)
    tx.connection.execute(
        sql.SQL("INSERT INTO {t} SELECT s.* FROM jsonb_populate_recordset(NULL::{t}, {src}) s")
        .format(t=table, src=source),
        params,
    )


def _link_deferred(tx: LedgerTxn, tables: dict[str, str]) -> None:
    tx.connection.execute(
        sql.SQL(
            "UPDATE {t} r SET current_authorization_id=x.current_authorization_id "
            "FROM jsonb_to_recordset(%s::jsonb) AS x(project_id uuid, run_id uuid, "
            "current_authorization_id uuid) WHERE (r.project_id,r.run_id)=(x.project_id,x.run_id) "
            "AND x.current_authorization_id IS NOT NULL"
        ).format(t=sql.Identifier(tx.schema, "runs")),
        (tables["runs"],),
    )
    tx.connection.execute(
        sql.SQL(
            "UPDATE {t} o SET latest_event_id=x.latest_event_id "
            "FROM jsonb_to_recordset(%s::jsonb) AS x(project_id uuid, operation_key text, "
            "latest_event_id uuid) WHERE (o.project_id,o.operation_key)="
            "(x.project_id,x.operation_key) AND x.latest_event_id IS NOT NULL"
        ).format(t=sql.Identifier(tx.schema, "operations")),
        (tables["operations"],),
    )


def _restore_ledger(
    manifest: RecoveryManifest, context: AccessContext, ledger: Ledger, document: bytes
) -> int:
    """One transaction: rows, the dispatch barrier and cleared verification, or nothing.

    Returns how many releases the snapshot recorded as locally verified; none stay verified.
    """
    project = manifest.project_id
    decision = barrier_decision_id(manifest.snapshot_digest)
    try:
        with ledger.transaction() as tx:
            tables = _split_tables(tx, document, manifest)
            withheld = tx.connection.execute(
                "SELECT count(*) FROM jsonb_array_elements(%s::jsonb) e "
                "WHERE (e->>'local_verified')::boolean",
                (tables["releases"],),
            ).fetchone()
            assert withheld is not None
            present = tx.connection.execute(
                sql.SQL("SELECT 1 FROM {} WHERE project_id=%s").format(tx.table("projects")),
                (project,),
            ).fetchone()
            if present is not None:
                # A target that already holds the project is only acceptable when it is this very
                # restore, repeated after the object copy failed part way.
                tx.lock(project)
                again = tx.connection.execute(
                    sql.SQL("SELECT 1 FROM {} WHERE project_id=%s AND decision_id=%s").format(
                        tx.table("pause_history")
                    ),
                    (project, decision),
                ).fetchone()
                if again is None:
                    raise ContractError("determinism_conflict")
                return int(withheld[0])
            installed = optional_tables(tx)
            if ("call_allowance_scopes" in tables) != bool(installed):
                raise ContractError("schema_incompatible")
            for name in (*SNAPSHOT_TABLES, *installed):
                _insert(tx, name, tables[name], project)
            _link_deferred(tx, tables)
            if pending_attempts(tx, project) != manifest.pending_attempt_ids:
                raise ContractError("hash_mismatch")
            tx.lock(project)
            tx.connection.execute(
                sql.SQL(
                    "UPDATE {} SET local_verified=false, import_receipt_ref=NULL "
                    "WHERE project_id=%s AND local_verified"
                ).format(tx.table("releases")),
                (project,),
            )
            old = tx.get_pause("project", project, None)
            tx.record_pause(
                "project",
                project,
                None,
                True,
                expected_version=old.version,
                actor_id=context.actor_id,
                reason=BARRIER_REASON,
                decided_at=database_instant(tx),
                decision_id=decision,
            )
            return int(withheld[0])
    except psycopg.errors.IntegrityError:
        raise ContractError("determinism_conflict") from None
    except psycopg.errors.DataError:
        raise ContractError("invalid_schema") from None


def restore(
    manifest: RecoveryManifest,
    context: AccessContext,
    ledger: Ledger,
    source: ObjectStore,
    target: ObjectStore,
) -> RecoveryReport:
    """Recover a backup into an empty project of `ledger` and `target`; always leaves it fenced.

    Objects are copied first (immutable and idempotent); the ledger and its barrier land together
    last. A reference that cannot be copied is reported, never skipped silently.
    """
    require_recovery_scopes(context)
    if type(manifest) is not RecoveryManifest or manifest.project_id != context.project_id:
        raise ContractError("forbidden")
    if source is target:
        raise ContractError("forbidden")
    if manifest.snapshot_digest != binding_digest(
        manifest.project_id,
        manifest.ledger_snapshot_ref,
        manifest.recovery_point,
        manifest.content_refs,
        manifest.audit_refs,
        manifest.pending_attempt_ids,
        manifest.excluded_release_digests,
    ):
        raise ContractError("hash_mismatch")
    document = _read_snapshot(manifest, context, source)
    if hashlib.sha256(document).hexdigest() != manifest.ledger_snapshot_ref.digest:
        raise ContractError("hash_mismatch")
    target.put_verified(io.BytesIO(document), manifest.ledger_snapshot_ref, context)
    verified: list[Ref] = []
    missing: list[Ref] = []
    reasons: dict[tuple[str, str], Reason] = {}
    denied = False
    for ref in (*manifest.content_refs, *manifest.audit_refs):
        try:
            copy_object(ref, context, source, target)
        except ContractError as error:
            if error.code in DENIED:
                denied = True
                reasons.setdefault(
                    ("denied", error.code),
                    Reason(code=error.code, message="current authority withheld restored object"),  # type: ignore[arg-type]
                )
            elif error.code in ABSENT:
                reasons.setdefault(
                    ("absent", error.code),
                    Reason(code=error.code, message="backup object missing or unverifiable"),  # type: ignore[arg-type]
                )
            else:
                raise
            missing.append(ref)
        else:
            verified.append(ref)
    cleared = _restore_ledger(manifest, context, ledger, document)
    with ledger.transaction() as tx:
        tx.lock(manifest.project_id)
        blocked = tx.get_pause("project", manifest.project_id, None).paused
    if manifest.pending_attempt_ids:
        reasons[("pending", "dispatch_unknown")] = Reason(
            code="dispatch_unknown",
            message="attempts unresolved at the recovery point need reconciliation",
        )
    if cleared:
        reasons[("cleared", "forbidden")] = Reason(
            code="forbidden",
            message="release verification cleared; a fresh import under current policy is needed",
        )
    return RecoveryReport(
        verified_refs=tuple(verified),
        missing_refs=tuple(missing),
        dispatch_blocked=blocked,
        access_blocked=denied or bool(cleared),
        reasons=tuple(reasons[key] for key in sorted(reasons)),
    )

