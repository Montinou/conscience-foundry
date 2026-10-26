"""Independent backup: one consistent ledger snapshot bound to selected content and audit metadata.

A backup copies bytes into a separate destination store and never deletes or edits anything. The
ledger snapshot is assembled while the project row is locked, which is the same first lock every
dispatch, reservation and settlement takes, so no writer can commit between the tables and the
recovery point is not a mixed snapshot. Immutable, content-addressed objects are copied after the
lock is released. The manifest binds the snapshot, the recovery point, the copied references and
the attempts that were still unresolved at that point into one digest.

Selected content is only the verified-release closure the importer recorded (registered content
edges); audit metadata is a closed list of ledger reference columns. Administrative links are never
followed, so excluded source bytes (admission snapshots, revisions of unselected sources) are not
read. Authority is checked per call: the exact context and its scopes, current source permission
for every selected release source, and `auditMetadataRead` for every source the ledger names.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Any, Self

from psycopg import sql
from pydantic import BeforeValidator, model_validator

from conscience_foundry.contracts.common import (
    ContractError,
    Digest,
    Id,
    Instant,
    Ref,
    WireModel,
)
from conscience_foundry.contracts.release import ImportReceipt
from conscience_foundry.execution.evidence import current_policy, identity, limits_for, read_model
from conscience_foundry.ledger.db import TABLES, Ledger, LedgerTxn
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.release.context import ReleaseContext, checked_context, require_audit
from conscience_foundry.release.importer import load_release, require_current
from conscience_foundry.storage.local import ObjectStore

SNAPSHOT_SCHEMA = "cfoundry.ledger-snapshot.v1"
SNAPSHOT_MEDIA_TYPE = "application/json"
REQUIRED_SCOPES = frozenset({"read", "auditMetadataRead"})
TERMINAL_STATES = ("succeeded", "failed", "cancelled")

# Parents before children. Two cycles exist and are resolved by the restore, not here: the
# current authorization of a run and the latest result of an operation are set after both exist.
SNAPSHOT_TABLES: tuple[str, ...] = (
    "projects",
    "batches",
    "admission_reports",
    "assets",
    "admission_entries",
    "runs",
    "authorizations",
    "operations",
    "plans",
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
    "admission_withdrawals",
    "releases",
    "publications",
    "active_releases",
    "activation_history",
    "release_incidents",
    "pause_state",
    "pause_history",
)
assert set(SNAPSHOT_TABLES) == TABLES - {"schema_version"}, "snapshot misses a ledger table"
# Additive tables (call allowances). They hold spend-control counters, so a snapshot carries them
# whenever the source ledger has them installed.
OPTIONAL_TABLES: tuple[str, ...] = ("call_allowance_scopes", "call_allowance_events")

# Audit metadata only: governance records, evidence and result manifests (which list outputs but
# are not followed). Revisions and admission snapshots are source-derived content and stay out
# unless a verified release selects them.
AUDIT_COLUMNS: tuple[tuple[str, str], ...] = (
    ("batches", "manifest_ref"),
    ("admission_reports", "report_ref"),
    ("admission_reports", "policy_ref"),
    ("authorizations", "authorization_ref"),
    ("plans", "plan_ref"),
    ("reservations", "evidence_ref"),
    ("attempts", "attempt_ref"),
    ("attempts", "result_ref"),
    ("dispatch_claims", "reserved_attempt_ref"),
    ("dispatch_claims", "dispatched_attempt_ref"),
    ("operation_results", "record_ref"),
    ("operation_results", "evidence_ref"),
    ("operation_results", "result_ref"),
    ("operation_results", "selected_result_ref"),
    ("integrity_holds", "evidence_ref"),
    ("attempt_observations", "evidence_ref"),
    ("attempt_observations", "attempt_ref"),
    ("control_decisions", "evidence_ref"),
    ("reviews", "review_ref"),
    ("admission_withdrawals", "evidence_ref"),
    ("releases", "release_ref"),
    ("releases", "import_receipt_ref"),
    ("publications", "publication_ref"),
    ("activation_history", "activation_ref"),
    ("release_incidents", "receipt_ref"),
)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class RecoveryManifest(WireModel):
    project_id: Id
    ledger_snapshot_ref: Ref
    recovery_point: Instant
    content_refs: Annotated[tuple[Ref, ...], BeforeValidator(_tuple)]
    audit_refs: Annotated[tuple[Ref, ...], BeforeValidator(_tuple)]
    pending_attempt_ids: Annotated[tuple[Id, ...], BeforeValidator(_tuple)]
    snapshot_digest: Digest

    @model_validator(mode="after")
    def internally_consistent(self) -> Self:
        refs = (self.ledger_snapshot_ref, *self.content_refs, *self.audit_refs)
        if any(ref.project_id != self.project_id for ref in refs):
            raise ValueError("reference outside the project")
        if self.ledger_snapshot_ref.artifact_schema != SNAPSHOT_SCHEMA:
            raise ValueError("snapshot reference has the wrong schema")
        if len({identity(ref) for ref in refs}) != len(refs):
            raise ValueError("duplicate reference")
        if list(self.pending_attempt_ids) != sorted(set(self.pending_attempt_ids)):
            raise ValueError("pending attempts must be sorted and unique")
        return self


def manifest_wire(manifest: RecoveryManifest) -> bytes:
    """The exact bytes an operator stores and the restore decodes."""
    document = manifest.model_dump(mode="json", by_alias=True, exclude_none=True)
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def binding_digest(
    project_id: Id,
    snapshot_ref: Ref,
    recovery_point: Instant,
    content_refs: Sequence[Ref],
    audit_refs: Sequence[Ref],
    pending_attempt_ids: Sequence[Id],
) -> Digest:
    """Digest over identities only: locations are hints and never part of what was captured."""

    def ident(ref: Ref) -> list[object]:
        return list(identity(ref))

    document = {
        "schema": "cfoundry.recovery-binding.v1",
        "projectId": project_id,
        "snapshot": ident(snapshot_ref),
        "recoveryPoint": recovery_point,
        "content": [ident(ref) for ref in content_refs],
        "audit": [ident(ref) for ref in audit_refs],
        "pending": list(pending_attempt_ids),
    }
    raw = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def require_recovery_scopes(context: AccessContext) -> None:
    if type(context) is not AccessContext or not REQUIRED_SCOPES <= context.scopes:
        raise ContractError("forbidden")


def database_instant(tx: LedgerTxn) -> Instant:
    """The database clock, so a recovery point agrees with the snapshot it labels."""
    row = tx.connection.execute(
        "SELECT pg_catalog.to_char(pg_catalog.clock_timestamp() AT TIME ZONE 'UTC', "
        "'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')"
    ).fetchone()
    if row is None:
        raise ContractError("unavailable")
    value: Instant = row[0]
    return value


def optional_tables(tx: LedgerTxn) -> tuple[str, ...]:
    """The additive tables actually installed; a half-installed pair is unsafe to snapshot."""
    rows = tx.connection.execute(
        "SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
        "ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relkind='r' AND c.relname=ANY(%s)",
        (tx.schema, list(OPTIONAL_TABLES)),
    ).fetchall()
    present = {row[0] for row in rows}
    if not present:
        return ()
    if present != set(OPTIONAL_TABLES):
        raise ContractError("schema_incompatible")
    return OPTIONAL_TABLES


def pending_attempts(tx: LedgerTxn, project_id: Id) -> tuple[Id, ...]:
    """Every attempt that may still be executing remotely or awaiting reconciliation."""
    rows = tx.connection.execute(
        sql.SQL("SELECT attempt_id::text FROM {} WHERE project_id=%s AND NOT state=ANY(%s)").format(
            tx.table("attempts")
        ),
        (project_id, list(TERMINAL_STATES)),
    ).fetchall()
    return tuple(sorted(row[0] for row in rows))


def _snapshot_document(tx: LedgerTxn, project_id: Id, recovery_point: Instant) -> bytes:
    names = (*SNAPSHOT_TABLES, *optional_tables(tx))
    pieces: list[sql.Composable] = []
    params: list[Any] = [SNAPSHOT_SCHEMA, project_id, recovery_point]
    for name in names:
        table = sql.Identifier(tx.schema, name)
        pieces.append(
            sql.SQL(
                "{}::text, (SELECT coalesce(jsonb_agg(pg_catalog.to_jsonb(t) "
                "ORDER BY pg_catalog.to_jsonb(t)::text), '[]'::jsonb) FROM {} t "
                "WHERE t.project_id=%s)"
            ).format(sql.Literal(name), table)
        )
        params.append(project_id)
    query = sql.SQL(
        "SELECT (jsonb_build_object('schemaVersion', %s::text, 'projectId', %s::text, "
        "'recoveryPoint', %s::text) || jsonb_build_object('tables', "
        "jsonb_build_object({})))::text"
    ).format(sql.SQL(", ").join(pieces))
    row = tx.connection.execute(query, params).fetchone()
    if row is None or type(row[0]) is not str:
        raise ContractError("unavailable")
    return row[0].encode("utf-8")


def _source_ids(tx: LedgerTxn, project_id: Id) -> tuple[str, ...]:
    rows = tx.connection.execute(
        sql.SQL("SELECT DISTINCT source_id::text FROM {} WHERE project_id=%s ORDER BY 1").format(
            tx.table("assets")
        ),
        (project_id,),
    ).fetchall()
    return tuple(row[0] for row in rows)


def _verified_closure(
    tx: LedgerTxn, project_id: Id, release: ReleaseContext
) -> dict[tuple[object, ...], Ref]:
    """Release manifests and the closure each verified import recorded; nothing else is content."""
    rows = tx.connection.execute(
        sql.SQL(
            "SELECT release_digest FROM {} WHERE project_id=%s AND local_verified "
            "AND import_receipt_ref IS NOT NULL ORDER BY release_digest"
        ).format(tx.table("releases")),
        (project_id,),
    ).fetchall()
    content: dict[tuple[object, ...], Ref] = {}
    for (digest,) in rows:
        loaded = load_release(tx, digest, release)
        # Current authority overrides the historical import: a revoked, held or withdrawn source
        # stops its release from being copied, and the backup fails closed.
        require_current(tx, loaded.model.source_entries, release, ("read",))
        if loaded.row.import_receipt_ref is None:
            raise ContractError("hash_mismatch")
        _, receipt = read_model(loaded.row.import_receipt_ref, ImportReceipt, release)
        if receipt.status != "local_verified" or identity(receipt.release_ref) != identity(
            loaded.row.release_ref
        ):
            raise ContractError("hash_mismatch")
        for ref in (loaded.row.release_ref, *receipt.verified_artifacts):
            content.setdefault(identity(ref), ref)
    return content


def _audit_refs(
    tx: LedgerTxn, project_id: Id, exclude: dict[tuple[object, ...], Ref]
) -> dict[tuple[object, ...], Ref]:
    audit: dict[tuple[object, ...], Ref] = {}
    for table, column in AUDIT_COLUMNS:
        rows = tx.connection.execute(
            sql.SQL("SELECT DISTINCT {col} FROM {table} WHERE project_id=%s AND {col} IS NOT NULL")
            .format(col=sql.Identifier(column), table=tx.table(table)),
            (project_id,),
        ).fetchall()
        for (stored,) in rows:
            ref = Ref.model_validate(stored)
            if ref.project_id != project_id:
                raise ContractError("forbidden")
            key = identity(ref)
            if key not in exclude:
                audit.setdefault(key, ref)
    return audit


def _ordered(refs: dict[tuple[object, ...], Ref]) -> tuple[Ref, ...]:
    return tuple(ref for _, ref in sorted(refs.items(), key=lambda item: repr(item[0])))


def copy_object(ref: Ref, context: AccessContext, source: ObjectStore, target: ObjectStore) -> None:
    """Stream one object through a verified private snapshot; the target verifies again."""
    with source.open_verified(ref, context) as handle:
        target.put_verified(handle, ref, context)


def backup(
    context: AccessContext,
    ledger: Ledger,
    store: ObjectStore,
    destination: ObjectStore,
    *,
    release: ReleaseContext,
) -> RecoveryManifest:
    """Copy one consistent recovery point to `destination`; deletes nothing, fails closed.

    `release` supplies the trusted limits and current policy (the same dependency every release
    operation takes); `store` must be the store it was built with.
    """
    checked_context(context, store, release)
    require_recovery_scopes(context)
    if destination is store:
        raise ContractError("forbidden")
    project = context.project_id
    with ledger.transaction() as tx:
        # Fence: nothing that reserves, dispatches or settles can commit until this unwinds.
        tx.lock(project)
        recovery_point = database_instant(tx)
        policy = current_policy(release, project)
        require_audit(release, policy, _source_ids(tx, project))
        snapshot = _snapshot_document(tx, project, recovery_point)
        pending = pending_attempts(tx, project)
        content = _verified_closure(tx, project, release)
        audit = _audit_refs(tx, project, content)
    snapshot_ref = Ref(
        schema_version="kf.artifact-ref.v1",
        project_id=project,
        digest=hashlib.sha256(snapshot).hexdigest(),
        size_bytes=len(snapshot),
        media_type=SNAPSHOT_MEDIA_TYPE,
        artifact_schema=SNAPSHOT_SCHEMA,
        locations=(),
    )
    content_refs, audit_refs = _ordered(content), _ordered(audit)
    manifest = RecoveryManifest(
        project_id=project,
        ledger_snapshot_ref=snapshot_ref,
        recovery_point=recovery_point,
        content_refs=content_refs,
        audit_refs=audit_refs,
        pending_attempt_ids=pending,
        snapshot_digest=binding_digest(
            project, snapshot_ref, recovery_point, content_refs, audit_refs, pending
        ),
    )
    # The operator restores this manifest under the kf.library-release.v1 limits (no manifest
    # schema is registered), so a manifest those limits would refuse is refused here, before
    # anything is copied, instead of being discovered at restore time.
    restore_bound = limits_for(release, "kf.library-release.v1")
    RecoveryManifest.from_wire(manifest_wire(manifest), restore_bound)
    destination.put_verified(io.BytesIO(snapshot), snapshot_ref, context)
    for ref in (*content_refs, *audit_refs):
        copy_object(ref, context, store, destination)
    return manifest


def independent_media(source_root: Path, destination_root: Path) -> bool:
    """True only when the roots sit on different devices and neither contains the other.

    A second directory on the same disk is not an independent copy. This inspects the two
    filesystem roots only; it cannot prove the media are physically or administratively separate,
    so a live acceptance still needs the operator's own confirmation of the destination.
    """
    try:
        first, second = source_root.resolve(strict=True), destination_root.resolve(strict=True)
        if os.stat(first).st_dev == os.stat(second).st_dev:
            return False
    except OSError:
        return False
    return not (first.is_relative_to(second) or second.is_relative_to(first))
