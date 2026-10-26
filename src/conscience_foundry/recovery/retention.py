"""Retention report: cleanup eligibility only. It reads state and never deletes anything.

A staged result may be cleaned up only when every condition holds together: no attempt in the
project is unresolved, the result manifest and every output it lists are verified in the local
store, the same objects are verified in the independent backup when the policy requires one, and
the minimum staging age has passed. A backup copies a result manifest as audit metadata only, so an
output that no verified release selected is not in the backup and keeps its result ineligible.
Age alone never qualifies an object. Passing the funded horizon never qualifies it either: an
object that is not yet safe to clean past its horizon is reported as an unresolved storage-cost
liability and stays exactly where it is, because expiry is not permission to delete the only copy.

Eligibility is derived from ledger rows and from verified reads of the stores given; the reference
graph is the ledger's own attempt and result references.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from psycopg import sql

from conscience_foundry.contracts.common import ContractError, ContractLimits, Instant, Reason, Ref
from conscience_foundry.contracts.execution import ResultManifest
from conscience_foundry.contracts.release import RetentionPolicy
from conscience_foundry.execution.evidence import identity
from conscience_foundry.ledger.db import Ledger
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.recovery.backup import TERMINAL_STATES, require_recovery_scopes
from conscience_foundry.storage.local import ObjectStore

UNRECONCILED = Reason(
    code="dispatch_unknown", message="attempts in the project are not reconciled"
)
TOO_YOUNG = Reason(code="unavailable", message="minimum staging age not reached")
NO_LOCAL = Reason(code="artifact_missing", message="verified local copy is missing")
NO_BACKUP = Reason(code="artifact_missing", message="verified independent backup is missing")
NO_BACKUP_STORE = Reason(code="unavailable", message="no backup store was given to verify")
RESULT_UNREADABLE = Reason(
    code="invalid_schema", message="result manifest cannot be read within its bounds"
)
OUTPUT_NO_LOCAL = Reason(
    code="artifact_missing", message="a result output has no verified local copy"
)
OUTPUT_NO_BACKUP = Reason(
    code="artifact_missing", message="a result output has no verified independent backup"
)
ESCALATION_DUE = Reason(code="unavailable", message="operator action due before funded horizon")
HORIZON_PASSED = Reason(
    code="storage_full", message="unresolved storage liability beyond the funded horizon"
)
ABSENT = frozenset({"artifact_missing", "hash_mismatch"})


@dataclass(frozen=True)
class RetentionEntry:
    ref: Ref
    eligible: bool
    reasons: tuple[Reason, ...]


@dataclass(frozen=True)
class RetentionReport:
    entries: tuple[RetentionEntry, ...]
    checked_at: Instant


def _moment(value: Instant) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _verified(ref: Ref, context: AccessContext, store: ObjectStore) -> bool:
    try:
        with store.open_verified(ref, context):
            return True
    except ContractError as error:
        if error.code in ABSENT:
            return False
        raise


def _outputs(
    ref: Ref, context: AccessContext, store: ObjectStore, limits: ContractLimits
) -> tuple[Ref, ...] | None:
    """The outputs a verified local result manifest lists; None when the manifest is absent."""
    try:
        raw = store.read_verified(ref, context, limits.max_json_bytes).data
    except ContractError as error:
        if error.code in ABSENT:
            return None
        raise
    manifest = ResultManifest.from_wire(raw, limits)
    if manifest.project_id != context.project_id:
        raise ContractError("forbidden")
    return manifest.outputs


def retention_report(
    context: AccessContext,
    ledger: Ledger,
    store: ObjectStore,
    policy: RetentionPolicy,
    now: Instant,
    *,
    limits: ContractLimits,
    backup: ObjectStore | None = None,
) -> RetentionReport:
    """Report, per staged result, whether its staging copy could be cleaned up.

    `store` holds the local copy to verify; `backup` is the independent backup store, required to
    verify a copy when the policy demands one. `limits` bound the read of each result manifest
    (the trusted `kf.result.v1` limits); an output list that cannot be read within them is reported,
    never assumed present.
    """
    require_recovery_scopes(context)
    if type(policy) is not RetentionPolicy:
        raise ContractError("invalid_schema")
    at = _moment(now)
    project = context.project_id
    with ledger.transaction() as tx:
        tx.lock(project)
        unreconciled = tx.connection.execute(
            sql.SQL("SELECT 1 FROM {} WHERE project_id=%s AND NOT state=ANY(%s) LIMIT 1").format(
                tx.table("attempts")
            ),
            (project, list(TERMINAL_STATES)),
        ).fetchone()
        rows = tx.connection.execute(
            sql.SQL(
                "SELECT result_ref, min(created_at) FROM {} "
                "WHERE project_id=%s AND result_ref IS NOT NULL GROUP BY result_ref"
            ).format(tx.table("attempts")),
            (project,),
        ).fetchall()
    staged: dict[tuple[object, ...], tuple[Ref, datetime]] = {}
    for stored, first in rows:
        ref = Ref.model_validate(stored)
        key = identity(ref)
        moment = first.astimezone(UTC)
        if key not in staged or moment < staged[key][1]:
            staged[key] = (ref, moment)
    entries: list[RetentionEntry] = []
    for ref, started in sorted(staged.values(), key=lambda item: item[0].digest):
        reasons: list[Reason] = []
        if unreconciled is not None:
            reasons.append(UNRECONCILED)
        if at < started + timedelta(seconds=policy.min_staging_age_seconds):
            reasons.append(TOO_YOUNG)
        outputs: tuple[Ref, ...] = ()
        try:
            listed = _outputs(ref, context, store, limits)
        except ContractError as error:
            if error.code not in {"invalid_schema", "limit_exceeded", "unsupported_schema"}:
                raise
            reasons.append(RESULT_UNREADABLE)
        else:
            if listed is None:
                reasons.append(NO_LOCAL)
            else:
                outputs = listed
        if any(not _verified(output, context, store) for output in outputs):
            reasons.append(OUTPUT_NO_LOCAL)
        if policy.backup_required:
            if backup is None:
                reasons.append(NO_BACKUP_STORE)
            else:
                if not _verified(ref, context, backup):
                    reasons.append(NO_BACKUP)
                if any(not _verified(output, context, backup) for output in outputs):
                    reasons.append(OUTPUT_NO_BACKUP)
        if reasons:
            horizon = started + timedelta(seconds=policy.funded_staging_horizon_seconds)
            if at >= horizon:
                reasons.append(HORIZON_PASSED)
            elif at >= horizon - timedelta(seconds=policy.escalation_lead_seconds):
                reasons.append(ESCALATION_DUE)
        entries.append(RetentionEntry(ref, not reasons, tuple(reasons)))
    return RetentionReport(tuple(entries), now)
