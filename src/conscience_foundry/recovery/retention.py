"""Retention report: cleanup eligibility only. It reads state and never deletes anything.

A staged result may be cleaned up only when every condition holds together: no attempt in the
project is unresolved, the source the result came from is still readable under current policy,
the result manifest and every output it lists are verified in the local store, the same objects
are verified in the independent backup when the policy requires one, and the minimum staging age
has passed. Outputs carry source-derived content, so they are opened only for a source with current
read permission; otherwise the result is reported ineligible and its outputs stay unread.
`auditMetadataRead` is required for every source a staged result implicates, and a denial fails
the report closed, as it does a backup. A backup copies a result manifest as audit metadata only,
so an output that no verified release selected is not in the backup and keeps its result ineligible.
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
from conscience_foundry.contracts.project import PolicyArtifact
from conscience_foundry.contracts.release import RetentionPolicy
from conscience_foundry.execution.evidence import current_policy, identity, limits_for
from conscience_foundry.ledger.db import Ledger
from conscience_foundry.policy.access import AccessContext, require_permission
from conscience_foundry.recovery.backup import TERMINAL_STATES, require_recovery_scopes
from conscience_foundry.release.context import ReleaseContext, checked_context, require_audit
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
SOURCE_NOT_READABLE = Reason(
    code="forbidden", message="current policy does not permit reading this result's source"
)
ESCALATION_DUE = Reason(code="unavailable", message="operator action due before funded horizon")
HORIZON_PASSED = Reason(
    code="storage_full", message="unresolved storage liability beyond the funded horizon"
)
ABSENT = frozenset({"artifact_missing", "hash_mismatch"})
# Current policy says the source is not readable (denied or unknown): a verdict, not a failure.
UNREADABLE = frozenset({"forbidden", "permission_unknown"})


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


def _readable(policy: PolicyArtifact, context: AccessContext, sources: frozenset[str]) -> bool:
    """True when current policy allows reading every source; no source at all is not readable."""
    if not sources:
        return False
    try:
        for source in sources:
            require_permission(context, policy, source, "read")
    except ContractError as error:
        if error.code in UNREADABLE:
            return False
        raise
    return True


def retention_report(
    context: AccessContext,
    ledger: Ledger,
    store: ObjectStore,
    policy: RetentionPolicy,
    now: Instant,
    *,
    release: ReleaseContext,
    backup: ObjectStore | None = None,
) -> RetentionReport:
    """Report, per staged result, whether its staging copy could be cleaned up.

    `store` holds the local copy to verify and must be the store `release` was built with;
    `backup` is the independent backup store, required to verify a copy when the policy demands
    one. `release` supplies current source permission and the trusted `kf.result.v1` limits that
    bound the read of each result manifest (an output list that cannot be read within them is
    reported, never assumed present).
    """
    checked_context(context, store, release)
    require_recovery_scopes(context)
    if type(policy) is not RetentionPolicy:
        raise ContractError("invalid_schema")
    limits = limits_for(release, "kf.result.v1")
    at = _moment(now)
    project = context.project_id
    with ledger.transaction() as tx:
        tx.lock(project)
        current = current_policy(release, project)
        unreconciled = tx.connection.execute(
            sql.SQL("SELECT 1 FROM {} WHERE project_id=%s AND NOT state=ANY(%s) LIMIT 1").format(
                tx.table("attempts")
            ),
            (project, list(TERMINAL_STATES)),
        ).fetchone()
        # Result to attempt to operation to asset to source: whose content each result carries.
        rows = tx.connection.execute(
            sql.SQL(
                "SELECT t.result_ref, t.created_at, a.source_id::text FROM {} t "
                "JOIN {} o ON (t.project_id,t.operation_key)=(o.project_id,o.operation_key) "
                "JOIN {} a ON (o.project_id,o.asset_id)=(a.project_id,a.asset_id) "
                "WHERE t.project_id=%s AND t.result_ref IS NOT NULL"
            ).format(tx.table("attempts"), tx.table("operations"), tx.table("assets")),
            (project,),
        ).fetchall()
    staged: dict[tuple[object, ...], tuple[Ref, datetime, set[str]]] = {}
    for stored, first, source in rows:
        ref = Ref.model_validate(stored)
        key = identity(ref)
        moment = first.astimezone(UTC)
        if key not in staged:
            staged[key] = (ref, moment, {source})
            continue
        known, earliest, sources = staged[key]
        sources.add(source)
        staged[key] = (known, min(earliest, moment), sources)
    # Result metadata is audit metadata of every source it implicates; a denial fails closed.
    implicated = {source for _, _, found in staged.values() for source in found}
    require_audit(release, current, tuple(sorted(implicated)))
    entries: list[RetentionEntry] = []
    for ref, started, sources in sorted(staged.values(), key=lambda item: item[0].digest):
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
        # Outputs are source-derived content: without current read permission they stay unopened.
        if outputs and not _readable(current, context, frozenset(sources)):
            reasons.append(SOURCE_NOT_READABLE)
            outputs = ()
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
