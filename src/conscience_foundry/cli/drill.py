"""`restore-drill`: prove a backup restores, into a fresh target, and record evidence for preflight.

The drill loads a second operator config (the drill config) and restores the recovery manifest into
a target that exists only for this run: the ledger schema ``<base>_<drill-id>`` and the object
directory ``<root>/<drill-id>`` of that config, where the drill id is 12 fresh hex characters. A new
target every time means a repeated drill never meets the restore's refusal of a populated project,
and the live ledger and live object store are never opened: the bytes come from the live config's
backup store and go only to the drill's.

Evidence is produced only for a recovery that completed: every object restored and re-read verified,
the ledger snapshot verified, the dispatch barrier written. ``independence`` is ``verified`` only
when the backup store is R2 *and* the operator attests it; a different directory or an unattested
bucket is ``unverified``, which preflight refuses. Nothing here is imported from `commands`, which
registers the command and owns the evidence file.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from uuid import uuid4

from conscience_foundry.cli.config import (
    R2StoreSettings,
    Runtime,
    load_config,
    resolve_dsn,
)
from conscience_foundry.contracts.common import (
    ArtifactLocation,
    ContractError,
    Instant,
    Ref,
)
from conscience_foundry.ledger.allowance import install_allowance_schema
from conscience_foundry.operator.packet import BackupEvidence
from conscience_foundry.recovery.backup import RecoveryManifest
from conscience_foundry.recovery.restore import RecoveryReport, restore

REPORT_SCHEMA = "cfoundry.restore-drill-report.v1"
DRILL_ID_LENGTH = 12
SCHEMA_LIMIT = 63
MAX_BASE_SCHEMA = SCHEMA_LIMIT - DRILL_ID_LENGTH - 1
"""A base of up to 50 characters, ``_`` and the id fill the 63 a ledger schema name may have."""
MAX_VALID_FOR_SECONDS = 10**9

Independence = Literal["verified", "unverified"]


@dataclass(frozen=True)
class DrillResult:
    drill_id: str
    report: RecoveryReport
    independence: Independence
    evidence: bytes | None = None
    """Set only for a recovery that completed and was verified end to end."""
    report_ref: Ref | None = None
    valid_until: Instant | None = None


def positive_seconds(value: str) -> int:
    if not value.isdigit() or len(value) > 10 or not 0 < int(value) <= MAX_VALID_FOR_SECONDS:
        raise argparse.ArgumentTypeError("invalid")
    return int(value)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--manifest", required=True, help="recovery manifest from a backup")
    parser.add_argument("--drill-config", required=True, help="operator config of the drill target")
    parser.add_argument(
        "--evidence-output", required=True, help="new private file for the backup evidence"
    )
    parser.add_argument(
        "--valid-for-seconds",
        required=True,
        type=positive_seconds,
        help="how long the evidence stays valid after the drill",
    )
    parser.add_argument(
        "--attest-independent",
        action="store_true",
        help="the operator confirms the remote backup store is independent of the primary",
    )


def after(instant: Instant, seconds: int) -> Instant:
    """The instant `seconds` later, in the wire format; an unrepresentable one is refused."""
    try:
        moment = datetime.strptime(instant, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
        later = moment + timedelta(seconds=seconds)
    except (ValueError, OverflowError):
        raise ContractError("invalid_schema") from None
    return later.strftime("%Y-%m-%dT%H:%M:%S.") + f"{later.microsecond // 1000:03d}Z"


def _canonical(document: object) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _snapshot_has_allowances(live: Runtime, manifest: RecoveryManifest) -> bool:
    """Whether the recovery point carries call-allowance counters; the target must match it."""
    snapshot = manifest.ledger_snapshot_ref
    document = live.backup.read_verified(snapshot, live.access, snapshot.size_bytes).data
    try:
        tables = json.loads(document)["tables"]
    except (ValueError, KeyError, TypeError):
        raise ContractError("hash_mismatch") from None
    return isinstance(tables, dict) and "call_allowance_scopes" in tables


def _verify_restored(manifest: RecoveryManifest, target: Runtime) -> int:
    """Re-read every restored object, and the ledger snapshot, from the drill's own store."""
    refs = (manifest.ledger_snapshot_ref, *manifest.content_refs, *manifest.audit_refs)
    for ref in refs:
        target.store.open_verified(ref, target.access).close()
    return len(refs)


def run_drill(
    live: Runtime,
    manifest: RecoveryManifest,
    *,
    drill_config: str,
    valid_for_seconds: int,
    attest_independent: bool,
) -> DrillResult:
    destination = live.config.backup_store
    if destination is None:
        raise ContractError("config_required")
    base = load_config(drill_config)
    if (
        len(base.ledger.schema_name) > MAX_BASE_SCHEMA
        or base.project_id != live.config.project_id
        or base.project_id != manifest.project_id
    ):
        raise ContractError("config_invalid")
    drill_id = uuid4().hex[:DRILL_ID_LENGTH]
    root = Path(base.object_store.root_path) / drill_id
    config = base.model_copy(
        update={
            "ledger": base.ledger.model_copy(
                update={"schema_name": f"{base.ledger.schema_name}_{drill_id}"}
            ),
            "object_store": base.object_store.model_copy(update={"root_path": str(root)}),
        }
    )
    resolve_dsn(config.ledger)  # a missing credential blocks before anything is created
    target = Runtime(config, live.services, "restore-drill")
    try:
        if target.access != live.access:
            # The restore reads under one context and writes under it too: the two configs must
            # name the same project, operator and scopes.
            raise ContractError("forbidden")
        allowances = _snapshot_has_allowances(live, manifest)
        try:
            os.mkdir(root, 0o700)
        except OSError:
            raise ContractError("unavailable") from None
        target.ledger.migrate()
        if allowances:
            install_allowance_schema(target.ledger)
        report = restore(manifest, live.access, target.ledger, live.backup, target.store)
        independence: Independence = (
            "verified"
            if attest_independent and isinstance(destination, R2StoreSettings)
            else "unverified"
        )
        if report.missing_refs:
            return DrillResult(drill_id, report, independence)  # incomplete: no evidence
        if not report.dispatch_blocked:
            raise ContractError("determinism_conflict")  # the restore always leaves the barrier
        verified = _verify_restored(manifest, target)
        completed = live.clock()
        valid_until = after(completed, valid_for_seconds)
        report_bytes = _canonical(
            {
                "schemaVersion": REPORT_SCHEMA,
                "projectId": manifest.project_id,
                "drillId": drill_id,
                "snapshotDigest": manifest.snapshot_digest,
                "recoveryPoint": manifest.recovery_point,
                "completedAt": completed,
                "verifiedObjects": verified,
                "pendingAttempts": len(manifest.pending_attempt_ids),
                "excludedReleases": len(manifest.excluded_release_digests),
                "dispatchBlocked": report.dispatch_blocked,
                "backupStoreKind": destination.kind,
            }
        )
        digest = hashlib.sha256(report_bytes).hexdigest()
        report_ref = Ref(
            schema_version="cf.artifact-ref.v1",
            project_id=manifest.project_id,
            digest=digest,
            size_bytes=len(report_bytes),
            media_type="application/json",
            artifact_schema=REPORT_SCHEMA,
            locations=(
                ArtifactLocation(
                    store_id=config.object_store.store_id,
                    object_key=f"sha256/{digest[:2]}/{digest}",
                ),
            ),
        )
        target.store.put_verified(io.BytesIO(report_bytes), report_ref, target.access)
        evidence = BackupEvidence(
            schema_version="cfoundry.backup-evidence.v1",
            project_id=manifest.project_id,
            backup_store_id=destination.store_id,
            independence=independence,
            restore_evidence_ref=report_ref,
            valid_until=valid_until,
        )
        document = evidence.model_dump(mode="json", by_alias=True, exclude_none=True)
        return DrillResult(
            drill_id, report, independence, _canonical(document), report_ref, valid_until
        )
    finally:
        target.close()
