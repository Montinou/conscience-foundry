"""Durable local import of a pinned release's selected-content closure.

Import verifies bytes already installed in the one trusted store and records a
receipt. It grants no publication, activation or consumer access: a matching
pin proves bytes equal operator configuration, not permission or quality.
"""

from __future__ import annotations

import errno
import hashlib
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from psycopg import sql

from conscience_foundry.contracts.canonical import DocumentRevision, QualityReport, RevisionReview
from conscience_foundry.contracts.common import (
    ContractError,
    Id,
    Ref,
    WireModel,
)
from conscience_foundry.contracts.release import (
    CoverageReport,
    ImportReceipt,
    LibraryRelease,
    ProvenanceReport,
    ReleaseSource,
)
from conscience_foundry.execution.evidence import (
    clock,
    current_policy,
    identity,
    limits_for,
    put_record,
    read_artifact,
    read_model,
)
from conscience_foundry.ledger.db import Ledger, LedgerTxn
from conscience_foundry.ledger.publication import ReleaseRow, mark_local_verified
from conscience_foundry.ledger.publication import load_release as load_release_row
from conscience_foundry.policy.access import AccessContext, require_permission
from conscience_foundry.release.context import (
    ReleaseContext,
    TrustedReleasePin,
    approve,
    bounded_model,
    check_pin,
    checked_context,
    recheck_policy,
    request_bytes,
    require_audit,
)
from conscience_foundry.release.coverage import metadata_ids
from conscience_foundry.release.edges import edge_roles
from conscience_foundry.storage.local import ObjectStore


@dataclass(frozen=True)
class LoadedRelease:
    row: ReleaseRow
    model: LibraryRelease


def store_record(record: WireModel, release: ReleaseContext) -> Ref:
    """Install immutable bytes first; the caller records the returned ref afterwards."""
    try:
        return put_record(record, release)
    except OSError as error:
        full = error.errno in {errno.ENOSPC, errno.EDQUOT}
        raise ContractError("storage_full" if full else "unavailable") from None


def load_release(tx: LedgerTxn, release_digest: str, release: ReleaseContext) -> LoadedRelease:
    """Read the pinned manifest only; reports and content stay unopened."""
    row = load_release_row(tx, release.access.project_id, release_digest)
    if row is None:
        raise ContractError("unavailable")
    if row.release_ref.digest != release_digest:
        raise ContractError("hash_mismatch")
    _, model = read_model(row.release_ref, LibraryRelease, release)
    model.validate_f1()
    if (
        model.project_id != release.access.project_id
        or model.selection_digest() != row.selection_digest
    ):
        raise ContractError("hash_mismatch")
    return LoadedRelease(row, model)


def check_capabilities(model: LibraryRelease, pin: TrustedReleasePin) -> None:
    if not set(model.capabilities) <= set(pin.capabilities):
        raise ContractError("unsupported_capability")


def _clear(tx: LedgerTxn, source: ReleaseSource, release: ReleaseContext) -> None:
    project = release.access.project_id
    rows = metadata_ids(
        tx,
        sql.SQL(
            "SELECT r.operation_key,a.source_id::text,a.asset_id::text,o.held::text FROM {} r "
            "JOIN {} o ON (r.project_id,r.operation_key)=(o.project_id,o.operation_key) "
            "JOIN {} a ON (o.project_id,o.asset_id)=(a.project_id,a.asset_id) "
            "WHERE r.project_id=%s AND r.review_ref->>'digest'=%s "
            "AND r.revision_ref->>'digest'=%s"
        ).format(tx.table("reviews"), tx.table("operations"), tx.table("assets")),
        (project, source.review_ref.digest, source.revision_ref.digest),
        release,
    )
    if len(rows) != 1:
        raise ContractError("unavailable")
    operation_key, source_id, asset_id, held = rows[0]
    if source_id != source.source_id:
        raise ContractError("revision_mismatch")
    holds = metadata_ids(
        tx,
        sql.SQL("SELECT hold_id::text FROM {} WHERE project_id=%s AND operation_key=%s").format(
            tx.table("integrity_holds")
        ),
        (project, operation_key),
        release,
    )
    if held == "true" or holds:
        raise ContractError("determinism_conflict")
    withdrawn = metadata_ids(
        tx,
        sql.SQL(
            "SELECT decision_id::text FROM {} WHERE project_id=%s AND asset_id=%s::uuid"
        ).format(tx.table("admission_withdrawals")),
        (project, asset_id),
        release,
    )
    if withdrawn:
        raise ContractError("forbidden")


def require_current(
    tx: LedgerTxn,
    sources: tuple[ReleaseSource, ...],
    release: ReleaseContext,
    effects: tuple[str, ...],
) -> None:
    """Current policy, holds and withdrawals override any historical acceptance."""
    policy = current_policy(release, release.access.project_id)
    for source in sources:
        for effect in effects:
            require_permission(release.access, policy, source.source_id, effect)
        _clear(tx, source, release)


def _implicated_sources(
    tx: LedgerTxn, sources: tuple[ReleaseSource, ...], release: ReleaseContext
) -> tuple[str, ...]:
    """Identity-only routing of sources whose admission metadata the reports can expose."""
    rows = metadata_ids(
        tx,
        sql.SQL(
            "SELECT DISTINCT e.source_id::text FROM {} v "
            "JOIN {} a ON (v.project_id,v.operation_key)=(a.project_id,a.operation_key) "
            "JOIN {} r ON (a.project_id,a.run_id)=(r.project_id,r.run_id) "
            "JOIN {} e ON (r.project_id,r.admission_report_digest)="
            "(e.project_id,e.report_digest) "
            "WHERE v.project_id=%s AND v.review_ref->>'digest'=ANY(%s)"
        ).format(
            tx.table("reviews"),
            tx.table("attempts"),
            tx.table("runs"),
            tx.table("admission_entries"),
        ),
        (release.access.project_id, [source.review_ref.digest for source in sources]),
        release,
    )
    return tuple(sorted(row[0] for row in rows))


def _closure(
    root: Ref, model: LibraryRelease, release: ReleaseContext
) -> dict[tuple[object, ...], tuple[Ref, Any]]:
    """Registered selected-content edges only; audit edges are opaque links."""
    bound = limits_for(release, "kf.library-release.v1")
    seen: dict[tuple[object, ...], tuple[Ref, Any]] = {identity(root): (root, model)}
    active: set[tuple[object, ...]] = {identity(root)}
    total = root.size_bytes

    def visit(reference: Ref) -> None:
        nonlocal total
        key = identity(reference)
        if key in active:
            raise ContractError("invalid_schema")
        if key in seen:
            return
        if len(seen) >= bound.max_array_items:
            raise ContractError("limit_exceeded")
        data, value = read_artifact(reference, release)
        total += len(data)
        if total > bound.max_output_bytes:
            raise ContractError("limit_exceeded")
        active.add(key)
        seen[key] = (reference, value)
        for edge in edge_roles(reference.artifact_schema, value):
            if edge.role == "content":
                visit(edge.ref)
        active.remove(key)

    for edge in edge_roles("kf.library-release.v1", model):
        if edge.role == "content":
            visit(edge.ref)
    return seen


def _verify_content(
    model: LibraryRelease, seen: dict[tuple[object, ...], tuple[Ref, Any]], project: Id
) -> tuple[str, ...]:
    def get[Kind](ref: Ref, kind: type[Kind]) -> Kind:
        value = seen[identity(ref)][1]
        if type(value) is not kind:
            raise ContractError("unsupported_schema")
        return value

    coverage = get(model.coverage_report_ref, CoverageReport)
    provenance = get(model.provenance_report_ref, ProvenanceReport)
    coverage.validate_selection(model)
    provenance.validate_selection(model)
    for entry in model.source_entries:
        revision = get(entry.revision_ref, DocumentRevision)
        review = get(entry.review_ref, RevisionReview)
        quality = get(revision.quality_report_ref, QualityReport)
        if (
            revision.project_id != project
            or revision.source_id != entry.source_id
            or review.decision != "accepted"
        ):
            raise ContractError("revision_mismatch")
        review.validate_quality(revision, quality)
        text = seen[identity(revision.text_ref)][1]
        if (
            type(text) is not bytes
            or revision.text_ref.artifact_schema != "kf.canonical-text.v1"
            or revision.text_ref.digest != revision.original_ref.digest
            or revision.text_ref.size_bytes != revision.original_ref.size_bytes
        ):
            raise ContractError("revision_mismatch")
        revision.validate_f1(len(text.decode("utf-8")))
    return tuple(
        sorted(
            {entry.source_id for entry in coverage.entries}
            | {entry.source_id for entry in provenance.entries}
        )
    )


def import_release(
    release_ref: Ref,
    context: AccessContext,
    ledger: Ledger,
    store: ObjectStore,
    *,
    release: ReleaseContext,
    pin: TrustedReleasePin,
) -> ImportReceipt:
    """Verify the pinned selected-content closure, then atomically record a receipt.

    Failure raises and persists nothing; a verified import is never reverted here.
    """
    checked_context(context, store, release)
    if type(release_ref) is not Ref:
        raise ContractError("invalid_schema")
    check_pin(pin, release_ref.digest, release)
    bounded_model(release_ref, release, "kf.artifact-ref.v1")
    project = context.project_id
    if release_ref.project_id != project or release_ref.artifact_schema != "kf.library-release.v1":
        raise ContractError("forbidden")
    with ledger.transaction() as tx:
        tx.lock(project)
        loaded = load_release(tx, release_ref.digest, release)
        if identity(loaded.row.release_ref) != identity(release_ref):
            raise ContractError("hash_mismatch")
        check_capabilities(loaded.model, pin)
        sources = loaded.model.source_entries
        require_current(tx, sources, release, ("read", "extract"))
        policy = current_policy(release, project)
        # Report metadata is checked from ledger identities before any report is opened.
        require_audit(release, policy, _implicated_sources(tx, sources, release))
        seen = _closure(loaded.row.release_ref, loaded.model, release)
        require_audit(release, policy, _verify_content(loaded.model, seen, project))
        closure = tuple(sorted(value[0].digest for value in seen.values()))
        raw = request_bytes(
            {
                "projectId": project,
                "releaseDigest": release_ref.digest,
                "storeId": pin.store_id,
            },
            release,
        )
        state = request_bytes(
            {
                "projectId": project,
                "releaseDigest": release_ref.digest,
                "policyVersion": policy.policy_version,
                "closure": list(closure),
            },
            release,
        )
        approve(release, "import_release", raw, hashlib.sha256(state).hexdigest())
        recheck_policy(policy, release)
        if loaded.row.local_verified or loaded.row.import_receipt_ref is not None:
            if loaded.row.import_receipt_ref is None or not loaded.row.local_verified:
                raise ContractError("hash_mismatch")
            _, prior = read_model(loaded.row.import_receipt_ref, ImportReceipt, release)
            if prior.status != "local_verified" or identity(prior.release_ref) != identity(
                loaded.row.release_ref
            ):
                raise ContractError("hash_mismatch")
            return prior
        receipt = ImportReceipt(
            schema_version="kf.import-receipt.v1",
            project_id=project,
            import_id=str(uuid4()),
            release_ref=loaded.row.release_ref,
            verified_artifacts=tuple(
                value[0] for key, value in seen.items() if key != identity(loaded.row.release_ref)
            ),
            status="local_verified",
            checked_at=clock(release),
            reasons=(),
        )
        receipt_ref = store_record(receipt, release)
        mark_local_verified(tx, project, release_ref.digest, receipt_ref)
        return receipt
