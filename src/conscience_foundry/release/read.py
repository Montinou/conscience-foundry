"""Local trusted span reads against a pinned, locally verified release.

A read needs the operator pin, a locally verified release and current authority
on every call. A hash match never replaces current permission or hold checks.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from conscience_foundry.contracts.canonical import DocumentRevision, DocumentSpan
from conscience_foundry.contracts.common import ContractError, ContractLimits, Digest
from conscience_foundry.core.spans import check_exact_quote
from conscience_foundry.execution.evidence import limits_for, read_artifact, read_model
from conscience_foundry.ledger.db import Ledger
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.release.context import (
    ReleaseContext,
    TrustedReleasePin,
    check_pin,
    checked_context,
)
from conscience_foundry.release.importer import check_capabilities, load_release, require_current
from conscience_foundry.storage.local import ObjectStore, VerifiedBytes


@dataclass(frozen=True)
class ResolvedSlice:
    """Exact slice only; it is not proof of the full text without separate verification."""

    text: str
    text_digest: Digest
    revision_id: Digest
    span: DocumentSpan


def resolve_span(
    context: AccessContext,
    release_digest: Digest,
    span: DocumentSpan,
    ledger: Ledger,
    store: ObjectStore,
    *,
    release: ReleaseContext,
    pin: TrustedReleasePin,
) -> ResolvedSlice:
    """Load the full canonical text under its limit, verify it, return only the slice.

    `text_digest` hashes the returned slice's UTF-8 bytes. The full-text digest is
    verified here against the pinned revision and is never taken from the caller.
    """
    checked_context(context, store, release)
    if type(span) is not DocumentSpan:
        raise ContractError("invalid_schema")
    check_pin(pin, release_digest, release)
    if span.project_id != context.project_id:
        raise ContractError("forbidden")
    with ledger.transaction() as tx:
        tx.lock(context.project_id)
        loaded = load_release(tx, release_digest, release)
        check_capabilities(loaded.model, pin)
        if not loaded.row.local_verified or loaded.row.import_receipt_ref is None:
            raise ContractError("unavailable")
        entries = [
            entry for entry in loaded.model.source_entries if entry.source_id == span.source_id
        ]
        if len(entries) != 1:
            raise ContractError("revision_mismatch")
        # Authority is rechecked for this source only; unrelated sources stay unopened.
        require_current(tx, (entries[0],), release, ("read", "extract"))
        _, revision = read_model(entries[0].revision_ref, DocumentRevision, release)
        if (revision.project_id, revision.source_id, revision.revision_id) != (
            context.project_id,
            span.source_id,
            span.revision_id,
        ):
            raise ContractError("revision_mismatch")
        raw, _ = read_artifact(revision.text_ref, release)
        full = VerifiedBytes(raw, revision.text_ref.digest)
        limits = limits_for(release, "kf.canonical-text.v1")
        text = raw.decode("utf-8")[span.start : span.end]
        check_exact_quote(full, span, text, revision=revision, limits=limits)
        return ResolvedSlice(
            text, hashlib.sha256(text.encode("utf-8")).hexdigest(), revision.revision_id, span
        )


def verify_resolved_slice(
    resolved: ResolvedSlice,
    full_text: VerifiedBytes,
    revision: DocumentRevision,
    *,
    limits: ContractLimits,
) -> None:
    """Independent check: authorized full bytes must reproduce the exact returned slice.

    The caller obtains `full_text` and `revision` through separately authorized
    access; the slice response alone, even with a valid digest, proves nothing.
    """
    if type(resolved) is not ResolvedSlice:
        raise ContractError("invalid_schema")
    check_exact_quote(full_text, resolved.span, resolved.text, revision=revision, limits=limits)
    if resolved.revision_id != revision.revision_id:
        raise ContractError("revision_mismatch")
    if resolved.text_digest != hashlib.sha256(resolved.text.encode("utf-8")).hexdigest():
        raise ContractError("hash_mismatch")
