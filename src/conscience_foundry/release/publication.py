"""Publication evidence chain and operator activation of a locally verified release.

Publication grants exposure eligibility; activation moves the pointer. Neither
substitutes for the other or for execution authorization, and effective
eligibility is re-derived from current authority at every activation.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from types import MappingProxyType

from conscience_foundry.contracts.canonical import RevisionReview
from conscience_foundry.contracts.common import ContractError, Ref
from conscience_foundry.contracts.project import PolicyArtifact
from conscience_foundry.contracts.release import (
    ActivationRecord,
    ImportReceipt,
    PublicationAuthorization,
    PublicationRecord,
)
from conscience_foundry.execution.evidence import (
    clock,
    current_policy,
    identity,
    limits_for,
    read_artifact,
    read_model,
)
from conscience_foundry.ledger.db import Ledger, LedgerTxn
from conscience_foundry.ledger.publication import (
    STAGES,
    PublicationEvent,
    active_pointer,
    insert_publication,
    move_pointer,
    publication_event,
    publication_tail,
)
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.release.context import (
    ReleaseContext,
    TrustedReleasePin,
    approve,
    bounded_model,
    check_pin,
    checked_context,
    recheck_policy,
    request_bytes,
)
from conscience_foundry.release.importer import (
    LoadedRelease,
    check_capabilities,
    load_release,
    record_failure,
    require_current,
    store_record,
)

# Closed per-stage evidence schemas, bound below to this project and release.
# Reports are excluded: they need audit metadata handling and are not stage proof.
PUBLICATION_EVIDENCE: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "candidate": frozenset({"kf.library-release.v1"}),
        "validated": frozenset({"kf.revision-review.v1"}),
        # F1 has no transport or transport-completion schema: `transferred` accepts the
        # release ref as evidence, so it is operator-attested only (exact release-authority
        # approval) and proves no transport. Accepted F1 limitation; revisit at T21/F5.
        "transferred": frozenset({"kf.library-release.v1"}),
        "local_verified": frozenset({"kf.import-receipt.v1"}),
        "published": frozenset({"kf.import-receipt.v1"}),
        "retired": frozenset({"kf.import-receipt.v1"}),
    }
)


def _validated(
    loaded: LoadedRelease,
    record: PublicationRecord,
    release: ReleaseContext,
    pin: TrustedReleasePin | None,
) -> None:
    """D08 validated: verified closure (the stored local import receipt) plus capabilities.

    Accepted reviews and the current policy version are checked by the caller and
    `_evidence`; the capability set comes only from the operator-configured pin.
    """
    receipt = loaded.row.import_receipt_ref
    if not loaded.row.local_verified or receipt is None:
        raise ContractError("unavailable")
    stored = read_model(receipt, ImportReceipt, release)[1]
    if stored.status != "local_verified" or stored.release_ref.digest != record.release_digest:
        raise ContractError("hash_mismatch")
    if pin is None:
        raise ContractError("forbidden")
    check_pin(pin, record.release_digest, release)
    check_capabilities(loaded.model, pin)


def _evidence(record: PublicationRecord, loaded: LoadedRelease, release: ReleaseContext) -> None:
    allowed = PUBLICATION_EVIDENCE[record.stage]
    reviews = {identity(entry.review_ref) for entry in loaded.model.source_entries}
    seen: set[tuple[object, ...]] = set()
    for ref in record.evidence_refs:
        if ref.artifact_schema not in allowed:
            raise ContractError("unsupported_schema")
        if ref.artifact_schema == "kf.library-release.v1":
            if ref.digest != record.release_digest:
                raise ContractError("forbidden")
        read_artifact_value = read_artifact(ref, release)[1]
        if ref.artifact_schema == "kf.import-receipt.v1":
            receipt = loaded.row.import_receipt_ref
            if (
                type(read_artifact_value) is not ImportReceipt
                or read_artifact_value.status != "local_verified"
                or read_artifact_value.release_ref.digest != record.release_digest
                or not loaded.row.local_verified
                or receipt is None
                or identity(receipt) != identity(ref)
            ):
                raise ContractError("forbidden")
        elif ref.artifact_schema == "kf.revision-review.v1":
            if (
                type(read_artifact_value) is not RevisionReview
                or read_artifact_value.decision != "accepted"
                or identity(ref) not in reviews
            ):
                raise ContractError("forbidden")
        seen.add(identity(ref))
    if record.stage == "validated" and seen != reviews:
        raise ContractError("forbidden")


def _grant(
    record: PublicationRecord, release: ReleaseContext, policy: PolicyArtifact
) -> tuple[Ref, bytes]:
    """The stored grant must bind this project, release and the current policy version."""
    ref = record.publication_authorization_ref
    if ref is None:
        raise ContractError("forbidden")
    raw, grant = read_model(ref, PublicationAuthorization, release)
    now = clock(release)
    if (
        grant.project_id != release.access.project_id
        or grant.release_digest != record.release_digest
        or grant.authorized_at > now
    ):
        raise ContractError("forbidden")
    if grant.expires_at <= now:
        raise ContractError("authorization_expired")
    _, pinned = read_model(grant.policy_ref, PolicyArtifact, release)
    if pinned.policy_version != policy.policy_version:
        raise ContractError("permission_unknown")
    return ref, raw


def _chain(record: PublicationRecord, tail: PublicationEvent | None) -> None:
    if record.previous_event_id != (tail.event_id if tail is not None else None):
        raise ContractError("activation_conflict")
    expected = 0 if tail is None else STAGES.index(tail.stage) + 1
    if expected >= len(STAGES) or STAGES[expected] != record.stage:
        raise ContractError("invalid_schema")


def append_publication(
    record: PublicationRecord,
    context: AccessContext,
    ledger: Ledger,
    *,
    release: ReleaseContext,
    pin: TrustedReleasePin | None = None,
) -> None:
    """Append one stage event: CAS on the chain tail, strict stage order, bound evidence."""
    checked_context(context, release.store, release)
    if type(record) is not PublicationRecord:
        raise ContractError("invalid_schema")
    raw = bounded_model(record, release, "kf.publication-record.v1")
    if PublicationRecord.from_wire(raw, limits_for(release, "kf.publication-record.v1")) != record:
        raise ContractError("forbidden")
    if (
        record.project_id != context.project_id
        or record.actor_id != context.actor_id
        or record.recorded_at > clock(release)
    ):
        raise ContractError("forbidden")
    try:
        _append(record, context, ledger, release, pin, raw)
    except ContractError as error:
        # D08: a transition that cannot complete records an incident and the confirmed
        # stage does not advance (the failed transaction has already rolled back).
        record_failure(ledger, release, record.release_digest, "publication", error, record.stage)
        raise


def _append(
    record: PublicationRecord,
    context: AccessContext,
    ledger: Ledger,
    release: ReleaseContext,
    pin: TrustedReleasePin | None,
    raw: bytes,
) -> None:
    with ledger.transaction() as tx:
        tx.lock(context.project_id)
        prior = publication_event(tx, context.project_id, record.event_id)
        if prior is not None:
            if (
                prior.record_ref.digest != hashlib.sha256(raw).hexdigest()
                or prior.release_digest != record.release_digest
            ):
                raise ContractError("determinism_conflict")
            return
        loaded = load_release(tx, record.release_digest, release)
        tail = publication_tail(tx, context.project_id, record.release_digest)
        _chain(record, tail)
        policy = current_policy(release, context.project_id)
        _, pinned = read_model(record.policy_ref, PolicyArtifact, release)
        if pinned.policy_version != policy.policy_version:
            raise ContractError("permission_unknown")
        if record.stage == "validated":
            _validated(loaded, record, release, pin)
        _evidence(record, loaded, release)
        grant: tuple[Ref, bytes] | None = None
        if record.stage == "published":
            if not loaded.row.local_verified:
                raise ContractError("unavailable")
            grant = _grant(record, release, policy)
            require_current(
                tx, loaded.model.source_entries, release, ("read", "extract", "publish")
            )
        state = request_bytes(
            {
                "projectId": context.project_id,
                "releaseDigest": record.release_digest,
                "stage": record.stage,
                "tailEventId": tail.event_id if tail is not None else None,
                "policyVersion": policy.policy_version,
            },
            release,
        )
        approve(
            release,
            "append_publication",
            raw,
            hashlib.sha256(state).hexdigest(),
            grant[0] if grant is not None else None,
            grant[1] if grant is not None else None,
        )
        recheck_policy(policy, release)
        insert_publication(tx, record, store_record(record, release))


def _published(tx: LedgerTxn, loaded: LoadedRelease, release: ReleaseContext) -> PublicationEvent:
    tail = publication_tail(tx, release.access.project_id, loaded.row.release_ref.digest)
    if tail is None or tail.stage != "published":
        raise ContractError("forbidden")
    return tail


def activate(
    record: ActivationRecord,
    context: AccessContext,
    ledger: Ledger,
    *,
    release: ReleaseContext,
) -> None:
    """Compare-and-swap the active pointer to a published, locally verified release.

    Eligibility is derived now: latest stage published (not retired), valid grant,
    current permission and no integrity hold. Failure leaves the pointer unchanged.
    """
    checked_context(context, release.store, release)
    if type(record) is not ActivationRecord:
        raise ContractError("invalid_schema")
    raw = bounded_model(record, release, "kf.activation.v1")
    if ActivationRecord.from_wire(raw, limits_for(release, "kf.activation.v1")) != record:
        raise ContractError("forbidden")
    if (
        record.project_id != context.project_id
        or record.actor_id != context.actor_id
        or record.activated_at > clock(release)
    ):
        raise ContractError("forbidden")
    with ledger.transaction() as tx:
        tx.lock(context.project_id)
        loaded = load_release(tx, record.next_release_digest, release)
        if not loaded.row.local_verified or loaded.row.import_receipt_ref is None:
            raise ContractError("forbidden")
        tail = _published(tx, loaded, release)
        _, published = read_model(tail.record_ref, PublicationRecord, release)
        if (published.event_id, published.stage, published.release_digest) != (
            tail.event_id,
            "published",
            record.next_release_digest,
        ):
            raise ContractError("hash_mismatch")
        policy = current_policy(release, context.project_id)
        _grant(published, release, policy)
        require_current(tx, loaded.model.source_entries, release, ("read", "extract", "publish"))
        current = active_pointer(tx, context.project_id)
        if record.expected_previous_release_digest != (
            current.release_digest if current is not None else None
        ):
            raise ContractError("activation_conflict")
        state = request_bytes(
            {
                "projectId": context.project_id,
                "currentReleaseDigest": current.release_digest if current else None,
                "currentVersion": current.version if current else 0,
                "nextReleaseDigest": record.next_release_digest,
                "publicationEventId": tail.event_id,
                "policyVersion": policy.policy_version,
            },
            release,
        )
        approve(release, "activate_release", raw, hashlib.sha256(state).hexdigest())
        recheck_policy(policy, release)
        move_pointer(tx, record, store_record(record, release), current)
