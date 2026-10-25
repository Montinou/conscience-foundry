"""Explicit trusted private-review dependencies; artifact bytes confer no authority."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Literal, Protocol

from conscience_foundry.contracts.common import (
    ContractError,
    ContractLimits,
    Digest,
    Id,
    Instant,
    Ref,
    WireModel,
)
from conscience_foundry.contracts.project import PolicyArtifact
from conscience_foundry.execution.evidence import bounded_request, clock, current_policy, limits_for
from conscience_foundry.policy.access import AccessContext, require_permission
from conscience_foundry.storage.local import ObjectStore

Action = Literal["record_review", "build_release", "withdraw_admission"]


@dataclass(frozen=True)
class ReleaseProof:
    project_id: Id
    actor_id: Id
    action: Action
    request_bytes: bytes = field(repr=False)
    request_digest: Digest
    state_digest: Digest
    evidence_ref: Ref | None
    revision_ref: Ref | None
    evidence_bytes: bytes | None = field(repr=False)
    now: Instant


@dataclass(frozen=True)
class ReleaseApproval:
    project_id: Id
    actor_id: Id
    action: Action
    request_digest: Digest
    state_digest: Digest
    evidence_digest: Digest | None
    revision_ref: Ref | None


class ReleaseAuthority(Protocol):
    def approve(self, proof: ReleaseProof) -> ReleaseApproval: ...


@dataclass(frozen=True)
class ReleaseContext:
    access: AccessContext
    store: ObjectStore = field(repr=False)
    clock: Callable[[], Instant] = field(repr=False)
    limits_by_schema: Mapping[str, ContractLimits] = field(repr=False)
    output_store_id: str
    current_policy: Callable[[Id], PolicyArtifact] = field(repr=False)
    authority: ReleaseAuthority = field(repr=False)


def checked_context(
    context: AccessContext,
    store: ObjectStore,
    release: ReleaseContext,
) -> None:
    if type(release) is not ReleaseContext or type(context) is not AccessContext:
        raise ContractError("forbidden")
    if context != release.access or store is not release.store:
        raise ContractError("forbidden")
    clock(release)
    if type(release.output_store_id) is not str or not release.output_store_id:
        raise ContractError("invalid_schema")


def require_audit(
    release: ReleaseContext, policy: PolicyArtifact, sources: tuple[str, ...]
) -> None:
    if "auditMetadataRead" not in release.access.scopes:
        raise ContractError("forbidden")
    for source in sources:
        require_permission(release.access, policy, source, "auditMetadataRead")


def bounded_model(value: WireModel, release: ReleaseContext, schema: str) -> bytes:
    """Bound direct trusted-API models before their JSON projection is allocated."""
    bound = limits_for(release, schema)
    pending: list[tuple[object, int]] = [(value, 0)]
    while pending:
        child, depth = pending.pop()
        if depth > bound.max_depth:
            raise ContractError("limit_exceeded")
        if isinstance(child, WireModel):
            pending.extend((getattr(child, key), depth + 1) for key in type(child).model_fields)
        elif type(child) is tuple:
            if len(child) > bound.max_array_items:
                raise ContractError("limit_exceeded")
            pending.extend((item, depth + 1) for item in child)
        elif type(child) is str:
            if len(child) > bound.max_string_scalars:
                raise ContractError("limit_exceeded")
        elif child is not None and type(child) not in (bool, int):
            raise ContractError("invalid_schema")
    raw = value.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8")
    if len(raw) > min(bound.max_json_bytes, bound.max_output_bytes):
        raise ContractError("limit_exceeded")
    return raw


def request_bytes(value: object, release: ReleaseContext) -> bytes:
    return bounded_request(value, release)


def approve(
    release: ReleaseContext,
    action: Action,
    raw: bytes,
    state_digest: str,
    evidence_ref: Ref | None = None,
    evidence_bytes: bytes | None = None,
    revision_ref: Ref | None = None,
) -> None:
    if type(raw) is not bytes:
        raise ContractError("invalid_schema")
    bound = limits_for(release, "kf.revision-review.v1")
    if len(raw) > min(bound.max_json_bytes, bound.max_output_bytes):
        raise ContractError("limit_exceeded")
    proof = ReleaseProof(
        release.access.project_id,
        release.access.actor_id,
        action,
        raw,
        hashlib.sha256(raw).hexdigest(),
        state_digest,
        evidence_ref,
        revision_ref,
        evidence_bytes,
        clock(release),
    )
    expected = ReleaseApproval(
        proof.project_id,
        proof.actor_id,
        action,
        proof.request_digest,
        state_digest,
        evidence_ref.digest if evidence_ref else None,
        revision_ref,
    )
    try:
        facts = release.authority.approve(proof)
    except Exception:
        raise ContractError("forbidden") from None
    if type(facts) is not ReleaseApproval or facts != expected:
        raise ContractError("forbidden")


def recheck_policy(before: PolicyArtifact, release: ReleaseContext) -> None:
    if current_policy(release, release.access.project_id) != before:
        raise ContractError("unavailable")
