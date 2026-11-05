"""Explicit trusted dependencies and action proofs for enrichment."""

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
)
from conscience_foundry.contracts.project import PolicyArtifact
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.local import ObjectStore

Action = Literal[
    "install_task_schemas",
    "register",
    "claim",
    "record",
    "adjudicate",
    "select",
    "revoke",
    "build_annotations",
]


@dataclass(frozen=True)
class EnrichmentProof:
    action: Action
    project_id: Id
    actor_id: Id
    request_digest: Digest
    state_digest: Digest
    evidence_refs: tuple[Ref, ...]
    request_bytes: bytes = field(repr=False)
    run_id: Id | None = None
    operation_key: Digest | None = None
    attempt_id: Id | None = None


class EnrichmentAuthority(Protocol):
    def approve(self, proof: EnrichmentProof) -> bool: ...


@dataclass(frozen=True)
class EnrichmentContext:
    access: AccessContext
    store: ObjectStore = field(repr=False)
    clock: Callable[[], Instant] = field(repr=False)
    limits_by_schema: Mapping[str, ContractLimits] = field(repr=False)
    output_store_id: str
    current_policy: Callable[[], PolicyArtifact] = field(repr=False)
    authority: EnrichmentAuthority = field(repr=False)


def approve(
    context: EnrichmentContext,
    action: Action,
    raw: bytes,
    state_digest: Digest,
    evidence_refs: tuple[Ref, ...],
    *,
    run_id: Id | None = None,
    operation_key: Digest | None = None,
) -> None:
    if type(context) is not EnrichmentContext or type(raw) is not bytes:
        raise ContractError("forbidden")
    proof = EnrichmentProof(
        action,
        context.access.project_id,
        context.access.actor_id,
        hashlib.sha256(raw).hexdigest(),
        state_digest,
        evidence_refs,
        raw,
        run_id,
        operation_key,
    )
    try:
        allowed = context.authority.approve(proof)
    except Exception:
        raise ContractError("forbidden") from None
    if allowed is not True:
        raise ContractError("forbidden")
