"""Trusted local capabilities; local execution is cooperative, not a sandbox."""

from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from typing import Protocol

from conscience_foundry.contracts.common import Digest, Id, Instant, Ref


@dataclass(frozen=True)
class TransportGrants:
    """Transient tokens; only a trusted transport adapter can establish scope.

    ``material`` holds one opaque piece per credential. For R2 it is exactly two, read-only first
    and read-write second (see ``conscience_foundry.storage.r2``): the worker reads declared
    inputs with the first and writes and reads back under its attempt prefix with the second.
    """

    project_id: Id
    plan_digest: Digest
    attempt_id: Id
    destination_id: str
    expires_at: Instant
    material: tuple[bytes, ...] = field(repr=False)
    output_scope: bytes = field(repr=False)


@dataclass(frozen=True)
class LocalWorkerGrant:
    project_id: Id
    run_id: Id
    plan_digest: Digest
    attempt_id: Id
    destination_id: str
    expires_at: Instant
    output_scope: bytes = field(repr=False)
    nonce: str = field(repr=False)


@dataclass(frozen=True)
class LocalGrantProof:
    project_id: Id
    run_id: Id
    plan_digest: Digest
    attempt_id: Id
    destination_id: str
    expires_at: Instant
    input_refs: tuple[Ref, ...]
    output_scope: bytes = field(repr=False)
    nonce_digest: Digest = field(repr=False)


@dataclass(frozen=True)
class LocalGrantFacts(LocalGrantProof):
    scopes: frozenset[str]


class LocalGrantAuthority(Protocol):
    def local_grant(self, proof: LocalGrantProof) -> LocalGrantFacts: ...


class LocalWriteAuthority(Protocol):
    def write_permit(
        self, project_id: Id, run_id: Id, attempt_id: Id, ref: Ref
    ) -> AbstractContextManager[None]: ...
    def revalidate_write(self, project_id: Id, run_id: Id, attempt_id: Id, ref: Ref) -> None: ...
