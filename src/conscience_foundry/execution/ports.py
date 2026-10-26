"""Explicit trusted control ports; none is selected by untrusted artifact data."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Literal, Protocol

from conscience_foundry.contracts.accounting import ResourceUsage
from conscience_foundry.contracts.admission import SourceAsset
from conscience_foundry.contracts.common import ContractLimits, Digest, Id, Instant, Money, Ref
from conscience_foundry.contracts.execution import (
    AttemptState,
    ExecutionConfig,
    ExecutionPlan,
    ResourceEnvelope,
    RunAuthorization,
    StageAttempt,
)
from conscience_foundry.contracts.project import PolicyArtifact
from conscience_foundry.ledger.budget import BudgetEvidenceClaim
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.local import ObjectStore


@dataclass(frozen=True)
class Submission:
    remote_call_id: str | None
    accepted: bool | None


@dataclass(frozen=True)
class Observation:
    state: AttemptState
    result_ref: Ref | None
    usage: ResourceUsage | None
    evidence: Ref


@dataclass(frozen=True)
class TransportGrants:
    """Transient tokens; only a trusted transport adapter can establish scope."""

    project_id: Id
    plan_digest: Digest
    attempt_id: Id
    destination_id: str
    expires_at: Instant
    material: tuple[bytes, ...] = field(repr=False)
    output_scope: bytes = field(repr=False)


TransportIssuer = Callable[[StageAttempt], TransportGrants]
"""Mints transient grants for one attempt that is already reserved, funded and claimed.

Asked only after the claim commits, so no write-capable material exists for a dispatch the ledger
refused (budget, pause, an existing claim).
"""


@dataclass(frozen=True)
class TransportProof:
    """Bound transient request; adapters interpret opaque provider scope semantics."""

    project_id: Id
    plan_digest: Digest
    attempt_id: Id
    destination_id: str
    expires_at: Instant
    input_refs: tuple[Ref, ...]
    material: tuple[bytes, ...] = field(repr=False)
    material_fingerprint: Digest = field(repr=False)
    output_scope: bytes = field(repr=False)


@dataclass(frozen=True)
class TransportFacts:
    """Actual token scope independently attested by the trusted transport adapter."""

    project_id: Id
    plan_digest: Digest
    attempt_id: Id
    destination_id: str
    expires_at: Instant
    input_refs: tuple[Ref, ...]
    material_fingerprint: Digest = field(repr=False)
    output_scope: bytes = field(repr=False)
    output_attempt_id: Id
    attempt_isolated: bool


class Executor(Protocol):
    def submit(
        self, plan: ExecutionPlan, attempt: StageAttempt, grants: TransportGrants
    ) -> Submission: ...
    def observe(self, attempt: StageAttempt) -> Observation: ...
    def cancel(self, attempt: StageAttempt) -> Observation: ...


@dataclass(frozen=True)
class EvidenceBinding:
    evidence_digest: Digest
    request_digest: Digest
    project_id: Id
    run_id: Id | None
    reservation_id: Id | None
    attempt_id: Id | None
    authorization_digest: Digest | None
    plan_digest: Digest | None

    @classmethod
    def from_budget(cls, claim: BudgetEvidenceClaim) -> EvidenceBinding:
        return cls(
            claim.evidence_ref.digest,
            claim.request_digest,
            claim.project_id,
            claim.run_id,
            claim.reservation_id,
            claim.attempt_id,
            claim.authorization_ref.digest,
            claim.plan_ref.digest if claim.plan_ref is not None else None,
        )


@dataclass(frozen=True)
class GrantFacts:
    binding: EvidenceBinding
    approved_grant_digest: Digest
    actor_id: Id
    previous_authorization_id: Id | None


@dataclass(frozen=True)
class CapabilityFacts:
    execution_config_ref: Ref
    tariff_ref: Ref
    resource_policy_ref: Ref
    image_digest: Digest
    destination_id: str
    resources: ResourceEnvelope


@dataclass(frozen=True)
class CostAllocation:
    category: Literal["cpu", "ram", "runtime", "transfer", "storage", "region"]
    amount_usd: Money


@dataclass(frozen=True)
class EstimateFacts:
    binding: EvidenceBinding
    amount_ceiling_usd: Money
    currency: Literal["USD"]
    plan_refs: tuple[Ref, ...]
    capabilities: tuple[CapabilityFacts, ...]
    allocations: tuple[CostAllocation, ...]
    funded_from: Instant
    funded_until: Instant
    first_upload_at: Instant | None


@dataclass(frozen=True)
class BillingFacts:
    binding: EvidenceBinding
    cost_status: Literal["actual", "estimated", "unknown"]
    amount_usd: Money | None
    final: bool
    no_further_liability: bool
    no_external_effect: bool


@dataclass(frozen=True)
class ObservationFacts:
    binding: EvidenceBinding
    remote_call_id: str | None
    state: AttemptState
    result_digest: Digest | None
    no_external_effect: bool
    confirmed_termination: bool


@dataclass(frozen=True)
class ControlFacts:
    binding: EvidenceBinding
    actor_id: Id
    action: str
    snapshot_digest: Digest | None
    unresolved_attempt_ids: tuple[Id, ...]
    acknowledges_duplicate_charge_risk: bool
    liabilities_resolved: bool


@dataclass(frozen=True)
class VerifiedPlan:
    ref: Ref
    data: bytes = field(repr=False)
    model: ExecutionPlan
    authorization_ref: Ref
    authorization: RunAuthorization
    config: ExecutionConfig
    config_bytes: bytes = field(repr=False)
    tariff_bytes: bytes = field(repr=False)
    resource_policy_bytes: bytes = field(repr=False)
    source_asset: SourceAsset


@dataclass(frozen=True)
class BudgetProof:
    claim: BudgetEvidenceClaim
    binding: EvidenceBinding
    evidence_bytes: bytes = field(repr=False)
    authorization: RunAuthorization
    plans: tuple[VerifiedPlan, ...]
    funding_evidence_ref: Ref | None = None
    funding_evidence_bytes: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True)
class ObservationProof:
    binding: EvidenceBinding
    evidence_ref: Ref
    evidence_bytes: bytes = field(repr=False)
    request_bytes: bytes = field(repr=False)
    attempt: StageAttempt
    observation: Observation
    now: Instant


@dataclass(frozen=True)
class ControlProof:
    binding: EvidenceBinding
    evidence_ref: Ref
    evidence_bytes: bytes = field(repr=False)
    request_bytes: bytes = field(repr=False)
    actor_id: Id
    action: str
    snapshot_digest: Digest | None
    now: Instant


class EvidenceAuthority(Protocol):
    """Operator-pinned schema decoders and independently authenticated facts.

    Decoder installation and provider authenticity are external trusted adapter
    duties. There is no default adapter, unknown-schema JSON fallback or plugin
    loader. Facts must come from independent evidence, never request echoing.
    """

    decoders: Mapping[str, Callable[[bytes, ContractLimits], object]]

    def budget(self, proof: BudgetProof) -> GrantFacts | EstimateFacts | BillingFacts: ...
    def observation(self, proof: ObservationProof) -> ObservationFacts: ...
    def control(self, proof: ControlProof) -> ControlFacts: ...
    def transport(self, proof: TransportProof) -> TransportFacts: ...


@dataclass(frozen=True)
class ControlContext:
    access: AccessContext
    clock: Callable[[], Instant] = field(repr=False)
    limits_by_schema: Mapping[str, ContractLimits] = field(repr=False)
    current_policy: Callable[[Id], PolicyArtifact] = field(repr=False)
    authorize: Callable[[str, Id, Id | None, Id], bool] = field(repr=False)
    evidence_authority: EvidenceAuthority = field(repr=False)
    output_store_id: str
    store: ObjectStore = field(repr=False)
    transport_limits: ContractLimits = field(repr=False)


@dataclass(frozen=True)
class ManualRetry:
    evidence_ref: Ref
    expected_snapshot_digest: Digest
    unresolved_attempt_ids: tuple[Id, ...]
