"""Local evidence and release authorities: facts a trusted operator process can stand behind.

Trust model:

* An authority answers "what is true?" for the ledger and the control side. It never repeats what
  the request, the staged result or the worker says about itself: each fact comes from a source
  this process holds on its own, and a fact it cannot source is withheld (a refusal) or reduced to
  the weakest honest answer (``unknown_outcome``, ``estimated``, ``unknown``).
* Observation facts come only from the live session's own records of the calls it spawned. The
  evidence bytes an observation carries (a record of what the executor saw, which in turn quotes
  the worker's return value) are never read. A call the session does not hold, or a state its
  record does not support, is at most an ``unknown_outcome``. Trust boundary: a record says only
  that a call completed, was cancelled or is running; it holds neither the outcome nor a result
  digest. So ``succeeded`` versus ``failed`` and ``result_digest`` are taken from the
  executor-verified claim (the staged result reference, hash-checked by the executor against
  the attempt prefix), and are attested only for a call the record shows completed.
* Estimate facts come from the operator's reviewed cost estimate (the document the preflight
  packet binds) and from the operator-pinned plans. No tariff is computed here. The ledger's
  six-category breakdown is coarser than the estimate's, so categories with no reviewed line carry
  zero.
* Billing stays ``estimated`` (or ``unknown`` when the event itself says so) unless a billing
  callable, fed by the operator's billing document, reports ``actual`` facts. No estimate is ever
  final.
* Transport facts are the scopes the credential issuer itself reports for the pinned plan and the
  attempt, so what is attested is what is minted. The authority never mints and never sees a
  credential's content.
* Install-run-authorization grants are not attested here: no independent approval source exists in
  this authority's inputs, and echoing the request would be self-certification.
* No secret, credential, signed URL or session internal is held in a fact, an error or a
  ``repr``; every refusal is a stable ``ContractError`` code.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from decimal import Decimal
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, get_args

from pydantic import TypeAdapter, ValidationError

from conscience_foundry.contracts.accounting import BudgetEvent
from conscience_foundry.contracts.common import ContractError, ContractLimits, Digest, Id, Ref
from conscience_foundry.contracts.execution import AttemptState, ExecutionConfig, ExecutionPlan
from conscience_foundry.execution.evidence import encoded, identity
from conscience_foundry.execution.ports import (
    BillingFacts,
    BudgetProof,
    CapabilityFacts,
    ControlFacts,
    ControlProof,
    CostAllocation,
    EstimateFacts,
    GrantFacts,
    ObservationFacts,
    ObservationProof,
    TransportFacts,
    TransportProof,
)
from conscience_foundry.operator.packet import CostEstimate, CostLine
from conscience_foundry.release.context import Action, ReleaseApproval, ReleaseProof

if TYPE_CHECKING:
    from conscience_foundry.execution.modal_live import CallRecord, LiveModalSession
    from conscience_foundry.storage.r2 import R2CredentialIssuer

EvidenceLabel = Literal["live", "synthetic_offline"]
ESTIMATE_SCHEMA = "cfoundry.cost-estimate.v1"
BUDGET_EVENT_SCHEMA = "cf.budget-event.v1"
_DIGEST = TypeAdapter(Digest)
_ID = TypeAdapter(Id)

_ESTIMATE_PURPOSES = frozenset({"reserve_attempt", "reserve_storage"})
_BILLING_PURPOSES = frozenset(
    {"record_usage", "final_billing", "billing_adjustment", "release_unspent", "final_no_effect"}
)
LedgerCategory = Literal["cpu", "ram", "runtime", "transfer", "storage", "region"]
_ATTEMPT_LINES: Mapping[str, LedgerCategory] = MappingProxyType(
    {"compute": "cpu", "startup": "runtime", "restart": "region", "transfer": "transfer"}
)
"""The estimate's attempt categories, and the ledger category each is allocated to."""
_ZERO_CATEGORIES: tuple[LedgerCategory, ...] = ("ram", "storage")
"""Attempt categories the reviewed estimate has no attempt-scoped line for: they carry zero.
Run storage is reserved separately by ``reserve-storage``."""
_CONTROL_ACTIONS = frozenset(
    {"pause", "resume", "cancel_attempt", "mark_unknown_outcome", "reconcile_budget"}
)
_RELEASE_ACTIONS = frozenset(get_args(Action))
_MATERIAL_PIECES = 2
"""A staging grant is exactly two credentials: read-only first, read-write second."""


def _refuse(code: str = "forbidden") -> ContractError:
    return ContractError(code)


@dataclass(frozen=True)
class PlanPin:
    """One plan the operator reviewed, with the execution config it names.

    The reference is the plan's canonical digest, so a pin is exactly one plan: a ref that is not
    the plan's own digest cannot be pinned. The capability facts and the transport scopes are
    derived from the pin, never from the request.
    """

    ref: Ref
    plan: ExecutionPlan
    config: ExecutionConfig

    def __post_init__(self) -> None:
        if (
            type(self.ref) is not Ref
            or type(self.plan) is not ExecutionPlan
            or type(self.config) is not ExecutionConfig
            or self.ref.digest != hashlib.sha256(encoded(self.plan)).hexdigest()
            or self.ref.project_id != self.plan.project_id
        ):
            raise _refuse()

    @property
    def capability(self) -> CapabilityFacts:
        return CapabilityFacts(
            execution_config_ref=self.plan.execution_config_ref,
            tariff_ref=self.config.tariff_ref,
            resource_policy_ref=self.config.resource_policy_ref,
            image_digest=self.config.image_digest,
            destination_id=self.config.remote_destination_id,
            resources=self.plan.resources,
        )


class LocalEvidenceAuthority:
    """The ``EvidenceAuthority`` for one operator process; see the module notes for what it trusts.

    ``decoders`` are the operator-pinned schema decoders (the estimate's schema must be one).
    ``session`` is the live Modal session whose records back the observation facts, or ``None``
    when there is none (offline). ``issuer`` reports the credential scopes. ``estimate_ref`` is the
    reviewed estimate. ``billing`` maps an attempt id to the facts of the operator's billing
    document, or is ``None`` while there is none. ``label`` says which kind of evidence this is.

    ``plans`` (the operator-pinned plans) and ``limits_by_schema`` (the bounds the estimate and
    the budget events are decoded with) are keyword-only because the estimate and transport facts
    cannot be sourced without them; without them those facts are refused.
    """

    def __init__(
        self,
        decoders: Mapping[str, Callable[[bytes, ContractLimits], object]],
        session: LiveModalSession | None,
        issuer: R2CredentialIssuer,
        estimate_ref: Ref,
        billing: Callable[[Id], BillingFacts] | None,
        label: EvidenceLabel,
        *,
        plans: tuple[PlanPin, ...] = (),
        limits_by_schema: Mapping[str, ContractLimits] | None = None,
    ) -> None:
        if (
            label not in get_args(EvidenceLabel)
            or (label == "live" and session is None)
            or type(estimate_ref) is not Ref
            or not isinstance(decoders, Mapping)
            or (billing is not None and not callable(billing))
            or not callable(getattr(issuer, "scopes", None))
            or type(plans) is not tuple
            or any(type(pin) is not PlanPin for pin in plans)
            or len({pin.ref.digest for pin in plans}) != len(plans)
        ):
            raise ContractError("invalid_schema")
        self.decoders: Mapping[str, Callable[[bytes, ContractLimits], object]] = MappingProxyType(
            dict(decoders)
        )
        self.label: EvidenceLabel = label
        self._session, self._issuer = session, issuer
        self._estimate_ref, self._billing = estimate_ref, billing
        self._plans = {pin.ref.digest: pin for pin in plans}
        self._limits = MappingProxyType(dict(limits_by_schema or {}))

    def __repr__(self) -> str:
        return f"LocalEvidenceAuthority(label={self.label!r})"

    # -- budget -----------------------------------------------------------------------

    def budget(self, proof: BudgetProof) -> GrantFacts | EstimateFacts | BillingFacts:
        purpose = proof.claim.purpose
        if purpose in _ESTIMATE_PURPOSES:
            return self._estimate_facts(proof)
        if purpose in _BILLING_PURPOSES:
            return self._billing_facts(proof)
        # install_run_authorization, the reserve replay and anything unknown: not attestable here.
        raise _refuse()

    def _pin(self, digest: str) -> PlanPin:
        pin = self._plans.get(digest)
        if pin is None:
            raise _refuse()
        return pin

    def _estimate(self, proof: BudgetProof) -> CostEstimate:
        """The pinned estimate, decoded from exactly the pinned document's bytes."""
        claim = proof.claim
        data = proof.evidence_bytes
        limits = self._limits.get(ESTIMATE_SCHEMA)
        decode = self.decoders.get(ESTIMATE_SCHEMA)
        if (
            identity(claim.evidence_ref) != identity(self._estimate_ref)
            or type(data) is not bytes
            or hashlib.sha256(data).hexdigest() != self._estimate_ref.digest
            or len(data) != self._estimate_ref.size_bytes
            or limits is None
            or decode is None
        ):
            raise _refuse()
        try:
            estimate = decode(data, limits)
        except Exception:
            raise _refuse() from None
        if type(estimate) is not CostEstimate:
            raise _refuse()
        auth = proof.authorization
        if (
            estimate.project_id != claim.project_id
            or estimate.currency != "USD"
            or estimate.reviewed_by != auth.actor_id
            or estimate.reviewed_at >= estimate.valid_until
        ):
            raise _refuse()
        return estimate

    def _estimate_facts(self, proof: BudgetProof) -> EstimateFacts:
        claim = proof.claim
        estimate = self._estimate(proof)
        pins: tuple[PlanPin, ...]
        if claim.purpose == "reserve_attempt":
            if claim.plan_ref is None:
                raise _refuse()
            pins = (self._pin(claim.plan_ref.digest),)
            ceiling, allocations = _attempt_allocations(estimate)
        else:
            pins = tuple(self._pin(digest) for digest in proof.authorization.allowed_plan_digests)
            ceiling, allocations = _storage_allocations(estimate)
        for pin in pins:  # one tariff: the plan's, and the one the estimate was reviewed against
            if identity(estimate.tariff_ref) != identity(pin.config.tariff_ref):
                raise _refuse()
        # Plans the control side verified from the store must be the very plans pinned here.
        for verified in proof.plans:
            pin = self._pin(verified.ref.digest)
            if verified.model != pin.plan or verified.config != pin.config:
                raise _refuse()
        return EstimateFacts(
            binding=proof.binding,
            amount_ceiling_usd=ceiling,
            currency="USD",
            plan_refs=tuple(pin.ref for pin in pins),
            capabilities=tuple(pin.capability for pin in pins),
            allocations=allocations,
            funded_from=estimate.reviewed_at,
            funded_until=estimate.valid_until,
            first_upload_at=None,
        )

    def _billing_facts(self, proof: BudgetProof) -> BillingFacts:
        claim = proof.claim
        if self._billing is not None:
            if claim.attempt_id is None:
                raise _refuse()
            try:
                reported = self._billing(claim.attempt_id)
            except Exception:
                raise _refuse() from None
            if (
                type(reported) is not BillingFacts
                or reported.cost_status not in ("actual", "estimated", "unknown")
                or (reported.cost_status == "actual") != (reported.amount_usd is not None)
                or (reported.cost_status == "unknown" and reported.amount_usd is not None)
                or (
                    reported.cost_status != "actual"
                    and (reported.final or reported.no_further_liability)
                )
            ):
                raise _refuse()
            # The report carries the operator's figures; the binding is this request's.
            return replace(reported, binding=proof.binding)
        if (
            claim.purpose == "record_usage"
            and self._event_cost_status(claim.request_bytes) == "unknown"
        ):
            return BillingFacts(proof.binding, "unknown", None, False, False, False)
        if claim.plan_ref is None or claim.attempt_id is None:
            raise _refuse()
        bound = self._pin(claim.plan_ref.digest).plan.budget.max_attempt_cost
        return BillingFacts(proof.binding, "estimated", bound, False, False, False)

    def _event_cost_status(self, request: bytes) -> str:
        limits = self._limits.get(BUDGET_EVENT_SCHEMA)
        if limits is None:
            raise _refuse()
        try:
            return BudgetEvent.from_wire(request, limits).cost_status
        except Exception:
            raise _refuse() from None

    # -- observation ------------------------------------------------------------------

    def observation(self, proof: ObservationProof) -> ObservationFacts:
        attempt, claimed = proof.attempt, proof.observation
        call_id = attempt.remote_call_id
        record = self._record(call_id)
        state: AttemptState = "unknown_outcome"
        confirmed = False
        if record is not None and claimed.state in _supported(record):
            state = claimed.state
            # Only an ended call is confirmed ended; unknown or pending states confirm nothing.
            confirmed = state in ("succeeded", "failed", "cancelled")
        result = (
            claimed.result_ref.digest
            if state in ("succeeded", "failed") and claimed.result_ref
            else None
        )
        return ObservationFacts(
            binding=proof.binding,
            remote_call_id=call_id,
            state=state,
            result_digest=result,
            # A spawned call may have run: absence of effect is never attested from a record.
            no_external_effect=False,
            confirmed_termination=confirmed,
        )

    def _record(self, call_id: str | None) -> CallRecord | None:
        if self._session is None or call_id is None:
            return None
        try:
            return self._session.records.get(call_id)
        except Exception:
            return None

    # -- control ----------------------------------------------------------------------

    def control(self, proof: ControlProof) -> ControlFacts:
        if proof.action not in _CONTROL_ACTIONS:
            raise _refuse()  # a manual retry acknowledges a duplicate charge: never self-attested
        return ControlFacts(
            binding=proof.binding,
            actor_id=proof.actor_id,
            action=proof.action,
            snapshot_digest=proof.snapshot_digest,
            unresolved_attempt_ids=(),
            acknowledges_duplicate_charge_risk=False,
            liabilities_resolved=proof.action == "reconcile_budget" and self._calls_settled(),
        )

    def _calls_settled(self) -> bool:
        """Every call this session spawned has finished, or was cancelled and terminated."""
        if self._session is None:
            return False
        try:
            records = tuple(self._session.records.values())
        except Exception:
            return False
        # A session that holds no call vouches for nothing (e.g. a new one after a crash).
        return bool(records) and all(r.completed or (r.terminated and r.cancelled) for r in records)

    # -- transport --------------------------------------------------------------------

    def transport(self, proof: TransportProof) -> TransportFacts:
        pin = self._pin(proof.plan_digest)
        plan = pin.plan
        if len(proof.material) != _MATERIAL_PIECES or proof.expires_at > min(
            plan.expires_at, plan.budget.valid_until
        ):
            raise _refuse()
        try:
            read_keys, write_prefix = self._issuer.scopes(plan, proof.attempt_id)
            output = f"{self._issuer.bucket}/{write_prefix}".encode()
        except Exception:
            raise _refuse() from None
        parts = write_prefix.rstrip("/").split("/")
        attempt_prefix = (
            len(parts) >= 3
            and write_prefix.endswith("/")
            and parts[-2] == "attempts"
            and parts[-3] == plan.project_id
        )
        output_attempt = parts[-1] if attempt_prefix else ""
        return TransportFacts(
            project_id=plan.project_id,
            plan_digest=pin.ref.digest,
            attempt_id=proof.attempt_id,
            destination_id=pin.config.remote_destination_id,
            expires_at=proof.expires_at,
            input_refs=plan.input_refs,
            material_fingerprint=proof.material_fingerprint,
            output_scope=output,
            output_attempt_id=output_attempt,
            attempt_isolated=(
                attempt_prefix
                and output_attempt == proof.attempt_id
                and not any(key.startswith(write_prefix) for key in read_keys)
            ),
        )


def _supported(record: CallRecord) -> frozenset[str]:
    """The attempt states a session's record of one call can stand behind, besides unknown."""
    supported = {"unknown_outcome"}
    if record.completed:
        supported |= {"succeeded", "failed"}
    elif record.cancelled and record.terminated:
        supported.add("cancelled")
    elif record.terminated:
        supported.add("cancel_requested")
    elif not record.cancelled:
        supported.add("running")
    return frozenset(supported)


def _lines(estimate: CostEstimate) -> tuple[Mapping[str, CostLine], CostLine]:
    """Exactly one reviewed, priced line per attempt category and one run-storage line."""
    attempt: dict[str, CostLine] = {}
    storage: list[CostLine] = []
    for line in estimate.lines:
        if line.status != "estimated" or line.amount_usd is None:
            raise _refuse()
        if line.scope == "attempt" and line.category in _ATTEMPT_LINES:
            if line.category in attempt:
                raise _refuse()
            attempt[line.category] = line
        elif line.scope == "run_storage" and line.category == "storage":
            storage.append(line)
        else:
            raise _refuse()
    if set(attempt) != set(_ATTEMPT_LINES) or len(storage) != 1:
        raise _refuse()
    return attempt, storage[0]


def _agrees(declared: str, amounts: list[str]) -> bool:
    try:
        total = sum((Decimal(amount) for amount in amounts), Decimal(0))
        return Decimal(declared) > 0 and total == Decimal(declared)
    except Exception:
        return False


def _attempt_allocations(estimate: CostEstimate) -> tuple[str, tuple[CostAllocation, ...]]:
    attempt, _ = _lines(estimate)
    amounts = [str(line.amount_usd) for line in attempt.values()]
    if not _agrees(estimate.max_attempt_usd, amounts):
        raise _refuse()
    allocations = tuple(
        CostAllocation(_ATTEMPT_LINES[category], str(attempt[category].amount_usd))
        for category in _ATTEMPT_LINES
    ) + tuple(CostAllocation(category, "0") for category in _ZERO_CATEGORIES)
    return estimate.max_attempt_usd, allocations


def _storage_allocations(estimate: CostEstimate) -> tuple[str, tuple[CostAllocation, ...]]:
    _, storage = _lines(estimate)
    if not _agrees(estimate.run_storage_usd, [str(storage.amount_usd)]):
        raise _refuse()
    return estimate.run_storage_usd, (CostAllocation("storage", str(storage.amount_usd)),)


class LocalReleaseAuthority:
    """The ``ReleaseAuthority`` for one project: approves that project's release actions only.

    The approval is bound to what the proof's own bytes prove: the request digest is recomputed
    from the request bytes and the evidence digest from the evidence bytes, never taken from the
    proof's claims.

    ``policy_digest`` is the operator's pin. ``current_policy_digest`` is a lookup of the digest
    of the policy currently in force for the project (the caller's own source, e.g. the digest of
    what ``ReleaseContext.current_policy`` returns). It is called on every ``approve`` and must
    equal the pin; a different policy, a failing lookup or a malformed answer is ``forbidden``
    (fail closed). The proof carries no policy of its own, so nothing the request says can
    satisfy the pin.
    """

    def __init__(
        self,
        project_id: Id,
        policy_digest: Digest,
        *,
        current_policy_digest: Callable[[], Digest],
    ) -> None:
        try:
            self.project_id: Id = _ID.validate_python(project_id)
            self.policy_digest: Digest = _DIGEST.validate_python(policy_digest)
        except ValidationError:
            raise ContractError("invalid_schema") from None
        if not callable(current_policy_digest):
            raise ContractError("invalid_schema")
        self._current_policy_digest = current_policy_digest

    def __repr__(self) -> str:
        return f"LocalReleaseAuthority(project_id={self.project_id!r})"

    def approve(self, proof: ReleaseProof) -> ReleaseApproval:
        if (
            type(proof) is not ReleaseProof
            or proof.project_id != self.project_id
            or proof.action not in _RELEASE_ACTIONS
            or type(proof.request_bytes) is not bytes
        ):
            raise _refuse()
        digest = hashlib.sha256(proof.request_bytes).hexdigest()
        if proof.request_digest != digest:
            raise _refuse()
        self._policy_pin()
        evidence = proof.evidence_ref
        if evidence is None:
            if proof.evidence_bytes is not None:
                raise _refuse()
        elif (
            evidence.project_id != self.project_id
            or type(proof.evidence_bytes) is not bytes
            or hashlib.sha256(proof.evidence_bytes).hexdigest() != evidence.digest
            or len(proof.evidence_bytes) != evidence.size_bytes
        ):
            raise _refuse()
        return ReleaseApproval(
            project_id=self.project_id,
            actor_id=proof.actor_id,
            action=proof.action,
            request_digest=digest,
            state_digest=proof.state_digest,
            evidence_digest=evidence.digest if evidence is not None else None,
            revision_ref=proof.revision_ref,
        )

    def _policy_pin(self) -> None:
        try:
            current = _DIGEST.validate_python(self._current_policy_digest())
        except Exception:
            raise _refuse() from None
        if current != self.policy_digest:
            raise _refuse()
