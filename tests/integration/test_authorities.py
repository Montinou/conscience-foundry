"""Local evidence and release authorities, offline and database-free.

Every identifier, key and token below is synthetic. The authorities are driven with hand-built
proofs, the way the ledger and the control side would build them; the Cloudflare API is a fake
that fails the test if it is ever called (an authority attests scopes, it never mints).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import replace
from typing import Any, cast

import pytest

from conscience_foundry.cli.authorities import (
    LocalEvidenceAuthority,
    LocalReleaseAuthority,
    PlanPin,
)
from conscience_foundry.contracts.common import ContractError, ContractLimits, Ref
from conscience_foundry.contracts.execution import (
    ExecutionConfig,
    ExecutionPlan,
    RunAuthorization,
    StageAttempt,
)
from conscience_foundry.execution.evidence import encoded
from conscience_foundry.execution.modal_live import (
    CallRecord,
    LiveFunctionOptions,
    LiveModalSession,
)
from conscience_foundry.execution.ports import (
    BillingFacts,
    BudgetProof,
    CapabilityFacts,
    ControlProof,
    CostAllocation,
    EstimateFacts,
    EvidenceBinding,
    GrantFacts,
    Observation,
    ObservationProof,
    TransportProof,
    VerifiedPlan,
)
from conscience_foundry.ledger.budget import BudgetEvidenceClaim
from conscience_foundry.operator.packet import CostEstimate
from conscience_foundry.release.context import ReleaseProof
from conscience_foundry.storage.r2 import R2CredentialIssuer

PROJECT = "00000000-0000-0000-0000-000000000001"
ACTOR = "00000000-0000-0000-0000-000000000002"
OTHER_PROJECT = "00000000-0000-0000-0000-000000000003"
RUN = "00000000-0000-0000-0000-0000000000a2"
PLAN_ID = "00000000-0000-0000-0000-0000000000a1"
ATTEMPT = "00000000-0000-0000-0000-0000000000a3"
RESERVATION = "00000000-0000-0000-0000-0000000000a4"
AUTH_ID = "00000000-0000-0000-0000-0000000000a5"
NOW = "2030-01-01T00:00:00.000Z"
LATER = "2030-01-01T01:00:00.000Z"
BUCKET = "synthetic-staging"
PREFIX = "staging/f1"
CALL = "synthetic-call-id"
OTHER_CALL = "synthetic-other-call-id"
SECRET = "synthetic-token-canary"
ESTIMATE_SCHEMA = "cfoundry.cost-estimate.v1"
POLICY_DIGEST = "b" * 64
LIMITS = ContractLimits(
    schema_version="cf.contract-limits.v1",
    version="synthetic.v1",
    max_json_bytes=65536,
    max_string_scalars=1024,
    max_array_items=64,
    max_depth=16,
    max_manifest_items=8,
    max_source_bytes=4096,
    max_output_bytes=65536,
    max_error_message_scalars=80,
)
LIMITS_BY_SCHEMA: Mapping[str, ContractLimits] = {
    ESTIMATE_SCHEMA: LIMITS,
    "cf.budget-event.v1": LIMITS,
}


def ref_wire(schema: str, seed: str, size: int = 10) -> dict[str, Any]:
    return {
        "schemaVersion": "cf.artifact-ref.v1",
        "projectId": PROJECT,
        "digest": hashlib.sha256(seed.encode()).hexdigest(),
        "sizeBytes": size,
        "mediaType": "application/json",
        "artifactSchema": schema,
        "locations": [],
    }


def make_ref(schema: str, seed: str) -> Ref:
    return Ref.model_validate(ref_wire(schema, seed))


def make_plan() -> ExecutionPlan:
    return ExecutionPlan.model_validate(
        {
            "schemaVersion": "cf.execution-plan.v1",
            "projectId": PROJECT,
            "runId": RUN,
            "planId": PLAN_ID,
            "executionConfigRef": ref_wire("cf.execution-config.v1", "config"),
            "admissionReportRef": ref_wire("cf.admission-report.v1", "report"),
            "extractionSpecRef": ref_wire("cf.extraction-spec.v1", "spec"),
            "policyRef": ref_wire("cf.policy.v1", "policy"),
            "profileId": "synthetic.profile",
            "profileVersion": "v1",
            "contractSetRef": ref_wire("cf.contract-set.v1", "contracts"),
            "limitsRefs": [ref_wire("cf.contract-limits.v1", "limits")],
            "inputRefs": [ref_wire("cf.raw-original.v1", "input")],
            "operationKey": hashlib.sha256(b"operation").hexdigest(),
            "resources": {
                "cpuMilli": 100,
                "memoryMiB": 64,
                "gpuCount": 0,
                "maxWallSeconds": 10,
                "maxOutputBytes": 4096,
                "maxConcurrentAttempts": 1,
                "maxAttemptsPerOperation": 1,
                "automaticRetries": 0,
            },
            "budget": {
                "currency": "USD",
                "maxRunCost": "2",
                "maxAttemptCost": "1",
                "tariffRef": ref_wire("cf.tariff.v1", "tariff"),
                "authorizationId": AUTH_ID,
                "validUntil": LATER,
            },
            "expiresAt": LATER,
        }
    )


def make_config() -> ExecutionConfig:
    return ExecutionConfig(
        schema_version="cf.execution-config.v1",
        adapter_id="synthetic.worker",
        deployment_version="synthetic.v1",
        image_digest="a" * 64,
        tariff_ref=make_ref("cf.tariff.v1", "tariff"),
        resource_policy_ref=make_ref("cf.resource-policy.v1", "resources"),
        remote_destination_id="synthetic.worker",
    )


def make_pin() -> PlanPin:
    plan = make_plan()
    data = encoded(plan)
    ref = Ref.model_validate(
        {
            **ref_wire("cf.execution-plan.v1", "unused"),
            "digest": hashlib.sha256(data).hexdigest(),
            "sizeBytes": len(data),
        }
    )
    return PlanPin(ref, plan, make_config())


def line(category: str, scope: str, amount: str, basis: str = "synthetic basis") -> dict[str, Any]:
    return {
        "category": category,
        "scope": scope,
        "status": "estimated",
        "amountUsd": amount,
        "tariffRef": ref_wire("cf.tariff.v1", "tariff"),
        "basis": basis,
    }


def make_estimate(**changes: Any) -> CostEstimate:
    wire: dict[str, Any] = {
        "schemaVersion": ESTIMATE_SCHEMA,
        "projectId": PROJECT,
        "currency": "USD",
        "tariffRef": ref_wire("cf.tariff.v1", "tariff"),
        "maxAttemptUsd": "0.9",
        "runStorageUsd": "0.25",
        "lines": [
            line("compute", "attempt", "0.5"),
            line("startup", "attempt", "0.1"),
            line("restart", "attempt", "0.1"),
            line("transfer", "attempt", "0.2"),
            line("storage", "run_storage", "0.25"),
        ],
        "reviewedBy": ACTOR,
        "reviewedAt": "2029-12-31T00:00:00.000Z",
        "validUntil": LATER,
    }
    return CostEstimate.model_validate(wire | changes)


def estimate_ref(estimate: CostEstimate) -> Ref:
    data = encoded(estimate)
    return Ref.model_validate(
        {
            **ref_wire(ESTIMATE_SCHEMA, "unused"),
            "digest": hashlib.sha256(data).hexdigest(),
            "sizeBytes": len(data),
        }
    )


def make_authorization(pin: PlanPin) -> RunAuthorization:
    return RunAuthorization(
        schema_version="cf.run-authorization.v1",
        authorization_id=AUTH_ID,
        project_id=PROJECT,
        run_id=RUN,
        admission_report_digest="c" * 64,
        allowed_plan_digests=(pin.ref.digest,),
        max_run_cost="2",
        max_concurrent_attempts=1,
        actor_id=ACTOR,
        authorized_at="2029-12-31T00:00:00.000Z",
        expires_at=LATER,
    )


class Http:
    """The Cloudflare API double; an authority must never reach it."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, path: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls += 1
        raise AssertionError("an authority attests scopes; it never mints")


def make_issuer(http: Http) -> R2CredentialIssuer:
    return R2CredentialIssuer(
        account_id="synthetic-account-id",
        bucket=BUCKET,
        prefix=PREFIX,
        parent_access_key_id="synthetic-parent-key-id",
        token_env="SYNTHETIC_R2_API_TOKEN",
        total_bound_seconds=120,
        clock=lambda: NOW,
        http=http,
    )


class FixedClock:
    def now(self) -> str:
        return NOW


def make_session(records: Mapping[str, CallRecord] | None = None) -> LiveModalSession:
    session = LiveModalSession(
        "synthetic-profile",
        LiveFunctionOptions(
            app_name="synthetic-app",
            function_name="synthetic-function",
            python_version="3.12",
            requirements_path="synthetic-requirements.txt",
            cpu_milli=100,
            memory_mib=64,
            startup_timeout_seconds=10,
            execution_timeout_seconds=10,
        ),
        30,
        FixedClock(),
    )
    # The session records the calls it spawns; the fake modal flow is covered in its own tests.
    for call_id, record in (records or {}).items():
        session._records[call_id] = record
    return session


def decoders() -> Mapping[str, Any]:
    return {ESTIMATE_SCHEMA: CostEstimate.from_wire}


class Rig:
    """One authority plus the documents it is pinned to."""

    def __init__(
        self,
        *,
        session: LiveModalSession | None = None,
        billing: Any = None,
        label: Any = "synthetic_offline",
        estimate: CostEstimate | None = None,
    ) -> None:
        self.http = Http()
        self.issuer = make_issuer(self.http)
        self.pin = make_pin()
        self.estimate = estimate or make_estimate()
        self.estimate_bytes = encoded(self.estimate)
        self.estimate_ref = estimate_ref(self.estimate)
        self.auth = make_authorization(self.pin)
        self.auth_ref = make_ref("cf.run-authorization.v1", "auth")
        self.authority = LocalEvidenceAuthority(
            decoders(),
            session,
            self.issuer,
            self.estimate_ref,
            billing,
            label,
            plans=(self.pin,),
            limits_by_schema=LIMITS_BY_SCHEMA,
        )

    def claim(
        self,
        purpose: str,
        evidence: Ref | None = None,
        *,
        request: bytes = b"{}",
        attempt: bool = False,
        plan: bool = False,
    ) -> BudgetEvidenceClaim:
        return BudgetEvidenceClaim(
            purpose,
            evidence or self.estimate_ref,
            PROJECT,
            RUN,
            RESERVATION,
            ATTEMPT if attempt else None,
            NOW,
            self.auth_ref,
            self.pin.ref if plan else None,
            None,
            request,
            hashlib.sha256(request).hexdigest(),
        )

    def proof(
        self,
        claim: BudgetEvidenceClaim,
        *,
        evidence_bytes: bytes | None = None,
        plans: tuple[VerifiedPlan, ...] = (),
    ) -> BudgetProof:
        return BudgetProof(
            claim,
            EvidenceBinding.from_budget(claim),
            self.estimate_bytes if evidence_bytes is None else evidence_bytes,
            self.auth,
            plans,
        )

    def verified(self) -> VerifiedPlan:
        return VerifiedPlan(
            self.pin.ref,
            b"",
            self.pin.plan,
            self.auth_ref,
            self.auth,
            self.pin.config,
            b"",
            b"",
            b"",
            cast(Any, None),
        )

    def attempt(self, state: str = "dispatching", call_id: str | None = CALL) -> StageAttempt:
        return StageAttempt.model_validate(
            {
                "schemaVersion": "cf.stage-attempt.v1",
                "projectId": PROJECT,
                "planId": PLAN_ID,
                "operationKey": self.pin.plan.operation_key,
                "attemptId": ATTEMPT,
                "attemptNumber": 1,
                "reservationId": RESERVATION,
                "state": state,
                "createdAt": NOW,
                **({"remoteCallId": call_id} if call_id else {}),
            }
        )

    def observation_proof(
        self,
        state: str,
        *,
        attempt_state: str = "dispatching",
        call_id: str | None = CALL,
        result: Ref | None = None,
        evidence_bytes: bytes = b"{}",
    ) -> ObservationProof:
        evidence = make_ref("cf.modal-call-observation.v1", "observation")
        observation = Observation(cast(Any, state), result, None, evidence)
        binding = EvidenceBinding(
            evidence.digest,
            "d" * 64,
            PROJECT,
            RUN,
            RESERVATION,
            ATTEMPT,
            self.auth_ref.digest,
            self.pin.ref.digest,
        )
        return ObservationProof(
            binding,
            evidence,
            evidence_bytes,
            b"{}",
            self.attempt(attempt_state, call_id),
            observation,
            NOW,
        )


# -- observation --------------------------------------------------------------------------------


def test_observation_refuses_worker_echo() -> None:
    """Evidence bytes that claim success prove nothing: only the session's own records count."""
    running = Rig(session=make_session({CALL: CallRecord(NOW)}))
    echo = json.dumps({"state": "succeeded", "remoteCallId": CALL}).encode()
    result = make_ref("cf.result.v1", "manifest")

    facts = running.authority.observation(
        running.observation_proof("succeeded", result=result, evidence_bytes=echo)
    )

    # The call is known but has not completed, so "succeeded" is not attestable.
    assert facts.state == "unknown_outcome"
    assert facts.result_digest is None
    assert facts.confirmed_termination is False and facts.no_external_effect is False

    # A completed call is attested from the record, and the evidence bytes change nothing.
    done = Rig(session=make_session({CALL: CallRecord(NOW, completed=True)}))
    same = done.observation_proof("succeeded", result=result, evidence_bytes=echo)
    other = done.observation_proof("succeeded", result=result, evidence_bytes=b"nonsense")
    first, second = done.authority.observation(same), done.authority.observation(other)
    assert first == second
    assert first.state == "succeeded" and first.remote_call_id == CALL
    assert first.result_digest == result.digest and first.confirmed_termination is True
    assert first.no_external_effect is False

    # An unknown outcome confirms nothing, even for a call that has ended.
    unclear = done.authority.observation(done.observation_proof("unknown_outcome"))
    assert unclear.state == "unknown_outcome" and unclear.confirmed_termination is False

    # A record that does not support the claimed state is never upgraded to it.
    assert (
        done.authority.observation(done.observation_proof("cancelled")).state == "unknown_outcome"
    )
    assert done.authority.observation(done.observation_proof("running")).state == "unknown_outcome"


def test_no_session_record_attests_unknown_at_most() -> None:
    for session in (
        None,
        make_session(),
        make_session({OTHER_CALL: CallRecord(NOW, completed=True)}),
    ):
        rig = Rig(session=session)
        for claimed in ("succeeded", "failed", "cancelled", "running", "unknown_outcome"):
            facts = rig.authority.observation(rig.observation_proof(claimed, result=None))
            assert facts.state == "unknown_outcome"
            assert facts.result_digest is None
            assert facts.confirmed_termination is False
            assert facts.no_external_effect is False
            # the ledger's own call id is carried so the unknown outcome can be recorded
            assert facts.remote_call_id == CALL
        nothing = rig.authority.observation(rig.observation_proof("unknown_outcome", call_id=None))
        assert nothing.remote_call_id is None and nothing.state == "unknown_outcome"


def test_observation_states_follow_the_record() -> None:
    cancelled = CallRecord(NOW, terminated=True, cancelled=True)
    asked = CallRecord(NOW, terminated=True)
    rig = Rig(session=make_session({CALL: cancelled}))
    facts = rig.authority.observation(
        rig.observation_proof("cancelled", attempt_state="cancel_requested")
    )
    assert facts.state == "cancelled" and facts.confirmed_termination is True
    assert facts.no_external_effect is False  # a spawned call may have run

    pending = Rig(session=make_session({CALL: asked}))
    waiting = pending.authority.observation(
        pending.observation_proof("cancel_requested", attempt_state="cancel_requested")
    )
    assert waiting.state == "cancel_requested" and waiting.confirmed_termination is False
    assert (
        pending.authority.observation(pending.observation_proof("running")).state
        == "unknown_outcome"
    )


def test_failed_observation_follows_the_record() -> None:
    result = make_ref("cf.result.v1", "manifest")
    done = Rig(session=make_session({CALL: CallRecord(NOW, completed=True)}))
    failed = done.authority.observation(done.observation_proof("failed", result=result))
    assert failed.state == "failed" and failed.confirmed_termination is True
    assert failed.result_digest == result.digest and failed.no_external_effect is False

    # a call that has not completed cannot be attested as failed
    running = Rig(session=make_session({CALL: CallRecord(NOW)}))
    unsupported = running.authority.observation(running.observation_proof("failed", result=result))
    assert unsupported.state == "unknown_outcome" and unsupported.result_digest is None
    assert unsupported.confirmed_termination is False


def test_observation_agrees_with_what_the_adapter_reports_for_unfinished_calls() -> None:
    """A state the executor derives from the same SDK answers must be one the record stands behind.

    Otherwise the control side sees the authority's facts disagree with the observation and
    refuses the reconcile, leaving the attempt as it was.
    """
    # a worker refusal that proved no result ends the call: the executor says failed (no lease)
    refused = Rig(session=make_session({CALL: CallRecord(NOW, remote_error=True)}))
    failed = refused.authority.observation(refused.observation_proof("failed"))
    assert failed.state == "failed" and failed.confirmed_termination is True
    assert failed.result_digest is None and failed.no_external_effect is False
    # the refusal proves no manifest, and nothing else: it is no success and no cancellation
    for claimed in ("succeeded", "cancelled", "running"):
        assert refused.authority.observation(refused.observation_proof(claimed)).state == (
            "unknown_outcome"
        )
    # a call that showed no refusal cannot be attested failed
    quiet = Rig(session=make_session({CALL: CallRecord(NOW)}))
    assert quiet.authority.observation(quiet.observation_proof("failed")).state == "unknown_outcome"

    # a cancel that was recorded in the ledger but never delivered stays a standing request
    standing = quiet.authority.observation(
        quiet.observation_proof("cancel_requested", attempt_state="cancel_requested")
    )
    assert standing.state == "cancel_requested" and standing.confirmed_termination is False
    assert standing.result_digest is None and standing.no_external_effect is False
    # ... for a refused call too, whose lease may be held (the request is kept, not settled)
    kept = refused.authority.observation(
        refused.observation_proof("cancel_requested", attempt_state="cancel_requested")
    )
    assert kept.state == "cancel_requested"
    # but a cancel nobody recorded is never attested, and neither is a call the session never saw
    unrequested = quiet.observation_proof("cancel_requested", attempt_state="running")
    assert quiet.authority.observation(unrequested).state == "unknown_outcome"
    stranger = Rig(session=make_session({OTHER_CALL: CallRecord(NOW)}))
    unseen = stranger.observation_proof("cancel_requested", attempt_state="cancel_requested")
    assert stranger.authority.observation(unseen).state == "unknown_outcome"


# -- budget -------------------------------------------------------------------------------------


def final_event(amount: str = "0.7") -> bytes:
    return json.dumps(
        {
            "schemaVersion": "cf.budget-event.v1",
            "projectId": PROJECT,
            "runId": RUN,
            "reservationId": RESERVATION,
            "scope": "attempt",
            "attemptId": ATTEMPT,
            "eventId": "00000000-0000-0000-0000-0000000000e1",
            "eventType": "settle",
            "amountUsd": amount,
            "costStatus": "actual",
            "evidenceRef": ref_wire("cf.billing-doc.v1", "bill"),
            "createdAt": NOW,
        }
    ).encode()


def test_billing_estimated_without_report() -> None:
    rig = Rig()  # no billing callable: no independent report
    claim = rig.claim("final_billing", request=final_event(), attempt=True, plan=True)
    facts = rig.authority.budget(rig.proof(claim, plans=(rig.verified(),)))

    assert isinstance(facts, BillingFacts)
    assert facts.cost_status == "estimated"
    assert facts.amount_usd == "1"  # the plan's attempt bound, not a worker or request figure
    assert facts.final is False and facts.no_further_liability is False
    assert facts.binding == EvidenceBinding.from_budget(claim)

    # An event that says the cost is unknown is attested unknown, never estimated into a number.
    unknown = json.loads(final_event())
    unknown |= {"eventType": "record_usage", "costStatus": "unknown"}
    del unknown["amountUsd"]
    usage = rig.claim("record_usage", request=json.dumps(unknown).encode(), attempt=True, plan=True)
    attested = rig.authority.budget(rig.proof(usage, plans=(rig.verified(),)))
    assert isinstance(attested, BillingFacts)
    assert attested.cost_status == "unknown" and attested.amount_usd is None

    # With the operator's billing document the status can be actual; nothing else makes it so.
    seen: list[str] = []

    def report(attempt_id: str) -> BillingFacts:
        seen.append(attempt_id)
        return BillingFacts(
            EvidenceBinding("0" * 64, "0" * 64, PROJECT, None, None, None, None, None),
            "actual",
            "0.7",
            True,
            True,
            False,
        )

    billed = Rig(billing=report)
    bill_claim = billed.claim("final_billing", request=final_event(), attempt=True, plan=True)
    actual = billed.authority.budget(billed.proof(bill_claim))
    assert isinstance(actual, BillingFacts)
    assert actual.cost_status == "actual" and actual.amount_usd == "0.7" and actual.final is True
    assert actual.binding == EvidenceBinding.from_budget(bill_claim)  # bound to this request
    assert seen == [ATTEMPT]


def test_billing_report_cannot_make_an_estimate_final() -> None:
    other = EvidenceBinding("0" * 64, "0" * 64, PROJECT, None, None, None, None, None)
    for facts in (
        BillingFacts(other, "estimated", "1", True, True, False),
        BillingFacts(other, "unknown", None, False, True, False),
        BillingFacts(other, "actual", None, True, True, False),
    ):
        rig = Rig(billing=lambda _attempt, facts=facts: facts)
        claim = rig.claim("final_billing", request=final_event(), attempt=True, plan=True)
        with pytest.raises(ContractError) as refused:
            rig.authority.budget(rig.proof(claim))
        assert refused.value.code == "forbidden"
    broken = Rig(billing=lambda _attempt: cast(Any, "nope"))
    claim = broken.claim("final_billing", request=final_event(), attempt=True, plan=True)
    with pytest.raises(ContractError):
        broken.authority.budget(broken.proof(claim))


def test_storage_reservation_facts_from_estimate() -> None:
    rig = Rig()
    claim = rig.claim("reserve_storage", request=b"{}")
    facts = rig.authority.budget(rig.proof(claim))

    assert isinstance(facts, EstimateFacts)
    # The storage line of the reviewed estimate: no tariff is computed here.
    assert facts.amount_ceiling_usd == "0.25" and facts.currency == "USD"
    assert facts.allocations == (CostAllocation("storage", "0.25"),)
    assert facts.plan_refs == (rig.pin.ref,)
    assert facts.capabilities == (
        CapabilityFacts(
            execution_config_ref=rig.pin.plan.execution_config_ref,
            tariff_ref=rig.pin.config.tariff_ref,
            resource_policy_ref=rig.pin.config.resource_policy_ref,
            image_digest=rig.pin.config.image_digest,
            destination_id="synthetic.worker",
            resources=rig.pin.plan.resources,
        ),
    )
    assert (facts.funded_from, facts.funded_until) == (
        rig.estimate.reviewed_at,
        rig.estimate.valid_until,
    )
    assert facts.first_upload_at is None
    assert facts.binding == EvidenceBinding.from_budget(claim)
    # The ledger asks twice, the second time with the verified plans: the answer must not move.
    assert rig.authority.budget(rig.proof(claim, plans=(rig.verified(),))) == facts


def test_attempt_estimate_facts_cover_every_category() -> None:
    rig = Rig()
    claim = rig.claim("reserve_attempt", request=encoded(rig.pin.plan), plan=True)
    facts = rig.authority.budget(rig.proof(claim, plans=(rig.verified(),)))

    assert isinstance(facts, EstimateFacts)
    assert facts.amount_ceiling_usd == "0.9"
    assert {item.category for item in facts.allocations} == {
        "cpu",
        "ram",
        "runtime",
        "transfer",
        "storage",
        "region",
    }
    from decimal import Decimal

    assert sum(Decimal(item.amount_usd) for item in facts.allocations) == Decimal("0.9")
    assert facts.plan_refs == (rig.pin.ref,)


def test_estimate_refused_when_not_the_pinned_document() -> None:
    rig = Rig()
    other = make_estimate(
        runStorageUsd="9", lines=make_estimate().model_dump(by_alias=True)["lines"]
    )
    other_ref = estimate_ref(other)
    claim = rig.claim("reserve_storage", evidence=other_ref)
    with pytest.raises(ContractError):
        rig.authority.budget(rig.proof(claim, evidence_bytes=encoded(other)))
    # The bytes must be the pinned document's bytes, not just carry its reference.
    with pytest.raises(ContractError):
        rig.authority.budget(rig.proof(rig.claim("reserve_storage"), evidence_bytes=encoded(other)))


def test_estimate_refused_when_it_does_not_hold() -> None:
    cases: dict[str, CostEstimate] = {
        "project": make_estimate(projectId=OTHER_PROJECT),
        "reviewer": make_estimate(reviewedBy=OTHER_PROJECT),
        "tariff": make_estimate(tariffRef=ref_wire("cf.tariff.v1", "another tariff")),
        "sum": make_estimate(maxAttemptUsd="0.8"),
    }
    for name, estimate in cases.items():
        rig = Rig(estimate=estimate)
        claim = rig.claim("reserve_attempt", request=encoded(rig.pin.plan), plan=True)
        with pytest.raises(ContractError, match="forbidden") as refused:
            rig.authority.budget(rig.proof(claim, plans=(rig.verified(),)))
        assert refused.value.code == "forbidden", name
        # the same rig, with the reviewed estimate, is attested: the refusal is about this case
        good = Rig()
        good.authority.budget(
            good.proof(
                good.claim("reserve_attempt", request=encoded(good.pin.plan), plan=True),
                plans=(good.verified(),),
            )
        )


def test_plan_pin_must_be_its_plans_canonical_digest() -> None:
    rig = Rig()
    with pytest.raises(ContractError):
        replace(rig.pin, ref=make_ref("cf.execution-plan.v1", "another plan"))


def test_estimate_refused_for_an_unpinned_plan() -> None:
    rig = Rig()
    unknown = replace(
        rig.claim("reserve_attempt", request=b"{}", plan=True),
        plan_ref=make_ref("cf.execution-plan.v1", "unknown"),
    )
    with pytest.raises(ContractError) as refused:
        rig.authority.budget(rig.proof(unknown))
    assert refused.value.code == "forbidden"
    # an authorization naming a plan nobody pinned cannot be reserved either
    grown = rig.auth.model_copy(update={"allowed_plan_digests": (rig.pin.ref.digest, "7" * 64)})
    storage = BudgetProof(
        rig.claim("reserve_storage"),
        EvidenceBinding.from_budget(rig.claim("reserve_storage")),
        rig.estimate_bytes,
        grown,
        (),
    )
    with pytest.raises(ContractError):
        rig.authority.budget(storage)


def test_grants_and_unknown_purposes_are_not_attested() -> None:
    rig = Rig()
    for purpose in ("install_run_authorization", "reserve", "anything_else"):
        with pytest.raises(ContractError) as refused:
            rig.authority.budget(rig.proof(rig.claim(purpose)))
        assert refused.value.code == "forbidden"


def grant_claim(
    rig: Rig, data: bytes, previous: str | None = None
) -> tuple[BudgetEvidenceClaim, Ref]:
    ref = Ref.model_validate(
        {
            **ref_wire("cf.run-authorization.v1", "unused"),
            "digest": hashlib.sha256(data).hexdigest(),
            "sizeBytes": len(data),
        }
    )
    claim = BudgetEvidenceClaim(
        "install_run_authorization",
        ref,
        PROJECT,
        RUN,
        None,
        None,
        NOW,
        ref,
        None,
        None,
        data,
        hashlib.sha256(data).hexdigest(),
        expected_previous_authorization_id=previous,
    )
    return claim, ref


def pinned_grant_authority(rig: Rig, digest: str | None) -> LocalEvidenceAuthority:
    return LocalEvidenceAuthority(
        decoders(),
        None,
        rig.issuer,
        rig.estimate_ref,
        None,
        "synthetic_offline",
        plans=(rig.pin,),
        limits_by_schema=LIMITS_BY_SCHEMA,
        approved_grant_digest=digest,
    )


def test_grant_facts_only_for_the_pinned_authorization() -> None:
    rig = Rig()
    data = encoded(rig.auth)
    pinned = hashlib.sha256(data).hexdigest()
    authority = pinned_grant_authority(rig, pinned)
    previous = "00000000-0000-0000-0000-0000000000b9"
    for expected_previous in (None, previous):
        claim, _ = grant_claim(rig, data, expected_previous)
        proof = BudgetProof(claim, EvidenceBinding.from_budget(claim), data, rig.auth, ())
        facts = authority.budget(proof)
        assert facts == GrantFacts(proof.binding, pinned, ACTOR, expected_previous)
    # another authorization, bytes that are not the pinned ones, or no pin at all: refused
    other = encoded(rig.auth.model_copy(update={"max_run_cost": "1"}))
    other_claim, _ = grant_claim(rig, other)
    claim, _ = grant_claim(rig, data)
    for candidate, proof in (
        (authority, BudgetProof(other_claim, EvidenceBinding.from_budget(other_claim), other,
                                rig.auth, ())),
        (authority, BudgetProof(claim, EvidenceBinding.from_budget(claim), other, rig.auth, ())),
        (pinned_grant_authority(rig, None),
         BudgetProof(claim, EvidenceBinding.from_budget(claim), data, rig.auth, ())),
    ):  # fmt: skip
        with pytest.raises(ContractError) as refused:
            candidate.budget(proof)
        assert refused.value.code == "forbidden"
    with pytest.raises(ContractError) as malformed:
        pinned_grant_authority(rig, "not-a-digest")
    assert malformed.value.code == "invalid_schema"


# -- control ------------------------------------------------------------------------------------


def control_proof(rig: Rig, action: str, snapshot: str | None = None) -> ControlProof:
    evidence = make_ref("cf.control-evidence.v1", "control")
    binding = EvidenceBinding(evidence.digest, "e" * 64, PROJECT, RUN, None, None, None, None)
    return ControlProof(binding, evidence, b"{}", b"{}", ACTOR, action, snapshot, NOW)


def test_control_facts_follow_the_session() -> None:
    settled = Rig(session=make_session({CALL: CallRecord(NOW, terminated=True, cancelled=True)}))
    open_call = Rig(session=make_session({CALL: CallRecord(NOW)}))
    empty = Rig(session=make_session())  # a fresh session holds nothing it could vouch for
    for rig, resolved in ((settled, True), (open_call, False), (Rig(), False), (empty, False)):
        facts = rig.authority.control(control_proof(rig, "reconcile_budget", "f" * 64))
        assert facts.liabilities_resolved is resolved
        assert facts.snapshot_digest == "f" * 64 and facts.action == "reconcile_budget"
        assert facts.actor_id == ACTOR and facts.acknowledges_duplicate_charge_risk is False
    cancel = open_call.authority.control(control_proof(open_call, "cancel_attempt"))
    assert cancel.action == "cancel_attempt" and cancel.liabilities_resolved is False
    for action in ("manual_retry", "something_else"):
        with pytest.raises(ContractError):
            open_call.authority.control(control_proof(open_call, action))


# -- transport ----------------------------------------------------------------------------------


def transport_proof(rig: Rig, **changes: Any) -> TransportProof:
    read_keys, write_prefix = rig.issuer.scopes(rig.pin.plan, ATTEMPT)
    values: dict[str, Any] = {
        "project_id": PROJECT,
        "plan_digest": rig.pin.ref.digest,
        "attempt_id": ATTEMPT,
        "destination_id": "synthetic.worker",
        "expires_at": LATER,
        "input_refs": rig.pin.plan.input_refs,
        "material": (b"synthetic-read-only", b"synthetic-read-write"),
        "material_fingerprint": "9" * 64,
        "output_scope": f"{BUCKET}/{write_prefix}".encode(),
    }
    assert read_keys
    return TransportProof(**(values | changes))


def test_transport_facts_match_minted_scopes() -> None:
    rig = Rig()
    read_keys, write_prefix = rig.issuer.scopes(rig.pin.plan, ATTEMPT)
    facts = rig.authority.transport(transport_proof(rig))

    assert facts.output_scope == f"{BUCKET}/{write_prefix}".encode()
    assert facts.output_attempt_id == ATTEMPT and facts.attempt_isolated is True
    assert facts.project_id == PROJECT and facts.plan_digest == rig.pin.ref.digest
    assert facts.destination_id == "synthetic.worker"
    assert facts.input_refs == rig.pin.plan.input_refs
    assert facts.material_fingerprint == "9" * 64 and facts.expires_at == LATER
    assert write_prefix.endswith(f"/attempts/{ATTEMPT}/") and read_keys
    assert rig.http.calls == 0  # the scopes are the issuer's own; nothing was minted

    # A proof for a wider or another attempt's scope is attested as what the issuer would mint,
    # which differs from the request, so the control side's comparison refuses it.
    wide = transport_proof(rig, output_scope=f"{BUCKET}/{PREFIX}/".encode())
    assert rig.authority.transport(wide).output_scope == facts.output_scope
    assert rig.authority.transport(wide).output_scope != wide.output_scope
    elsewhere = transport_proof(rig, attempt_id="00000000-0000-0000-0000-0000000000ff")
    assert rig.authority.transport(elsewhere).output_scope != elsewhere.output_scope


def test_transport_refuses_what_cannot_be_attested() -> None:
    rig = Rig()
    for changes in (
        {"plan_digest": "1" * 64},
        {"material": (b"only-one",)},
        {"expires_at": "2031-01-01T00:00:00.000Z"},
        {"destination_id": "another.destination"},
        {"project_id": OTHER_PROJECT},
    ):
        proof = transport_proof(rig, **changes)
        try:
            facts = rig.authority.transport(proof)
        except ContractError as error:
            assert error.code == "forbidden"
        else:  # attested as the pin says, which differs from the request
            assert (
                (facts.destination_id, facts.project_id)
                != (
                    proof.destination_id,
                    proof.project_id,
                )
                or facts.plan_digest != proof.plan_digest
                or facts.expires_at != proof.expires_at
            )


# -- hygiene ------------------------------------------------------------------------------------


def test_authority_never_shows_a_secret_or_a_session_internal() -> None:
    rig = Rig(session=make_session({CALL: CallRecord(NOW)}), label="live")
    text = repr(rig.authority) + str(rig.authority.label)
    for needle in (SECRET, "synthetic-parent-key-id", "SYNTHETIC_R2_API_TOKEN", CALL):
        assert needle not in text
    bad = Rig(session=make_session())
    errors: list[str] = []
    try:
        bad.authority.budget(bad.proof(bad.claim("reserve_storage", evidence=make_ref("x", "y"))))
    except ContractError as error:
        errors.append(str(error) + repr(error))
    assert errors and all("synthetic" not in item for item in errors)


def test_label_is_closed_and_live_needs_a_session() -> None:
    rig = Rig()
    for label in ("live", "synthetic_offline"):
        session = make_session() if label == "live" else None
        LocalEvidenceAuthority(
            decoders(),
            session,
            rig.issuer,
            rig.estimate_ref,
            None,
            label,
            plans=(rig.pin,),
            limits_by_schema=LIMITS_BY_SCHEMA,
        )
    for session, label in ((None, "live"), (None, "other"), (make_session(), "document")):
        with pytest.raises(ContractError):
            LocalEvidenceAuthority(
                decoders(),
                session,
                rig.issuer,
                rig.estimate_ref,
                None,
                label,  # type: ignore[arg-type]
                plans=(rig.pin,),
                limits_by_schema=LIMITS_BY_SCHEMA,
            )


# -- release ------------------------------------------------------------------------------------


def release_proof(**changes: Any) -> ReleaseProof:
    request = b'{"stateDigest":"s"}'
    values: dict[str, Any] = {
        "project_id": PROJECT,
        "actor_id": ACTOR,
        "action": "build_release",
        "request_bytes": request,
        "request_digest": hashlib.sha256(request).hexdigest(),
        "state_digest": "5" * 64,
        "evidence_ref": None,
        "revision_ref": None,
        "evidence_bytes": None,
        "now": NOW,
    }
    return ReleaseProof(**(values | changes))


def pinned_authority(current: str = POLICY_DIGEST, project: str = PROJECT) -> LocalReleaseAuthority:
    return LocalReleaseAuthority(project, POLICY_DIGEST, current_policy_digest=lambda: current)


def test_release_authority_refuses_other_project() -> None:
    authority = pinned_authority()
    proof = release_proof()
    approval = authority.approve(proof)
    assert (approval.project_id, approval.actor_id, approval.action) == (
        PROJECT,
        ACTOR,
        "build_release",
    )
    assert approval.request_digest == proof.request_digest
    assert approval.state_digest == proof.state_digest
    assert approval.evidence_digest is None and approval.revision_ref is None

    with pytest.raises(ContractError) as refused:
        authority.approve(release_proof(project_id=OTHER_PROJECT))
    assert refused.value.code == "forbidden"
    with pytest.raises(ContractError):
        pinned_authority(project=OTHER_PROJECT).approve(proof)


def test_release_authority_binds_what_it_approves() -> None:
    authority = pinned_authority()
    # the request digest is recomputed from the bytes, never taken from the proof
    with pytest.raises(ContractError):
        authority.approve(release_proof(request_digest="0" * 64))
    # evidence bytes must be the evidence reference's bytes
    evidence = make_ref("cf.evidence.v1", "evidence")
    with pytest.raises(ContractError):
        authority.approve(release_proof(evidence_ref=evidence, evidence_bytes=b"other"))
    data = b"synthetic evidence"
    real = Ref.model_validate(
        {
            **ref_wire("cf.evidence.v1", "unused"),
            "digest": hashlib.sha256(data).hexdigest(),
            "sizeBytes": len(data),
        }
    )
    approved = authority.approve(release_proof(evidence_ref=real, evidence_bytes=data))
    assert approved.evidence_digest == real.digest
    # an action outside the release actions is refused
    with pytest.raises(ContractError):
        authority.approve(release_proof(action="delete_everything"))
    with pytest.raises(ContractError):
        LocalReleaseAuthority(PROJECT, "not-a-digest", current_policy_digest=lambda: POLICY_DIGEST)


def test_release_authority_approves_only_the_pinned_policy() -> None:
    proof = release_proof()
    assert pinned_authority(POLICY_DIGEST).approve(proof).project_id == PROJECT
    # the current policy is looked up on every approval, not once at construction
    current = {"digest": POLICY_DIGEST}
    live = LocalReleaseAuthority(
        PROJECT, POLICY_DIGEST, current_policy_digest=lambda: current["digest"]
    )
    live.approve(proof)
    current["digest"] = "a" * 64
    with pytest.raises(ContractError) as changed:
        live.approve(proof)
    assert changed.value.code == "forbidden"
    with pytest.raises(ContractError) as other:
        pinned_authority("a" * 64).approve(proof)
    assert other.value.code == "forbidden"


def test_release_authority_fails_closed_when_the_policy_lookup_fails() -> None:
    def broken() -> str:
        raise RuntimeError("store unavailable")

    def malformed() -> str:
        return "not-a-digest"

    for lookup in (broken, malformed):
        authority = LocalReleaseAuthority(PROJECT, POLICY_DIGEST, current_policy_digest=lookup)
        with pytest.raises(ContractError) as refused:
            authority.approve(release_proof())
        assert refused.value.code == "forbidden"
        assert "store unavailable" not in repr(refused.value)


def test_evidence_label_comes_from_the_authority_and_its_open_session() -> None:
    # offline: no session, or a session that is not open, is synthetic whatever the label says
    assert Rig().authority.evidence_label() == "synthetic_offline"
    session = make_session()
    assert session.is_open is False
    live = Rig(session=session, label="live")
    assert live.authority.evidence_label() == "synthetic_offline"  # a session that is not open
    session._state = "open"  # the app is running
    assert session.is_open is True
    assert live.authority.evidence_label() == "live"
    # an authority that is not a live one never reports live, even over an open session
    assert Rig(session=session).authority.evidence_label() == "synthetic_offline"
    session._state = "closed"
    assert live.authority.evidence_label() == "synthetic_offline"
