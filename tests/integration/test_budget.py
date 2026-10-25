"""Synthetic real-PostgreSQL budget boundaries, never execution grants."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from decimal import Decimal
from threading import Barrier
from typing import Any
from uuid import uuid4

import pytest
from psycopg import sql
from test_ledger_db import ACTOR, ASSET, PROJECT, RUN, TIME, admission, encoded, limits, reference

from conscience_foundry.contracts.accounting import BillingAdjustment, BudgetEvent
from conscience_foundry.contracts.admission import IntakeManifest
from conscience_foundry.contracts.common import ArtifactRef, ContractError
from conscience_foundry.contracts.execution import ExecutionConfig, ExecutionPlan, RunAuthorization
from conscience_foundry.core.identity import F1Operation, operation_key
from conscience_foundry.ledger.budget import (
    BudgetContext,
    BudgetEvidenceClaim,
    apply_billing_adjustment,
    apply_budget_event,
    install_run_authorization,
    reserve_attempt,
    reserve_storage,
)
from conscience_foundry.ledger.db import Ledger, register_admission
from conscience_foundry.policy.access import AccessContext

pytestmark = pytest.mark.database
EXPIRY = "2026-10-26T00:00:00.000Z"


class Authority:
    """Explicit synthetic control evidence; no production resolver is supplied."""

    def __init__(self) -> None:
        self.allowed = True
        self.evidence: dict[str, set[bytes]] = {}
        self.calls: list[BudgetEvidenceClaim] = []

    def authorize(self, action: str, project: str, run: str, actor: str) -> bool:
        return self.allowed and project == PROJECT and actor == ACTOR and bool(run and action)

    def verify(self, claim: BudgetEvidenceClaim) -> bool:
        self.calls.append(claim)
        return (
            self.allowed
            and claim.project_id == PROJECT
            and claim.request_digest == hashlib.sha256(claim.request_bytes).hexdigest()
            and claim.request_bytes in self.evidence.get(claim.evidence_ref.digest, set())
        )

    def allow(self, ref: ArtifactRef, data: bytes) -> None:
        self.evidence.setdefault(ref.digest, set()).add(data)


@dataclass
class Case:
    data: Any
    plan: ExecutionPlan
    plan_bytes: bytes
    plan_ref: ArtifactRef
    auth: RunAuthorization
    auth_bytes: bytes
    auth_ref: ArtifactRef
    config_bytes: bytes
    context: BudgetContext
    authority: Authority
    evidence: ArtifactRef


def case(*, run_id: str = RUN, cost: str = "4", cap: str = "10", attempts: int = 3) -> Case:
    data = admission()
    manifest = IntakeManifest.from_wire(data.evidence.manifest_bytes, limits())
    tariff = reference(b"{}", "kf.tariff.v1")
    config = ExecutionConfig(
        schema_version="kf.execution-config.v1",
        adapter_id="synthetic.worker",
        deployment_version="synthetic.v1",
        image_digest="a" * 64,
        tariff_ref=tariff,
        resource_policy_ref=reference(b"{}", "kf.resource-policy.v1"),
        remote_destination_id="synthetic.worker",
    )
    config_bytes = encoded(config)
    limit_ref = reference(encoded(limits()), "kf.contract-limits.v1")
    contract_set = reference(b"{}", "kf.contract-set.v1")
    extraction = reference(b"{}", "kf.extraction-spec.v1")
    original = data.report.entries[0].snapshot_ref
    assert original is not None
    key = operation_key(
        F1Operation(
            PROJECT,
            ASSET,
            manifest.items[0].source_id,
            (original.digest,),
            extraction.digest,
            manifest.profile_id,
            manifest.profile_version,
            manifest.policy_ref.digest,
            contract_set.digest,
            (limit_ref.digest,),
        ),
        limits=limits(),
    )
    authorization_id = str(uuid4())
    plan = ExecutionPlan.model_validate(
        {
            "schemaVersion": "kf.execution-plan.v1",
            "projectId": PROJECT,
            "runId": run_id,
            "planId": str(uuid4()),
            "executionConfigRef": reference(config_bytes, config.schema_version),
            "admissionReportRef": data.report_ref,
            "extractionSpecRef": extraction,
            "policyRef": manifest.policy_ref,
            "profileId": manifest.profile_id,
            "profileVersion": manifest.profile_version,
            "contractSetRef": contract_set,
            "limitsRefs": (limit_ref,),
            "inputRefs": (original,),
            "operationKey": key,
            "resources": {
                "cpuMilli": 100,
                "memoryMiB": 64,
                "gpuCount": 0,
                "maxWallSeconds": 10,
                "maxOutputBytes": 1024,
                "maxConcurrentAttempts": 3,
                "maxAttemptsPerOperation": attempts,
                "automaticRetries": 0,
            },
            "budget": {
                "currency": "USD",
                "maxRunCost": cap,
                "maxAttemptCost": cost,
                "tariffRef": tariff,
                "authorizationId": authorization_id,
                "validUntil": EXPIRY,
            },
            "expiresAt": EXPIRY,
        }
    )
    plan_bytes = encoded(plan)
    auth = RunAuthorization(
        schema_version="kf.run-authorization.v1",
        authorization_id=authorization_id,
        project_id=PROJECT,
        run_id=run_id,
        admission_report_digest=data.report_ref.digest,
        allowed_plan_digests=(hashlib.sha256(plan_bytes).hexdigest(),),
        max_run_cost=cap,
        max_concurrent_attempts=3,
        actor_id=ACTOR,
        authorized_at=TIME,
        expires_at=EXPIRY,
    )
    auth_bytes = encoded(auth)
    authority = Authority()
    proof = reference(b"synthetic estimate", "kf.synthetic-evidence.v1")
    authority.allow(proof, plan_bytes)
    authority.allow(reference(auth_bytes, auth.schema_version), auth_bytes)
    schemas = (
        "kf.intake.v1",
        "kf.admission-report.v1",
        "kf.policy.v1",
        "kf.execution-plan.v1",
        "kf.run-authorization.v1",
        "kf.execution-config.v1",
        "kf.budget-event.v1",
        "kf.billing-adjustment.v1",
    )
    current_policy = data.evidence.pinned_policy.model_copy(
        update={"allowed_remote_destinations": ("synthetic.worker",)}
    )
    context = BudgetContext(
        now=TIME,
        access=AccessContext(
            PROJECT,
            ACTOR,
            frozenset(
                {
                    "read",
                    "extract",
                    "remoteTransfer",
                    "auditMetadataRead",
                }
            ),
        ),
        current_policy=current_policy,
        limits_by_schema={s: limits() for s in schemas},
        authorize=authority.authorize,
        verify_evidence=authority.verify,
    )
    return Case(
        data,
        plan,
        plan_bytes,
        reference(plan_bytes, plan.schema_version),
        auth,
        auth_bytes,
        reference(auth_bytes, auth.schema_version),
        config_bytes,
        context,
        authority,
        proof,
    )


def setup(ledger: Ledger, c: Case) -> None:
    with ledger.transaction() as tx:
        register_admission(
            c.data.manifest_ref, c.data.report, c.data.report_ref, tx, evidence=c.data.evidence
        )
        tx.create_run(PROJECT, c.plan.run_id, c.data.report_ref.digest)
        install_run_authorization(
            c.auth,
            c.auth_ref,
            c.auth_bytes,
            tx,
            context=c.context,
            expected_previous_authorization_id=None,
        )


def allocate(ledger: Ledger, c: Case) -> Any:
    with ledger.transaction() as tx:
        return reserve_attempt(
            c.plan,
            c.auth,
            c.evidence,
            tx,
            context=c.context,
            plan_ref=c.plan_ref,
            plan_bytes=c.plan_bytes,
            authorization_ref=c.auth_ref,
            authorization_bytes=c.auth_bytes,
            admission=c.data.evidence,
            asset_id=ASSET,
            execution_config_bytes=c.config_bytes,
        )


def balances(ledger: Ledger, run_id: str = RUN) -> tuple[Decimal, Decimal, Decimal, bool]:
    with ledger.transaction() as tx:
        row = tx.connection.execute(
            sql.SQL(
                "SELECT coalesce(sum(settled_usd),0),coalesce(sum(outstanding_usd),0),"
                "coalesce(sum(released_usd),0) FROM {} WHERE project_id=%s AND run_id=%s"
            ).format(tx.table("reservations")),
            (PROJECT, run_id),
        ).fetchone()
        frozen = tx.connection.execute(
            sql.SQL("SELECT frozen FROM {} WHERE project_id=%s AND run_id=%s").format(
                tx.table("runs")
            ),
            (PROJECT, run_id),
        ).fetchone()
        assert row is not None and frozen is not None
        return (*row, frozen[0])


def event(
    c: Case, attempt: Any, kind: str, amount: str | None, status: str = "actual"
) -> BudgetEvent:
    value = BudgetEvent.model_validate(
        {
            "schemaVersion": "kf.budget-event.v1",
            "projectId": PROJECT,
            "runId": c.plan.run_id,
            "reservationId": attempt.reservation_id,
            "attemptId": attempt.attempt_id,
            "scope": "attempt",
            "eventId": str(uuid4()),
            "eventType": kind,
            **({"amountUsd": amount} if amount is not None else {}),
            "costStatus": status,
            "evidenceRef": c.evidence,
            "createdAt": TIME,
        }
    )
    c.authority.allow(c.evidence, encoded(value))
    return value


def apply(ledger: Ledger, c: Case, e: BudgetEvent) -> None:
    with ledger.transaction() as tx:
        apply_budget_event(e, tx, event_bytes=encoded(e), context=c.context)


def test_concurrent_final_allowance(ledger: Ledger) -> None:
    c = case(cost="6")
    setup(ledger, c)
    barrier = Barrier(2)

    def compete() -> bool:
        barrier.wait(timeout=5)
        try:
            allocate(ledger, c)
            return True
        except ContractError as error:
            assert error.code == "budget_exhausted"
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(lambda _: compete(), range(2))) == 1
    assert balances(ledger) == (Decimal(0), Decimal(6), Decimal(0), False)


def test_corrected_bill_cas_and_replay(ledger: Ledger) -> None:
    c = case()
    setup(ledger, c)
    attempt = allocate(ledger, c)
    settled = event(c, attempt, "settle", "4")
    apply(ledger, c, settled)
    adjustments = []
    for prior, revised in (("4", "3"), ("3", "5")):
        correction = BillingAdjustment(
            schema_version="kf.billing-adjustment.v1",
            project_id=PROJECT,
            run_id=RUN,
            reservation_id=attempt.reservation_id,
            adjustment_id=str(uuid4()),
            settlement_event_id=settled.event_id,
            expected_prior_actual_usd=prior,
            revised_actual_usd=revised,
            evidence_ref=c.evidence,
            created_at=TIME,
        )
        c.authority.allow(c.evidence, encoded(correction))
        with ledger.transaction() as tx:
            apply_billing_adjustment(
                correction, tx, adjustment_bytes=encoded(correction), context=c.context
            )
            apply_billing_adjustment(
                correction, tx, adjustment_bytes=encoded(correction), context=c.context
            )
        assert balances(ledger) == (Decimal(revised), Decimal(0), Decimal(0), True)
        adjustments.append(correction)
    with ledger.transaction() as tx, pytest.raises(ContractError, match="determinism_conflict"):
        stale = adjustments[0].model_copy(update={"adjustment_id": str(uuid4())})
        c.authority.allow(c.evidence, encoded(stale))
        apply_billing_adjustment(stale, tx, adjustment_bytes=encoded(stale), context=c.context)
    with pytest.raises(ContractError):
        allocate(ledger, c)


def test_unknown_estimated_and_atomic_final_release(ledger: Ledger) -> None:
    c = case()
    setup(ledger, c)
    attempt = allocate(ledger, c)
    for amount, status in ((None, "unknown"), ("1", "estimated")):
        apply(ledger, c, event(c, attempt, "record_usage", amount, status))
        assert balances(ledger)[0:3] == (Decimal(0), Decimal(4), Decimal(0))
    settled = event(c, attempt, "settle", "1.5")
    apply(ledger, c, settled)
    apply(ledger, c, settled)
    assert balances(ledger)[0:3] == (Decimal("1.5"), Decimal(0), Decimal("2.5"))
    release = event(c, attempt, "release_unspent", "2.5")
    apply(ledger, c, release)
    apply(ledger, c, release)
    assert balances(ledger)[0:3] == (Decimal("1.5"), Decimal(0), Decimal("2.5"))
    with pytest.raises(ContractError):
        apply(ledger, c, release.model_copy(update={"event_id": str(uuid4())}))


def test_full_actual_overrun_is_visible_and_frozen(ledger: Ledger) -> None:
    c = case()
    setup(ledger, c)
    attempt = allocate(ledger, c)
    apply(ledger, c, event(c, attempt, "settle", "12"))
    assert balances(ledger) == (Decimal(12), Decimal(0), Decimal(0), True)
    with pytest.raises(ContractError):
        allocate(ledger, c)


@pytest.mark.parametrize("amount", ["5", "12"])
def test_observed_actual_overrun_freezes_without_retiring_liability(
    ledger: Ledger, amount: str
) -> None:
    c = case()
    setup(ledger, c)
    attempt = allocate(ledger, c)
    observed = event(c, attempt, "record_usage", amount)
    apply(ledger, c, observed)
    assert balances(ledger) == (Decimal(0), Decimal(4), Decimal(0), True)
    with pytest.raises(ContractError):
        allocate(ledger, c)
    apply(ledger, c, observed)
    assert balances(ledger) == (Decimal(0), Decimal(4), Decimal(0), True)


@pytest.mark.parametrize("no_effect", [False, True])
def test_storage_accounting_keeps_original_grant_after_amendment_and_expiry(
    ledger: Ledger, no_effect: bool
) -> None:
    c = case()
    setup(ledger, c)
    request = json.dumps(
        {
            "projectId": PROJECT,
            "runId": RUN,
            "authorizationDigest": c.auth_ref.digest,
            "currency": "USD",
            "amountUsd": "3",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    c.authority.allow(c.evidence, request)
    with ledger.transaction() as tx:
        storage = reserve_storage(RUN, "3", c.evidence, tx, context=c.context)
    amended = c.auth.model_copy(update={"authorization_id": str(uuid4())})
    amended_bytes = encoded(amended)
    amended_ref = reference(amended_bytes, amended.schema_version)
    c.authority.allow(amended_ref, amended_bytes)
    with ledger.transaction() as tx:
        install_run_authorization(
            amended,
            amended_ref,
            amended_bytes,
            tx,
            context=c.context,
            expected_previous_authorization_id=c.auth.authorization_id,
        )

    def original_evidence(claim: BudgetEvidenceClaim) -> bool:
        return claim.authorization_ref == c.auth_ref and c.authority.verify(claim)

    c.context = replace(c.context, now=EXPIRY, verify_evidence=original_evidence)

    def storage_event(kind: str, amount: str) -> BudgetEvent:
        value = BudgetEvent(
            schema_version="kf.budget-event.v1",
            project_id=PROJECT,
            run_id=RUN,
            reservation_id=storage,
            scope="run_storage",
            event_id=str(uuid4()),
            event_type=kind,
            amount_usd=amount,
            cost_status="actual",
            evidence_ref=c.evidence,
            created_at=TIME,
        )
        c.authority.allow(c.evidence, encoded(value))
        return value

    if no_effect:
        release = storage_event("release_unspent", "3")
        apply(ledger, c, release)
        apply(ledger, c, release)
        assert balances(ledger) == (Decimal(0), Decimal(0), Decimal(3), False)
        assert c.authority.calls[-1].authorization_ref == c.auth_ref
        assert c.authority.calls[-1].purpose == "final_no_effect"
        return

    settled = storage_event("settle", "2")
    apply(ledger, c, settled)
    release = storage_event("release_unspent", "1")
    apply(ledger, c, release)
    adjustment = BillingAdjustment(
        schema_version="kf.billing-adjustment.v1",
        project_id=PROJECT,
        run_id=RUN,
        reservation_id=storage,
        adjustment_id=str(uuid4()),
        settlement_event_id=settled.event_id,
        expected_prior_actual_usd="2",
        revised_actual_usd="1",
        evidence_ref=c.evidence,
        created_at=TIME,
    )
    c.authority.allow(c.evidence, encoded(adjustment))
    with ledger.transaction() as tx:
        apply_billing_adjustment(
            adjustment, tx, adjustment_bytes=encoded(adjustment), context=c.context
        )
    apply(ledger, c, settled)
    apply(ledger, c, release)
    with ledger.transaction() as tx:
        apply_billing_adjustment(
            adjustment, tx, adjustment_bytes=encoded(adjustment), context=c.context
        )
    assert balances(ledger) == (Decimal(1), Decimal(0), Decimal(1), True)
    assert all(
        claim.authorization_ref == c.auth_ref
        for claim in c.authority.calls
        if claim.purpose in {"final_billing", "release_unspent", "billing_adjustment"}
    )


def test_reservation_original_grant_cannot_cross_runs(ledger: Ledger) -> None:
    c = case()
    other = case(run_id=str(uuid4()))
    setup(ledger, c)
    setup(ledger, other)
    attempt = allocate(ledger, c)
    import psycopg

    with ledger.transaction() as tx:
        with pytest.raises(psycopg.errors.ForeignKeyViolation), tx.connection.transaction():
            tx.connection.execute(
                sql.SQL(
                    "UPDATE {} SET authorization_id=%s "
                    "WHERE project_id=%s AND reservation_id=%s"
                ).format(tx.table("reservations")),
                (other.auth.authorization_id, PROJECT, attempt.reservation_id),
            )
        assert tx.connection.execute(
            sql.SQL(
                "SELECT authorization_id::text FROM {} "
                "WHERE project_id=%s AND reservation_id=%s"
            ).format(tx.table("reservations")),
            (PROJECT, attempt.reservation_id),
        ).fetchone() == (c.auth.authorization_id,)


def test_authority_current_policy_expiry_and_raw_pins_fail_closed(ledger: Ledger) -> None:
    c = case()
    setup(ledger, c)
    variants = [
        replace(c, plan_bytes=c.plan_bytes + b" "),
        replace(c, context=replace(c.context, now=EXPIRY)),
        replace(
            c,
            context=replace(
                c.context, access=AccessContext(PROJECT, ACTOR, frozenset({"read", "extract"}))
            ),
        ),
        replace(
            c,
            context=replace(
                c.context,
                current_policy=c.context.current_policy.model_copy(
                    update={"allowed_remote_destinations": ()}
                ),
            ),
        ),
    ]
    for invalid in variants:
        with pytest.raises(ContractError):
            allocate(ledger, invalid)
    c.authority.allowed = False
    with pytest.raises(ContractError):
        allocate(ledger, c)
    assert balances(ledger)[0:3] == (Decimal(0), Decimal(0), Decimal(0))


def test_storage_liability_outlives_worker(ledger: Ledger) -> None:
    c = case()
    setup(ledger, c)
    with ledger.transaction() as tx:
        c.authority.allow(
            c.evidence,
            json.dumps(
                {
                    "projectId": PROJECT,
                    "runId": RUN,
                    "authorizationDigest": c.auth_ref.digest,
                    "currency": "USD",
                    "amountUsd": "3",
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode(),
        )
        storage = reserve_storage(RUN, "3", c.evidence, tx, context=c.context)
    attempt = allocate(ledger, c)
    apply(ledger, c, event(c, attempt, "settle", "2"))
    assert balances(ledger)[0:3] == (Decimal(2), Decimal(3), Decimal(2))
    with ledger.transaction() as tx:
        e = BudgetEvent(
            schema_version="kf.budget-event.v1",
            project_id=PROJECT,
            run_id=RUN,
            reservation_id=storage,
            scope="run_storage",
            event_id=str(uuid4()),
            event_type="record_usage",
            cost_status="unknown",
            evidence_ref=c.evidence,
            created_at=TIME,
        )
        c.authority.allow(c.evidence, encoded(e))
        apply_budget_event(e, tx, event_bytes=encoded(e), context=c.context)
    assert balances(ledger)[1] == Decimal(3)


def test_authentic_final_evidence_cannot_approve_a_different_amount(ledger: Ledger) -> None:
    c = case()
    setup(ledger, c)
    attempt = allocate(ledger, c)
    valid = event(c, attempt, "settle", "1")
    forged = valid.model_copy(update={"amount_usd": "9"})
    with pytest.raises(ContractError, match="forbidden"):
        apply(ledger, c, forged)
    assert balances(ledger)[0:3] == (Decimal(0), Decimal(4), Decimal(0))
    apply(ledger, c, valid)
    assert balances(ledger)[0:3] == (Decimal(1), Decimal(0), Decimal(3))


def test_operation_attempt_counter_spans_runs(ledger: Ledger) -> None:
    first = case(attempts=1)
    second = case(run_id=str(uuid4()), attempts=1)
    setup(ledger, first)
    setup(ledger, second)
    allocate(ledger, first)
    with pytest.raises(ContractError, match="limit_exceeded"):
        allocate(ledger, second)
    assert balances(ledger, second.plan.run_id)[1] == 0


def test_unknown_outcome_cannot_hide_in_a_new_run(ledger: Ledger) -> None:
    first, second = case(), case(run_id=str(uuid4()))
    setup(ledger, first)
    setup(ledger, second)
    attempt = allocate(ledger, first)
    with ledger.transaction() as tx:
        tx.connection.execute(
            sql.SQL(
                "UPDATE {} SET state='unknown_outcome' WHERE project_id=%s AND attempt_id=%s"
            ).format(tx.table("attempts")),
            (PROJECT, attempt.attempt_id),
        )
    with pytest.raises(ContractError, match="dispatch_unknown"):
        allocate(ledger, second)
    assert balances(ledger, first.plan.run_id)[1] == 4
    assert balances(ledger, second.plan.run_id)[1] == 0


def test_pause_and_nonboolean_or_failed_authority_retain_balances(ledger: Ledger) -> None:
    c = case()
    setup(ledger, c)
    with ledger.transaction() as tx:
        tx.record_pause(
            "run",
            PROJECT,
            RUN,
            True,
            expected_version=0,
            actor_id=ACTOR,
            reason="synthetic_pause",
            decided_at=TIME,
            decision_id=str(uuid4()),
        )
    with pytest.raises(ContractError, match="forbidden"):
        allocate(ledger, c)
    with ledger.transaction() as tx:
        tx.record_pause(
            "run",
            PROJECT,
            RUN,
            False,
            expected_version=1,
            actor_id=ACTOR,
            reason="synthetic_resume",
            decided_at=TIME,
            decision_id=str(uuid4()),
        )
    for result in (None, 1, "allow"):
        invalid = replace(
            c, context=replace(c.context, authorize=lambda *args, result=result: result)
        )
        with pytest.raises(ContractError, match="forbidden"):
            allocate(ledger, invalid)
        invalid = replace(
            c, context=replace(c.context, verify_evidence=lambda claim, result=result: result)
        )
        with pytest.raises(ContractError, match="forbidden"):
            allocate(ledger, invalid)
    assert balances(ledger)[0:3] == (Decimal(0), Decimal(0), Decimal(0))


def test_cap_amendment_requires_exact_grant_evidence_and_cas(ledger: Ledger) -> None:
    c = case()
    setup(ledger, c)
    allocate(ledger, c)
    raised = c.auth.model_copy(update={"authorization_id": str(uuid4()), "max_run_cost": "20"})
    raw = encoded(raised)
    ref = reference(raw, raised.schema_version)
    with ledger.transaction() as tx:
        with pytest.raises(ContractError, match="forbidden"):
            install_run_authorization(
                raised,
                ref,
                raw,
                tx,
                context=c.context,
                expected_previous_authorization_id=c.auth.authorization_id,
            )
        assert balances(ledger)[1] == 4
    c.authority.allow(ref, raw)
    with ledger.transaction() as tx:
        with pytest.raises(ContractError, match="activation_conflict"):
            install_run_authorization(
                raised, ref, raw, tx, context=c.context, expected_previous_authorization_id=None
            )
        install_run_authorization(
            raised,
            ref,
            raw,
            tx,
            context=c.context,
            expected_previous_authorization_id=c.auth.authorization_id,
        )
    assert balances(ledger)[1] == 4


def test_old_attempt_billing_uses_original_pins_after_amendment_and_expiry(ledger: Ledger) -> None:
    c = case()
    setup(ledger, c)
    attempt = allocate(ledger, c)
    new = c.auth.model_copy(
        update={
            "authorization_id": str(uuid4()),
            "allowed_plan_digests": ("f" * 64,),
        }
    )
    raw = encoded(new)
    ref = reference(raw, new.schema_version)
    c.authority.allow(ref, raw)
    with ledger.transaction() as tx:
        install_run_authorization(
            new,
            ref,
            raw,
            tx,
            context=c.context,
            expected_previous_authorization_id=c.auth.authorization_id,
        )
    c.context = replace(c.context, now=EXPIRY)
    settled = event(c, attempt, "settle", "2")
    apply(ledger, c, settled)
    proof = c.authority.calls[-1]
    assert proof.authorization_ref == c.auth_ref
    assert proof.plan_ref == c.plan_ref
    assert proof.execution_config_ref is None
    assert balances(ledger)[0:3] == (Decimal(2), Decimal(0), Decimal(2))


def test_storage_amount_is_bounded_before_decimal_or_sql(ledger: Ledger) -> None:
    c = case()
    setup(ledger, c)
    with ledger.transaction() as tx, pytest.raises(ContractError, match="limit_exceeded"):
        reserve_storage(
            RUN, "1" * (limits().max_string_scalars + 1), c.evidence, tx, context=c.context
        )
    assert balances(ledger)[1] == 0


def test_accounting_replay_rechecks_current_evidence_authority(ledger: Ledger) -> None:
    c = case()
    setup(ledger, c)
    attempt = allocate(ledger, c)
    settled = event(c, attempt, "settle", "2")
    apply(ledger, c, settled)
    denied = replace(c, context=replace(c.context, verify_evidence=lambda claim: False))
    with pytest.raises(ContractError, match="forbidden"):
        apply(ledger, denied, settled)
    correction = BillingAdjustment(
        schema_version="kf.billing-adjustment.v1",
        project_id=PROJECT,
        run_id=RUN,
        reservation_id=attempt.reservation_id,
        adjustment_id=str(uuid4()),
        settlement_event_id=settled.event_id,
        expected_prior_actual_usd="2",
        revised_actual_usd="1",
        evidence_ref=c.evidence,
        created_at=TIME,
    )
    c.authority.allow(c.evidence, encoded(correction))
    with ledger.transaction() as tx:
        apply_billing_adjustment(
            correction, tx, adjustment_bytes=encoded(correction), context=c.context
        )
    with ledger.transaction() as tx, pytest.raises(ContractError, match="forbidden"):
        apply_billing_adjustment(
            correction, tx, adjustment_bytes=encoded(correction), context=denied.context
        )
    assert balances(ledger) == (Decimal(1), Decimal(0), Decimal(2), True)


def test_concurrent_corrections_compare_and_swap_effective_actual(ledger: Ledger) -> None:
    c = case()
    setup(ledger, c)
    attempt = allocate(ledger, c)
    settled = event(c, attempt, "settle", "4")
    apply(ledger, c, settled)
    corrections = [
        BillingAdjustment(
            schema_version="kf.billing-adjustment.v1",
            project_id=PROJECT,
            run_id=RUN,
            reservation_id=attempt.reservation_id,
            adjustment_id=str(uuid4()),
            settlement_event_id=settled.event_id,
            expected_prior_actual_usd="4",
            revised_actual_usd=revised,
            evidence_ref=c.evidence,
            created_at=TIME,
        )
        for revised in ("3", "5")
    ]
    for correction in corrections:
        c.authority.allow(c.evidence, encoded(correction))
    barrier = Barrier(2)

    def compete(correction: BillingAdjustment) -> bool:
        barrier.wait(timeout=5)
        try:
            with ledger.transaction() as tx:
                apply_billing_adjustment(
                    correction, tx, adjustment_bytes=encoded(correction), context=c.context
                )
            return True
        except ContractError as error:
            assert error.code == "determinism_conflict"
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(compete, corrections)) == 1
    actual, outstanding, released, frozen = balances(ledger)
    assert actual in (Decimal(3), Decimal(5))
    assert (outstanding, released, frozen) == (0, 0, True)


def test_finality_evidence_exception_and_unknown_policy_fail_without_writes(ledger: Ledger) -> None:
    c = case()
    setup(ledger, c)
    attempt = allocate(ledger, c)
    denied_policy = c.context.current_policy.model_copy(
        update={
            "sources": tuple(
                source.model_copy(update={"read": "unknown"})
                for source in c.context.current_policy.sources
            )
        }
    )
    with pytest.raises(ContractError, match="permission_unknown"):
        allocate(ledger, replace(c, context=replace(c.context, current_policy=denied_policy)))
    final = event(c, attempt, "settle", "1")

    def unavailable(claim: BudgetEvidenceClaim) -> bool:
        raise RuntimeError("synthetic unavailable evidence")

    with ledger.transaction() as tx:
        with pytest.raises(ContractError, match="forbidden"):
            apply_budget_event(
                final,
                tx,
                event_bytes=encoded(final),
                context=replace(c.context, verify_evidence=unavailable),
            )
    assert balances(ledger)[0:3] == (Decimal(0), Decimal(4), Decimal(0))
