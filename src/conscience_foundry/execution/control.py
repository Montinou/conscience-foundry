"""Durable local control of bounded remote effects; no live provider implementation."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import Literal
from uuid import uuid4

from psycopg import sql
from pydantic import TypeAdapter, ValidationError

from conscience_foundry.contracts.accounting import (
    BudgetEvent,
    OperationResultRecord,
    ResourceUsage,
)
from conscience_foundry.contracts.admission import IntakeManifest
from conscience_foundry.contracts.common import ContractError, Digest, Id, Reason, Ref
from conscience_foundry.contracts.execution import (
    ExecutionPlan,
    RunAuthorization,
    StageAttempt,
)
from conscience_foundry.execution.evidence import (
    admission_evidence,
    authorize,
    bounded_request,
    budget_context,
    check_binding,
    checked_reason,
    clock,
    control_facts,
    current_policy,
    encoded,
    identity,
    limits_for,
    read_artifact,
    read_model,
    verified_plan,
)
from conscience_foundry.execution.ports import (
    ControlContext,
    EvidenceBinding,
    Executor,
    ManualRetry,
    Observation,
    ObservationFacts,
    ObservationProof,
    Submission,
    TransportFacts,
    TransportGrants,
    TransportProof,
)
from conscience_foundry.ledger._budget_inputs import DuplicateRiskAuthorization
from conscience_foundry.ledger.acceptance import integrity_hold, select_result, verify_result
from conscience_foundry.ledger.attempts import (
    TERMINAL,
    TRANSITIONS,
    append_observation,
    claim_attempt,
    load_attempt,
    observation_seen,
    record_decision,
    save_attempt,
    snapshot,
    transition,
)
from conscience_foundry.ledger.budget import apply_budget_event, reserve_attempt
from conscience_foundry.ledger.db import Ledger, LedgerTxn, PauseState
from conscience_foundry.policy.access import AccessContext, require_permission


def _load(
    tx: LedgerTxn, attempt_id: Id, control: ControlContext
) -> tuple[StageAttempt, Id, Ref, Ref]:
    TypeAdapter(Id).validate_python(attempt_id)
    ref, run, plan, auth = load_attempt(tx, control.access.project_id, attempt_id)
    _, attempt = read_model(ref, StageAttempt, control)
    if attempt.attempt_id != attempt_id or attempt.project_id != control.access.project_id:
        raise ContractError("hash_mismatch")
    row = tx.connection.execute(
        sql.SQL(
            "SELECT state,plan_id::text,operation_key,reservation_id::text,"
            "remote_call_id,result_ref "
            "FROM {} WHERE project_id=%s AND attempt_id=%s"
        ).format(tx.table("attempts")),
        (attempt.project_id, attempt_id),
    ).fetchone()
    expected_result = Ref.model_validate(row[5]) if row is not None and row[5] is not None else None
    if (
        row is None
        or tuple(row[:5])
        != (
            attempt.state,
            attempt.plan_id,
            attempt.operation_key,
            attempt.reservation_id,
            attempt.remote_call_id,
        )
        or ((expected_result is None) != (attempt.result_manifest_ref is None))
        or (
            expected_result is not None
            and attempt.result_manifest_ref is not None
            and identity(expected_result) != identity(attempt.result_manifest_ref)
        )
    ):
        raise ContractError("hash_mismatch")
    return attempt, run, plan, auth


def _amended(attempt: StageAttempt, **changes: object) -> StageAttempt:
    """Same state, newly learned facts (remote id, result ref); never a state change."""
    value = attempt.model_dump(by_alias=True, exclude_none=True)
    value.update(changes)
    return StageAttempt.model_validate(value)


def _grants(
    grants: TransportGrants,
    plan: ExecutionPlan,
    auth: RunAuthorization,
    plan_ref: Ref,
    destination: str,
    control: ControlContext,
) -> None:
    if type(grants) is not TransportGrants:
        raise ContractError("forbidden")
    bound = control.transport_limits
    if type(grants.material) is not tuple or type(grants.output_scope) is not bytes:
        raise ContractError("forbidden")
    if len(grants.material) > bound.max_array_items:
        raise ContractError("limit_exceeded")
    if not grants.output_scope:
        raise ContractError("forbidden")
    total = (
        len(grants.output_scope)
        + 8 * (len(grants.material) + 2)
        + len(b"kf.transport-material.internal.v1\n")
    )
    if total > bound.max_source_bytes:
        raise ContractError("limit_exceeded")
    for piece in grants.material:
        if type(piece) is not bytes:
            raise ContractError("forbidden")
        total += len(piece)
        if total > bound.max_source_bytes:
            raise ContractError("limit_exceeded")
    labels = (
        grants.project_id,
        grants.plan_digest,
        grants.attempt_id,
        grants.destination_id,
        grants.expires_at,
    )
    for label in labels:
        if type(label) is not str:
            raise ContractError("forbidden")
        if len(label) > bound.max_string_scalars:
            raise ContractError("limit_exceeded")
        if any(0xD800 <= ord(character) <= 0xDFFF for character in label):
            raise ContractError("forbidden")
        total += len(label.encode("utf-8"))
    if len(plan.input_refs) > bound.max_array_items:
        raise ContractError("limit_exceeded")
    total += sum(len(encoded(ref)) for ref in plan.input_refs)
    if total > bound.max_source_bytes:
        raise ContractError("limit_exceeded")
    if (
        grants.project_id != plan.project_id
        or grants.plan_digest != plan_ref.digest
        or grants.destination_id != destination
    ):
        raise ContractError("forbidden")
    try:
        TypeAdapter(Id).validate_python(grants.attempt_id)
        from conscience_foundry.contracts.common import Instant

        TypeAdapter(Instant).validate_python(grants.expires_at)
    except ValidationError:
        raise ContractError("forbidden") from None
    if not clock(control) < grants.expires_at <= min(plan.expires_at, auth.expires_at):
        raise ContractError("authorization_expired")
    # Length delimiters distinguish e.g. (b"ab", b"c") from (b"a", b"bc").
    digest = hashlib.sha256(b"kf.transport-material.internal.v1\n")
    digest.update(len(grants.material).to_bytes(8, "big"))
    for piece in grants.material:
        digest.update(len(piece).to_bytes(8, "big"))
        digest.update(piece)
    digest.update(len(grants.output_scope).to_bytes(8, "big"))
    digest.update(grants.output_scope)
    fingerprint = digest.hexdigest()
    proof = TransportProof(
        grants.project_id,
        grants.plan_digest,
        grants.attempt_id,
        grants.destination_id,
        grants.expires_at,
        plan.input_refs,
        grants.material,
        fingerprint,
        grants.output_scope,
    )
    try:
        facts = control.evidence_authority.transport(proof)
    except Exception:
        raise ContractError("forbidden") from None
    if type(facts) is not TransportFacts:
        raise ContractError("forbidden")
    for label in (
        facts.project_id,
        facts.plan_digest,
        facts.attempt_id,
        facts.destination_id,
        facts.expires_at,
        facts.material_fingerprint,
        facts.output_attempt_id,
    ):
        if type(label) is not str or len(label) > bound.max_string_scalars:
            raise ContractError("forbidden")
    if (
        type(facts.output_scope) is not bytes
        or type(facts.input_refs) is not tuple
        or len(facts.output_scope) > bound.max_source_bytes
        or len(facts.input_refs) != len(plan.input_refs)
        or any(type(ref) is not Ref for ref in facts.input_refs)
    ):
        raise ContractError("forbidden")
    try:
        actual_inputs = tuple(Ref.from_wire(encoded(ref), bound) for ref in facts.input_refs)
    except Exception:
        raise ContractError("forbidden") from None
    if (
        (
            facts.project_id,
            facts.plan_digest,
            facts.attempt_id,
            facts.destination_id,
            facts.expires_at,
            facts.material_fingerprint,
            facts.output_scope,
            facts.output_attempt_id,
            facts.attempt_isolated,
        )
        != (
            grants.project_id,
            grants.plan_digest,
            grants.attempt_id,
            grants.destination_id,
            grants.expires_at,
            fingerprint,
            grants.output_scope,
            grants.attempt_id,
            True,
        )
        or facts.attempt_isolated is not True
        or tuple(identity(ref) for ref in actual_inputs)
        != tuple(identity(ref) for ref in plan.input_refs)
    ):
        raise ContractError("forbidden")
    # Attestation can take time; validity must still hold at the use boundary.
    if not clock(control) < grants.expires_at <= min(plan.expires_at, auth.expires_at):
        raise ContractError("authorization_expired")


def dispatch(
    plan: ExecutionPlan,
    authorization: RunAuthorization,
    context: AccessContext,
    ledger: Ledger,
    executor: Executor,
    grants: TransportGrants,
    *,
    control: ControlContext,
    plan_ref: Ref,
    authorization_ref: Ref,
    asset_id: Id,
    evidence_ref: Ref,
    manual_retry: ManualRetry | None = None,
) -> StageAttempt:
    if context != control.access:
        raise ContractError("forbidden")
    authorize(control, "dispatch", context.project_id, plan.run_id)
    with ledger.transaction() as tx:
        tx.lock(context.project_id, plan.run_id)
        verified = verified_plan(plan_ref, authorization_ref, tx, control, spending=True)
        if verified.model != plan or verified.authorization != authorization:
            raise ContractError("hash_mismatch")
        _grants(
            grants, plan, authorization, plan_ref, verified.config.remote_destination_id, control
        )
        existing = tx.connection.execute(
            sql.SQL("SELECT 1 FROM {} WHERE project_id=%s AND attempt_id=%s").format(
                tx.table("attempts")
            ),
            (context.project_id, grants.attempt_id),
        ).fetchone()
        if existing:
            old, _, old_plan, old_auth = _load(tx, grants.attempt_id, control)
            if identity(old_plan) != identity(plan_ref) or identity(old_auth) != identity(
                authorization_ref
            ):
                raise ContractError("determinism_conflict")
            return old  # Never resubmit an existing durable claim.
        admission, _, _ = admission_evidence(plan, tx, control)
        budget = budget_context(control, tx=tx)
        risk = None
        if manual_retry is not None:
            if type(manual_retry) is not ManualRetry:
                raise ContractError("forbidden")
            risk = DuplicateRiskAuthorization(
                manual_retry.evidence_ref,
                manual_retry.expected_snapshot_digest,
                manual_retry.unresolved_attempt_ids,
                plan_ref.digest,
                authorization.authorization_id,
            )
            budget = replace(
                budget,
                duplicate_risk_verifier=lambda risk, p, a: _manual_retry(
                    tx,
                    control,
                    risk,
                    plan,
                    authorization,
                    plan_ref,
                    authorization_ref,
                    grants.attempt_id,
                ),
            )
        attempt = reserve_attempt(
            plan,
            authorization,
            evidence_ref,
            tx,
            context=budget,
            plan_ref=plan_ref,
            plan_bytes=verified.data,
            authorization_ref=authorization_ref,
            authorization_bytes=read_artifact(authorization_ref, control)[0],
            admission=admission,
            asset_id=asset_id,
            execution_config_bytes=verified.config_bytes,
            attempt_id=grants.attempt_id,
            duplicate_risk=risk,
        )
        attempt = claim_attempt(tx, attempt, control)
    # The committed claim/reservation precedes every external effect. No DB lock
    # is retained across submit, and an exception is deliberately uncertain.
    try:
        _grants(
            grants, plan, authorization, plan_ref, verified.config.remote_destination_id, control
        )
    except ContractError:
        # No executor was invoked: local control can prove no submission effect.
        # Financial liability still needs the separate final-no-liability gate.
        with ledger.transaction() as tx:
            current, run, _, _ = _load(tx, attempt.attempt_id, control)
            tx.lock(current.project_id, run, current.operation_key)
            current, _, _, _ = _load(tx, attempt.attempt_id, control)
            if current.state == "dispatching":
                current = transition(
                    current,
                    "failed",
                    control,
                    reason=Reason(code="forbidden", message="Transport proof unavailable"),
                )
                save_attempt(tx, current, control)
            request = bounded_request(
                {
                    "action": "transport_proof_refused",
                    "attemptId": current.attempt_id,
                    "submitInvoked": False,
                    "state": current.state,
                },
                control,
            )
            append_observation(tx, current, evidence_ref, request, control)
            return current
    try:
        submission = executor.submit(plan, attempt, grants)
    except Exception:
        submission = Submission(None, None)
    identified = (
        type(submission) is Submission
        and type(submission.remote_call_id) is str
        and bool(submission.remote_call_id)
        and len(submission.remote_call_id)
        <= limits_for(control, "kf.stage-attempt.v1").max_string_scalars
    )
    usable = identified and submission.accepted is True
    with ledger.transaction() as tx:
        current, run, _, _ = _load(tx, attempt.attempt_id, control)
        tx.lock(current.project_id, run, current.operation_key)
        current, _, _, _ = _load(tx, attempt.attempt_id, control)
        if current.state != "dispatching":
            # A concurrent reconciler or cancellation owns the state, but the provider's
            # answer is still evidence: keep the state, learn the remote id, record it.
            if identified and current.remote_call_id is None and current.state not in TERMINAL:
                learned = _amended(current, remoteCallId=submission.remote_call_id)
                save_attempt(tx, learned, control)
                append_observation(
                    tx,
                    learned,
                    evidence_ref,
                    bounded_request(
                        {
                            "action": "submission",
                            "attemptId": learned.attempt_id,
                            "state": learned.state,
                            "remoteCallId": learned.remote_call_id,
                        },
                        control,
                    ),
                    control,
                )
                return learned
            return current
        result = transition(
            current,
            "running" if usable else "unknown_outcome",
            control,
            **({"remoteCallId": submission.remote_call_id} if identified else {}),
        )
        save_attempt(tx, result, control)
        request = bounded_request(
            {
                "action": "submission",
                "attemptId": current.attempt_id,
                "state": result.state,
                **({"remoteCallId": result.remote_call_id} if result.remote_call_id else {}),
            },
            control,
        )
        append_observation(tx, result, evidence_ref, request, control)
        return result


def _observation(
    attempt: StageAttempt,
    run: Id,
    plan_ref: Ref,
    auth_ref: Ref,
    observation: Observation,
    control: ControlContext,
) -> tuple[ObservationFacts, bytes]:
    if type(observation) is not Observation:
        raise ContractError("invalid_schema")
    if type(observation.state) is not str or observation.state not in set(TRANSITIONS) | TERMINAL:
        raise ContractError("invalid_schema")
    usage = None
    if observation.usage is not None:
        if type(observation.usage) is not ResourceUsage:
            raise ContractError("invalid_schema")
        usage = ResourceUsage.from_wire(
            encoded(observation.usage), limits_for(control, "kf.result.v1")
        )
    request = bounded_request(
        {
            "projectId": attempt.project_id,
            "attemptId": attempt.attempt_id,
            "planDigest": plan_ref.digest,
            "state": observation.state,
            # Only fields invariant for this observation: the stored remote id changes with
            # the first reconcile, and it is enforced separately against the attested facts.
            **(
                {"resultRef": observation.result_ref.model_dump(by_alias=True)}
                if observation.result_ref
                else {}
            ),
            **({"usage": usage.model_dump(by_alias=True, exclude_none=True)} if usage else {}),
        },
        control,
    )
    raw, _ = read_artifact(observation.evidence, control, evidence=True)
    binding = EvidenceBinding(
        observation.evidence.digest,
        hashlib.sha256(request).hexdigest(),
        attempt.project_id,
        run,
        attempt.reservation_id,
        attempt.attempt_id,
        auth_ref.digest,
        plan_ref.digest,
    )
    try:
        facts = control.evidence_authority.observation(
            ObservationProof(
                binding, observation.evidence, raw, request, attempt, observation, clock(control)
            )
        )
    except Exception:
        raise ContractError("forbidden") from None
    if type(facts) is not ObservationFacts:
        raise ContractError("forbidden")
    check_binding(facts.binding, binding)
    identified = (
        type(facts.remote_call_id) is str
        and bool(facts.remote_call_id)
        and len(facts.remote_call_id)
        <= limits_for(control, "kf.stage-attempt.v1").max_string_scalars
    )
    if facts.remote_call_id is not None and not identified:
        raise ContractError("forbidden")
    if observation.state in {"running", "succeeded", "failed", "cancelled"} and not identified:
        if observation.state not in {"failed", "cancelled"} or facts.no_external_effect is not True:
            raise ContractError("forbidden")
    if (
        facts.state != observation.state
        or facts.result_digest
        != (observation.result_ref.digest if observation.result_ref else None)
        or (attempt.remote_call_id is not None and facts.remote_call_id != attempt.remote_call_id)
    ):
        raise ContractError("forbidden")
    if observation.state in {"succeeded", "failed", "cancelled"}:
        if facts.confirmed_termination is not True and not (
            attempt.state in {"planned", "reserved", "dispatching"}
            and facts.no_external_effect is True
        ):
            raise ContractError("forbidden")
    if (
        observation.state == "failed"
        and attempt.state == "dispatching"
        and facts.no_external_effect is not True
    ):
        raise ContractError("forbidden")
    if (
        observation.state == "cancelled"
        and attempt.state in {"planned", "reserved"}
        and facts.no_external_effect is not True
    ):
        raise ContractError("forbidden")
    return facts, request


def _reconcile_observation(
    attempt_id: Id, ledger: Ledger, observation: Observation, control: ControlContext
) -> OperationResultRecord | None:
    with ledger.transaction() as tx:
        attempt, run, plan_ref, auth_ref = _load(tx, attempt_id, control)
        authorize(control, "reconcile", attempt.project_id, run)
        tx.lock(attempt.project_id, run, attempt.operation_key)
        # Re-read after acquiring serialization: another reconciler may have won.
        attempt, _, _, _ = _load(tx, attempt_id, control)
        plan = verified_plan(plan_ref, auth_ref, tx, control, spending=False)
        if observation.usage is not None and (
            identity(observation.usage.tariff_ref) != identity(plan.config.tariff_ref)
        ):
            raise ContractError("forbidden")
        facts, request = _observation(attempt, run, plan_ref, auth_ref, observation, control)
        seen = observation_seen(tx, attempt, observation.evidence, request)
        verified = None
        record = None
        if observation.result_ref is not None:
            verified = verify_result(observation.result_ref, attempt, plan, control)
            if observation.state != verified.manifest.status:
                raise ContractError("result_incomplete")
        if observation.state == "succeeded" and verified is None:
            raise ContractError("result_incomplete")
        if seen:
            if (
                verified is not None
                and verified.comparison_digest is not None
                and observation.result_ref is not None
            ):
                return select_result(
                    tx, attempt, observation.result_ref, verified, observation.evidence, control
                )
            return None
        usage = (
            observation.usage
            if observation.usage is not None
            else (verified.manifest.usage if verified is not None else None)
        )
        if usage is not None:
            event = BudgetEvent(
                schema_version="kf.budget-event.v1",
                project_id=attempt.project_id,
                run_id=run,
                reservation_id=attempt.reservation_id,
                attempt_id=attempt.attempt_id,
                scope="attempt",
                event_id=str(uuid4()),
                event_type="record_usage",
                cost_status=usage.cost_status,
                evidence_ref=observation.evidence,
                created_at=clock(control),
                **({"amount_usd": usage.cost_usd} if usage.cost_usd is not None else {}),
            )
            apply_budget_event(
                event, tx, event_bytes=encoded(event), context=budget_context(control, tx=tx)
            )
        if attempt.state in TERMINAL:
            contradictory = observation.state != attempt.state
            if not contradictory and observation.state == "succeeded" and verified is not None:
                assert observation.result_ref is not None
                record = select_result(
                    tx, attempt, observation.result_ref, verified, observation.evidence, control
                )
            if contradictory:
                integrity_hold(tx, attempt, observation.evidence, control)
            append_observation(tx, attempt, observation.evidence, request, control)
            return record
        changes: dict[str, object] = {}
        if facts.remote_call_id is not None:
            changes["remoteCallId"] = facts.remote_call_id
        if observation.result_ref is not None:
            changes["resultManifestRef"] = observation.result_ref
        if observation.state == attempt.state:
            updated = _amended(attempt, **changes)
        else:
            # Direct succeeded reconciliation from dispatching is accepted only
            # through the explicitly verified intermediate running state.
            if attempt.state == "dispatching" and observation.state == "succeeded":
                attempt = transition(attempt, "running", control, **changes)
            updated = transition(attempt, observation.state, control, **changes)
        if verified is not None and verified.comparison_digest is not None:
            assert observation.result_ref is not None
            record = select_result(
                tx, updated, observation.result_ref, verified, observation.evidence, control
            )
        save_attempt(tx, updated, control)
        append_observation(tx, updated, observation.evidence, request, control)
        return record


def reconcile(
    attempt_id: Id, ledger: Ledger, executor: Executor, store: object, *, control: ControlContext
) -> OperationResultRecord | None:
    if store is not control.store:
        raise ContractError("forbidden")
    with ledger.transaction() as tx:
        attempt, run, _, _ = _load(tx, attempt_id, control)
        authorize(control, "reconcile", attempt.project_id, run)
    try:
        observation = executor.observe(attempt)
    except Exception:
        # Unobservability is uncertainty, never a terminal or billing assertion.
        with ledger.transaction() as tx:
            current, run, _, _ = _load(tx, attempt_id, control)
            tx.lock(current.project_id, run, current.operation_key)
            current, _, _, _ = _load(tx, attempt_id, control)
            if current.state in {"dispatching", "running", "cancel_requested"}:
                save_attempt(tx, transition(current, "unknown_outcome", control), control)
        return None
    return _reconcile_observation(attempt_id, ledger, observation, control)


def set_pause(
    scope: Literal["project", "run"],
    project_id: Id,
    run_id: Id | None,
    paused: bool,
    expected_version: int,
    context: AccessContext,
    ledger: Ledger,
    *,
    control: ControlContext,
    reason: Reason,
    evidence_ref: Ref,
) -> PauseState:
    if context != control.access or type(paused) is not bool:
        raise ContractError("forbidden")
    reason = checked_reason(reason, control)
    action = "pause" if paused else "resume"
    request = bounded_request(
        {
            "action": action,
            "projectId": project_id,
            "scope": scope,
            "paused": paused,
            "expectedVersion": expected_version,
            "reason": reason.model_dump(by_alias=True),
            **({"runId": run_id} if run_id else {}),
        },
        control,
    )
    with ledger.transaction() as tx:
        tx.lock(project_id, run_id)
        control_facts(control, action, run_id, evidence_ref, request)
        current_policy(control, project_id)
        if not paused:
            _resume_grants(tx, project_id, run_id, control)
        state = tx.record_pause(
            scope,
            project_id,
            run_id,
            paused,
            expected_version=expected_version,
            actor_id=context.actor_id,
            reason=reason.code,
            decided_at=clock(control),
            decision_id=str(uuid4()),
        )
        record_decision(tx, project_id, run_id, action, evidence_ref, request, control)
        return state


def _resume_grants(tx: LedgerTxn, project: Id, run: Id | None, control: ControlContext) -> None:
    predicate = sql.SQL(
        "r.project_id=%s AND (r.run_id=%s OR (%s::uuid IS NULL AND ("
        "EXISTS(SELECT 1 FROM {reservations} v WHERE (v.project_id,v.run_id)="
        "(r.project_id,r.run_id) AND NOT v.final_billing) OR EXISTS(SELECT 1 FROM {attempts} a "
        "WHERE (a.project_id,a.run_id)=(r.project_id,r.run_id) "
        "AND a.state NOT IN ('succeeded','failed','cancelled')))))"
    ).format(reservations=tx.table("reservations"), attempts=tx.table("attempts"))
    bound = limits_for(control, "kf.run-authorization.v1")
    count = tx.connection.execute(
        sql.SQL("SELECT count(*) FROM {} r WHERE {}").format(tx.table("runs"), predicate),
        (project, run, run),
    ).fetchone()
    if count is None or count[0] > bound.max_array_items or (run is not None and count[0] != 1):
        raise ContractError("forbidden")
    rows = tx.connection.execute(
        sql.SQL(
            "SELECT r.run_id::text,r.current_authorization_id::text,g.authorization_ref "
            "FROM {} r LEFT JOIN {} g ON (r.project_id,r.run_id,r.current_authorization_id)="
            "(g.project_id,g.run_id,g.authorization_id) WHERE {} ORDER BY r.run_id LIMIT %s"
        ).format(tx.table("runs"), tx.table("authorizations"), predicate),
        (project, run, run, bound.max_array_items + 1),
    ).fetchall()
    for run_id, authorization_id, reference in rows:
        if reference is None:
            raise ContractError("budget_unconfigured")
        _, auth = read_model(Ref.model_validate(reference), RunAuthorization, control)
        if (auth.project_id, auth.run_id, auth.authorization_id) != (
            project,
            run_id,
            authorization_id,
        ) or not auth.authorized_at <= clock(control) < auth.expires_at:
            raise ContractError("authorization_expired")


def cancel_attempt(
    attempt_id: Id,
    ledger: Ledger,
    executor: Executor,
    *,
    control: ControlContext,
    reason: Reason,
    evidence_ref: Ref,
) -> StageAttempt:
    reason = checked_reason(reason, control)
    with ledger.transaction() as tx:
        attempt, run, plan_ref, auth_ref = _load(tx, attempt_id, control)
        tx.lock(attempt.project_id, run, attempt.operation_key)
        attempt, _, _, _ = _load(tx, attempt_id, control)
        request = bounded_request(
            {
                "action": "cancel_attempt",
                "attemptId": attempt_id,
                "state": attempt.state,
                "reason": reason.model_dump(by_alias=True),
                **({"remoteCallId": attempt.remote_call_id} if attempt.remote_call_id else {}),
            },
            control,
        )
        control_facts(
            control,
            "cancel_attempt",
            run,
            evidence_ref,
            request,
            reservation=attempt.reservation_id,
            attempt=attempt_id,
            authorization_ref=auth_ref,
            plan_ref=plan_ref,
        )
        if attempt.state in TERMINAL:
            return attempt
        if attempt.state in {"dispatching", "running", "unknown_outcome"}:
            attempt = transition(attempt, "cancel_requested", control, reason=reason)
            save_attempt(tx, attempt, control)
        elif attempt.state not in {"planned", "reserved", "cancel_requested"}:
            raise ContractError("forbidden")
        record_decision(
            tx,
            attempt.project_id,
            run,
            "cancel_attempt",
            evidence_ref,
            request,
            control,
            operation=attempt.operation_key,
        )
    try:
        observation = executor.cancel(attempt)
    except Exception:
        return attempt  # Requested cancellation remains uncertain and funded.
    _reconcile_observation(attempt_id, ledger, observation, control)
    with ledger.transaction() as tx:
        return _load(tx, attempt_id, control)[0]


def mark_unknown_outcome(
    attempt_id: Id,
    ledger: Ledger,
    *,
    control: ControlContext,
    reason: Reason,
    evidence_ref: Ref,
) -> StageAttempt:
    """Evidenced resolution of a stale claim: dispatching/running -> unknown_outcome.

    A crash after provider acceptance strands `dispatching` with no remote id. This is the
    only way out besides reconciliation; it asserts uncertainty, never absence of effect,
    so the reservation keeps its funds and the manual-retry gate still applies.
    """
    reason = checked_reason(reason, control)
    with ledger.transaction() as tx:
        attempt, run, plan_ref, auth_ref = _load(tx, attempt_id, control)
        tx.lock(attempt.project_id, run, attempt.operation_key)
        attempt, _, _, _ = _load(tx, attempt_id, control)
        # State-independent request so an identical replay stays bound to its evidence.
        request = bounded_request(
            {
                "action": "mark_unknown_outcome",
                "projectId": attempt.project_id,
                "attemptId": attempt_id,
                "reason": reason.model_dump(by_alias=True),
            },
            control,
        )
        control_facts(
            control,
            "mark_unknown_outcome",
            run,
            evidence_ref,
            request,
            reservation=attempt.reservation_id,
            attempt=attempt_id,
            authorization_ref=auth_ref,
            plan_ref=plan_ref,
        )
        if attempt.state == "unknown_outcome":
            return attempt
        if attempt.state not in {"dispatching", "running"}:
            raise ContractError("forbidden")
        attempt = transition(attempt, "unknown_outcome", control)
        save_attempt(tx, attempt, control)
        append_observation(tx, attempt, evidence_ref, request, control)
        return attempt


def _audit_run(tx: LedgerTxn, project: Id, run: Id, control: ControlContext) -> None:
    row = tx.connection.execute(
        sql.SQL(
            "SELECT b.manifest_ref FROM {} r JOIN {} a ON "
            "(r.project_id,r.admission_report_digest)=(a.project_id,a.report_digest) JOIN {} b ON "
            "(a.project_id,a.batch_id)=(b.project_id,b.batch_id) "
            "WHERE r.project_id=%s AND r.run_id=%s"
        ).format(tx.table("runs"), tx.table("admission_reports"), tx.table("batches")),
        (project, run),
    ).fetchone()
    if row is None:
        raise ContractError("forbidden")
    policy = current_policy(control, project)
    _, manifest = read_model(Ref.model_validate(row[0]), IntakeManifest, control)
    for item in manifest.items:
        require_permission(control.access, policy, item.source_id, "auditMetadataRead")


def control_snapshot(
    project_id: Id,
    run_id: Id,
    ledger: Ledger,
    *,
    control: ControlContext,
    operation_key: Digest | None = None,
) -> Digest:
    authorize(control, "control_read", project_id, run_id)
    with ledger.transaction() as tx:
        tx.lock(project_id, run_id, operation_key)
        _audit_run(tx, project_id, run_id, control)
        return snapshot(tx, project_id, run_id, control, operation_key)


def _manual_retry(
    tx: LedgerTxn,
    control: ControlContext,
    risk: DuplicateRiskAuthorization,
    plan: ExecutionPlan,
    auth: RunAuthorization,
    plan_ref: Ref,
    auth_ref: Ref,
    attempt_id: Id,
) -> bool:
    current = snapshot(tx, plan.project_id, plan.run_id, control, plan.operation_key)
    if current != risk.expected_snapshot_digest:
        raise ContractError("determinism_conflict")
    bound = limits_for(control, "kf.stage-attempt.v1")
    count = tx.connection.execute(
        sql.SQL(
            "SELECT count(*) FROM {} WHERE project_id=%s AND ((run_id=%s AND state IN "
            "('unknown_outcome','cancel_requested')) OR (operation_key=%s AND state NOT IN "
            "('succeeded','failed','cancelled')))"
        ).format(tx.table("attempts")),
        (plan.project_id, plan.run_id, plan.operation_key),
    ).fetchone()
    if count is None or count[0] == 0 or count[0] > bound.max_array_items:
        raise ContractError("forbidden")
    rows = tx.connection.execute(
        sql.SQL(
            "SELECT a.attempt_id::text,a.state,p.plan_digest,p.authorization_id::text "
            "FROM {} a JOIN {} p "
            "ON (a.project_id,a.plan_id)=(p.project_id,p.plan_id) WHERE a.project_id=%s "
            "AND ((a.run_id=%s AND a.state IN ('unknown_outcome','cancel_requested')) "
            "OR (a.operation_key=%s AND a.state NOT IN ('succeeded','failed','cancelled'))) "
            "ORDER BY a.attempt_id LIMIT %s"
        ).format(tx.table("attempts"), tx.table("plans")),
        (plan.project_id, plan.run_id, plan.operation_key, bound.max_array_items + 1),
    ).fetchall()
    expected = tuple(row[0] for row in rows)
    if (
        type(risk.unresolved_attempt_ids) is not tuple
        or tuple(sorted(risk.unresolved_attempt_ids)) != expected
        or len(set(risk.unresolved_attempt_ids)) != len(expected)
        or any(
            row[1] != "unknown_outcome"
            or row[2] == plan_ref.digest
            or row[3] == auth.authorization_id
            for row in rows
        )
    ):
        raise ContractError("forbidden")
    request = bounded_request(
        {
            "action": "manual_retry",
            "projectId": plan.project_id,
            "runId": plan.run_id,
            "operationKey": plan.operation_key,
            "newPlanRef": plan_ref.model_dump(by_alias=True),
            "authorizationRef": auth_ref.model_dump(by_alias=True),
            "attemptId": attempt_id,
            "snapshotDigest": current,
            "unresolvedAttemptIds": list(expected),
        },
        control,
    )
    facts = control_facts(
        control,
        "manual_retry",
        plan.run_id,
        risk.evidence_ref,
        request,
        attempt=attempt_id,
        authorization_ref=auth_ref,
        plan_ref=plan_ref,
        snapshot=current,
    )
    if (
        facts.acknowledges_duplicate_charge_risk is not True
        or facts.unresolved_attempt_ids != expected
    ):
        raise ContractError("forbidden")
    record_decision(
        tx,
        plan.project_id,
        plan.run_id,
        "manual_retry",
        risk.evidence_ref,
        request,
        control,
        operation=plan.operation_key,
    )
    return True


def reconcile_budget(
    project_id: Id,
    run_id: Id,
    expected_snapshot_digest: Digest,
    context: AccessContext,
    ledger: Ledger,
    *,
    control: ControlContext,
    reason: Reason,
    evidence_ref: Ref,
) -> None:
    if context != control.access:
        raise ContractError("forbidden")
    reason = checked_reason(reason, control)
    authorize(control, "reconcile_budget", project_id, run_id)
    with ledger.transaction() as tx:
        tx.lock(project_id, run_id)
        _audit_run(tx, project_id, run_id, control)
        current = snapshot(tx, project_id, run_id, control, None)
        if current != expected_snapshot_digest:
            raise ContractError("determinism_conflict")
        request = bounded_request(
            {
                "action": "reconcile_budget",
                "projectId": project_id,
                "runId": run_id,
                "snapshotDigest": current,
                "reason": reason.model_dump(by_alias=True),
            },
            control,
        )
        facts = control_facts(
            control, "reconcile_budget", run_id, evidence_ref, request, snapshot=current
        )
        if facts.liabilities_resolved is not True:
            raise ContractError("forbidden")
        unsafe = tx.connection.execute(
            sql.SQL(
                "SELECT EXISTS(SELECT 1 FROM {} WHERE project_id=%s AND run_id=%s AND "
                "(NOT final_billing OR outstanding_usd<>0)) OR EXISTS(SELECT 1 FROM {} WHERE "
                "project_id=%s AND run_id=%s AND state NOT IN ('succeeded','failed','cancelled'))"
            ).format(tx.table("reservations"), tx.table("attempts")),
            (project_id, run_id, project_id, run_id),
        ).fetchone()
        totals = tx.connection.execute(
            sql.SQL(
                "SELECT coalesce(sum(v.settled_usd+v.outstanding_usd),0),r.max_run_cost,r.frozen "
                "FROM {} r LEFT JOIN {} v ON (r.project_id,r.run_id)=(v.project_id,v.run_id) "
                "WHERE r.project_id=%s AND r.run_id=%s GROUP BY r.max_run_cost,r.frozen"
            ).format(tx.table("runs"), tx.table("reservations")),
            (project_id, run_id),
        ).fetchone()
        if (
            unsafe is None
            or unsafe[0]
            or totals is None
            or totals[1] is None
            or totals[0] > totals[1]
            or totals[2] is not True
        ):
            raise ContractError("forbidden")
        record_decision(tx, project_id, run_id, "reconcile_budget", evidence_ref, request, control)
        tx.connection.execute(
            sql.SQL(
                "UPDATE {} SET frozen=false,freeze_reason=NULL WHERE project_id=%s AND run_id=%s"
            ).format(tx.table("runs")),
            (project_id, run_id),
        )
