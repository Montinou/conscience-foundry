"""Durable local control of bounded remote effects; no live provider implementation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from typing import Any, Literal, cast, get_args
from uuid import uuid4

from psycopg import sql
from pydantic import TypeAdapter, ValidationError

from conscience_foundry.contracts.accounting import (
    BudgetEvent,
    OperationResultRecord,
    ResourceUsage,
)
from conscience_foundry.contracts.admission import IntakeManifest
from conscience_foundry.contracts.common import (
    ContractError,
    Digest,
    ErrorCode,
    Id,
    Reason,
    Ref,
)
from conscience_foundry.contracts.execution import (
    ExecutionPlan,
    LocalExecutionConfig,
    RunAuthorization,
    StageAttempt,
    execution_destination,
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
from conscience_foundry.execution.local_contracts import LocalWorkerGrant
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
    TransportIssuer,
    TransportProof,
)
from conscience_foundry.execution.staged_import import import_staged_result
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
        + len(b"cf.transport-material.internal.v1\n")
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
    digest = hashlib.sha256(b"cf.transport-material.internal.v1\n")
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


def _local_grants(
    grants: object,
    plan: ExecutionPlan,
    auth: RunAuthorization,
    plan_ref: Ref,
    config: object,
    control: ControlContext,
) -> None:
    from conscience_foundry.contracts.common import Instant
    from conscience_foundry.execution.local_contracts import (
        LocalGrantFacts,
        LocalGrantProof,
        LocalWorkerGrant,
    )

    if type(grants) is not LocalWorkerGrant or type(config) is not LocalExecutionConfig:
        raise ContractError("forbidden")
    bound = control.transport_limits
    try:
        TypeAdapter(Id).validate_python(grants.attempt_id)
        TypeAdapter(Instant).validate_python(grants.expires_at)
        if (
            (grants.project_id, grants.run_id, grants.plan_digest, grants.destination_id)
            != (plan.project_id, plan.run_id, plan_ref.digest, config.local_destination_id)
            or type(grants.output_scope) is not bytes
            or not grants.output_scope
            or len(grants.output_scope) > bound.max_source_bytes
            or type(grants.nonce) is not str
            or not grants.nonce
            or len(grants.nonce) > bound.max_string_scalars
            or len(plan.input_refs) > bound.max_array_items
            or plan.execution_config_ref.artifact_schema != config.schema_version
            or plan.execution_config_ref.size_bytes != len(encoded(config))
            or plan.execution_config_ref.digest != hashlib.sha256(encoded(config)).hexdigest()
        ):
            raise ContractError("forbidden")
        if not clock(control) < grants.expires_at <= min(plan.expires_at, auth.expires_at):
            raise ContractError("authorization_expired")
        proof = LocalGrantProof(
            grants.project_id,
            grants.run_id,
            grants.plan_digest,
            grants.attempt_id,
            grants.destination_id,
            grants.expires_at,
            plan.input_refs,
            grants.output_scope,
            hashlib.sha256(grants.nonce.encode()).hexdigest(),
        )
        authority = getattr(control.evidence_authority, "local_grant", None)
        if not callable(authority):
            raise ContractError("forbidden")
        facts = authority(proof)
        if type(facts) is not LocalGrantFacts or facts.scopes != frozenset({"read", "extract"}):
            raise ContractError("forbidden")
        if (
            LocalGrantProof(
                facts.project_id,
                facts.run_id,
                facts.plan_digest,
                facts.attempt_id,
                facts.destination_id,
                facts.expires_at,
                facts.input_refs,
                facts.output_scope,
                facts.nonce_digest,
            )
            != proof
        ):
            raise ContractError("forbidden")
        if not clock(control) < grants.expires_at <= min(plan.expires_at, auth.expires_at):
            raise ContractError("authorization_expired")
    except ContractError:
        raise
    except Exception:
        raise ContractError("forbidden") from None


def _mint(issuer: TransportIssuer, attempt: StageAttempt) -> TransportGrants:
    """Ask the trusted issuer for this exact claimed attempt; anything else is a refusal."""
    try:
        minted = issuer(attempt)
    except Exception:
        raise ContractError("forbidden") from None
    if type(minted) is not TransportGrants or minted.attempt_id != attempt.attempt_id:
        raise ContractError("forbidden")
    return minted


def _mint_local(issuer: Any, attempt: StageAttempt) -> LocalWorkerGrant:
    try:
        minted = issuer(attempt)
    except Exception:
        raise ContractError("forbidden") from None
    if type(minted) is not LocalWorkerGrant or minted.attempt_id != attempt.attempt_id:
        raise ContractError("forbidden")
    return minted


def _close_unsubmitted(
    ledger: Ledger,
    attempt: StageAttempt,
    evidence_ref: Ref,
    control: ControlContext,
    *,
    state: Literal["failed", "unknown_outcome"],
    reason: Reason,
    action: str,
) -> StageAttempt:
    """End a claimed dispatch that never reached the executor, with the evidence of why."""
    with ledger.transaction() as tx:
        current, run, _, _ = _load(tx, attempt.attempt_id, control)
        tx.lock(current.project_id, run, current.operation_key)
        current, _, _, _ = _load(tx, attempt.attempt_id, control)
        if current.state == "dispatching":
            current = transition(
                current,
                state,
                control,
                **({"reason": reason} if state == "failed" else {}),
            )
            save_attempt(tx, current, control)
        request = bounded_request(
            {
                "action": action,
                "attemptId": current.attempt_id,
                "submitInvoked": False,
                "state": current.state,
            },
            control,
        )
        append_observation(tx, current, evidence_ref, request, control)
        return current


def dispatch(
    plan: ExecutionPlan,
    authorization: RunAuthorization,
    context: AccessContext,
    ledger: Ledger,
    executor: Executor,
    grants: TransportGrants | TransportIssuer,
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
    # Prepared grants are checked and bound to their own attempt id up front. An issuer is asked
    # only after the reservation and claim commit, for the attempt id chosen here.
    prepared = grants if type(grants) is TransportGrants else None
    if prepared is None and not callable(grants):
        raise ContractError("forbidden")
    attempt_id = prepared.attempt_id if prepared is not None else str(uuid4())
    with ledger.transaction() as tx:
        tx.lock(context.project_id, plan.run_id)
        verified = verified_plan(plan_ref, authorization_ref, tx, control, spending=True)
        if isinstance(verified.config, LocalExecutionConfig):
            try:
                from conscience_foundry.execution.local_executor import LocalExecutor
            except ImportError:
                raise ContractError("adapter_unavailable") from None
            if (
                type(executor) is not LocalExecutor
                or prepared is not None
                or not callable(grants)
                or not callable(getattr(control.evidence_authority, "local_grant", None))
                or control.stage_inputs is not None
                or control.staged_reader is None
                or control.staged_writer is None
            ):
                raise ContractError("adapter_unavailable")
        if verified.model != plan or verified.authorization != authorization:
            raise ContractError("hash_mismatch")
        if verified.data != encoded(plan):
            # Every adapter digests the canonical serialization; the stored bytes must be those.
            raise ContractError("invalid_schema")
        if prepared is not None:
            _grants(
                prepared,
                plan,
                authorization,
                plan_ref,
                execution_destination(verified.config),
                control,
            )
        existing = tx.connection.execute(
            sql.SQL("SELECT 1 FROM {} WHERE project_id=%s AND attempt_id=%s").format(
                tx.table("attempts")
            ),
            (context.project_id, attempt_id),
        ).fetchone()
        if existing:
            old, _, old_plan, old_auth = _load(tx, attempt_id, control)
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
                    attempt_id,
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
            attempt_id=attempt_id,
            duplicate_risk=risk,
        )
        attempt = claim_attempt(tx, attempt, control)
    # The committed claim/reservation precedes every external effect. No DB lock
    # is retained across submit, and an exception is deliberately uncertain.
    if control.stage_inputs is not None:
        # Before any write-capable material exists. Nothing is submitted if staging stops, but a
        # `dispatch_unknown` leaves the staged state unproven, so it is never reported as failed.
        code: str | None = None
        try:
            control.stage_inputs(plan, context)
        except ContractError as error:
            code = error.code
        except Exception:
            code = "dispatch_unknown"
        if code is not None:
            return _close_unsubmitted(
                ledger,
                attempt,
                evidence_ref,
                control,
                state="unknown_outcome" if code == "dispatch_unknown" else "failed",
                reason=Reason(
                    code=cast(ErrorCode, code if code in get_args(ErrorCode) else "forbidden"),
                    message="Input staging refused",
                ),
                action="input_staging_refused",
            )
    minted: LocalWorkerGrant | TransportGrants
    try:
        if isinstance(verified.config, LocalExecutionConfig):
            minted = _mint_local(grants, attempt)
            _local_grants(minted, plan, authorization, plan_ref, verified.config, control)
        else:
            minted = (
                prepared if prepared is not None else _mint(cast(TransportIssuer, grants), attempt)
            )
            _grants(
                minted,
                plan,
                authorization,
                plan_ref,
                execution_destination(verified.config),
                control,
            )
    except ContractError:
        # No executor was invoked: local control can prove no submission effect.
        # Financial liability still needs the separate final-no-liability gate.
        return _close_unsubmitted(
            ledger,
            attempt,
            evidence_ref,
            control,
            state="failed",
            reason=Reason(code="forbidden", message="Transport proof unavailable"),
            action="transport_proof_refused",
        )
    try:
        submission = executor.submit(plan, attempt, minted)
    except Exception:
        submission = Submission(None, None)
    identified = (
        type(submission) is Submission
        and type(submission.remote_call_id) is str
        and bool(submission.remote_call_id)
        and len(submission.remote_call_id)
        <= limits_for(control, "cf.stage-attempt.v1").max_string_scalars
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
            encoded(observation.usage), limits_for(control, "cf.result.v1")
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
        <= limits_for(control, "cf.stage-attempt.v1").max_string_scalars
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


@dataclass(frozen=True)
class AttestedObservation:
    """An observation proven against the attempt as it stood, before any result is imported."""

    attempt: StageAttempt
    observation: Observation
    facts: ObservationFacts
    request: bytes = field(repr=False)


def _attest(
    attempt_id: Id, ledger: Ledger, observation: Observation, control: ControlContext
) -> AttestedObservation:
    """Short transaction: authorize and attest the observation; nothing is recorded."""
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
        return AttestedObservation(attempt, observation, facts, request)


def _fail_closed(attempt_id: Id, ledger: Ledger, control: ControlContext) -> None:
    """Uncertainty about a live attempt is `unknown_outcome`, never a terminal assertion."""
    with ledger.transaction() as tx:
        current, run, _, _ = _load(tx, attempt_id, control)
        tx.lock(current.project_id, run, current.operation_key)
        current, _, _, _ = _load(tx, attempt_id, control)
        if current.state in {"dispatching", "running", "cancel_requested"}:
            save_attempt(tx, transition(current, "unknown_outcome", control), control)


def _reconcile_observation(
    attempt_id: Id, ledger: Ledger, observation: Observation, control: ControlContext
) -> OperationResultRecord | None:
    attested = _attest(attempt_id, ledger, observation, control)
    # Outside any transaction: remote reads must not hold a lock or a connection.
    if observation.result_ref is not None and control.staged_reader is not None:
        try:
            destination = (
                control.staged_writer(attested.attempt.project_id, attested.attempt.attempt_id)
                if control.staged_writer is not None
                else control.store
            )
            import_staged_result(
                control.staged_reader(attested.attempt.project_id, attested.attempt.attempt_id),
                destination,
                observation.result_ref,
                control.access,
                limits_by_schema=control.limits_by_schema,
            )
        except ContractError:
            # An unproven import is not a verdict on the result: acceptance never ran.
            _fail_closed(attempt_id, ledger, control)
            return None
    return _apply(attempt_id, ledger, attested, control)


def _apply(
    attempt_id: Id, ledger: Ledger, attested: AttestedObservation, control: ControlContext
) -> OperationResultRecord | None:
    observation, facts, request = attested.observation, attested.facts, attested.request
    with ledger.transaction() as tx:
        attempt, run, plan_ref, auth_ref = _load(tx, attempt_id, control)
        authorize(control, "reconcile", attempt.project_id, run)
        tx.lock(attempt.project_id, run, attempt.operation_key)
        attempt, _, _, _ = _load(tx, attempt_id, control)
        # What was attested describes the attempt as it was; any move since voids it.
        if (attempt.state, attempt.remote_call_id) != (
            attested.attempt.state,
            attested.attempt.remote_call_id,
        ):
            raise ContractError("determinism_conflict")
        plan = verified_plan(plan_ref, auth_ref, tx, control, spending=False)
        if observation.result_ref is not None:
            current = tx.connection.execute(
                sql.SQL(
                    "SELECT o.held, EXISTS(SELECT 1 FROM {} h WHERE h.project_id=%s "
                    "AND h.operation_key=%s), EXISTS(SELECT 1 FROM {} w "
                    "WHERE w.project_id=%s AND w.asset_id=%s AND w.source_id=%s) "
                    "FROM {} o WHERE o.project_id=%s AND o.operation_key=%s"
                ).format(
                    tx.table("integrity_holds"),
                    tx.table("admission_withdrawals"),
                    tx.table("operations"),
                ),
                (
                    attempt.project_id,
                    attempt.operation_key,
                    attempt.project_id,
                    plan.source_asset.asset_id,
                    plan.source_asset.source_id,
                    attempt.project_id,
                    attempt.operation_key,
                ),
            ).fetchone()
            if current is None or any(current):
                raise ContractError("forbidden")
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
                schema_version="cf.budget-event.v1",
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
        _fail_closed(attempt_id, ledger, control)
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
    bound = limits_for(control, "cf.run-authorization.v1")
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


DEADLINE_REASON = "limit_exceeded"
"""The only reason code a deadline cancel or unknown mark may carry."""


def _permission(
    control: ControlContext, reason: Reason, deadline_token: object | None, deadline_action: str
) -> str | None:
    """The grant to check instead of the operator's, when the live session's token is held.

    ``None`` means the ordinary action. A token is a capability held by identity: it must be the
    very object the control context carries (never ``None`` against ``None``), and it only
    stands for a deadline, so the reason must say so.
    """
    if deadline_token is None:
        return None
    if (
        control.deadline_token is None
        or deadline_token is not control.deadline_token
        or reason.code != DEADLINE_REASON
    ):
        raise ContractError("forbidden")
    return deadline_action


def cancel_attempt(
    attempt_id: Id,
    ledger: Ledger,
    executor: Executor,
    *,
    control: ControlContext,
    reason: Reason,
    evidence_ref: Ref,
    deadline_token: object | None = None,
) -> StageAttempt:
    """Request cancellation of an attempt's remote call; the provider alone settles it.

    Without ``deadline_token`` the operator's ``cancel_attempt`` grant is checked. With the live
    session's token (and ``limit_exceeded``) the ``deadline_cancel`` grant is checked instead, so
    the reconcile step can cancel a call at its deadline and nothing else.
    """
    reason = checked_reason(reason, control)
    permission = _permission(control, reason, deadline_token, "deadline_cancel")
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
            permission=permission,
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
    deadline_token: object | None = None,
) -> StageAttempt:
    """Evidenced resolution of a stale claim: dispatching/running -> unknown_outcome.

    A crash after provider acceptance strands `dispatching` with no remote id. This is the
    only way out besides reconciliation; it asserts uncertainty, never absence of effect,
    so the reservation keeps its funds and the manual-retry gate still applies.

    With the live session's ``deadline_token`` (and ``limit_exceeded``) the ``deadline_unknown``
    grant is checked instead of ``mark_unknown_outcome``, which no CLI command holds.
    """
    reason = checked_reason(reason, control)
    permission = _permission(control, reason, deadline_token, "deadline_unknown")
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
            permission=permission,
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
    bound = limits_for(control, "cf.stage-attempt.v1")
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
