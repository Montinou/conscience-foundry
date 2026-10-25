"""Durable attempt state, bounded CAS snapshots and append-only observations."""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import uuid4

from psycopg import sql
from psycopg.types.json import Jsonb

from conscience_foundry.contracts.common import ContractError, Id, Ref
from conscience_foundry.contracts.execution import StageAttempt
from conscience_foundry.execution.evidence import (
    bounded_request,
    clock,
    encoded,
    limits_for,
    put_record,
)
from conscience_foundry.execution.ports import ControlContext
from conscience_foundry.ledger.db import LedgerTxn

TERMINAL = frozenset({"succeeded", "failed", "cancelled"})
TRANSITIONS = {
    "planned": frozenset({"reserved", "cancelled"}),
    "reserved": frozenset({"dispatching", "cancelled"}),
    "dispatching": frozenset({"running", "failed", "unknown_outcome", "cancel_requested"}),
    "running": frozenset({"succeeded", "failed", "unknown_outcome", "cancel_requested"}),
    "unknown_outcome": frozenset(
        {"running", "succeeded", "failed", "cancelled", "cancel_requested"}
    ),
    "cancel_requested": frozenset({"cancelled", "succeeded", "failed", "unknown_outcome"}),
}


def json_ref(ref: Ref) -> Jsonb:
    return Jsonb(ref.model_dump(by_alias=True, exclude_none=True))


def load_attempt(tx: LedgerTxn, project: Id, attempt_id: Id) -> tuple[Ref, Id, Ref, Ref]:
    row = tx.connection.execute(
        sql.SQL(
            "SELECT a.attempt_ref,a.run_id::text,p.plan_ref,g.authorization_ref "
            "FROM {} a JOIN {} p "
            "ON (a.project_id,a.plan_id)=(p.project_id,p.plan_id) JOIN {} g "
            "ON (p.project_id,p.run_id,p.authorization_id)="
            "(g.project_id,g.run_id,g.authorization_id) "
            "WHERE a.project_id=%s AND a.attempt_id=%s"
        ).format(tx.table("attempts"), tx.table("plans"), tx.table("authorizations")),
        (project, attempt_id),
    ).fetchone()
    if row is None or row[0] is None:
        raise ContractError("artifact_missing")
    ref = Ref.model_validate(row[0])
    # The caller verifies the exact immutable snapshot bytes through its store.
    return ref, row[1], Ref.model_validate(row[2]), Ref.model_validate(row[3])


def save_attempt(tx: LedgerTxn, attempt: StageAttempt, control: ControlContext) -> Ref:
    row = tx.connection.execute(
        sql.SQL(
            "SELECT state,attempt_ref FROM {} WHERE project_id=%s AND attempt_id=%s FOR UPDATE"
        ).format(tx.table("attempts")),
        (attempt.project_id, attempt.attempt_id),
    ).fetchone()
    if row is None:
        raise ContractError("artifact_missing")
    if row[0] in TERMINAL:
        # A stale controller may never replace an immutable terminal snapshot.
        existing = Ref.model_validate(row[1])
        if hashlib.sha256(encoded(attempt)).hexdigest() != existing.digest:
            raise ContractError("determinism_conflict")
        return existing
    ref = put_record(attempt, control)
    tx.connection.execute(
        sql.SQL(
            "UPDATE {} SET state=%s,attempt_ref=%s,dispatched_at=%s,finished_at=%s,"
            "remote_call_id=%s,result_ref=%s WHERE project_id=%s AND attempt_id=%s"
        ).format(tx.table("attempts")),
        (
            attempt.state,
            json_ref(ref),
            attempt.dispatched_at,
            attempt.finished_at,
            attempt.remote_call_id,
            json_ref(attempt.result_manifest_ref) if attempt.result_manifest_ref else None,
            attempt.project_id,
            attempt.attempt_id,
        ),
    )
    return ref


def transition(
    attempt: StageAttempt, state: str, control: ControlContext, **changes: Any
) -> StageAttempt:
    if attempt.state in TERMINAL or state not in TRANSITIONS.get(attempt.state, frozenset()):
        raise ContractError("determinism_conflict")
    value = attempt.model_dump(by_alias=True, exclude_none=True)
    value.update(state=state, **changes)
    if state in TERMINAL:
        value["finishedAt"] = clock(control)
    else:
        value.pop("finishedAt", None)
    return StageAttempt.model_validate(value)


def claim_attempt(tx: LedgerTxn, attempt: StageAttempt, control: ControlContext) -> StageAttempt:
    if tx.connection.execute(
        sql.SQL("SELECT 1 FROM {} WHERE project_id=%s AND attempt_id=%s").format(
            tx.table("dispatch_claims")
        ),
        (attempt.project_id, attempt.attempt_id),
    ).fetchone():
        raise ContractError("dispatch_unknown")
    reserved_ref = put_record(attempt, control)
    result = transition(attempt, "dispatching", control, dispatchedAt=clock(control))
    dispatched_ref = save_attempt(tx, result, control)
    tx.connection.execute(
        sql.SQL(
            "INSERT INTO {} (project_id,attempt_id,claimed_at,claim_id,reserved_attempt_ref,"
            "dispatched_attempt_ref) VALUES (%s,%s,%s,%s,%s,%s)"
        ).format(tx.table("dispatch_claims")),
        (
            attempt.project_id,
            attempt.attempt_id,
            clock(control),
            str(uuid4()),
            json_ref(reserved_ref),
            json_ref(dispatched_ref),
        ),
    )
    return result


def observation_seen(
    tx: LedgerTxn, attempt: StageAttempt, evidence_ref: Ref, request: bytes
) -> bool:
    row = tx.connection.execute(
        sql.SQL(
            "SELECT request_digest FROM {} WHERE project_id=%s AND attempt_id=%s "
            "AND evidence_digest=%s"
        ).format(tx.table("attempt_observations")),
        (attempt.project_id, attempt.attempt_id, evidence_ref.digest),
    ).fetchone()
    if row is None:
        return False
    if row[0] != hashlib.sha256(request).hexdigest():
        raise ContractError("determinism_conflict")
    return True


def append_observation(
    tx: LedgerTxn,
    attempt: StageAttempt,
    evidence_ref: Ref,
    request: bytes,
    control: ControlContext,
) -> None:
    ref = put_record(attempt, control)
    tx.connection.execute(
        sql.SQL(
            "INSERT INTO {} (project_id,attempt_id,observation_id,evidence_digest,request_digest,"
            "evidence_ref,record_bytes,attempt_ref,observed_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        ).format(tx.table("attempt_observations")),
        (
            attempt.project_id,
            attempt.attempt_id,
            str(uuid4()),
            evidence_ref.digest,
            hashlib.sha256(request).hexdigest(),
            json_ref(evidence_ref),
            request,
            json_ref(ref),
            clock(control),
        ),
    )


def record_decision(
    tx: LedgerTxn,
    project: Id,
    run: Id | None,
    action: str,
    evidence_ref: Ref,
    request: bytes,
    control: ControlContext,
    *,
    operation: str | None = None,
) -> None:
    tx.connection.execute(
        sql.SQL(
            "INSERT INTO {} (project_id,decision_id,run_id,operation_key,action,evidence_ref,"
            "request_digest,record_bytes,actor_id,decided_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        ).format(tx.table("control_decisions")),
        (
            project,
            str(uuid4()),
            run,
            operation,
            action,
            json_ref(evidence_ref),
            hashlib.sha256(request).hexdigest(),
            request,
            control.access.actor_id,
            clock(control),
        ),
    )


def snapshot(
    tx: LedgerTxn, project: Id, run: Id, control: ControlContext, operation: str | None
) -> str:
    """Fixed metadata projection; counts and serialized bytes are bounded before hashing."""
    tx.lock(project, run, operation)
    bound = limits_for(control, "kf.stage-attempt.v1")
    filters: list[tuple[str, tuple[str, ...], str, tuple[object, ...], str]] = [
        (
            "runs",
            (
                "run_id",
                "admission_report_digest",
                "current_authorization_id",
                "max_run_cost",
                "max_concurrent_attempts",
                "frozen",
                "freeze_reason",
            ),
            "project_id=%s AND run_id=%s",
            (project, run),
            "run_id",
        ),
        (
            "authorizations",
            (
                "authorization_id",
                "authorization_ref",
                "allowed_plan_digests",
                "max_run_cost",
                "max_concurrent_attempts",
                "actor_id",
                "authorized_at",
                "expires_at",
            ),
            "project_id=%s AND run_id=%s",
            (project, run),
            "authorization_id",
        ),
        (
            "plans",
            ("plan_id", "plan_digest", "authorization_id", "operation_key"),
            "project_id=%s AND run_id=%s",
            (project, run),
            "plan_id",
        ),
        (
            "reservations",
            (
                "reservation_id",
                "run_id",
                "authorization_id",
                "operation_key",
                "scope",
                "reserved_usd",
                "outstanding_usd",
                "settled_usd",
                "released_usd",
                "final_billing",
                "evidence_ref",
            ),
            "project_id=%s AND (run_id=%s OR operation_key=%s)",
            (project, run, operation),
            "reservation_id",
        ),
        (
            "attempts",
            (
                "attempt_id",
                "run_id",
                "operation_key",
                "state",
                "reservation_id",
                "attempt_ref",
                "remote_call_id",
                "result_ref",
            ),
            "project_id=%s AND (run_id=%s OR operation_key=%s)",
            (project, run, operation),
            "attempt_id",
        ),
        (
            "budget_events",
            ("event_id", "record_digest"),
            "project_id=%s AND run_id=%s",
            (project, run),
            "event_id",
        ),
        (
            "billing_adjustments",
            ("adjustment_id", "record_digest"),
            "project_id=%s AND run_id=%s",
            (project, run),
            "adjustment_id",
        ),
        (
            "pause_state",
            ("scope", "run_id", "paused", "version"),
            "project_id=%s AND (run_id=%s OR scope='project')",
            (project, run),
            "scope",
        ),
        (
            "operations",
            (
                "operation_key",
                "held",
                "attempts_allocated",
                "latest_event_id",
                "selected_comparison_digest",
            ),
            "project_id=%s AND operation_key IN (SELECT operation_key FROM {plans} "
            "WHERE project_id=%s AND run_id=%s) OR (project_id=%s AND operation_key=%s)",
            (project, project, run, project, operation),
            "operation_key",
        ),
        (
            "dispatch_claims",
            ("attempt_id", "claim_id", "reserved_attempt_ref", "dispatched_attempt_ref"),
            "project_id=%s AND attempt_id IN (SELECT attempt_id FROM {attempts} "
            "WHERE project_id=%s AND (run_id=%s OR operation_key=%s))",
            (project, project, run, operation),
            "attempt_id",
        ),
        (
            "attempt_observations",
            ("observation_id", "attempt_id", "evidence_digest", "request_digest", "attempt_ref"),
            "project_id=%s AND attempt_id IN (SELECT attempt_id FROM {attempts} "
            "WHERE project_id=%s AND (run_id=%s OR operation_key=%s))",
            (project, project, run, operation),
            "observation_id",
        ),
        (
            "control_decisions",
            ("decision_id", "request_digest"),
            "project_id=%s AND (run_id=%s OR run_id IS NULL)",
            (project, run),
            "decision_id",
        ),
    ]
    payload: dict[str, object] = {
        "projectId": project,
        "runId": run,
        "scope": "manual_retry" if operation else "run_budget",
    }
    if operation:
        payload["operationKey"] = operation
    count = 0
    for table, columns, where, parameters, order in filters:
        predicate = sql.SQL(where).format(plans=tx.table("plans"), attempts=tx.table("attempts"))
        total = tx.connection.execute(
            sql.SQL("SELECT count(*) FROM {} WHERE {}").format(tx.table(table), predicate),
            parameters,
        ).fetchone()
        assert total is not None
        count += total[0]
        if count > bound.max_array_items:
            raise ContractError("limit_exceeded")
        selection = sql.SQL(",").join(
            sql.SQL("coalesce({}::text,'')").format(sql.Identifier(column)) for column in columns
        )
        rows = tx.connection.execute(
            sql.SQL("SELECT {} FROM {} WHERE {} ORDER BY {} LIMIT %s").format(
                selection, tx.table(table), predicate, sql.Identifier(order)
            ),
            (*parameters, bound.max_array_items + 1),
        ).fetchall()
        payload[table] = [list(row) for row in rows]
    return hashlib.sha256(
        b"kf.control-snapshot.v1\n" + bounded_request(payload, control)
    ).hexdigest()
