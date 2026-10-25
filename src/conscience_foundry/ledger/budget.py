"""Atomic F1 liabilities; trusted control supplies current authority and evidence.

These functions never contact providers or release liabilities from estimates.
The evidence resolver is an explicit authenticated control port, not wire data.
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal, localcontext
from typing import Any
from uuid import uuid4

from psycopg import sql
from psycopg.types.json import Jsonb
from pydantic import TypeAdapter, ValidationError

from conscience_foundry.contracts.accounting import BillingAdjustment, BudgetEvent
from conscience_foundry.contracts.admission import AdmissionReport, IntakeManifest
from conscience_foundry.contracts.common import (
    MAX_SAFE_INTEGER,
    ContractError,
    Id,
    Money,
    Ref,
)
from conscience_foundry.contracts.execution import (
    ExecutionConfig,
    ExecutionPlan,
    RunAuthorization,
    StageAttempt,
    validate_plan_authorization,
)
from conscience_foundry.contracts.project import PolicyArtifact
from conscience_foundry.core.identity import F1Operation, operation_key
from conscience_foundry.ledger._budget_inputs import (
    BudgetContext as BudgetContext,
)
from conscience_foundry.ledger._budget_inputs import (
    BudgetEvidenceClaim as BudgetEvidenceClaim,
)
from conscience_foundry.ledger._budget_inputs import (
    DuplicateRiskAuthorization,
    _context,
    _identity,
    _limits,
    _parse,
    _proof,
    _stored_ref,
)
from conscience_foundry.ledger.db import AdmissionRegistrationEvidence, LedgerTxn
from conscience_foundry.policy.access import require_permission


def _json(ref: Ref) -> Jsonb:
    return Jsonb(ref.model_dump(by_alias=True, exclude_none=True))


def _totals(tx: LedgerTxn, project: Id, run: Id) -> tuple[Decimal, Decimal]:
    row = tx.connection.execute(
        sql.SQL(
            "SELECT coalesce(sum(settled_usd),0),coalesce(sum(outstanding_usd),0) "
            "FROM {} WHERE project_id=%s AND run_id=%s"
        ).format(tx.table("reservations")),
        (project, run),
    ).fetchone()
    assert row is not None
    return row[0], row[1]


def _remaining(cap: Decimal, actual: Decimal, outstanding: Decimal, amount: Decimal) -> bool:
    # Money is an arbitrary-length bounded decimal string, not a binary float.
    with localcontext() as arithmetic:
        arithmetic.prec = (
            sum(len(x.as_tuple().digits) for x in (cap, actual, outstanding, amount)) + 20
        )
        return actual + outstanding + amount <= cap


def _installed(tx: LedgerTxn, project: Id, run: Id) -> tuple[Any, ...]:
    tx.lock(project, run)
    row = tx.connection.execute(
        sql.SQL(
            "SELECT r.current_authorization_id::text,r.max_run_cost,r.max_concurrent_attempts,"
            "r.frozen,a.authorization_ref,a.allowed_plan_digests,a.authorized_at,a.expires_at,"
            "r.admission_report_digest FROM {} r JOIN {} a ON "
            "(r.project_id,r.run_id,r.current_authorization_id)="
            "(a.project_id,a.run_id,a.authorization_id) WHERE r.project_id=%s AND r.run_id=%s"
        ).format(tx.table("runs"), tx.table("authorizations")),
        (project, run),
    ).fetchone()
    if row is None:
        raise ContractError("budget_unconfigured")
    return row


def _spending(
    tx: LedgerTxn,
    project: Id,
    run: Id,
    row: tuple[Any, ...],
    context: BudgetContext,
    amount: Decimal,
    *, allow_unknown: bool = False,
) -> None:
    from datetime import datetime

    now = datetime.fromisoformat(context.now)
    if now < row[6] or now >= row[7]:
        raise ContractError("authorization_expired")
    if (
        row[3]
        or tx.get_pause("project", project, None).paused
        or tx.get_pause("run", project, run).paused
    ):
        raise ContractError("forbidden")
    unresolved = tx.connection.execute(
        sql.SQL(
            "SELECT 1 FROM {} WHERE project_id=%s AND run_id=%s "
            "AND state IN ('unknown_outcome','cancel_requested') LIMIT 1"
        ).format(tx.table("attempts")),
        (project, run),
    ).fetchone()
    if unresolved and not allow_unknown:
        raise ContractError("dispatch_unknown")
    actual, outstanding = _totals(tx, project, run)
    if not _remaining(row[1], actual, outstanding, amount):
        raise ContractError("budget_exhausted")


def install_run_authorization(
    auth: RunAuthorization,
    auth_ref: Ref,
    auth_bytes: bytes,
    tx: LedgerTxn,
    *,
    context: BudgetContext,
    expected_previous_authorization_id: Id | None,
) -> None:
    """Authenticate an exact immutable grant and CAS the current run pointer."""
    with tx.connection.transaction():
        parsed = _parse(
            RunAuthorization,
            auth_bytes,
            auth_ref,
            "kf.run-authorization.v1",
            context.access.project_id,
            context,
        )
        if type(auth) is not RunAuthorization or parsed != auth:
            raise ContractError("hash_mismatch")
        _context(context, auth.project_id, auth.run_id, "install_run_authorization")
        if auth.actor_id != context.access.actor_id:
            raise ContractError("forbidden")
        if not auth.authorized_at <= context.now < auth.expires_at:
            raise ContractError("authorization_expired")
        tx.lock(auth.project_id, auth.run_id)
        run = tx.connection.execute(
            sql.SQL(
                "SELECT current_authorization_id::text,admission_report_digest FROM {} "
                "WHERE project_id=%s AND run_id=%s"
            ).format(tx.table("runs")),
            (auth.project_id, auth.run_id),
        ).fetchone()
        assert run is not None
        if run[1] != auth.admission_report_digest:
            raise ContractError("forbidden")
        _proof(
            context,
            "install_run_authorization",
            auth_ref,
            auth.run_id,
            auth_ref,
            auth_bytes,
            expected_previous=expected_previous_authorization_id,
        )
        old = tx.connection.execute(
            sql.SQL(
                "SELECT authorization_ref FROM {} WHERE project_id=%s AND authorization_id=%s"
            ).format(tx.table("authorizations")),
            (auth.project_id, auth.authorization_id),
        ).fetchone()
        if old:
            if _identity(_stored_ref(old[0])) != _identity(auth_ref):
                raise ContractError("determinism_conflict")
            if run[0] == auth.authorization_id:
                return
            raise ContractError("activation_conflict")
        if run[0] != expected_previous_authorization_id:
            raise ContractError("activation_conflict")
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,authorization_id,run_id,authorization_ref,"
                "allowed_plan_digests,max_run_cost,max_concurrent_attempts,actor_id,authorized_at,"
                "expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            ).format(tx.table("authorizations")),
            (
                auth.project_id,
                auth.authorization_id,
                auth.run_id,
                _json(auth_ref),
                list(auth.allowed_plan_digests),
                auth.max_run_cost,
                auth.max_concurrent_attempts,
                auth.actor_id,
                auth.authorized_at,
                auth.expires_at,
            ),
        )
        actual, outstanding = _totals(tx, auth.project_id, auth.run_id)
        exceeds = not _remaining(Decimal(auth.max_run_cost), actual, outstanding, Decimal(0))
        tx.connection.execute(
            sql.SQL(
                "UPDATE {} SET current_authorization_id=%s,max_run_cost=%s,"
                "max_concurrent_attempts=%s,frozen=frozen OR %s,"
                "freeze_reason=CASE WHEN %s THEN 'authorization_below_liability' ELSE "
                "freeze_reason END "
                "WHERE project_id=%s AND run_id=%s"
            ).format(tx.table("runs")),
            (
                auth.authorization_id,
                auth.max_run_cost,
                auth.max_concurrent_attempts,
                exceeds,
                exceeds,
                auth.project_id,
                auth.run_id,
            ),
        )


def _admitted(
    plan: ExecutionPlan,
    admission: AdmissionRegistrationEvidence,
    asset: Id,
    tx: LedgerTxn,
    context: BudgetContext,
) -> str:
    manifest = IntakeManifest.from_wire(admission.manifest_bytes, _limits(context, "kf.intake.v1"))
    report = _parse(
        AdmissionReport,
        admission.report_bytes,
        plan.admission_report_ref,
        "kf.admission-report.v1",
        plan.project_id,
        context,
    )
    policy = _parse(
        PolicyArtifact,
        admission.policy_bytes,
        plan.policy_ref,
        "kf.policy.v1",
        plan.project_id,
        context,
    )
    if policy != admission.pinned_policy or _identity(manifest.policy_ref) != _identity(
        plan.policy_ref
    ):
        raise ContractError("hash_mismatch")
    report.validate_manifest(manifest, policy)
    manifest_digest = hashlib.sha256(admission.manifest_bytes).hexdigest()
    if report.manifest_digest != manifest_digest:
        raise ContractError("hash_mismatch")
    registered = tx.connection.execute(
        sql.SQL(
            "SELECT report_ref,manifest_digest FROM {} WHERE project_id=%s AND report_digest=%s"
        ).format(tx.table("admission_reports")),
        (plan.project_id, plan.admission_report_ref.digest),
    ).fetchone()
    if (
        registered is None
        or registered[1] != manifest_digest
        or _identity(_stored_ref(registered[0])) != _identity(plan.admission_report_ref)
    ):
        raise ContractError("forbidden")
    entry = next((entry for entry in report.entries if entry.asset_id == asset), None)
    item = next((item for item in manifest.items if item.asset_id == asset), None)
    row = tx.connection.execute(
        sql.SQL(
            "SELECT source_id::text,status,snapshot_ref FROM {} "
            "WHERE project_id=%s AND report_digest=%s AND asset_id=%s"
        ).format(tx.table("admission_entries")),
        (plan.project_id, plan.admission_report_ref.digest, asset),
    ).fetchone()
    if (
        item is None
        or entry is None
        or entry.status != "admitted"
        or entry.snapshot_ref is None
        or row is None
    ):
        raise ContractError("forbidden")
    if (
        row[:2] != (item.source_id, "admitted")
        or _identity(_stored_ref(row[2])) != _identity(entry.snapshot_ref)
        or _identity(plan.input_refs[0]) != _identity(entry.snapshot_ref)
        or (item.original_digest, item.size_bytes)
        != (entry.snapshot_ref.digest, entry.snapshot_ref.size_bytes)
        or (plan.profile_id, plan.profile_version)
        != (manifest.profile_id, manifest.profile_version)
    ):
        raise ContractError("forbidden")
    expected = operation_key(
        F1Operation(
            plan.project_id,
            asset,
            item.source_id,
            (entry.snapshot_ref.digest,),
            plan.extraction_spec_ref.digest,
            plan.profile_id,
            plan.profile_version,
            plan.policy_ref.digest,
            plan.contract_set_ref.digest,
            tuple(ref.digest for ref in plan.limits_refs),
        ),
        limits=_limits(context, "kf.execution-plan.v1"),
    )
    if plan.operation_key != expected:
        raise ContractError("hash_mismatch")
    return item.source_id


def _reservation(
    tx: LedgerTxn,
    project: Id,
    run: Id,
    amount: str,
    evidence: Ref,
    reservation: Id,
    operation: str | None,
    authorization: Id,
) -> None:
    tx.connection.execute(
        sql.SQL(
            "INSERT INTO {} (project_id,reservation_id,run_id,operation_key,scope,reserved_usd,"
            "outstanding_usd,settled_usd,evidence_ref,authorization_id) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,0,%s,%s)"
        ).format(tx.table("reservations")),
        (
            project,
            reservation,
            run,
            operation,
            "attempt" if operation is not None else "run_storage",
            amount,
            amount,
            _json(evidence),
            authorization,
        ),
    )


def _reserve_event(
    tx: LedgerTxn,
    context: BudgetContext,
    run: Id,
    reservation: Id,
    amount: str,
    evidence: Ref,
    attempt: Id | None,
) -> None:
    event = BudgetEvent.model_validate(
        {
            "schema_version": "kf.budget-event.v1",
            "project_id": context.access.project_id,
            "run_id": run,
            "reservation_id": reservation,
            "scope": "attempt" if attempt else "run_storage",
            **({"attempt_id": attempt} if attempt is not None else {}),
            "event_id": str(uuid4()),
            "event_type": "reserve",
            "amount_usd": amount,
            "cost_status": "estimated",
            "evidence_ref": evidence,
            "created_at": context.now,
        }
    )
    data = event.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8")
    tx.append_budget_event(event, event_bytes=data, limits=_limits(context, "kf.budget-event.v1"))


def reserve_attempt(
    plan: ExecutionPlan,
    auth: RunAuthorization,
    evidence: Ref,
    tx: LedgerTxn,
    *,
    context: BudgetContext,
    plan_ref: Ref,
    plan_bytes: bytes,
    authorization_ref: Ref,
    authorization_bytes: bytes,
    admission: AdmissionRegistrationEvidence,
    asset_id: Id,
    execution_config_bytes: bytes,
    attempt_id: Id | None = None,
    duplicate_risk: DuplicateRiskAuthorization | None = None,
) -> StageAttempt:
    """Reserve one separately authorized attempt before any external effect."""
    with tx.connection.transaction():
        parsed = _parse(
            ExecutionPlan,
            plan_bytes,
            plan_ref,
            "kf.execution-plan.v1",
            context.access.project_id,
            context,
        )
        grant = _parse(
            RunAuthorization,
            authorization_bytes,
            authorization_ref,
            "kf.run-authorization.v1",
            context.access.project_id,
            context,
        )
        if (
            type(plan) is not ExecutionPlan
            or parsed != plan
            or type(auth) is not RunAuthorization
            or grant != auth
        ):
            raise ContractError("hash_mismatch")
        _context(context, plan.project_id, plan.run_id, "reserve_attempt")
        validate_plan_authorization(
            plan,
            auth,
            context.now,
            plan_bytes=plan_bytes,
            limits=_limits(context, "kf.execution-plan.v1"),
        )
        config = _parse(
            ExecutionConfig,
            execution_config_bytes,
            plan.execution_config_ref,
            "kf.execution-config.v1",
            plan.project_id,
            context,
        )
        if _identity(config.tariff_ref) != _identity(plan.budget.tariff_ref):
            raise ContractError("forbidden")
        installed = _installed(tx, plan.project_id, plan.run_id)
        if installed[0] != auth.authorization_id or _identity(
            _stored_ref(installed[4])
        ) != _identity(authorization_ref):
            raise ContractError("forbidden")
        if installed[8] != plan.admission_report_ref.digest:
            raise ContractError("forbidden")
        duplicate_allowed = False
        if duplicate_risk is not None:
            if (type(duplicate_risk) is not DuplicateRiskAuthorization
                    or duplicate_risk.new_plan_digest != plan_ref.digest
                    or duplicate_risk.new_authorization_id != auth.authorization_id
                    or context.duplicate_risk_verifier is None):
                raise ContractError("forbidden")
            try:
                duplicate_allowed = (
                    context.duplicate_risk_verifier(duplicate_risk, plan, auth) is True
                )
            except Exception:
                raise ContractError("forbidden") from None
            if not duplicate_allowed:
                raise ContractError("forbidden")
        _spending(
            tx,
            plan.project_id,
            plan.run_id,
            installed,
            context,
            Decimal(plan.budget.max_attempt_cost),
            allow_unknown=duplicate_allowed,
        )
        source = _admitted(plan, admission, asset_id, tx, context)
        for effect in ("read", "extract", "remoteTransfer"):
            require_permission(context.access, context.current_policy, source, effect)
        if config.remote_destination_id not in context.current_policy.allowed_remote_destinations:
            raise ContractError("forbidden")
        reservation = str(uuid4())
        if attempt_id is None:
            attempt_id = str(uuid4())
        else:
            try:
                TypeAdapter(Id).validate_python(attempt_id)
            except ValidationError:
                raise ContractError("invalid_schema") from None
            if tx.connection.execute(sql.SQL(
                "SELECT 1 FROM {} WHERE project_id=%s AND attempt_id=%s"
            ).format(tx.table("attempts")), (plan.project_id, attempt_id)).fetchone():
                raise ContractError("dispatch_unknown")
        _proof(
            context,
            "reserve_attempt",
            evidence,
            plan.run_id,
            authorization_ref,
            plan_bytes,
            reservation=reservation,
            attempt=attempt_id,
            plan_ref=plan_ref,
            config_ref=plan.execution_config_ref,
        )
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,operation_key,asset_id) VALUES (%s,%s,%s) ON "
                "CONFLICT DO NOTHING"
            ).format(tx.table("operations")),
            (plan.project_id, plan.operation_key, asset_id),
        )
        tx.lock(plan.project_id, plan.run_id, plan.operation_key)
        operation = tx.connection.execute(
            sql.SQL(
                "SELECT asset_id::text,attempts_allocated,held FROM {} WHERE project_id=%s AND "
                "operation_key=%s"
            ).format(tx.table("operations")),
            (plan.project_id, plan.operation_key),
        ).fetchone()
        assert operation is not None
        if operation[0] != asset_id or operation[2]:
            raise ContractError("forbidden")
        unresolved = tx.connection.execute(
            sql.SQL(
                "SELECT 1 FROM {} WHERE project_id=%s AND operation_key=%s "
                "AND state IN ('unknown_outcome','cancel_requested') LIMIT 1"
            ).format(tx.table("attempts")),
            (plan.project_id, plan.operation_key),
        ).fetchone()
        if unresolved and not duplicate_allowed:
            raise ContractError("dispatch_unknown")
        if operation[1] >= min(plan.resources.max_attempts_per_operation, MAX_SAFE_INTEGER):
            raise ContractError("limit_exceeded")
        live = tx.connection.execute(
            sql.SQL(
                "SELECT count(*) FROM {} WHERE project_id=%s AND run_id=%s "
                "AND state NOT IN ('succeeded','failed','cancelled')"
            ).format(tx.table("attempts")),
            (plan.project_id, plan.run_id),
        ).fetchone()
        assert live is not None
        if live[0] >= min(installed[2], plan.resources.max_concurrent_attempts):
            raise ContractError("limit_exceeded")
        old = tx.connection.execute(
            sql.SQL("SELECT plan_ref FROM {} WHERE project_id=%s AND plan_id=%s").format(
                tx.table("plans")
            ),
            (plan.project_id, plan.plan_id),
        ).fetchone()
        if old and _identity(_stored_ref(old[0])) != _identity(plan_ref):
            raise ContractError("determinism_conflict")
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} "
                "(project_id,plan_id,run_id,plan_digest,plan_ref,authorization_id,operation_key) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING"
            ).format(tx.table("plans")),
            (
                plan.project_id,
                plan.plan_id,
                plan.run_id,
                plan_ref.digest,
                _json(plan_ref),
                auth.authorization_id,
                plan.operation_key,
            ),
        )
        _reservation(
            tx,
            plan.project_id,
            plan.run_id,
            plan.budget.max_attempt_cost,
            evidence,
            reservation,
            plan.operation_key,
            auth.authorization_id,
        )
        number = operation[1] + 1
        attempt = StageAttempt(
            schema_version="kf.stage-attempt.v1",
            project_id=plan.project_id,
            plan_id=plan.plan_id,
            operation_key=plan.operation_key,
            attempt_id=attempt_id,
            attempt_number=number,
            reservation_id=reservation,
            state="reserved",
            created_at=context.now,
        )
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,attempt_id,run_id,plan_id,operation_key,attempt_number,"
                "reservation_id,state,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,'reserved',%s)"
            ).format(tx.table("attempts")),
            (
                plan.project_id,
                attempt_id,
                plan.run_id,
                plan.plan_id,
                plan.operation_key,
                number,
                reservation,
                context.now,
            ),
        )
        tx.connection.execute(
            sql.SQL(
                "UPDATE {} SET attempts_allocated=%s WHERE project_id=%s AND operation_key=%s"
            ).format(tx.table("operations")),
            (number, plan.project_id, plan.operation_key),
        )
        _reserve_event(
            tx,
            context,
            plan.run_id,
            reservation,
            plan.budget.max_attempt_cost,
            evidence,
            attempt_id,
        )
        return attempt


def reserve_storage(
    run_id: Id,
    amount: Money,
    evidence: Ref,
    tx: LedgerTxn,
    *,
    context: BudgetContext,
) -> Id:
    """Reserve the separately evidenced funded storage horizon before upload."""
    with tx.connection.transaction():
        project = context.access.project_id
        _context(context, project, run_id, "reserve_storage")
        if type(amount) is not str:
            raise ContractError("invalid_schema")
        if len(amount) > _limits(context, "kf.budget-event.v1").max_string_scalars:
            raise ContractError("limit_exceeded")
        try:
            TypeAdapter(Money).validate_python(amount)
        except ValidationError:
            raise ContractError("invalid_schema") from None
        if type(amount) is not str or Decimal(amount) <= 0:
            raise ContractError("invalid_schema")
        installed = _installed(tx, project, run_id)
        _spending(tx, project, run_id, installed, context, Decimal(amount))
        auth_ref = _stored_ref(installed[4])
        request = json.dumps(
            {
                "projectId": project,
                "runId": run_id,
                "authorizationDigest": auth_ref.digest,
                "currency": "USD",
                "amountUsd": amount,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        # The finite internal request uses the same explicitly pinned JSON ceiling.
        from conscience_foundry.contracts.codec import load_json

        load_json(request, _limits(context, "kf.budget-event.v1"))
        reservation = str(uuid4())
        _proof(
            context, "reserve_storage", evidence, run_id, auth_ref, request, reservation=reservation
        )
        _reservation(tx, project, run_id, amount, evidence, reservation, None, installed[0])
        _reserve_event(tx, context, run_id, reservation, amount, evidence, None)
        return reservation


def _reservation_row(tx: LedgerTxn, project: Id, run: Id, reservation: Id) -> tuple[Any, ...]:
    row = tx.connection.execute(
        sql.SQL(
            "SELECT scope,reserved_usd,outstanding_usd,settled_usd,released_usd,final_billing,"
            "operation_key FROM {} WHERE project_id=%s AND run_id=%s AND reservation_id=%s FOR "
            "UPDATE"
        ).format(tx.table("reservations")),
        (project, run, reservation),
    ).fetchone()
    if row is None:
        raise ContractError("forbidden")
    return row


def _event_replay(tx: LedgerTxn, event: BudgetEvent, data: bytes) -> bool:
    row = tx.connection.execute(
        sql.SQL("SELECT record_bytes FROM {} WHERE project_id=%s AND event_id=%s").format(
            tx.table("budget_events")
        ),
        (event.project_id, event.event_id),
    ).fetchone()
    if row is None:
        return False
    if bytes(row[0]) != data:
        raise ContractError("determinism_conflict")
    return True


def _prior_kind(
    tx: LedgerTxn, event: BudgetEvent, kind: str, context: BudgetContext
) -> BudgetEvent | None:
    rows = tx.connection.execute(
        sql.SQL(
            "SELECT record_bytes FROM {} WHERE project_id=%s AND run_id=%s AND reservation_id=%s"
        ).format(tx.table("budget_events")),
        (event.project_id, event.run_id, event.reservation_id),
    ).fetchall()
    for row in rows:
        parsed = BudgetEvent.from_wire(bytes(row[0]), _limits(context, "kf.budget-event.v1"))
        if parsed.event_type == kind:
            return parsed
    return None


def _accounting_pins(
    tx: LedgerTxn,
    project: Id,
    run: Id,
    reservation: Id,
    attempt: Id | None,
) -> tuple[Ref, Ref | None]:
    original = tx.connection.execute(
        sql.SQL(
            "SELECT a.authorization_ref,r.authorization_id::text FROM {} r JOIN {} a ON "
            "(r.project_id,r.run_id,r.authorization_id)="
            "(a.project_id,a.run_id,a.authorization_id) "
            "WHERE r.project_id=%s AND r.run_id=%s AND r.reservation_id=%s"
        ).format(tx.table("reservations"), tx.table("authorizations")),
        (project, run, reservation),
    ).fetchone()
    if original is None:
        raise ContractError("forbidden")
    if attempt is None:
        return _stored_ref(original[0]), None
    row = tx.connection.execute(
        sql.SQL(
            "SELECT p.plan_ref,p.authorization_id::text FROM {} t JOIN {} p "
            "ON (t.project_id,t.run_id,t.plan_id)=(p.project_id,p.run_id,p.plan_id) "
            "WHERE t.project_id=%s AND t.run_id=%s AND t.attempt_id=%s AND t.reservation_id=%s"
        ).format(tx.table("attempts"), tx.table("plans")),
        (project, run, attempt, reservation),
    ).fetchone()
    if row is None or row[1] != original[1]:
        raise ContractError("forbidden")
    return _stored_ref(original[0]), _stored_ref(row[0])


def apply_budget_event(
    event: BudgetEvent,
    tx: LedgerTxn,
    *,
    event_bytes: bytes,
    context: BudgetContext,
) -> None:
    """Record observations, or final authoritative settlement without clipping."""
    with tx.connection.transaction():
        parsed = BudgetEvent.from_wire(event_bytes, _limits(context, "kf.budget-event.v1"))
        if type(event) is not BudgetEvent or parsed != event:
            raise ContractError("hash_mismatch")
        _context(context, event.project_id, event.run_id, "apply_budget_event")
        installed = _installed(tx, event.project_id, event.run_id)
        row = _reservation_row(tx, event.project_id, event.run_id, event.reservation_id)
        if row[0] != event.scope:
            raise ContractError("forbidden")
        if event.scope == "attempt":
            bound = tx.connection.execute(
                sql.SQL(
                    "SELECT attempt_id::text FROM {} WHERE project_id=%s AND run_id=%s AND "
                    "reservation_id=%s"
                ).format(tx.table("attempts")),
                (event.project_id, event.run_id, event.reservation_id),
            ).fetchone()
            if bound != (event.attempt_id,):
                raise ContractError("forbidden")
        replay = _event_replay(tx, event, event_bytes)
        if event.created_at > context.now:
            raise ContractError("invalid_schema")
        purpose = {
            "reserve": "reserve" if replay else None,
            "record_usage": "record_usage",
            "settle": "final_billing",
            "release_unspent": (
                "release_unspent"
                if row[5] and _prior_kind(tx, event, "settle", context) is not None
                else "final_no_effect"
            ),
        }.get(event.event_type)
        if purpose is None:
            raise ContractError("forbidden")  # Only allocation APIs may create reserve events.
        auth_pin, plan_pin = _accounting_pins(
            tx, event.project_id, event.run_id, event.reservation_id, event.attempt_id
        )
        _proof(
            context,
            purpose,
            event.evidence_ref,
            event.run_id,
            auth_pin,
            event_bytes,
            reservation=event.reservation_id,
            attempt=event.attempt_id,
            plan_ref=plan_pin,
        )
        if replay:
            return
        amount = Decimal(event.amount_usd) if event.amount_usd is not None else None
        if event.event_type == "settle":
            if row[5] or amount is None:
                raise ContractError("determinism_conflict")
            tx.connection.execute(
                sql.SQL(
                    "UPDATE {} SET settled_usd=%s,outstanding_usd=0,"
                    "released_usd=greatest(reserved_usd-%s,0),final_billing=true,evidence_ref=%s "
                    "WHERE project_id=%s AND run_id=%s AND reservation_id=%s"
                ).format(tx.table("reservations")),
                (
                    event.amount_usd,
                    event.amount_usd,
                    _json(event.evidence_ref),
                    event.project_id,
                    event.run_id,
                    event.reservation_id,
                ),
            )
            actual, outstanding = _totals(tx, event.project_id, event.run_id)
            if amount > row[1] or not _remaining(installed[1], actual, outstanding, Decimal(0)):
                tx.connection.execute(
                    sql.SQL(
                        "UPDATE {} SET frozen=true,freeze_reason='actual_overrun' WHERE "
                        "project_id=%s AND run_id=%s"
                    ).format(tx.table("runs")),
                    (event.project_id, event.run_id),
                )
        elif event.event_type == "release_unspent":
            if amount is None or _prior_kind(tx, event, "release_unspent", context) is not None:
                raise ContractError("determinism_conflict")
            if row[5]:
                settlement = _prior_kind(tx, event, "settle", context)
                if (
                    settlement is None
                    or amount != row[4]
                    or _identity(settlement.evidence_ref) != _identity(event.evidence_ref)
                ):
                    raise ContractError("forbidden")
            else:
                if amount != row[1] or row[3] != 0:
                    raise ContractError("forbidden")
                tx.connection.execute(
                    sql.SQL(
                        "UPDATE {} SET "
                        "outstanding_usd=0,released_usd=reserved_usd,"
                        "final_billing=true,evidence_ref=%s "
                        "WHERE project_id=%s AND run_id=%s AND reservation_id=%s"
                    ).format(tx.table("reservations")),
                    (
                        _json(event.evidence_ref),
                        event.project_id,
                        event.run_id,
                        event.reservation_id,
                    ),
                )
        elif row[5]:
            raise ContractError("determinism_conflict")
        elif event.event_type == "record_usage" and event.cost_status == "actual":
            actual, outstanding = _totals(tx, event.project_id, event.run_id)
            if amount is not None and (
                amount > row[1] or not _remaining(installed[1], actual, outstanding, Decimal(0))
            ):
                # Known usage may prove an overrun before final billing. Keep the
                # liability outstanding, but stop new admission immediately.
                tx.connection.execute(
                    sql.SQL(
                        "UPDATE {} SET frozen=true,freeze_reason='actual_overrun' WHERE "
                        "project_id=%s AND run_id=%s"
                    ).format(tx.table("runs")),
                    (event.project_id, event.run_id),
                )
        tx.append_budget_event(
            event, event_bytes=event_bytes, limits=_limits(context, "kf.budget-event.v1")
        )


def apply_billing_adjustment(
    adjustment: BillingAdjustment,
    tx: LedgerTxn,
    *,
    adjustment_bytes: bytes,
    context: BudgetContext,
) -> None:
    """CAS a final settlement's effective actual total; never reopen its balance."""
    with tx.connection.transaction():
        parsed = BillingAdjustment.from_wire(
            adjustment_bytes, _limits(context, "kf.billing-adjustment.v1")
        )
        if type(adjustment) is not BillingAdjustment or parsed != adjustment:
            raise ContractError("hash_mismatch")
        _context(context, adjustment.project_id, adjustment.run_id, "apply_billing_adjustment")
        _installed(tx, adjustment.project_id, adjustment.run_id)
        old = tx.connection.execute(
            sql.SQL("SELECT record_bytes FROM {} WHERE project_id=%s AND adjustment_id=%s").format(
                tx.table("billing_adjustments")
            ),
            (adjustment.project_id, adjustment.adjustment_id),
        ).fetchone()
        if old:
            if bytes(old[0]) != adjustment_bytes:
                raise ContractError("determinism_conflict")
        row = _reservation_row(
            tx, adjustment.project_id, adjustment.run_id, adjustment.reservation_id
        )
        settlement_row = tx.connection.execute(
            sql.SQL(
                "SELECT record_bytes FROM {} WHERE project_id=%s AND event_id=%s AND run_id=%s "
                "AND reservation_id=%s"
            ).format(tx.table("budget_events")),
            (
                adjustment.project_id,
                adjustment.settlement_event_id,
                adjustment.run_id,
                adjustment.reservation_id,
            ),
        ).fetchone()
        if settlement_row is None or not row[5]:
            raise ContractError("determinism_conflict")
        settlement = BudgetEvent.from_wire(
            bytes(settlement_row[0]), _limits(context, "kf.budget-event.v1")
        )
        if settlement.event_type != "settle" or adjustment.created_at > context.now:
            raise ContractError("forbidden")
        auth_pin, plan_pin = _accounting_pins(
            tx,
            adjustment.project_id,
            adjustment.run_id,
            adjustment.reservation_id,
            settlement.attempt_id,
        )
        _proof(
            context,
            "billing_adjustment",
            adjustment.evidence_ref,
            adjustment.run_id,
            auth_pin,
            adjustment_bytes,
            reservation=adjustment.reservation_id,
            attempt=settlement.attempt_id,
            plan_ref=plan_pin,
        )
        if old:
            return
        if row[3] != Decimal(adjustment.expected_prior_actual_usd):
            raise ContractError("determinism_conflict")
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} "
                "(project_id,adjustment_id,run_id,reservation_id,"
                "settlement_event_id,record_digest,record_bytes) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s)"
            ).format(tx.table("billing_adjustments")),
            (
                adjustment.project_id,
                adjustment.adjustment_id,
                adjustment.run_id,
                adjustment.reservation_id,
                adjustment.settlement_event_id,
                hashlib.sha256(adjustment_bytes).hexdigest(),
                adjustment_bytes,
            ),
        )
        tx.connection.execute(
            sql.SQL(
                "UPDATE {} SET settled_usd=%s WHERE project_id=%s AND run_id=%s AND "
                "reservation_id=%s"
            ).format(tx.table("reservations")),
            (
                adjustment.revised_actual_usd,
                adjustment.project_id,
                adjustment.run_id,
                adjustment.reservation_id,
            ),
        )
        tx.connection.execute(
            sql.SQL(
                "UPDATE {} SET frozen=true,freeze_reason='billing_adjustment' WHERE "
                "project_id=%s AND run_id=%s"
            ).format(tx.table("runs")),
            (adjustment.project_id, adjustment.run_id),
        )
