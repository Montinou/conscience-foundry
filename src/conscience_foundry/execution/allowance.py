"""Shared durable call allowance: a library mechanism, not a dispatcher or a model API.

A scope is the admitted operation (project and operation key). Its finite limits, cumulative
request/repair/transport/transition/token counters and local call identities live in PostgreSQL,
so a restart, a new coordinator connection or a new scheduling run inherits them and can never
reset them. Allowances are reserved atomically, before any external effect, under the project
lock; a rejection consumes nothing. Conservative token maxima are never decremented: actual
usage is reported elsewhere, and unknown outcomes keep their allocation.

Monetary reservations stay with D05: this module only reads them. An unknown request freezes
further billable submissions until its call is reconciled or a separate D05 manual-retry
decision exists for the operation. Callers are trusted control code; a model response or
transport fake can neither lower a bound nor lift a freeze.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Literal

from pydantic import TypeAdapter, ValidationError

from conscience_foundry.contracts.codec import hash_jcs
from conscience_foundry.contracts.common import (
    MAX_SAFE_INTEGER,
    ContractError,
    Digest,
    Id,
    Instant,
    scalar_string,
)
from conscience_foundry.ledger import allowance as store
from conscience_foundry.ledger.db import Ledger, LedgerTxn
from conscience_foundry.policy.access import AccessContext

Kind = Literal["request", "repair", "transport", "transition", "outcome"]
Outcome = Literal["pending", "known", "unknown"]
KINDS = frozenset({"request", "repair", "transport", "transition", "outcome"})
OUTCOMES = frozenset({"pending", "known", "unknown"})
EVENT_DOMAIN = "kf.call-allowance-event.v1"
EXTERNAL_ID_MAX = 256
_ID = TypeAdapter(Id)
_DIGEST = TypeAdapter(Digest)
_INSTANT = TypeAdapter(Instant)

LIMIT_KEYS = (
    ("max_requests", "maxRequests", 1),
    ("max_repairs", "maxRepairs", 0),
    ("max_transport_attempts", "maxTransportAttempts", 1),
    ("max_transitions", "maxTransitions", 0),
    ("max_input_tokens", "maxInputTokens", 1),
    ("max_output_tokens", "maxOutputTokens", 1),
    ("max_context_scalars", "maxContextScalars", 1),
)


def _text(adapter: TypeAdapter[str], value: object) -> str:
    if type(value) is not str:
        raise ContractError("invalid_schema")
    try:
        return adapter.validate_python(value)
    except ValidationError:
        raise ContractError("invalid_schema") from None


def _integer(value: object, minimum: int) -> int:
    if type(value) is not int or not minimum <= value <= MAX_SAFE_INTEGER:
        raise ContractError("invalid_schema")
    return value


@dataclass(frozen=True)
class CallLimits:
    """Required finite maxima; zero is meaningful only for repairs and transitions."""

    max_requests: int
    max_repairs: int
    max_transport_attempts: int
    max_transitions: int
    max_input_tokens: int
    max_output_tokens: int
    max_context_scalars: int
    deadline: Instant

    def __post_init__(self) -> None:
        for attribute, _, minimum in LIMIT_KEYS:
            _integer(getattr(self, attribute), minimum)
        _text(_INSTANT, self.deadline)

    def wire(self) -> dict[str, Any]:
        value: dict[str, Any] = {wire: getattr(self, name) for name, wire, _ in LIMIT_KEYS}
        value["deadline"] = self.deadline
        return value

    @classmethod
    def from_wire(cls, value: dict[str, Any]) -> CallLimits:
        if set(value) != {wire for _, wire, _ in LIMIT_KEYS} | {"deadline"}:
            raise ContractError("schema_incompatible")
        return cls(
            **{name: value[wire] for name, wire, _ in LIMIT_KEYS}, deadline=value["deadline"]
        )


@dataclass(frozen=True)
class AllowanceContext:
    """Binds counters to an existing admitted ledger scope; it creates none."""

    project_id: Id
    run_id: Id
    operation_key: Digest
    attempt_id: Id
    reservation_id: Id
    request_digest: Digest

    def __post_init__(self) -> None:
        for name, adapter in (
            ("project_id", _ID),
            ("run_id", _ID),
            ("attempt_id", _ID),
            ("reservation_id", _ID),
            ("operation_key", _DIGEST),
            ("request_digest", _DIGEST),
        ):
            _text(adapter, getattr(self, name))


@dataclass(frozen=True)
class CallEvent:
    """One idempotent allowance event keyed by its event_id.

    Submissions (request/repair/transport) are recorded `pending` with their conservative token
    reservations and a fresh local call_id. A later `outcome` event keeps that call_id whether
    or not a provider id ever arrives. Actual usage is never reported through this event.
    """

    event_id: Id
    call_id: Id
    context: AllowanceContext
    kind: Kind
    external_request_id: str | None
    reserved_input_tokens: int
    reserved_output_tokens: int
    context_scalars: int
    outcome: Outcome

    def __post_init__(self) -> None:
        _text(_ID, self.event_id)
        _text(_ID, self.call_id)
        if type(self.context) is not AllowanceContext:
            raise ContractError("invalid_schema")
        if self.kind not in KINDS or self.outcome not in OUTCOMES:
            raise ContractError("invalid_schema")
        for value in (
            self.reserved_input_tokens,
            self.reserved_output_tokens,
            self.context_scalars,
        ):
            _integer(value, 0)
        external = self.external_request_id
        if external is not None:
            if type(external) is not str or not 1 <= len(external) <= EXTERNAL_ID_MAX:
                raise ContractError("invalid_schema")
            try:
                scalar_string(external)
            except ValueError:
                raise ContractError("invalid_schema") from None
        if self.kind in store.SUBMISSION_KINDS:
            if (
                self.outcome != "pending"
                or self.reserved_input_tokens < 1
                or self.reserved_output_tokens < 1
            ):
                raise ContractError("invalid_schema")
        elif self.reserved_input_tokens or self.reserved_output_tokens or self.context_scalars:
            raise ContractError("invalid_schema")
        elif self.kind == "transition":
            if self.outcome != "known" or external is not None:
                raise ContractError("invalid_schema")
        elif self.outcome == "pending":
            raise ContractError("invalid_schema")


@dataclass(frozen=True)
class CallRef:
    call_id: Id
    external_request_id: str | None


@dataclass(frozen=True)
class CallState:
    """Cumulative durable allowances, never decremented by restart or unknown outcomes."""

    project_id: Id
    operation_key: Digest
    limits: CallLimits
    requests: int
    repairs: int
    transports: int
    transitions: int
    input_tokens: int
    output_tokens: int
    peak_context: int
    pending: tuple[CallRef, ...] = field(default=())
    unknown: tuple[CallRef, ...] = field(default=())
    version: int = 0
    exhausted: bool = False


@dataclass
class _Call:
    status: str
    run_id: str
    attempt_id: str
    reservation_id: str
    request_digest: str
    external_request_id: str | None


def _authorize(access: AccessContext, project_id: Id) -> None:
    """Exact trusted project scope plus an explicit enrich scope; wire data grants nothing."""
    if (
        type(access) is not AccessContext
        or access.project_id != project_id
        or "enrich" not in access.scopes
    ):
        raise ContractError("forbidden")


def _event_digest(event: CallEvent) -> Digest:
    value: dict[str, Any] = {
        "eventId": event.event_id,
        "callId": event.call_id,
        "projectId": event.context.project_id,
        "runId": event.context.run_id,
        "operationKey": event.context.operation_key,
        "attemptId": event.context.attempt_id,
        "reservationId": event.context.reservation_id,
        "requestDigest": event.context.request_digest,
        "kind": event.kind,
        "outcome": event.outcome,
        "reservedInputTokens": event.reserved_input_tokens,
        "reservedOutputTokens": event.reserved_output_tokens,
        "contextScalars": event.context_scalars,
    }
    if event.external_request_id is not None:
        value["externalRequestId"] = event.external_request_id
    return hash_jcs(EVENT_DOMAIN, value)


def _fold(events: list[store.EventRow]) -> dict[str, _Call]:
    calls: dict[str, _Call] = {}
    for item in events:
        if item.kind in store.SUBMISSION_KINDS:
            calls[item.call_id] = _Call(
                "pending",
                item.run_id,
                item.attempt_id,
                item.reservation_id,
                item.request_digest,
                item.external_request_id,
            )
        elif item.kind == "outcome":
            call = calls[item.call_id]
            call.status = item.outcome
            if item.external_request_id is not None:
                call.external_request_id = item.external_request_id
    return calls


def _is_exhausted(limits: CallLimits, row: store.ScopeRow) -> bool:
    return (
        row.requests >= limits.max_requests
        or row.transports >= limits.max_transport_attempts
        or row.input_tokens >= limits.max_input_tokens
        or row.output_tokens >= limits.max_output_tokens
    )


def _state(
    project: Id, operation_key: Digest, row: store.ScopeRow, events: list[store.EventRow]
) -> CallState:
    limits = CallLimits.from_wire(row.limits)
    calls = _fold(events)
    return CallState(
        project_id=project,
        operation_key=operation_key,
        limits=limits,
        requests=row.requests,
        repairs=row.repairs,
        transports=row.transports,
        transitions=row.transitions,
        input_tokens=row.input_tokens,
        output_tokens=row.output_tokens,
        peak_context=row.peak_context,
        pending=tuple(
            CallRef(call_id, call.external_request_id)
            for call_id, call in calls.items()
            if call.status == "pending"
        ),
        unknown=tuple(
            CallRef(call_id, call.external_request_id)
            for call_id, call in calls.items()
            if call.status == "unknown"
        ),
        version=row.version,
        exhausted=row.exhausted,
    )


def _prepare(
    tx: LedgerTxn, scope: AllowanceContext
) -> tuple[str, store.ScopeRow | None]:
    """Lock project, run and operation, then require the existing admitted binding."""
    tx.lock(scope.project_id, scope.run_id, scope.operation_key)
    store.require_installed(tx)
    attempt_state = store.bind_scope(
        tx,
        scope.project_id,
        scope.run_id,
        scope.operation_key,
        scope.attempt_id,
        scope.reservation_id,
    )
    return attempt_state, store.load_scope(tx, scope.project_id, scope.operation_key)


def _instant(value: str) -> datetime:
    _text(_INSTANT, value)
    return datetime.fromisoformat(value)


def open_allowance(
    scope: AllowanceContext,
    limits: CallLimits,
    context: AccessContext,
    ledger: Ledger,
    now: Instant,
) -> CallState:
    """Create the operation's allowance once; any later opener inherits it unchanged.

    A resumed or new-run caller supplying different limits conflicts rather than resets.
    """
    if type(scope) is not AllowanceContext or type(limits) is not CallLimits:
        raise ContractError("invalid_schema")
    moment = _instant(now)
    _authorize(context, scope.project_id)
    with ledger.transaction() as tx:
        _, row = _prepare(tx, scope)
        if row is not None:
            if row.limits != limits.wire():
                raise ContractError("determinism_conflict")
        else:
            if moment >= _instant(limits.deadline):
                raise ContractError("authorization_expired")
            store.insert_scope(tx, scope.project_id, scope.operation_key, limits.wire())
            row = store.load_scope(tx, scope.project_id, scope.operation_key)
            assert row is not None
        return _state(
            scope.project_id,
            scope.operation_key,
            row,
            store.load_events(tx, scope.project_id, scope.operation_key),
        )


def resume_allowance(scope: AllowanceContext, context: AccessContext, ledger: Ledger) -> CallState:
    """Read the durable shared state; the scope key is fixed by the admitted ledger rows."""
    if type(scope) is not AllowanceContext:
        raise ContractError("invalid_schema")
    _authorize(context, scope.project_id)
    with ledger.transaction() as tx:
        _, row = _prepare(tx, scope)
        if row is None:
            raise ContractError("limits_missing")
        return _state(
            scope.project_id,
            scope.operation_key,
            row,
            store.load_events(tx, scope.project_id, scope.operation_key),
        )


def _gate(tx: LedgerTxn, scope: AllowanceContext, limits: CallLimits, moment: datetime) -> None:
    """Deadline, current pause and run freeze apply to every new allowance consumption."""
    if moment >= _instant(limits.deadline):
        raise ContractError("authorization_expired")
    if (
        store.run_frozen(tx, scope.project_id, scope.run_id)
        or tx.get_pause("project", scope.project_id, None).paused
        or tx.get_pause("run", scope.project_id, scope.run_id).paused
    ):
        raise ContractError("forbidden")


def _settle(call: _Call | None, event: CallEvent) -> None:
    """An outcome must name a call of this exact request and scope, and only move forward."""
    scope = event.context
    if call is None or (
        call.run_id,
        call.attempt_id,
        call.reservation_id,
        call.request_digest,
    ) != (scope.run_id, scope.attempt_id, scope.reservation_id, scope.request_digest):
        raise ContractError("revision_mismatch")
    if (call.status, event.outcome) not in {
        ("pending", "known"),
        ("pending", "unknown"),
        ("unknown", "known"),
    }:
        raise ContractError("determinism_conflict")
    if event.external_request_id is not None and call.external_request_id not in {
        None,
        event.external_request_id,
    }:
        raise ContractError("determinism_conflict")


def _reserve(
    tx: LedgerTxn,
    event: CallEvent,
    row: store.ScopeRow,
    limits: CallLimits,
    attempt_state: str,
    events: list[store.EventRow],
    calls: dict[str, _Call],
    moment: datetime,
) -> store.ScopeRow:
    """Return the advanced counters for a submission or transition, or raise consuming nothing."""
    scope = event.context
    if store.call_submitted(tx, scope.project_id, event.call_id):
        raise ContractError("determinism_conflict")
    _gate(tx, scope, limits, moment)
    if event.kind == "transition":
        if row.transitions + 1 > limits.max_transitions:
            raise ContractError("budget_exhausted")
        return replace(row, transitions=row.transitions + 1)
    if attempt_state in store.UNRESOLVED_ATTEMPT_STATES:
        raise ContractError("dispatch_unknown")
    if attempt_state not in store.ACTIVE_ATTEMPT_STATES:
        raise ContractError("forbidden")
    if event.context_scalars > limits.max_context_scalars:
        raise ContractError("limit_exceeded")
    repairs = row.repairs + (1 if event.kind == "repair" else 0)
    advanced = replace(
        row,
        requests=row.requests + 1,
        repairs=repairs,
        transports=row.transports + 1,
        input_tokens=row.input_tokens + event.reserved_input_tokens,
        output_tokens=row.output_tokens + event.reserved_output_tokens,
        peak_context=max(row.peak_context, event.context_scalars),
    )
    if (
        advanced.requests > limits.max_requests
        or advanced.repairs > limits.max_repairs
        or advanced.transports > limits.max_transport_attempts
        or advanced.input_tokens > limits.max_input_tokens
        or advanced.output_tokens > limits.max_output_tokens
    ):
        raise ContractError("budget_exhausted")
    if any(call.status in {"pending", "unknown"} for call in calls.values()):
        # An unresolved call may have been charged: only reconciliation of that call or a
        # separate D05 manual-retry decision unfreezes new billable effects.
        # A decision counts only when it follows the latest unresolved event (never stale).
        if store.manual_retry_decisions(tx, scope.project_id, scope.operation_key) <= 0:
            raise ContractError("dispatch_unknown")
        advanced = replace(advanced, retries_consumed=row.retries_consumed + 1)
    digests = {item.request_digest for item in events if item.kind in store.SUBMISSION_KINDS}
    if event.kind in {"repair", "transport"} and not digests:
        raise ContractError("forbidden")
    if event.kind == "transport" and scope.request_digest not in digests:
        raise ContractError("revision_mismatch")
    if event.kind == "request" and scope.request_digest in digests:
        raise ContractError("determinism_conflict")
    return advanced


def advance_allowance(
    event: CallEvent, context: AccessContext, ledger: Ledger, now: Instant
) -> CallState:
    """Reserve or record one event atomically; reject, consuming nothing, beyond any bound."""
    if type(event) is not CallEvent:
        raise ContractError("invalid_schema")
    moment = _instant(now)
    scope = event.context
    _authorize(context, scope.project_id)
    digest = _event_digest(event)
    with ledger.transaction() as tx:
        attempt_state, row = _prepare(tx, scope)
        if row is None:
            raise ContractError("limits_missing")
        events = store.load_events(tx, scope.project_id, scope.operation_key)
        prior = store.load_event(tx, scope.project_id, event.event_id)
        if prior is not None:
            if prior.event_digest != digest:
                raise ContractError("determinism_conflict")
            return _state(scope.project_id, scope.operation_key, row, events)
        limits = CallLimits.from_wire(row.limits)
        calls = _fold(events)
        if event.kind == "outcome":
            _settle(calls.get(event.call_id), event)
            advanced = row
        else:
            advanced = _reserve(tx, event, row, limits, attempt_state, events, calls, moment)
        advanced = replace(advanced, version=row.version + 1)
        advanced = replace(advanced, exhausted=_is_exhausted(limits, advanced))
        record = store.EventRow(
            event.event_id,
            event.call_id,
            scope.run_id,
            scope.attempt_id,
            scope.reservation_id,
            scope.request_digest,
            event.kind,
            event.outcome,
            event.external_request_id,
            event.reserved_input_tokens,
            event.reserved_output_tokens,
            event.context_scalars,
            digest,
            advanced.version,
        )
        store.append_event(
            tx, scope.project_id, scope.operation_key, record, recorded_at=now, scope=advanced
        )
        return _state(scope.project_id, scope.operation_key, advanced, [*events, record])


__all__ = [
    "AllowanceContext",
    "CallEvent",
    "CallLimits",
    "CallRef",
    "CallState",
    "advance_allowance",
    "open_allowance",
    "resume_allowance",
]
