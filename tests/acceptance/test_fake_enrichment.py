"""Shared durable call allowance against real isolated PostgreSQL, with a fake transport.

The fake supplies scripted responses, faults and editorial verdicts only. Every assertion about
counters, freezes, reservations and acceptance is made on production allowance, ledger, codec,
exact-anchor and envelope-validator behavior.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier
from typing import Any, cast
from uuid import uuid4

import pytest
from fake_enrichment import (
    ACTOR,
    CASES,
    ENRICH_ACCESS,
    NOW,
    PROJECT,
    DeterministicEditorialReview,
    EnrichmentHarness,
    Evaluation,
    FakeEnrichmentTransport,
    ScriptedResponse,
    SeededScope,
    TransportLost,
    allowance_context,
    operation_key_for,
    seed_admitted_scope,
    submit,
)
from psycopg import sql
from psycopg.types.json import Jsonb
from pydantic import ValidationError

from conscience_foundry.contracts.common import ContractError, Ref
from conscience_foundry.contracts.extensions import (
    DecisionRelease,
    DecisionRequest,
    DecisionResult,
    DecisionTaskSpec,
    DecisionValidationContext,
    EnrichmentResult,
    correlate_decision,
)
from conscience_foundry.core.spans import check_exact_quote
from conscience_foundry.execution.allowance import (
    AllowanceContext,
    CallEvent,
    CallLimits,
    CallRef,
    CallState,
    advance_allowance,
    open_allowance,
    resume_allowance,
)
from conscience_foundry.ledger.allowance import MIGRATION_NAME, install_allowance_schema
from conscience_foundry.ledger.db import Ledger
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.local import VerifiedBytes

RUN = "00000000-0000-0000-0000-000000000002"
RUN2 = "00000000-0000-0000-0000-0000000000a2"
LIMIT_FIELDS = {
    "maxRequests": "max_requests",
    "maxRepairs": "max_repairs",
    "maxTransportAttempts": "max_transport_attempts",
    "maxTransitions": "max_transitions",
    "maxInputTokens": "max_input_tokens",
    "maxOutputTokens": "max_output_tokens",
    "maxContextScalars": "max_context_scalars",
    "deadline": "deadline",
}
BASE = CASES["baseLimits"]
BEFORE_NOW = "2026-10-25T00:00:00.000Z"
AFTER_NOW = "2026-10-26T00:00:01.000Z"
LATER = "2026-10-26T00:30:00.000Z"


def authorize_manual_retry(ledger: Ledger, world: Any, decided_at: str) -> None:
    """Trusted setup standing in for an authenticated D05 manual-retry decision."""
    with ledger.transaction() as tx:
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,decision_id,run_id,operation_key,action,"
                "evidence_ref,request_digest,record_bytes,actor_id,decided_at) "
                "VALUES (%s,%s,%s,%s,'manual_retry',%s,%s,%s,%s,%s)"
            ).format(tx.table("control_decisions")),
            (PROJECT, str(uuid4()), RUN, world.key, Jsonb({}), "c" * 64, b"{}", ACTOR, decided_at),
        )


def limits_from(raw: dict[str, Any]) -> CallLimits:
    return CallLimits(**{LIMIT_FIELDS[key]: value for key, value in raw.items()})


def call_limits(**changes: Any) -> CallLimits:
    return replace(limits_from(BASE), **changes)


@pytest.fixture
def allowance_ledger(ledger: Any) -> Ledger:
    database = cast(Ledger, ledger)
    install_allowance_schema(database)
    return database


class World:
    """One admitted synthetic scope with an opened allowance and its evaluation harness."""

    def __init__(
        self,
        database: Ledger,
        limits: CallLimits | None = None,
        label: str = "synthetic.enrichment",
    ) -> None:
        self.ledger = database
        self.key = operation_key_for(label)
        self.seeded: SeededScope = seed_admitted_scope(
            database, run_id=RUN, operation_key=self.key
        )
        self.harness = EnrichmentHarness(
            operation_key=self.key,
            attempt_id=self.seeded.attempt_id,
            reservation_id=self.seeded.reservation_id,
        )
        self.scope = allowance_context(self.seeded, self.harness.request_digest)
        self.limits = limits or call_limits()
        self.opened = open_allowance(self.scope, self.limits, ENRICH_ACCESS, database, NOW)

    def state(self, database: Ledger | None = None) -> CallState:
        return resume_allowance(self.scope, ENRICH_ACCESS, database or self.ledger)

    def reservation(self) -> tuple[Any, ...]:
        with self.ledger.transaction() as tx:
            row = tx.connection.execute(
                sql.SQL(
                    "SELECT reserved_usd,outstanding_usd,settled_usd,released_usd FROM {} "
                    "WHERE project_id=%s AND reservation_id=%s"
                ).format(tx.table("reservations")),
                (PROJECT, self.seeded.reservation_id),
            ).fetchone()
        assert row is not None
        return row

    def event_count(self) -> int:
        with self.ledger.transaction() as tx:
            row = tx.connection.execute(
                sql.SQL("SELECT count(*) FROM {}.call_allowance_events WHERE project_id=%s").format(
                    sql.Identifier(tx.schema)
                ),
                (PROJECT,),
            ).fetchone()
        assert row is not None
        return int(row[0])


def event(
    scope: AllowanceContext, kind: str, outcome: str = "pending", **changes: Any
) -> CallEvent:
    base: dict[str, Any] = {
        "event_id": str(uuid4()),
        "call_id": str(uuid4()),
        "context": scope,
        "kind": kind,
        "external_request_id": None,
        "reserved_input_tokens": 10,
        "reserved_output_tokens": 10,
        "context_scalars": 5,
        "outcome": outcome,
    }
    if kind in {"transition", "outcome"}:
        base |= {"reserved_input_tokens": 0, "reserved_output_tokens": 0, "context_scalars": 0}
    return CallEvent(**(base | changes))


def faults(count: int) -> FakeEnrichmentTransport:
    return FakeEnrichmentTransport([{"kind": "fault"}] * count)


def script(name: str) -> dict[str, Any]:
    return next(item for item in CASES["responseCases"] if item["name"] == name)["script"]


def case_of(name: str) -> dict[str, Any]:
    return next(item for item in CASES["responseCases"] if item["name"] == name)


def fresh_harness() -> EnrichmentHarness:
    return EnrichmentHarness(
        operation_key=operation_key_for(), attempt_id=str(uuid4()), reservation_id=str(uuid4())
    )


def run_case(harness: EnrichmentHarness, name: str) -> Evaluation:
    transport = FakeEnrichmentTransport([script(name)])
    try:
        response: ScriptedResponse | None = transport.send(str(uuid4()), harness.request_digest)
    except TransportLost:
        response = None
    return harness.evaluate(response)


def check_case(harness: EnrichmentHarness, name: str) -> Evaluation:
    """Compare production-derived statuses with the independently stated fixture expectation."""
    evaluation = run_case(harness, name)
    expect = case_of(name)["expect"]
    result = evaluation.result
    assert (
        result.schema_status,
        result.anchor_status,
        result.semantic_status,
        result.disposition,
    ) == (
        expect["schemaStatus"],
        expect["anchorStatus"],
        expect["semanticStatus"],
        expect["disposition"],
    )
    assert evaluation.reason_code == expect["reasonCode"]
    assert evaluation.outcome == expect["outcome"]
    harness.correlate(result, evaluation.context)
    return evaluation


# --------------------------------------------------------------------------------- value objects


def test_limits_are_required_finite_and_explicit() -> None:
    valid = limits_from(BASE)
    assert call_limits(max_repairs=0, max_transitions=0).max_repairs == 0
    with pytest.raises(TypeError):
        CallLimits()  # type: ignore[call-arg]
    for field, bad in (
        ("max_requests", 0),
        ("max_transport_attempts", 0),
        ("max_input_tokens", 0),
        ("max_output_tokens", 0),
        ("max_context_scalars", 0),
        ("max_repairs", -1),
        ("max_transitions", True),
        ("max_requests", 9007199254741000),
        ("max_requests", 1.5),
        ("deadline", "2026-10-26T01:00:00Z"),
    ):
        with pytest.raises(ContractError):
            replace(valid, **{field: bad})


def test_event_shapes_reject_ambiguous_accounting() -> None:
    scope = AllowanceContext(
        PROJECT, RUN, "a" * 64, str(uuid4()), str(uuid4()), "b" * 64
    )
    event(scope, "request")
    event(scope, "transition", "known")
    event(scope, "outcome", "unknown")
    for kind, outcome, changes in (
        ("request", "known", {}),
        ("request", "pending", {"reserved_input_tokens": 0}),
        ("repair", "pending", {"reserved_output_tokens": 0}),
        ("outcome", "pending", {}),
        ("outcome", "known", {"reserved_input_tokens": 1}),
        ("transition", "known", {"context_scalars": 1}),
        ("transition", "pending", {}),
        ("request", "pending", {"external_request_id": ""}),
        ("retry", "pending", {}),
        ("request", "pending", {"call_id": "not-a-uuid"}),
    ):
        with pytest.raises(ContractError):
            event(scope, kind, outcome, **changes)
    with pytest.raises(ContractError):
        AllowanceContext(PROJECT, RUN, "short", str(uuid4()), str(uuid4()), "b" * 64)


def test_mechanism_loads_no_model_graph_provider_or_consumer_code() -> None:
    probe = (
        "import sys, json\n"
        "import conscience_foundry.execution.allowance, conscience_foundry.ledger.allowance\n"
        "banned = ('torch', 'transformers', 'langgraph', 'langchain', 'laya', 'openai',\n"
        "          'anthropic', 'boto3', 'modal', 'dagster', 'requests', 'httpx')\n"
        "print(json.dumps(sorted(m for m in sys.modules if m.split('.')[0] in banned)))\n"
    )
    done = subprocess.run(
        [sys.executable, "-I", "-c", probe], capture_output=True, text=True, check=True
    )
    assert json.loads(done.stdout) == []


# ------------------------------------------------------------------------------------ migration


@pytest.mark.database
def test_migration_applies_after_001_and_is_idempotent(ledger: Any) -> None:
    database = cast(Ledger, ledger)
    seeded = seed_admitted_scope(database, run_id=RUN, operation_key=operation_key_for())
    scope = allowance_context(seeded, "b" * 64)
    with pytest.raises(ContractError, match="schema_incompatible"):
        resume_allowance(scope, ENRICH_ACCESS, database)
    assert MIGRATION_NAME == "002_call_allowance.sql"
    install_allowance_schema(database)
    install_allowance_schema(database)
    with database.transaction() as tx:
        tables = tx.connection.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema=%s "
            "AND table_name LIKE 'call_allowance%%' ORDER BY 1",
            (tx.schema,),
        ).fetchall()
        version = tx.connection.execute(
            sql.SQL("SELECT version FROM {}.schema_version").format(sql.Identifier(tx.schema))
        ).fetchall()
    assert tables == [("call_allowance_events",), ("call_allowance_scopes",)]
    assert version == [(1,)]
    with database.transaction() as tx:
        tx.connection.execute(
            sql.SQL("COMMENT ON TABLE {}.call_allowance_scopes IS 'tampered'").format(
                sql.Identifier(tx.schema)
            )
        )
    with pytest.raises(ContractError, match="schema_incompatible"):
        install_allowance_schema(database)
    with pytest.raises(ContractError, match="schema_incompatible"):
        resume_allowance(scope, ENRICH_ACCESS, database)


# --------------------------------------------------------------------- durable shared allowance


@pytest.mark.database
def test_repair_transport_fault_and_restart_consume_the_same_allowance(
    allowance_ledger: Ledger,
) -> None:
    world = World(allowance_ledger, call_limits(max_repairs=1, max_transport_attempts=3))
    transport = FakeEnrichmentTransport(
        [
            script("malformed_non_json"),
            {"kind": "fault"},
            script("repeated_quote_first_explicit_range"),
        ]
    )
    first = submit(allowance_ledger, transport, world.scope, "request")
    malformed = world.harness.evaluate(first.response)
    assert malformed.result.schema_status == "invalid"
    assert first.settled.requests == 1 and first.settled.transports == 1

    repair = submit(allowance_ledger, transport, world.scope, "repair")
    assert repair.response is None and repair.outcome == "known"
    assert (repair.settled.requests, repair.settled.repairs, repair.settled.transports) == (2, 1, 2)

    # A restarted worker/coordinator opens fresh connections and sees the same durable counters.
    restarted = Ledger(allowance_ledger.connection_factory, schema=allowance_ledger.schema)
    assert world.state(restarted) == repair.settled
    resubmitted = submit(restarted, transport, world.scope, "transport")
    assert (
        resubmitted.settled.requests,
        resubmitted.settled.repairs,
        resubmitted.settled.transports,
    ) == (3, 1, 3)
    assert (resubmitted.settled.input_tokens, resubmitted.settled.output_tokens) == (30, 30)
    accepted = world.harness.evaluate(resubmitted.response)
    assert accepted.result.disposition == "accepted"
    world.harness.correlate(accepted.result, accepted.context)

    for kind in ("transport", "repair"):
        with pytest.raises(ContractError, match="budget_exhausted"):
            submit(restarted, transport, world.scope, kind)  # type: ignore[arg-type]
    assert world.state(restarted) == resubmitted.settled
    assert world.state().exhausted


@pytest.mark.database
def test_new_run_and_new_coordinator_connection_cannot_reset_inherited_state(
    allowance_ledger: Ledger,
) -> None:
    world = World(allowance_ledger, call_limits(max_requests=3, max_transport_attempts=3))
    transport = faults(6)
    submit(allowance_ledger, transport, world.scope, "request")
    submit(allowance_ledger, transport, world.scope, "transport")
    before = world.state()
    assert before.requests == 2

    second = seed_admitted_scope(allowance_ledger, run_id=RUN2, operation_key=world.key)
    scope2 = allowance_context(second, world.harness.request_digest)
    # A new scheduling run cannot widen, shorten or otherwise re-seed the inherited limits.
    for changed in (
        call_limits(max_requests=30),
        call_limits(max_transport_attempts=1),
        call_limits(deadline="2026-10-26T00:45:00.000Z"),
    ):
        with pytest.raises(ContractError, match="determinism_conflict"):
            open_allowance(scope2, changed, ENRICH_ACCESS, allowance_ledger, NOW)
    inherited = open_allowance(scope2, world.limits, ENRICH_ACCESS, allowance_ledger, NOW)
    assert inherited == before

    fresh = Ledger(allowance_ledger.connection_factory, schema=allowance_ledger.schema)
    last = submit(fresh, transport, scope2, "transport")
    assert (last.settled.requests, last.settled.transports) == (3, 3)
    with pytest.raises(ContractError, match="budget_exhausted"):
        submit(allowance_ledger, transport, world.scope, "transport")
    assert resume_allowance(scope2, ENRICH_ACCESS, fresh) == world.state()


@pytest.mark.database
def test_effects_only_follow_a_committed_reservation(allowance_ledger: Ledger) -> None:
    world = World(allowance_ledger)
    observed: list[CallState] = []
    independent = Ledger(allowance_ledger.connection_factory, schema=allowance_ledger.schema)

    def probe(call_id: str) -> None:
        observed.append(world.state(independent))
        assert [item.call_id for item in observed[-1].pending] == [call_id]

    transport = FakeEnrichmentTransport([{"kind": "fault"}], on_send=probe)
    result = submit(allowance_ledger, transport, world.scope, "request")
    assert observed[0].requests == 1 and observed[0].transports == 1
    assert observed[0].input_tokens == 10 and observed[0].output_tokens == 10
    assert result.settled.pending == ()

    exhausted = World(allowance_ledger, call_limits(max_requests=1), "synthetic.single")
    tripwire = FakeEnrichmentTransport([{"kind": "fault"}] * 2)
    submit(allowance_ledger, tripwire, exhausted.scope, "request")
    with pytest.raises(ContractError, match="budget_exhausted"):
        submit(allowance_ledger, tripwire, exhausted.scope, "transport")
    assert len(tripwire.sent) == 1, "a rejected reservation must never reach the transport"


# --------------------------------------------------------------------------- unknown outcomes


@pytest.mark.database
def test_unknown_request_retains_reservation_and_blocks_another_call(
    allowance_ledger: Ledger,
) -> None:
    world = World(allowance_ledger)
    before = world.reservation()
    transport = FakeEnrichmentTransport([{"kind": "lost"}, {"kind": "fault"}])
    lost = submit(allowance_ledger, transport, world.scope, "request")
    assert lost.outcome == "unknown" and lost.response is None
    assert lost.settled.unknown == (CallRef(lost.call_id, None),)
    assert lost.settled.pending == ()
    assert world.reservation() == before, "the monetary reservation stays outstanding"
    assert world.reservation()[1] == before[0] and world.reservation()[3] == 0

    frozen = world.state()
    for kind in ("request", "repair", "transport"):
        with pytest.raises(ContractError, match="dispatch_unknown"):
            submit(allowance_ledger, transport, world.scope, kind)  # type: ignore[arg-type]
    assert world.state() == frozen and len(transport.sent) == 1
    assert world.reservation() == before

    # No external effect: an internal transition is not frozen, and cannot reset any count.
    moved = advance_allowance(
        event(world.scope, "transition", "known"), ENRICH_ACCESS, allowance_ledger, NOW
    )
    assert moved.transitions == 1
    assert (moved.requests, moved.transports, moved.input_tokens) == (1, 1, 10)

    # Restart does not release the freeze or decrement the conservative maxima.
    restarted = Ledger(allowance_ledger.connection_factory, schema=allowance_ledger.schema)
    state = world.state(restarted)
    assert state.unknown == (CallRef(lost.call_id, None),)
    assert (state.input_tokens, state.output_tokens) == (10, 10)


@pytest.mark.database
def test_unknown_freeze_lifts_only_by_reconciliation_that_keeps_the_money(
    allowance_ledger: Ledger,
) -> None:
    world = World(allowance_ledger)
    before = world.reservation()
    transport = FakeEnrichmentTransport([{"kind": "lost"}, {"kind": "fault"}])
    lost = submit(allowance_ledger, transport, world.scope, "request")
    reconcile = event(
        world.scope,
        "outcome",
        "known",
        call_id=lost.call_id,
        external_request_id="synthetic-provider-7",
    )
    reconciled = advance_allowance(reconcile, ENRICH_ACCESS, allowance_ledger, NOW)
    assert reconciled.unknown == () and reconciled.pending == ()
    assert reconciled.input_tokens == 10, "reconciliation never decrements allocated maxima"
    assert world.reservation() == before, "allowance reconciliation is not a money release"
    again = submit(allowance_ledger, transport, world.scope, "transport")
    assert again.settled.requests == 2
    # A settled call cannot be resolved twice, nor moved back to unknown.
    for outcome in ("known", "unknown"):
        with pytest.raises(ContractError, match="determinism_conflict"):
            advance_allowance(
                event(world.scope, "outcome", outcome, call_id=lost.call_id),
                ENRICH_ACCESS,
                allowance_ledger,
                NOW,
            )


@pytest.mark.database
def test_unknown_freeze_lifts_by_separate_d05_authorization_once(
    allowance_ledger: Ledger,
) -> None:
    world = World(allowance_ledger)
    transport = FakeEnrichmentTransport([{"kind": "lost"}, {"kind": "fault"}, {"kind": "fault"}])
    submit(allowance_ledger, transport, world.scope, "request")
    with pytest.raises(ContractError, match="dispatch_unknown"):
        submit(allowance_ledger, transport, world.scope, "transport")

    authorize_manual_retry(allowance_ledger, world, AFTER_NOW)
    allowed = submit(allowance_ledger, transport, world.scope, "transport")
    assert allowed.settled.requests == 2 and len(allowed.settled.unknown) == 1
    with pytest.raises(ContractError, match="dispatch_unknown"):
        submit(allowance_ledger, transport, world.scope, "transport")
    authorize_manual_retry(allowance_ledger, world, AFTER_NOW)
    assert submit(allowance_ledger, transport, world.scope, "transport").settled.requests == 3


@pytest.mark.database
def test_d05_authorization_is_bound_to_the_unresolved_call_it_follows(
    allowance_ledger: Ledger,
) -> None:
    world = World(allowance_ledger)
    transport = FakeEnrichmentTransport(
        [{"kind": "lost"}, {"kind": "lost"}, {"kind": "fault"}, {"kind": "fault"}]
    )
    # A decision recorded before the unknown outcome cannot authorize that outcome's retry.
    authorize_manual_retry(allowance_ledger, world, BEFORE_NOW)
    submit(allowance_ledger, transport, world.scope, "request")
    with pytest.raises(ContractError, match="dispatch_unknown"):
        submit(allowance_ledger, transport, world.scope, "transport")

    # A decision that follows the unknown call is spent only on that episode: once the call is
    # reconciled known without using it, a later unknown call is frozen again.
    authorize_manual_retry(allowance_ledger, world, AFTER_NOW)
    lost = world.state().unknown[0]
    advance_allowance(
        event(world.scope, "outcome", "known", call_id=lost.call_id),
        ENRICH_ACCESS,
        allowance_ledger,
        LATER,
    )
    submit(allowance_ledger, transport, world.scope, "transport", now=LATER)
    with pytest.raises(ContractError, match="dispatch_unknown"):
        submit(allowance_ledger, transport, world.scope, "transport", now=LATER)
    authorize_manual_retry(allowance_ledger, world, "2026-10-26T00:45:00.000Z")
    assert (
        submit(allowance_ledger, transport, world.scope, "transport", now=LATER).settled.requests
        == 3
    )


# ----------------------------------------------------------------------------- replay / conflict


@pytest.mark.database
def test_replayed_events_do_not_consume_twice_and_changed_reuse_conflicts(
    allowance_ledger: Ledger,
) -> None:
    world = World(allowance_ledger)
    request = event(world.scope, "request")
    first = advance_allowance(request, ENRICH_ACCESS, allowance_ledger, NOW)
    count = world.event_count()
    replayed = advance_allowance(request, ENRICH_ACCESS, allowance_ledger, NOW)
    assert replayed == first and world.event_count() == count
    # An identical replay stays a no-op even after the deadline has passed.
    late = advance_allowance(request, ENRICH_ACCESS, allowance_ledger, "2026-12-01T00:00:00.000Z")
    assert late == first

    outcome = event(world.scope, "outcome", "known", call_id=request.call_id)
    settled = advance_allowance(outcome, ENRICH_ACCESS, allowance_ledger, NOW)
    assert advance_allowance(outcome, ENRICH_ACCESS, allowance_ledger, NOW) == settled
    assert world.event_count() == count + 1

    for changed in (
        replace(request, reserved_input_tokens=11),
        replace(request, kind="transport"),
        replace(request, external_request_id="other"),
        replace(request, call_id=str(uuid4())),
    ):
        with pytest.raises(ContractError, match="determinism_conflict"):
            advance_allowance(changed, ENRICH_ACCESS, allowance_ledger, NOW)
    # A new event may not reuse a submitted local call identity either.
    with pytest.raises(ContractError, match="determinism_conflict"):
        advance_allowance(
            event(world.scope, "request", call_id=request.call_id),
            ENRICH_ACCESS,
            allowance_ledger,
            NOW,
        )
    assert world.state().requests == 1 and world.state().input_tokens == 10


@pytest.mark.database
def test_concurrent_final_allowance_is_granted_once(allowance_ledger: Ledger) -> None:
    world = World(allowance_ledger, call_limits(max_requests=1))
    barrier = Barrier(4)

    def compete(_: int) -> bool:
        independent = Ledger(allowance_ledger.connection_factory, schema=allowance_ledger.schema)
        barrier.wait(timeout=5)
        try:
            advance_allowance(event(world.scope, "request"), ENRICH_ACCESS, independent, NOW)
            return True
        except ContractError as error:
            assert error.code == "budget_exhausted"
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(compete, range(4))) == 1
    assert world.state().requests == 1 and world.event_count() == 1


# -------------------------------------------------------------------------------- exhaustion


@pytest.mark.database
@pytest.mark.parametrize("case", CASES["exhaustionCases"], ids=lambda case: case["name"])
def test_every_bound_and_the_deadline_reject_without_consuming(
    allowance_ledger: Ledger, case: dict[str, Any]
) -> None:
    world = World(allowance_ledger, limits_from(case["limits"]))
    transport = faults(len(case["steps"]))
    for index, step in enumerate(case["steps"]):
        now = step.get("now", NOW)
        before = world.state()
        attempt = (
            (lambda step=step, now=now: advance_allowance(
                event(world.scope, "transition", "known"), ENRICH_ACCESS, allowance_ledger, now
            ))
            if step["kind"] == "transition"
            else (lambda step=step, now=now: submit(
                allowance_ledger,
                transport,
                world.scope,
                step["kind"],
                now=now,
                input_tokens=step["inputTokens"],
                output_tokens=step["outputTokens"],
                context_scalars=step["context"],
            ))
        )
        if index == case["failAt"]:
            with pytest.raises(ContractError) as rejected:
                attempt()
            assert rejected.value.code == case["code"]
            assert world.state() == before, "a rejected reservation consumes nothing"
            return
        attempt()
    raise AssertionError("exhaustion case never reached its failing step")


@pytest.mark.database
def test_transitions_cannot_reset_any_count(allowance_ledger: Ledger) -> None:
    world = World(allowance_ledger, call_limits(max_transitions=2, max_requests=2))
    transport = faults(3)
    submit(allowance_ledger, transport, world.scope, "request")
    with_transition = advance_allowance(
        event(world.scope, "transition", "known"), ENRICH_ACCESS, allowance_ledger, NOW
    )
    assert (
        with_transition.requests,
        with_transition.transports,
        with_transition.input_tokens,
        with_transition.output_tokens,
        with_transition.peak_context,
    ) == (1, 1, 10, 10, 5)
    assert with_transition.version > 2
    submit(allowance_ledger, transport, world.scope, "transport")
    with pytest.raises(ContractError, match="budget_exhausted"):
        submit(allowance_ledger, transport, world.scope, "transport")


# -------------------------------------------------------- gating: pause, permission, binding


@pytest.mark.database
def test_pause_freeze_permission_and_attempt_state_reject_effects(
    allowance_ledger: Ledger,
) -> None:
    world = World(allowance_ledger)
    transport = faults(8)
    in_flight = advance_allowance(
        event(world.scope, "request"), ENRICH_ACCESS, allowance_ledger, NOW
    )
    call_id = in_flight.pending[0].call_id

    def pause(scope: str, paused: bool, version: int) -> None:
        with allowance_ledger.transaction() as tx:
            tx.record_pause(
                scope,  # type: ignore[arg-type]
                PROJECT,
                RUN if scope == "run" else None,
                paused,
                expected_version=version,
                actor_id=ACTOR,
                reason="synthetic_pause",
                decided_at="2026-10-25T00:00:00.000Z",
                decision_id=str(uuid4()),
            )

    for scope in ("run", "project"):
        pause(scope, True, 0)
        with pytest.raises(ContractError, match="forbidden"):
            submit(allowance_ledger, transport, world.scope, "transport")
        with pytest.raises(ContractError, match="forbidden"):
            advance_allowance(
                event(world.scope, "transition", "known"), ENRICH_ACCESS, allowance_ledger, NOW
            )
        # Recording what already happened to an in-flight call is not a new effect.
        if scope == "run":
            settled = advance_allowance(
                event(world.scope, "outcome", "known", call_id=call_id),
                ENRICH_ACCESS,
                allowance_ledger,
                NOW,
            )
            assert settled.pending == ()
        pause(scope, False, 1)
    assert submit(allowance_ledger, transport, world.scope, "transport").settled.requests == 2

    for access in (
        AccessContext(PROJECT, ACTOR, frozenset({"read"})),
        AccessContext(PROJECT, ACTOR, frozenset()),
        AccessContext(str(uuid4()), ACTOR, frozenset({"enrich"})),
    ):
        with pytest.raises(ContractError, match="forbidden"):
            submit(allowance_ledger, transport, world.scope, "transport", access=access)
        with pytest.raises(ContractError, match="forbidden"):
            resume_allowance(world.scope, access, allowance_ledger)

    def mutate(statement: str) -> None:
        with allowance_ledger.transaction() as tx:
            tx.connection.execute(
                sql.SQL(statement).format(tx.table("runs"), tx.table("attempts")),
                (PROJECT, RUN, world.seeded.attempt_id),
            )

    mutate("UPDATE {0} SET frozen=true WHERE project_id=%s AND run_id=%s AND %s::text IS NOT NULL")
    with pytest.raises(ContractError, match="forbidden"):
        submit(allowance_ledger, transport, world.scope, "transport")
    mutate("UPDATE {0} SET frozen=false WHERE project_id=%s AND run_id=%s AND %s::text IS NOT NULL")
    mutate(
        "UPDATE {1} SET state='unknown_outcome' WHERE project_id=%s AND run_id=%s "
        "AND attempt_id=%s"
    )
    with pytest.raises(ContractError, match="dispatch_unknown"):
        submit(allowance_ledger, transport, world.scope, "transport")
    mutate(
        "UPDATE {1} SET state='failed',finished_at=now() WHERE project_id=%s AND run_id=%s "
        "AND attempt_id=%s"
    )
    with pytest.raises(ContractError, match="forbidden"):
        submit(allowance_ledger, transport, world.scope, "transport")
    assert len(transport.sent) == 1


@pytest.mark.database
def test_scope_binds_to_existing_admitted_ledger_rows(allowance_ledger: Ledger) -> None:
    world = World(allowance_ledger)
    other = seed_admitted_scope(allowance_ledger, run_id=RUN2, operation_key=world.key)
    stranger = seed_admitted_scope(
        allowance_ledger, run_id=RUN2, operation_key=operation_key_for("synthetic.other")
    )
    for forged in (
        replace(world.scope, reservation_id=str(uuid4())),
        replace(world.scope, attempt_id=str(uuid4())),
        replace(world.scope, attempt_id=other.attempt_id),  # another run's attempt
        replace(world.scope, reservation_id=other.reservation_id),
        replace(world.scope, run_id=RUN2),
        replace(world.scope, operation_key="d" * 64),
    ):
        with pytest.raises(ContractError, match="forbidden"):
            advance_allowance(event(forged, "request"), ENRICH_ACCESS, allowance_ledger, NOW)
        with pytest.raises(ContractError, match="forbidden"):
            resume_allowance(forged, ENRICH_ACCESS, allowance_ledger)
    # A different admitted operation never opened its own allowance has none to spend.
    unopened = allowance_context(stranger, world.harness.request_digest)
    with pytest.raises(ContractError, match="limits_missing"):
        advance_allowance(event(unopened, "request"), ENRICH_ACCESS, allowance_ledger, NOW)
    expired = replace(world.limits, deadline="2026-10-26T00:00:00.000Z")
    with pytest.raises(ContractError, match="authorization_expired"):
        open_allowance(unopened, expired, ENRICH_ACCESS, allowance_ledger, NOW)
    assert world.state().requests == 0


@pytest.mark.database
def test_request_correlation_rules_for_every_event_kind(allowance_ledger: Ledger) -> None:
    world = World(allowance_ledger)
    for kind in ("repair", "transport"):
        with pytest.raises(ContractError, match="forbidden"):
            advance_allowance(event(world.scope, kind), ENRICH_ACCESS, allowance_ledger, NOW)
    first = advance_allowance(event(world.scope, "request"), ENRICH_ACCESS, allowance_ledger, NOW)
    settle = event(world.scope, "outcome", "known", call_id=first.pending[0].call_id)
    wrong = replace(world.scope, request_digest="e" * 64)
    with pytest.raises(ContractError, match="revision_mismatch"):
        advance_allowance(replace(settle, context=wrong), ENRICH_ACCESS, allowance_ledger, NOW)
    with pytest.raises(ContractError, match="revision_mismatch"):
        advance_allowance(
            event(world.scope, "outcome", "known", call_id=str(uuid4())),
            ENRICH_ACCESS,
            allowance_ledger,
            NOW,
        )
    advance_allowance(settle, ENRICH_ACCESS, allowance_ledger, NOW)
    # A resubmission must be of the very same request; a duplicate must be declared as such.
    with pytest.raises(ContractError, match="revision_mismatch"):
        advance_allowance(
            event(wrong, "transport"), ENRICH_ACCESS, allowance_ledger, NOW
        )
    with pytest.raises(ContractError, match="determinism_conflict"):
        advance_allowance(event(world.scope, "request"), ENRICH_ACCESS, allowance_ledger, NOW)
    assert world.state().requests == 1


# ------------------------------------------------------------- full fake-response matrix


def test_fixture_cases_all_resolve_through_production_validators() -> None:
    harness = fresh_harness()
    for item in CASES["responseCases"]:
        evaluation = check_case(harness, item["name"])
        assert evaluation.result.disposition == "accepted" or item["expect"][
            "disposition"
        ] != "accepted"


@pytest.mark.parametrize("name", ["malformed_non_json", "malformed_schema_invalid"])
def test_fake_malformed_payload(name: str) -> None:
    harness = fresh_harness()
    evaluation = check_case(harness, name)
    result = evaluation.result
    assert result.schema_status == "invalid"
    assert result.disposition != "accepted"
    assert [reason.code for reason in result.reasons] == ["invalid_schema"]
    assert result.candidate_annotations_ref is None
    assert (result.anchor_status, result.semantic_status) == ("not_run", "pending")
    forged = result.model_dump(mode="json", by_alias=True) | {
        "disposition": "accepted",
        "reasons": [],
    }
    with pytest.raises(ValidationError):
        EnrichmentResult.model_validate(forged)


@pytest.mark.database
def test_fake_no_response(allowance_ledger: Ledger) -> None:
    world = World(allowance_ledger)
    before = world.reservation()
    transport = FakeEnrichmentTransport([script("no_response"), {"kind": "fault"}])
    lost = submit(allowance_ledger, transport, world.scope, "request")
    assert lost.outcome == "unknown" and lost.response is None
    evaluation = world.harness.evaluate(lost.response)
    result = evaluation.result
    assert (result.schema_status, result.anchor_status) == ("not_run", "not_run")
    assert result.disposition != "accepted" and result.reasons
    assert result.raw_response_ref is None and result.candidate_annotations_ref is None
    assert evaluation.outcome == "unknown"
    world.harness.correlate(result, evaluation.context)
    # No annotations may be fabricated for an absent response.
    fabricated = result.model_dump(mode="json", by_alias=True) | {
        "candidateAnnotationsRef": Ref.model_validate(
            {
                "schemaVersion": "kf.artifact-ref.v1",
                "projectId": PROJECT,
                "digest": "a" * 64,
                "sizeBytes": 1,
                "mediaType": "application/json",
                "artifactSchema": "kf.annotation-set.v1",
                "locations": [],
            }
        ).model_dump(mode="json", by_alias=True)
    }
    with pytest.raises(ValidationError):
        EnrichmentResult.model_validate(fabricated)
    # The unknown outcome is held under the local call_id with the money still outstanding.
    state = world.state()
    assert state.unknown == (CallRef(lost.call_id, None),)
    assert world.reservation() == before
    with pytest.raises(ContractError, match="dispatch_unknown"):
        submit(allowance_ledger, transport, world.scope, "transport")


@pytest.mark.parametrize("name", ["invented_quote", "stale_revision"])
def test_fake_invented_or_stale_quote(name: str) -> None:
    harness = fresh_harness()
    evaluation = check_case(harness, name)
    result = evaluation.result
    assert result.anchor_status == "invalid" and result.disposition != "accepted"
    assert result.reasons[0].code == case_of(name)["expect"]["reasonCode"]
    # An exact-looking record cannot be forced through the real correlation validator.
    forged = EnrichmentResult.model_validate(
        result.model_dump(mode="json", by_alias=True)
        | {
            "anchorStatus": "valid",
            "semanticStatus": "supported",
            "disposition": "accepted",
            "reasons": [],
        }
    )
    with pytest.raises(ContractError, match="invalid_schema"):
        harness.correlate(forged, evaluation.context)


def test_fake_repeated_quote_requires_explicit_range() -> None:
    harness = fresh_harness()
    ambiguous = check_case(harness, "repeated_quote_without_range")
    wrong = check_case(harness, "repeated_quote_wrong_range")
    for evaluation in (ambiguous, wrong):
        assert evaluation.result.anchor_status == "invalid"
        assert evaluation.result.disposition != "accepted"
        assert evaluation.result.reasons[0].code == "invalid_span"
    first = check_case(harness, "repeated_quote_first_explicit_range")
    second = check_case(harness, "repeated_quote_second_explicit_range")
    assert first.result.anchor_status == second.result.anchor_status == "valid"
    # Both authorized ranges are exact occurrences of the same quote, resolved deterministically.
    data = harness.text_bytes
    verified = VerifiedBytes(data, hashlib.sha256(data).hexdigest())
    for start, end in ((40, 53), (54, 67)):
        check_exact_quote(
            verified,
            harness.span_for(start, end, harness.revision_id),
            "See appendix.",
            revision=harness.revision,
            limits=harness.limits,
        )
    assert run_case(harness, "repeated_quote_second_explicit_range") == second
    check_case(harness, "unique_quote_resolves_without_range")


def test_fake_correct_anchor_reversed_negation() -> None:
    harness = fresh_harness()
    data = harness.text_bytes
    # The production exact-anchor checker passes: the quoted words are really there.
    check_exact_quote(
        VerifiedBytes(data, hashlib.sha256(data).hexdigest()),
        harness.span_for(0, 38, harness.revision_id),
        "The committee did not approve the plan",
        revision=harness.revision,
        limits=harness.limits,
    )
    evaluation = check_case(harness, "correct_anchor_reversed_negation")
    result = evaluation.result
    assert result.anchor_status == "valid"
    assert result.semantic_status == "disputed" and result.disposition == "needs_review"
    # Exactness is not support: the injected editorial verdict decides, and a self-asserted
    # acceptance fails both the envelope validator and the independent correlation.
    with pytest.raises(ValidationError):
        EnrichmentResult.model_validate(
            result.model_dump(mode="json", by_alias=True) | {"disposition": "accepted"}
        )
    claimed = EnrichmentResult.model_validate(
        result.model_dump(mode="json", by_alias=True)
        | {"semanticStatus": "supported", "disposition": "accepted"}
    )
    with pytest.raises(ContractError, match="invalid_schema"):
        harness.correlate(claimed, evaluation.context)
    # The verdict, not the transport, is what changes the outcome.
    approving = EnrichmentHarness(
        operation_key=harness.operation_key,
        attempt_id=harness.attempt_id,
        reservation_id=harness.reservation_id,
        review=DeterministicEditorialReview(
            {"The committee approved the plan.": "supported"}
        ),
    )
    assert run_case(approving, "correct_anchor_reversed_negation").result.disposition == "accepted"


def decision_fixture() -> (
    tuple[bytes, DecisionTaskSpec, DecisionRelease, DecisionValidationContext]
):
    def ref(schema: str) -> Ref:
        return Ref.model_validate(
            {
                "schemaVersion": "kf.artifact-ref.v1",
                "projectId": PROJECT,
                "digest": hashlib.sha256(schema.encode()).hexdigest(),
                "sizeBytes": len(schema),
                "mediaType": "application/json",
                "artifactSchema": schema,
                "locations": [],
            }
        )

    request = DecisionRequest.model_validate(
        {
            "schemaVersion": "kf.decision-request.v1",
            "projectId": PROJECT,
            "taskSpecRef": ref("kf.decision-task.v1"),
            "decisionReleaseRef": ref("kf.decision-release.v1"),
            "inputRef": ref("synthetic.payload.v1"),
            "policyRef": ref("kf.policy.v1"),
            "contextRevisionRefs": [],
            "operationKey": "c" * 64,
            "attemptId": str(uuid4()),
            "reservationId": str(uuid4()),
            "deadline": "2026-10-26T01:00:00.000Z",
        }
    )
    raw = request.model_dump_json(by_alias=True).encode()
    task = DecisionTaskSpec.model_validate(
        {
            "schemaVersion": "kf.decision-task.v1",
            "taskId": "synthetic.categorical",
            "version": "synthetic.v1",
            "inputSchemaRef": ref("json-schema.2020-12"),
            "outputSchemaRef": ref("json-schema.2020-12"),
            "options": ["first", "second"],
            "optionOrderVersion": "synthetic.v1",
            "fallbackPolicyRef": ref("synthetic.fallback.v1"),
        }
    )
    release = DecisionRelease.model_validate(
        {
            "schemaVersion": "kf.decision-release.v1",
            "releaseId": str(uuid4()),
            "implementation": "classifier",
            "taskSpecRefs": [ref("kf.decision-task.v1")],
            "runtimeRef": ref("synthetic.runtime.v1"),
            "stateBuilderRef": ref("synthetic.state.v1"),
            "datasetProvenanceRef": ref("synthetic.dataset.v1"),
            "decisionPolicyRef": ref("synthetic.decision-policy.v1"),
            "certifiedCohorts": ["cohort-a"],
            "evaluationRef": ref("synthetic.evaluation.v1"),
        }
    )
    context = DecisionValidationContext(
        request_digest=hashlib.sha256(raw).hexdigest(),
        project_id=PROJECT,
        operation_key=request.operation_key,
        attempt_id=request.attempt_id,
        task_spec_ref=request.task_spec_ref,
        decision_release_ref=request.decision_release_ref,
        output_schema_ref=task.output_schema_ref,
        policy_ref=request.policy_ref,
        decision_policy_ref=release.decision_policy_ref,
        fallback_policy_ref=task.fallback_policy_ref,
        implementation="classifier",
        probabilistic=False,
        calibration_required=False,
        probability_tolerance="0.000000001",
        expected_policy_outcome="needs_review",
        baseline_authorized=False,
        applicable_cohort="cohort-a",
        expected_cohort_status="uncertified",
    )
    return raw, task, release, context


@pytest.mark.database
def test_fake_wrong_request_or_uncertified_decision(allowance_ledger: Ledger) -> None:
    # Enrichment: a result or context for any other attempt/request fails the real C08 check.
    harness = fresh_harness()
    evaluation = run_case(harness, "repeated_quote_first_explicit_range")
    harness.correlate(evaluation.result, evaluation.context)
    other = fresh_harness()
    with pytest.raises(ContractError, match="revision_mismatch"):
        harness.correlate(
            evaluation.result, run_case(other, "repeated_quote_first_explicit_range").context
        )
    with pytest.raises(ContractError, match="revision_mismatch"):
        other.correlate(evaluation.result, evaluation.context)
    # Allowance: an outcome from another request or call scope is rejected by the ledger.
    world = World(allowance_ledger)
    submission = advance_allowance(
        event(world.scope, "request"), ENRICH_ACCESS, allowance_ledger, NOW
    )
    settle = event(world.scope, "outcome", "known", call_id=submission.pending[0].call_id)
    for scope, reason in (
        (replace(world.scope, request_digest=other.request_digest), "revision_mismatch"),
        (replace(world.scope, attempt_id=other.attempt_id), "forbidden"),
        (replace(world.scope, reservation_id=other.reservation_id), "forbidden"),
    ):
        with pytest.raises(ContractError, match=reason):
            advance_allowance(replace(settle, context=scope), ENRICH_ACCESS, allowance_ledger, NOW)
    assert world.state().pending == submission.pending

    # Decision: an uncertified cohort can never drive a prediction, by envelope or by policy.
    raw, task, release, context = decision_fixture()
    base: dict[str, Any] = {
        "schemaVersion": "kf.decision-result.v1",
        "projectId": PROJECT,
        "operationKey": context.operation_key,
        "attemptId": context.attempt_id,
        "requestDigest": context.request_digest,
        "taskSpecRef": context.task_spec_ref.model_dump(mode="json", by_alias=True),
        "decisionReleaseRef": context.decision_release_ref.model_dump(mode="json", by_alias=True),
        "status": "prediction",
        "prediction": "first",
        "cohortStatus": "uncertified",
        "policyOutcome": "use_prediction",
        "reason": {"code": "forbidden", "message": "Synthetic"},
        "traceRef": context.fallback_policy_ref.model_dump(mode="json", by_alias=True),
    }
    with pytest.raises(ValidationError):
        DecisionResult.model_validate(base)
    claims_certified = DecisionResult.model_validate(base | {"cohortStatus": "certified"})
    with pytest.raises(ContractError, match="forbidden"):
        correlate_decision(
            raw,
            claims_certified,
            limits=world.harness.limits,
            task_spec=task,
            decision_release=release,
            context=context,
        )
    correct = DecisionResult.model_validate(
        {key: value for key, value in base.items() if key != "prediction"}
        | {"status": "abstain", "policyOutcome": "needs_review"}
    )
    correlate_decision(
        raw,
        correct,
        limits=world.harness.limits,
        task_spec=task,
        decision_release=release,
        context=context,
    )
