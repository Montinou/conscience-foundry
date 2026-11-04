"""Pinned evidence and local allocation authority for cooperative execution."""

import hashlib
import io
import json
import os
import secrets
from collections.abc import Callable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, BinaryIO, Literal, Self, cast

from psycopg import sql
from pydantic import BeforeValidator, Field, model_validator

from conscience_foundry.contracts.common import (
    ArtifactLocation,
    ContractError,
    ContractLimits,
    Digest,
    Id,
    Instant,
    Money,
    PositiveInteger,
    Ref,
    WireModel,
)
from conscience_foundry.contracts.execution import ExecutionPlan, LocalExecutionConfig, StageAttempt
from conscience_foundry.execution.evidence import encoded, identity
from conscience_foundry.execution.local_allocation import (
    LocalActivationFacts,
    LocalAllocationPolicy,
    LocalAllocator,
)
from conscience_foundry.execution.local_contracts import (
    LocalGrantFacts,
    LocalGrantProof,
    LocalWorkerGrant,
)
from conscience_foundry.execution.ports import (
    BillingFacts,
    BudgetProof,
    CapabilityFacts,
    ControlContext,
    ControlFacts,
    ControlProof,
    CostAllocation,
    EstimateFacts,
    EvidenceBinding,
    ObservationFacts,
    ObservationProof,
    TransportFacts,
    TransportProof,
)
from conscience_foundry.ledger.db import Ledger
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.local import ObjectStore, VerifiedBytes


def _array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class LocalAllocationEstimate(WireModel):
    schema_version: Literal["cfoundry.local-allocation-estimate.v1"]
    project_id: Id
    scope: Literal["attempt", "run_storage"]
    authorization_ref: Ref
    plan_refs: Annotated[tuple[Ref, ...], BeforeValidator(_array)]
    config_refs: Annotated[tuple[Ref, ...], BeforeValidator(_array)]
    resource_policy_ref: Ref
    funded_from: Instant
    funded_until: Instant
    ceiling_usd: Money

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        refs = (
            self.authorization_ref,
            self.resource_policy_ref,
            *self.plan_refs,
            *self.config_refs,
        )
        if (
            not self.plan_refs
            or not self.config_refs
            or len({ref.digest for ref in self.plan_refs}) != len(self.plan_refs)
            or len({ref.digest for ref in self.config_refs}) != len(self.config_refs)
            or any(ref.project_id != self.project_id for ref in refs)
            or self.authorization_ref.artifact_schema != "cf.run-authorization.v1"
            or self.resource_policy_ref.artifact_schema != "cf.local-resource-policy.v1"
            or any(ref.artifact_schema != "cf.execution-plan.v1" for ref in self.plan_refs)
            or any(
                ref.artifact_schema != "cf.local-execution-config.v1" for ref in self.config_refs
            )
            or self.funded_from >= self.funded_until
            or Decimal(self.ceiling_usd) <= 0
        ):
            raise ValueError("invalid local allocation estimate")
        return self


@dataclass(frozen=True)
class LocalPlanPin:
    ref: Ref
    plan: ExecutionPlan
    config_ref: Ref
    config: LocalExecutionConfig

    def __post_init__(self) -> None:
        if (
            type(self.plan) is not ExecutionPlan
            or type(self.config) is not LocalExecutionConfig
            or type(self.ref) is not Ref
            or type(self.config_ref) is not Ref
            or self.ref.digest != hashlib.sha256(encoded(self.plan)).hexdigest()
            or self.ref.size_bytes != len(encoded(self.plan))
            or self.config_ref.digest != hashlib.sha256(encoded(self.config)).hexdigest()
            or self.config_ref.size_bytes != len(encoded(self.config))
            or identity(self.plan.execution_config_ref) != identity(self.config_ref)
            or self.ref.project_id != self.plan.project_id
            or self.config_ref.project_id != self.plan.project_id
        ):
            raise ContractError("forbidden")


class LocalStagingSource:
    def __init__(
        self,
        store: ObjectStore,
        operator: AccessContext,
        allocator: LocalAllocator,
        plan: ExecutionPlan,
        grant: LocalWorkerGrant,
    ) -> None:
        from conscience_foundry.execution.local_executor import local_staged_refs

        if type(plan) is not ExecutionPlan or type(grant) is not LocalWorkerGrant:
            raise ContractError("forbidden")
        self.store, self.operator, self.allocator = store, operator, allocator
        self.allowed = local_staged_refs(plan)
        self.proof = LocalGrantProof(
            grant.project_id,
            grant.run_id,
            grant.plan_digest,
            grant.attempt_id,
            grant.destination_id,
            grant.expires_at,
            plan.input_refs,
            grant.output_scope,
            hashlib.sha256(grant.nonce.encode()).hexdigest(),
        )
        if (
            plan.project_id != grant.project_id
            or hashlib.sha256(encoded(plan)).hexdigest() != grant.plan_digest
        ):
            raise ContractError("forbidden")

    def _check(self, ref: Ref, context: AccessContext) -> None:
        if (
            type(ref) is not Ref
            or ref not in self.allowed
            or type(context) is not AccessContext
            or context.project_id != self.proof.project_id
            or context.actor_id != self.proof.attempt_id
            or context.scopes != frozenset({"read", "extract"})
        ):
            raise ContractError("forbidden")
        facts = self.allocator.local_grant(self.proof)
        if type(facts) is not LocalGrantFacts or facts != LocalGrantFacts(
            **self.proof.__dict__, scopes=frozenset({"read", "extract"})
        ):
            raise ContractError("forbidden")

    def open_verified(self, ref: Ref, context: AccessContext) -> BinaryIO:
        self._check(ref, context)
        return self.store.open_verified(ref, self.operator)

    def read_verified(self, ref: Ref, context: AccessContext, limit: int) -> VerifiedBytes:
        self._check(ref, context)
        return self.store.read_verified(ref, self.operator, limit)

    def put_verified(self, stream: BinaryIO, expected: Ref, context: AccessContext) -> Ref:
        raise ContractError("forbidden")


class LocalRecoveryReader:
    """Read only the independently verified retained result closure for one attempt."""

    def __init__(
        self,
        *,
        allocator: LocalAllocator,
        root: Path,
        grant: LocalWorkerGrant,
        plan: ExecutionPlan,
        operator: AccessContext,
        limits_by_schema: Mapping[str, ContractLimits],
    ) -> None:
        from conscience_foundry.contracts.registry import validate_artifact
        from conscience_foundry.execution.staged_import import _ceiling, _limits
        from conscience_foundry.release.edges import edge_roles
        from conscience_foundry.storage.local_attempt import LocalAttemptStore, read_local_result

        if (
            type(grant) is not LocalWorkerGrant
            or type(plan) is not ExecutionPlan
            or type(operator) is not AccessContext
            or operator.project_id != grant.project_id
            or plan.project_id != grant.project_id
            or plan.run_id != grant.run_id
            or hashlib.sha256(encoded(plan)).hexdigest() != grant.plan_digest
        ):
            raise ContractError("forbidden")
        self.allocator, self.root, self.grant, self.operator = allocator, root, grant, operator
        self.proof = LocalGrantProof(
            grant.project_id,
            grant.run_id,
            grant.plan_digest,
            grant.attempt_id,
            grant.destination_id,
            grant.expires_at,
            plan.input_refs,
            grant.output_scope,
            hashlib.sha256(grant.nonce.encode()).hexdigest(),
        )
        self.limits = limits_by_schema
        self.allowed: list[Ref] = []
        self.view = object.__new__(LocalAttemptStore)
        self.view.root, self.view.project_id, self.view.attempt_id, self.view.grant = (
            root,
            grant.project_id,
            grant.attempt_id,
            grant,
        )
        with allocator.recovery_read_permit(self.proof, operator.actor_id):
            found = read_local_result(root, grant)
        if found is None:
            raise ContractError("artifact_missing")
        result, manifest_ref = found
        if (result.project_id, result.plan_id, result.attempt_id, result.operation_key) != (
            plan.project_id,
            plan.plan_id,
            grant.attempt_id,
            plan.operation_key,
        ):
            raise ContractError("forbidden")
        bound = _limits(limits_by_schema, "cf.result.v1")
        total = 0
        active: list[Ref] = []

        def visit(ref: Ref) -> None:
            nonlocal total
            if ref in active:
                raise ContractError("result_incomplete")
            if ref in self.allowed:
                return
            if len(self.allowed) + len(active) >= bound.max_array_items:
                raise ContractError("limit_exceeded")
            total += ref.size_bytes
            if total > bound.max_output_bytes:
                raise ContractError("limit_exceeded")
            data = self._read(ref, _ceiling(limits_by_schema, ref))
            value = validate_artifact(ref, data, limits_by_schema=limits_by_schema)
            active.append(ref)
            for edge in edge_roles(ref.artifact_schema, value):
                if edge.role == "content":
                    visit(edge.ref)
            active.pop()
            self.allowed.append(ref)

        for output in result.outputs:
            visit(output)
        visit(manifest_ref)

    def _read(self, ref: Ref, limit: int) -> bytes:
        if type(limit) is not int or limit <= 0 or ref.size_bytes > limit:
            raise ContractError("limit_exceeded")
        with self.allocator.recovery_read_permit(self.proof, self.operator.actor_id, ref):
            with self.view._directory() as directory:
                with self.view._snapshot(directory, "object-" + ref.digest, ref) as stream:
                    return stream.read()

    def read_verified(self, ref: Ref, context: AccessContext, limit: int) -> VerifiedBytes:
        if context != self.operator or type(ref) is not Ref or ref not in self.allowed:
            raise ContractError("forbidden")
        return VerifiedBytes(self._read(ref, limit), ref.digest)

    def open_verified(self, ref: Ref, context: AccessContext) -> BinaryIO:
        return io.BytesIO(self.read_verified(ref, context, ref.size_bytes).data)

    def put_verified(self, stream: BinaryIO, expected: Ref, context: AccessContext) -> Ref:
        raise ContractError("forbidden")


class LocalProcessObservation(WireModel):
    schema_version: Literal["cf.local-process-observation.v1"]
    attempt_id: Id
    action: Literal["observe", "cancel"]
    observed_state: Literal[
        "running", "succeeded", "failed", "cancelled", "cancel_requested", "unknown_outcome"
    ]


class LocalEvidenceWriter:
    def __init__(
        self,
        *,
        guard: "LocalCommittedGuard",
        allocator: LocalAllocator,
        executor: object,
        operator: AccessContext,
    ) -> None:
        self.guard, self.allocator, self.executor, self.operator = (
            guard,
            allocator,
            executor,
            operator,
        )

    def __call__(self, attempt: StageAttempt, schema: str, data: bytes) -> Ref:
        from conscience_foundry.execution.local_executor import LocalExecutor

        if (
            type(attempt) is not StageAttempt
            or type(self.executor) is not LocalExecutor
            or type(self.operator) is not AccessContext
            or schema != "cf.local-process-observation.v1"
            or type(data) is not bytes
        ):
            raise ContractError("forbidden")
        bound = self.guard.control.limits_by_schema.get("cf.stage-attempt.v1")
        if type(bound) is not ContractLimits:
            raise ContractError("limits_missing")
        observation = LocalProcessObservation.from_wire(data, bound)
        canonical = json.dumps(
            observation.model_dump(mode="json", by_alias=True),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        if data != canonical or observation.attempt_id != attempt.attempt_id:
            raise ContractError("forbidden")
        digest = hashlib.sha256(data).hexdigest()
        ref = Ref(
            schema_version="cf.artifact-ref.v1",
            project_id=attempt.project_id,
            digest=digest,
            size_bytes=len(data),
            media_type="application/json",
            artifact_schema=schema,
            locations=(
                ArtifactLocation(
                    store_id=self.allocator.operator_store_id,
                    object_key=f"sha256/{digest[:2]}/{digest}",
                ),
            ),
        )
        with self.guard.evidence(attempt) as facts:
            if (
                facts.actor_id != self.operator.actor_id
                or facts.project_id != self.operator.project_id
            ):
                raise ContractError("forbidden")
            inspection = (
                self.executor._inspect(attempt)
                if observation.action == "observe"
                else self.executor._inspect_cancel(attempt)
            )
            if inspection.state != observation.observed_state:
                raise ContractError("forbidden")
            self.allocator.import_writer(
                facts.project_id, facts.run_id, facts.attempt_id
            ).put_verified(io.BytesIO(data), ref, self.operator)
        return ref


class LocalAllocationReceipt(WireModel):
    schema_version: Literal[
        "cfoundry.local-attempt-allocation.v1", "cfoundry.local-storage-allocation.v1"
    ]
    project_id: Id
    run_id: Id
    reservation_id: Id
    storage_reservation_id: Id
    attempt_id: Id
    authorization_ref: Ref
    plan_ref: Ref
    config_ref: Ref
    resource_policy_ref: Ref
    amount_usd: Money
    funded_from: Instant
    funded_until: Instant
    output_scope_digest: Digest
    nonce_digest: Digest
    process_id: str
    terminal_state: Literal["succeeded", "failed", "cancelled"]
    result_ref: Ref | None = Field(default=None, exclude_if=lambda value: value is None)


class LocalReceiptIssuer:
    def __init__(
        self,
        *,
        guard: "LocalCommittedGuard",
        allocator: LocalAllocator,
        executor: object,
        operator: AccessContext,
    ) -> None:
        self.guard, self.allocator, self.executor, self.operator = (
            guard,
            allocator,
            executor,
            operator,
        )

    def attempt_candidate(self, attempt: StageAttempt) -> Ref:
        return self._candidate(attempt, False)

    def storage_candidate(self, attempt: StageAttempt) -> Ref:
        return self._candidate(attempt, True)

    def _candidate(self, attempt: StageAttempt, storage: bool) -> Ref:
        from conscience_foundry.execution.local_executor import LocalExecutor, _grant, _read

        if (
            type(attempt) is not StageAttempt
            or type(self.executor) is not LocalExecutor
            or type(self.operator) is not AccessContext
        ):
            raise ContractError("forbidden")
        with self.guard.evidence(attempt) as facts:
            if (facts.actor_id, facts.project_id) != (
                self.operator.actor_id,
                self.operator.project_id,
            ):
                raise ContractError("forbidden")
            intent = _read(self.executor.journal_root / attempt.attempt_id, "intent.json")
            grant = _grant(intent["grant"])
            proof = LocalGrantProof(
                grant.project_id,
                grant.run_id,
                grant.plan_digest,
                grant.attempt_id,
                grant.destination_id,
                grant.expires_at,
                facts.input_refs,
                grant.output_scope,
                hashlib.sha256(grant.nonce.encode()).hexdigest(),
            )
            self.allocator.local_grant(proof)
            inspection = self.executor._inspect(attempt)
            if (
                inspection.state not in {"succeeded", "failed", "cancelled"}
                or inspection.state != attempt.state
                or inspection.confirmed_termination is not True
                or inspection.pid is None
                or (inspection.state == "cancelled" and inspection.result_ref is not None)
                or (inspection.state != "cancelled" and inspection.result_ref is None)
                or inspection.result_ref != attempt.result_manifest_ref
            ):
                raise ContractError("forbidden")
            policy = self.allocator.policy
            receipt = LocalAllocationReceipt(
                schema_version=(
                    "cfoundry.local-storage-allocation.v1"
                    if storage
                    else "cfoundry.local-attempt-allocation.v1"
                ),
                project_id=facts.project_id,
                run_id=facts.run_id,
                reservation_id=facts.storage_reservation_id if storage else facts.reservation_id,
                storage_reservation_id=facts.storage_reservation_id,
                attempt_id=facts.attempt_id,
                authorization_ref=facts.authorization_ref,
                plan_ref=facts.plan_ref,
                config_ref=facts.config_ref,
                resource_policy_ref=policy.resource_policy_ref,
                amount_usd=policy.storage_price_usd if storage else policy.attempt_price_usd,
                funded_from=policy.funded_from,
                funded_until=policy.funded_until,
                output_scope_digest=hashlib.sha256(facts.output_scope).hexdigest(),
                nonce_digest=proof.nonce_digest,
                process_id=inspection.pid,
                terminal_state=cast(Literal["succeeded", "failed", "cancelled"], inspection.state),
                **(
                    {"result_ref": inspection.result_ref}
                    if inspection.result_ref is not None
                    else {}
                ),
            )
            raw = encoded(receipt)
            digest = hashlib.sha256(raw).hexdigest()
            ref = Ref(
                schema_version="cf.artifact-ref.v1",
                project_id=facts.project_id,
                digest=digest,
                size_bytes=len(raw),
                media_type="application/json",
                artifact_schema=receipt.schema_version,
                locations=(
                    ArtifactLocation(
                        store_id=self.allocator.operator_store_id,
                        object_key=f"sha256/{digest[:2]}/{digest}",
                    ),
                ),
            )
            self.allocator.import_writer(
                facts.project_id, facts.run_id, facts.attempt_id
            ).put_verified(io.BytesIO(raw), ref, self.operator)
            return ref


class LocalClosureGuard:
    def __init__(
        self, *, ledger: Ledger, control: ControlContext, allocator: LocalAllocator, candidate: Ref
    ) -> None:
        self.ledger, self.control, self.allocator, self.candidate = (
            ledger,
            control,
            allocator,
            candidate,
        )

    @contextmanager
    def __call__(self, project_id: Id, run_id: Id) -> Iterator[Callable[[tuple[Ref, ...]], bool]]:
        from conscience_foundry.execution.evidence import read_artifact
        from conscience_foundry.execution.local_allocation import _directory, _read
        from conscience_foundry.storage.local_attempt import LocalAttemptStore

        if (
            project_id != self.control.access.project_id
            or self.candidate.project_id != project_id
            or self.candidate.artifact_schema != "cfoundry.local-storage-allocation.v1"
        ):
            raise ContractError("forbidden")
        with self.ledger.transaction() as tx:
            tx.lock(project_id, run_id)
            _, receipt = read_artifact(self.candidate, self.control, evidence=True)
            if (
                type(receipt) is not LocalAllocationReceipt
                or receipt.project_id != project_id
                or receipt.run_id != run_id
                or receipt.schema_version != self.candidate.artifact_schema
            ):
                raise ContractError("forbidden")
            rows = tx.connection.execute(
                sql.SQL(
                    "SELECT a.attempt_id::text,a.reservation_id::text,a.state,"
                    "r.final_billing,r.outstanding_usd "
                    "FROM {} a JOIN {} r ON (r.project_id,r.run_id,r.reservation_id)="
                    "(a.project_id,a.run_id,a.reservation_id) WHERE a.project_id=%s AND a.run_id=%s"
                ).format(tx.table("attempts"), tx.table("reservations")),
                (project_id, run_id),
            ).fetchall()
            storage = tx.connection.execute(
                sql.SQL(
                    "SELECT r.reservation_id::text,a.authorization_ref FROM {} r JOIN {} a "
                    "ON (r.project_id,r.run_id,r.authorization_id)="
                    "(a.project_id,a.run_id,a.authorization_id) "
                    "WHERE r.project_id=%s AND r.run_id=%s AND r.scope='run_storage' "
                    "AND NOT r.final_billing AND r.outstanding_usd>0"
                ).format(tx.table("reservations"), tx.table("authorizations")),
                (project_id, run_id),
            ).fetchall()
            if (
                not rows
                or len(storage) != 1
                or storage[0][0] != receipt.reservation_id
                or Ref.model_validate(storage[0][1]) != receipt.authorization_ref
                or any(
                    row[2] not in {"succeeded", "failed", "cancelled"}
                    or row[3] is not True
                    or row[4] != 0
                    for row in rows
                )
            ):
                raise ContractError("forbidden")
            expected_attempts = {row[0]: row[1] for row in rows}

            def verify(refs: tuple[Ref, ...]) -> bool:
                if self.candidate not in refs:
                    return False
                fd = _directory(self.allocator.root)
                try:
                    state = json.loads(_read(fd, "allocator.json"))
                    self.allocator._check(state, fd)
                    run = state["runs"].get(run_id)
                    if type(run) is not dict or set(run["attempts"]) != set(expected_attempts):
                        return False
                    for attempt_id, record in run["attempts"].items():
                        facts = self.allocator._record_facts(record)
                        if (
                            facts.reservation_id != expected_attempts[attempt_id]
                            or facts.storage_reservation_id != receipt.reservation_id
                            or facts.authorization_ref != receipt.authorization_ref
                            or not callable(self.allocator.policy_reader)
                            or self.allocator.policy_reader(
                                project_id, facts.source_id, facts.actor_id
                            )
                            is not None
                        ):
                            return False
                    for item in run["refs"].values():
                        ref = Ref.model_validate(item["identity"]["ref"])
                        if item["status"] != "durable":
                            return False
                        if item["identity"]["kind"] == "operator":
                            with self.allocator.store.open_verified(ref, self.control.access):
                                pass
                            continue
                        attempt_id = item["identity"]["attempt_id"]
                        facts = self.allocator._record_facts(run["attempts"][attempt_id])
                        scope = json.loads(facts.output_scope)
                        grant = LocalWorkerGrant(
                            project_id,
                            run_id,
                            facts.plan_ref.digest,
                            attempt_id,
                            scope["destination_id"],
                            facts.expires_at,
                            facts.output_scope,
                            "retained",
                        )
                        view = object.__new__(LocalAttemptStore)
                        view.root, view.project_id, view.attempt_id, view.grant = (
                            facts.attempt_root,
                            project_id,
                            attempt_id,
                            grant,
                        )
                        with view._directory() as directory:
                            names = (
                                ("lease", "result")
                                if ref.artifact_schema == "cf.local-control.v1"
                                else ("object-" + ref.digest,)
                            )
                            valid = False
                            for name in names:
                                try:
                                    with view._snapshot(directory, name, ref):
                                        valid = True
                                        break
                                except ContractError:
                                    continue
                            if not valid:
                                return False
                    return True
                finally:
                    os.close(fd)

            yield verify


class LocalControlAuthority:
    def __init__(
        self,
        *,
        policy: LocalAllocationPolicy,
        estimates: tuple[tuple[Ref, bytes], ...],
        plans: tuple[LocalPlanPin, ...],
        limits_by_schema: Mapping[str, ContractLimits],
        allocator: LocalAllocator | None = None,
        executor: object | None = None,
        delegate: object | None = None,
        operator: AccessContext | None = None,
    ) -> None:
        required = (
            "cfoundry.local-allocation-estimate.v1",
            "cf.local-process-observation.v1",
            "cfoundry.local-attempt-allocation.v1",
            "cfoundry.local-storage-allocation.v1",
            "cf.budget-event.v1",
        )
        if type(policy) is not LocalAllocationPolicy or any(
            type(limits_by_schema.get(schema)) is not ContractLimits for schema in required
        ):
            raise ContractError("invalid_schema")
        if type(estimates) is not tuple or type(plans) is not tuple:
            raise ContractError("invalid_schema")
        self.policy = policy
        self.limits_by_schema = MappingProxyType({key: limits_by_schema[key] for key in required})
        self.allocator, self.executor, self.delegate = allocator, executor, delegate
        self.operator = operator
        self.plans = {pin.ref.digest: pin for pin in plans if type(pin) is LocalPlanPin}
        if len(self.plans) != len(plans):
            raise ContractError("invalid_schema")
        parsed: dict[str, tuple[Ref, bytes, LocalAllocationEstimate]] = {}
        for ref, raw in estimates:
            if (
                type(ref) is not Ref
                or type(raw) is not bytes
                or ref.artifact_schema != "cfoundry.local-allocation-estimate.v1"
                or ref.digest != hashlib.sha256(raw).hexdigest()
                or ref.size_bytes != len(raw)
            ):
                raise ContractError("forbidden")
            quote = LocalAllocationEstimate.from_wire(
                raw, self.limits_by_schema["cfoundry.local-allocation-estimate.v1"]
            )
            if quote.scope in parsed or ref.project_id != quote.project_id:
                raise ContractError("forbidden")
            parsed[quote.scope] = (ref, raw, quote)
        self.estimates = MappingProxyType(parsed)
        local_decoders = {
            "cfoundry.local-allocation-estimate.v1": LocalAllocationEstimate.from_wire,
            "cf.local-process-observation.v1": LocalProcessObservation.from_wire,
            "cfoundry.local-attempt-allocation.v1": LocalAllocationReceipt.from_wire,
            "cfoundry.local-storage-allocation.v1": LocalAllocationReceipt.from_wire,
        }
        delegated = getattr(delegate, "decoders", {}) if delegate is not None else {}
        if not isinstance(delegated, Mapping) or set(delegated) & set(local_decoders):
            raise ContractError("forbidden")
        self.decoders = MappingProxyType({**delegated, **local_decoders})

    def local_grant(self, proof: LocalGrantProof) -> LocalGrantFacts:
        if type(self.allocator) is not LocalAllocator or type(proof) is not LocalGrantProof:
            raise ContractError("forbidden")
        facts = self.allocator.local_grant(proof)
        if type(facts) is not LocalGrantFacts:
            raise ContractError("forbidden")
        return facts

    def control(self, proof: ControlProof) -> ControlFacts:
        if type(proof) is not ControlProof or proof.evidence_ref.artifact_schema in {
            "cfoundry.local-allocation-estimate.v1",
            "cf.local-process-observation.v1",
            "cfoundry.local-attempt-allocation.v1",
            "cfoundry.local-storage-allocation.v1",
        }:
            raise ContractError("forbidden")
        method = getattr(self.delegate, "control", None)
        if not callable(method):
            raise ContractError("forbidden")
        return cast(ControlFacts, method(proof))

    def transport(self, proof: TransportProof) -> TransportFacts:
        method = getattr(self.delegate, "transport", None)
        if type(proof) is not TransportProof or not callable(method):
            raise ContractError("forbidden")
        return cast(TransportFacts, method(proof))

    def observation(self, proof: ObservationProof) -> ObservationFacts:
        from conscience_foundry.execution.local_executor import LocalExecutor, _grant, _read
        from conscience_foundry.execution.ports import ObservationFacts, ObservationProof

        if type(proof) is not ObservationProof:
            raise ContractError("forbidden")
        if proof.evidence_ref.artifact_schema != "cf.local-process-observation.v1":
            method = getattr(self.delegate, "observation", None)
            if not callable(method):
                raise ContractError("forbidden")
            return cast(ObservationFacts, method(proof))
        if (
            type(self.allocator) is not LocalAllocator
            or type(self.executor) is not LocalExecutor
            or type(self.operator) is not AccessContext
            or proof.evidence_ref != proof.observation.evidence
            or proof.binding.evidence_digest != proof.evidence_ref.digest
            or proof.binding.request_digest != hashlib.sha256(proof.request_bytes).hexdigest()
            or proof.evidence_ref.digest != hashlib.sha256(proof.evidence_bytes).hexdigest()
            or proof.evidence_ref.size_bytes != len(proof.evidence_bytes)
            or proof.binding.project_id != proof.attempt.project_id
            or proof.binding.attempt_id != proof.attempt.attempt_id
            or proof.binding.reservation_id != proof.attempt.reservation_id
        ):
            raise ContractError("forbidden")
        record = LocalProcessObservation.from_wire(
            proof.evidence_bytes, self.limits_by_schema["cf.local-process-observation.v1"]
        )
        canonical = json.dumps(
            record.model_dump(mode="json", by_alias=True), sort_keys=True, separators=(",", ":")
        ).encode()
        pin = self.plans.get(proof.binding.plan_digest or "")
        if (
            canonical != proof.evidence_bytes
            or record.attempt_id != proof.attempt.attempt_id
            or pin is None
            or pin.plan.project_id != proof.binding.project_id
            or pin.plan.run_id != proof.binding.run_id
            or proof.binding.authorization_digest is None
        ):
            raise ContractError("forbidden")
        intent = _read(self.executor.journal_root / proof.attempt.attempt_id, "intent.json")
        grant = _grant(intent["grant"])
        grant_proof = LocalGrantProof(
            grant.project_id,
            grant.run_id,
            grant.plan_digest,
            grant.attempt_id,
            grant.destination_id,
            grant.expires_at,
            pin.plan.input_refs,
            grant.output_scope,
            hashlib.sha256(grant.nonce.encode()).hexdigest(),
        )
        with self.allocator.recovery_read_permit(
            grant_proof,
            self.operator.actor_id,
            authorization_digest=proof.binding.authorization_digest,
        ):
            inspected = (
                self.executor._inspect(proof.attempt)
                if record.action == "observe"
                else self.executor._inspect_cancel(proof.attempt)
            )
            if (
                inspected.state != record.observed_state
                or inspected.state != proof.observation.state
                or inspected.result_ref != proof.observation.result_ref
                or grant.plan_digest != pin.ref.digest
                or grant.project_id != proof.binding.project_id
                or grant.run_id != proof.binding.run_id
                or grant.attempt_id != proof.attempt.attempt_id
            ):
                raise ContractError("forbidden")
            pid = inspected.pid
            if inspected.state == "unknown_outcome" and pid is None:
                pid = self.executor._historical_pid(proof.attempt)
            return ObservationFacts(
                proof.binding,
                pid,
                inspected.state,
                inspected.result_ref.digest if inspected.result_ref else None,
                False,
                inspected.confirmed_termination,
            )

    def budget(self, proof: BudgetProof) -> object:
        if type(proof) is not BudgetProof:
            raise ContractError("forbidden")
        claim = proof.claim
        local_schemas = {
            "cfoundry.local-allocation-estimate.v1",
            "cf.local-process-observation.v1",
            "cfoundry.local-attempt-allocation.v1",
            "cfoundry.local-storage-allocation.v1",
        }
        if claim.evidence_ref.artifact_schema not in local_schemas:
            method = getattr(self.delegate, "budget", None)
            if not callable(method):
                raise ContractError("forbidden")
            return method(proof)
        if (
            claim.purpose == "record_usage"
            and claim.evidence_ref.artifact_schema == "cf.local-process-observation.v1"
        ):
            return self._usage(proof)
        if claim.purpose == "final_billing" and claim.evidence_ref.artifact_schema in {
            "cfoundry.local-attempt-allocation.v1",
            "cfoundry.local-storage-allocation.v1",
        }:
            return self._receipt(proof)
        scope = {"reserve_attempt": "attempt", "reserve_storage": "run_storage"}.get(claim.purpose)
        if scope is None or scope not in self.estimates:
            raise ContractError("forbidden")
        if type(self.allocator) is not LocalAllocator or self.allocator.policy != self.policy:
            raise ContractError("forbidden")
        self.allocator.check_new_reservation(
            claim.project_id,
            claim.run_id,
            scope=scope,
            reservation_id=claim.reservation_id,
            attempt_id=claim.attempt_id,
            authorization_ref=claim.authorization_ref,
            plan_ref=claim.plan_ref,
            config_ref=claim.execution_config_ref,
        )
        ref, raw, quote = self.estimates[scope]
        if (
            proof.binding != EvidenceBinding.from_budget(claim)
            or identity(claim.evidence_ref) != identity(ref)
            or proof.evidence_bytes != raw
            or hashlib.sha256(claim.request_bytes).hexdigest() != claim.request_digest
            or identity(claim.authorization_ref) != identity(quote.authorization_ref)
            or hashlib.sha256(encoded(proof.authorization)).hexdigest()
            != quote.authorization_ref.digest
            or (proof.authorization.project_id, proof.authorization.run_id)
            != (claim.project_id, claim.run_id)
            or quote.project_id != claim.project_id
            or identity(quote.resource_policy_ref) != identity(self.policy.resource_policy_ref)
            or (quote.funded_from, quote.funded_until)
            != (self.policy.funded_from, self.policy.funded_until)
            or not quote.funded_from <= claim.now < quote.funded_until
            or Decimal(quote.ceiling_usd)
            != Decimal(
                self.policy.attempt_price_usd
                if scope == "attempt"
                else self.policy.storage_price_usd
            )
        ):
            raise ContractError("forbidden")
        if scope == "attempt":
            if (
                claim.plan_ref is None
                or identity(claim.plan_ref) not in {identity(ref) for ref in quote.plan_refs}
                or not {ref.digest for ref in quote.plan_refs}
                <= set(proof.authorization.allowed_plan_digests)
            ):
                raise ContractError("forbidden")
        elif {ref.digest for ref in quote.plan_refs} != set(
            proof.authorization.allowed_plan_digests
        ):
            raise ContractError("forbidden")
        pins: list[LocalPlanPin] = []
        for plan_ref in quote.plan_refs:
            pin = self.plans.get(plan_ref.digest)
            if (
                pin is None
                or identity(pin.ref) != identity(plan_ref)
                or identity(pin.config.resource_policy_ref) != identity(quote.resource_policy_ref)
            ):
                raise ContractError("forbidden")
            pins.append(pin)
        if {identity(pin.config_ref) for pin in pins} != {
            identity(ref) for ref in quote.config_refs
        }:
            raise ContractError("forbidden")
        if scope == "attempt":
            assert claim.plan_ref is not None
            pins = [pin for pin in pins if identity(pin.ref) == identity(claim.plan_ref)]
            if (
                len(pins) != 1
                or claim.execution_config_ref is None
                or identity(pins[0].config_ref) != identity(claim.execution_config_ref)
                or claim.request_bytes != encoded(pins[0].plan)
            ):
                raise ContractError("forbidden")
        else:
            expected_request = json.dumps(
                {
                    "projectId": claim.project_id,
                    "runId": claim.run_id,
                    "authorizationDigest": claim.authorization_ref.digest,
                    "currency": "USD",
                    "amountUsd": quote.ceiling_usd,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            if claim.request_bytes != expected_request:
                raise ContractError("forbidden")
        if any(
            not any(
                p.ref == item.ref and p.plan == item.model and p.config == item.config for p in pins
            )
            for item in proof.plans
        ):
            raise ContractError("forbidden")
        capabilities = tuple(
            CapabilityFacts(
                p.plan.execution_config_ref,
                p.config.tariff_ref,
                p.config.resource_policy_ref,
                p.config.image_digest,
                p.config.local_destination_id,
                p.plan.resources,
            )
            for p in pins
        )
        categories: tuple[
            Literal["cpu", "ram", "runtime", "transfer", "storage", "region"], ...
        ] = ("cpu", "ram", "runtime", "transfer", "storage", "region")
        allocations = (
            tuple(
                CostAllocation(category, quote.ceiling_usd if category == "runtime" else "0")
                for category in categories
            )
            if scope == "attempt"
            else (CostAllocation("storage", quote.ceiling_usd),)
        )
        return EstimateFacts(
            proof.binding,
            quote.ceiling_usd,
            "USD",
            tuple(pin.ref for pin in pins),
            capabilities,
            allocations,
            quote.funded_from,
            quote.funded_until,
            None,
        )

    def _usage(self, proof: BudgetProof) -> BillingFacts:
        from conscience_foundry.contracts.accounting import BudgetEvent
        from conscience_foundry.execution.local_executor import LocalExecutor, _grant, _read
        from conscience_foundry.execution.ports import BillingFacts

        claim = proof.claim
        if (
            type(self.allocator) is not LocalAllocator
            or type(self.executor) is not LocalExecutor
            or type(self.operator) is not AccessContext
            or proof.binding != EvidenceBinding.from_budget(claim)
            or hashlib.sha256(claim.request_bytes).hexdigest() != claim.request_digest
            or hashlib.sha256(proof.evidence_bytes).hexdigest() != claim.evidence_ref.digest
            or len(proof.evidence_bytes) != claim.evidence_ref.size_bytes
            or hashlib.sha256(encoded(proof.authorization)).hexdigest()
            != claim.authorization_ref.digest
            or claim.attempt_id is None
            or claim.reservation_id is None
            or claim.plan_ref is None
        ):
            raise ContractError("forbidden")
        event = BudgetEvent.from_wire(
            claim.request_bytes, self.limits_by_schema["cf.budget-event.v1"]
        )
        observation = LocalProcessObservation.from_wire(
            proof.evidence_bytes, self.limits_by_schema["cf.local-process-observation.v1"]
        )
        pin = self.plans.get(claim.plan_ref.digest)
        if (
            encoded(event) != claim.request_bytes
            or event.event_type != "record_usage"
            or event.cost_status != "unknown"
            or event.amount_usd is not None
            or event.scope != "attempt"
            or event.evidence_ref != claim.evidence_ref
            or (event.project_id, event.run_id, event.attempt_id, event.reservation_id)
            != (claim.project_id, claim.run_id, claim.attempt_id, claim.reservation_id)
            or observation.action != "observe"
            or observation.attempt_id != claim.attempt_id
            or pin is None
            or identity(pin.ref) != identity(claim.plan_ref)
            or pin.plan.run_id != claim.run_id
            or pin.plan.project_id != claim.project_id
            or proof.authorization.actor_id != self.operator.actor_id
            or proof.authorization.project_id != claim.project_id
            or proof.authorization.run_id != claim.run_id
        ):
            raise ContractError("forbidden")
        intent = _read(self.executor.journal_root / claim.attempt_id, "intent.json")
        attempt = StageAttempt.model_validate(intent["attempt"])
        grant = _grant(intent["grant"])
        if (
            attempt.attempt_id != claim.attempt_id
            or attempt.project_id != claim.project_id
            or attempt.reservation_id != claim.reservation_id
            or grant.plan_digest != pin.ref.digest
            or grant.project_id != claim.project_id
            or grant.run_id != claim.run_id
            or grant.attempt_id != claim.attempt_id
        ):
            raise ContractError("forbidden")
        grant_proof = LocalGrantProof(
            grant.project_id,
            grant.run_id,
            grant.plan_digest,
            grant.attempt_id,
            grant.destination_id,
            grant.expires_at,
            pin.plan.input_refs,
            grant.output_scope,
            hashlib.sha256(grant.nonce.encode()).hexdigest(),
        )
        with self.allocator.recovery_read_permit(
            grant_proof, self.operator.actor_id, authorization_digest=claim.authorization_ref.digest
        ):
            inspected = self.executor._inspect(attempt)
            if inspected.state != observation.observed_state:
                raise ContractError("forbidden")
            return BillingFacts(proof.binding, "unknown", None, False, False, False)

    def _receipt(self, proof: BudgetProof) -> BillingFacts:
        # Final evidence always independently requires closed storage.
        return self._receipt_checked(proof, require_closed=True)

    def preclose_storage_candidate(self, proof: BudgetProof) -> BillingFacts:
        """Pure validation of an already durable storage candidate before closure."""
        if proof.claim.evidence_ref.artifact_schema != "cfoundry.local-storage-allocation.v1":
            raise ContractError("forbidden")
        return self._receipt_checked(proof, require_closed=False)

    def _receipt_checked(self, proof: BudgetProof, *, require_closed: bool) -> BillingFacts:
        from conscience_foundry.contracts.accounting import BudgetEvent
        from conscience_foundry.execution.local_executor import LocalExecutor, _grant, _read
        from conscience_foundry.execution.ports import BillingFacts

        claim = proof.claim
        if (
            type(self.allocator) is not LocalAllocator
            or type(self.executor) is not LocalExecutor
            or type(self.operator) is not AccessContext
            or proof.binding != EvidenceBinding.from_budget(claim)
            or hashlib.sha256(claim.request_bytes).hexdigest() != claim.request_digest
            or hashlib.sha256(proof.evidence_bytes).hexdigest() != claim.evidence_ref.digest
            or len(proof.evidence_bytes) != claim.evidence_ref.size_bytes
            or hashlib.sha256(encoded(proof.authorization)).hexdigest()
            != claim.authorization_ref.digest
        ):
            raise ContractError("forbidden")
        if claim.evidence_ref.artifact_schema not in (
            "cfoundry.local-attempt-allocation.v1",
            "cfoundry.local-storage-allocation.v1",
        ):
            raise ContractError("forbidden")
        receipt = LocalAllocationReceipt.from_wire(
            proof.evidence_bytes, self.limits_by_schema[claim.evidence_ref.artifact_schema]
        )
        event = BudgetEvent.from_wire(
            claim.request_bytes, self.limits_by_schema["cf.budget-event.v1"]
        )
        storage = receipt.schema_version == "cfoundry.local-storage-allocation.v1"
        pin = self.plans.get(receipt.plan_ref.digest)
        expected_price = self.policy.storage_price_usd if storage else self.policy.attempt_price_usd
        if (
            encoded(receipt) != proof.evidence_bytes
            or encoded(event) != claim.request_bytes
            or receipt.schema_version != claim.evidence_ref.artifact_schema
            or identity(event.evidence_ref) != identity(claim.evidence_ref)
            or event.event_type != "settle"
            or event.cost_status != "actual"
            or event.amount_usd != expected_price
            or receipt.amount_usd != expected_price
            or event.scope != ("run_storage" if storage else "attempt")
            or (event.project_id, event.run_id, event.reservation_id, event.attempt_id)
            != (claim.project_id, claim.run_id, claim.reservation_id, claim.attempt_id)
            or (receipt.project_id, receipt.run_id, receipt.reservation_id)
            != (claim.project_id, claim.run_id, claim.reservation_id)
            or (not storage and receipt.attempt_id != claim.attempt_id)
            or (storage and claim.attempt_id is not None)
            or receipt.authorization_ref != claim.authorization_ref
            or receipt.resource_policy_ref != self.policy.resource_policy_ref
            or (receipt.funded_from, receipt.funded_until)
            != (self.policy.funded_from, self.policy.funded_until)
            or pin is None
            or pin.ref != receipt.plan_ref
            or pin.config_ref != receipt.config_ref
            or (
                not storage
                and (claim.plan_ref is None or identity(claim.plan_ref) != identity(pin.ref))
            )
            or proof.authorization.actor_id != self.operator.actor_id
        ):
            raise ContractError("forbidden")
        intent = _read(self.executor.journal_root / receipt.attempt_id, "intent.json")
        attempt = StageAttempt.model_validate(intent["attempt"])
        grant = _grant(intent["grant"])
        grant_proof = LocalGrantProof(
            grant.project_id,
            grant.run_id,
            grant.plan_digest,
            grant.attempt_id,
            grant.destination_id,
            grant.expires_at,
            pin.plan.input_refs,
            grant.output_scope,
            hashlib.sha256(grant.nonce.encode()).hexdigest(),
        )
        with self.allocator.recovery_read_permit(
            grant_proof,
            self.operator.actor_id,
            authorization_digest=claim.authorization_ref.digest,
            operator_ref=claim.evidence_ref,
            require_closed=storage and require_closed,
        ) as facts:
            inspection = self.executor._inspect(attempt)
            if (
                inspection.state != receipt.terminal_state
                or not inspection.confirmed_termination
                or inspection.pid != receipt.process_id
                or inspection.result_ref != receipt.result_ref
                or (inspection.state == "cancelled" and inspection.result_ref is not None)
                or (inspection.state in {"succeeded", "failed"} and inspection.result_ref is None)
                or facts.attempt_id != receipt.attempt_id
                or facts.reservation_id
                != (attempt.reservation_id if storage else receipt.reservation_id)
                or facts.storage_reservation_id != receipt.storage_reservation_id
                or (storage and facts.storage_reservation_id != receipt.reservation_id)
                or facts.plan_ref != receipt.plan_ref
                or facts.config_ref != receipt.config_ref
                or hashlib.sha256(facts.output_scope).hexdigest() != receipt.output_scope_digest
                or grant_proof.nonce_digest != receipt.nonce_digest
            ):
                raise ContractError("forbidden")
            return BillingFacts(proof.binding, "actual", expected_price, True, True, False)


class LocalCommittedGuard:
    def __init__(
        self,
        ledger: Ledger,
        control: ControlContext,
        *,
        pin: LocalPlanPin,
        authorization_ref: Ref,
        attempt_root: Path,
    ) -> None:
        self.ledger, self.control = ledger, control
        self.pin, self.authorization_ref, self.attempt_root = pin, authorization_ref, attempt_root

    def __call__(
        self, project_id: Id, run_id: Id, attempt_id: Id
    ) -> AbstractContextManager[LocalActivationFacts]:
        return self._guard(project_id, run_id, attempt_id, None)

    def evidence(self, attempt: StageAttempt) -> AbstractContextManager[LocalActivationFacts]:
        if type(attempt) is not StageAttempt:
            raise ContractError("forbidden")
        return self._guard(attempt.project_id, self.pin.plan.run_id, attempt.attempt_id, attempt)

    @contextmanager
    def _guard(
        self, project_id: Id, run_id: Id, attempt_id: Id, expected: StageAttempt | None
    ) -> Iterator[LocalActivationFacts]:
        from conscience_foundry.execution.control import _load
        from conscience_foundry.execution.evidence import clock, verified_plan
        from conscience_foundry.storage.local_attempt import local_output_scope

        if (project_id, run_id) != (self.pin.plan.project_id, self.pin.plan.run_id):
            raise ContractError("forbidden")
        try:
            with self.ledger.transaction() as tx:
                tx.lock(project_id, run_id)
                attempt, actual_run, plan_ref, auth_ref = _load(tx, attempt_id, self.control)
                tx.lock(project_id, run_id, attempt.operation_key)
                attempt, actual_run, plan_ref, auth_ref = _load(tx, attempt_id, self.control)
                if (
                    actual_run != run_id
                    or (
                        expected is None
                        and (attempt.state != "dispatching" or attempt.remote_call_id is not None)
                    )
                    or (
                        expected is not None
                        and (attempt != expected or attempt.state in {"planned", "reserved"})
                    )
                    or identity(plan_ref) != identity(self.pin.ref)
                    or identity(auth_ref) != identity(self.authorization_ref)
                ):
                    raise ContractError("forbidden")
                verified = verified_plan(plan_ref, auth_ref, tx, self.control, spending=True)
                if (
                    verified.model != self.pin.plan
                    or verified.config != self.pin.config
                    or verified.authorization.actor_id != self.control.access.actor_id
                    or clock(self.control)
                    >= min(
                        verified.authorization.expires_at,
                        verified.model.expires_at,
                        verified.model.budget.valid_until,
                    )
                ):
                    raise ContractError("forbidden")
                run = tx.connection.execute(
                    sql.SQL(
                        "SELECT current_authorization_id::text,frozen FROM {} "
                        "WHERE project_id=%s AND run_id=%s"
                    ).format(tx.table("runs")),
                    (project_id, run_id),
                ).fetchone()
                if (
                    run is None
                    or run[0] != verified.authorization.authorization_id
                    or run[1]
                    or tx.get_pause("project", project_id, None).paused
                    or tx.get_pause("run", project_id, run_id).paused
                ):
                    raise ContractError("forbidden")
                rows = tx.connection.execute(
                    sql.SQL(
                        "SELECT reservation_id::text,scope,authorization_id::text,operation_key "
                        "FROM {} WHERE project_id=%s AND run_id=%s AND NOT final_billing "
                        "AND outstanding_usd>0 AND released_usd<reserved_usd "
                        "AND (reservation_id=%s OR scope='run_storage')"
                    ).format(tx.table("reservations")),
                    (project_id, run_id, attempt.reservation_id),
                ).fetchall()
                own = [row for row in rows if row[1] == "attempt"]
                storage = [row for row in rows if row[1] == "run_storage"]
                if (
                    len(own) != 1
                    or len(storage) != 1
                    or own[0][0] != attempt.reservation_id
                    or own[0][2] != verified.authorization.authorization_id
                    or own[0][3] != attempt.operation_key
                    or storage[0][2] != verified.authorization.authorization_id
                ):
                    raise ContractError("forbidden")
                held = tx.connection.execute(
                    sql.SQL("SELECT held FROM {} WHERE project_id=%s AND operation_key=%s").format(
                        tx.table("operations")
                    ),
                    (project_id, attempt.operation_key),
                ).fetchone()
                holds = tx.connection.execute(
                    sql.SQL(
                        "SELECT EXISTS(SELECT 1 FROM {} WHERE project_id=%s AND operation_key=%s)"
                    ).format(tx.table("integrity_holds")),
                    (project_id, attempt.operation_key),
                ).fetchone()
                withdrawn = tx.connection.execute(
                    sql.SQL(
                        "SELECT EXISTS(SELECT 1 FROM {} WHERE project_id=%s "
                        "AND asset_id=%s AND source_id=%s)"
                    ).format(tx.table("admission_withdrawals")),
                    (project_id, verified.source_asset.asset_id, verified.source_asset.source_id),
                ).fetchone()
                if (
                    held is None
                    or held[0]
                    or holds is None
                    or holds[0]
                    or withdrawn is None
                    or withdrawn[0]
                ):
                    raise ContractError("forbidden")
                scope = local_output_scope(
                    self.attempt_root,
                    destination_id=self.pin.config.local_destination_id,
                    project_id=project_id,
                    run_id=run_id,
                    attempt_id=attempt_id,
                    plan_digest=plan_ref.digest,
                )
                yield LocalActivationFacts(
                    project_id,
                    run_id,
                    attempt_id,
                    attempt.reservation_id,
                    storage[0][0],
                    auth_ref,
                    plan_ref,
                    verified.model.execution_config_ref,
                    verified.source_asset.source_id,
                    verified.authorization.actor_id,
                    verified.model.input_refs,
                    min(
                        verified.authorization.expires_at,
                        verified.model.expires_at,
                        verified.model.budget.valid_until,
                    ),
                    self.attempt_root,
                    scope,
                )
        except ContractError:
            raise
        except Exception:
            raise ContractError("forbidden") from None


class LocalGrantIssuer:
    def __init__(self, *, allocator: LocalAllocator, guard: LocalCommittedGuard) -> None:
        self.allocator, self.guard = allocator, guard

    def __call__(self, attempt: StageAttempt) -> LocalWorkerGrant:
        if type(attempt) is not StageAttempt or attempt.state != "dispatching":
            raise ContractError("forbidden")
        project, run = self.guard.pin.plan.project_id, self.guard.pin.plan.run_id
        self.allocator.activate_attempt(project, run, attempt.attempt_id)
        with self.guard(project, run, attempt.attempt_id) as facts:
            if facts.reservation_id != attempt.reservation_id:
                raise ContractError("forbidden")
        nonce = secrets.token_hex(32)
        self.allocator.bind_grant(
            project, run, attempt.attempt_id, hashlib.sha256(nonce.encode()).hexdigest()
        )
        return LocalWorkerGrant(
            project,
            run,
            facts.plan_ref.digest,
            attempt.attempt_id,
            self.guard.pin.config.local_destination_id,
            facts.expires_at,
            facts.output_scope,
            nonce,
        )


class LocalWorkerBootstrap(WireModel):
    schema_version: Literal["cfoundry.local-worker-bootstrap.v1"]
    project_id: Id
    actor_id: Id
    allocator_root: str
    allocator_device: str
    allocator_inode: str
    output_root: str
    output_device: str
    output_inode: str
    operator_store_root: str
    operator_device: str
    operator_inode: str
    operator_store_id: str
    policy_path: str
    policy_parent_device: str
    policy_parent_inode: str
    policy_limits: ContractLimits
    attempt_price_usd: Money
    storage_price_usd: Money
    run_storage_capacity_bytes: PositiveInteger
    operator_storage_capacity_bytes: PositiveInteger
    resource_policy_ref: Ref
    funded_from: Instant
    funded_until: Instant
    semantics: Literal["cooperative"]

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if (
            any(
                not Path(value).is_absolute()
                for value in (
                    self.allocator_root,
                    self.output_root,
                    self.operator_store_root,
                    self.policy_path,
                )
            )
            or any(
                not value.isascii() or not value.isdigit()
                for value in (
                    self.allocator_device,
                    self.allocator_inode,
                    self.output_device,
                    self.output_inode,
                    self.operator_device,
                    self.operator_inode,
                    self.policy_parent_device,
                    self.policy_parent_inode,
                )
            )
            or not self.operator_store_id
            or self.resource_policy_ref.project_id != self.project_id
        ):
            raise ValueError("invalid bootstrap binding")
        self.allocation_policy()
        return self

    def allocation_policy(self) -> LocalAllocationPolicy:
        return LocalAllocationPolicy(
            self.attempt_price_usd,
            self.storage_price_usd,
            self.run_storage_capacity_bytes,
            self.operator_storage_capacity_bytes,
            self.resource_policy_ref,
            self.funded_from,
            self.funded_until,
            self.semantics,
        )


def bootstrap_policy_reader(
    bootstrap: LocalWorkerBootstrap, clock: Callable[[], Instant]
) -> Callable[[Id, Id, Id], None]:
    from conscience_foundry.cli.config import read_trusted
    from conscience_foundry.contracts.project import PolicyArtifact
    from conscience_foundry.policy.access import AccessContext, require_permission

    def read_policy(project_id: Id, source_id: Id, actor_id: Id) -> None:
        if (project_id, actor_id) != (bootstrap.project_id, bootstrap.actor_id):
            raise ContractError("forbidden")
        path = Path(bootstrap.policy_path)
        try:
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = os.fstat(parent)
                if (str(info.st_dev), str(info.st_ino)) != (
                    bootstrap.policy_parent_device,
                    bootstrap.policy_parent_inode,
                ):
                    raise ContractError("forbidden")
                raw = read_trusted(path, bootstrap.policy_limits.max_json_bytes)
                current = os.stat(path.parent, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                    raise ContractError("forbidden")
            finally:
                os.close(parent)
            policy = PolicyArtifact.from_wire(raw, bootstrap.policy_limits)
            if policy.project_id != project_id or policy.effective_at > clock():
                raise ContractError("forbidden")
            context = AccessContext(project_id, actor_id, frozenset({"read", "extract"}))
            for effect in ("read", "extract"):
                require_permission(context, policy, source_id, effect)
        except ContractError:
            raise
        except Exception:
            raise ContractError("forbidden") from None

    return read_policy
