"""Trusted composition of the explicitly configured cooperative local executor."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import cast

from conscience_foundry.cli.config import Runtime, RuntimeConfig, TrustedServices, load_limits
from conscience_foundry.cli.local_authority import (
    LocalCommittedGuard,
    LocalPlanPin,
    LocalReceiptIssuer,
)
from conscience_foundry.cli.local_manifest import LocalQuoteManifestPins
from conscience_foundry.contracts.accounting import BudgetEvent
from conscience_foundry.contracts.common import (
    ContractError,
    ContractLimits,
    Digest,
    Id,
    Instant,
    Ref,
)
from conscience_foundry.contracts.execution import StageAttempt
from conscience_foundry.execution.local_allocation import LocalActivationFacts, LocalAllocator
from conscience_foundry.execution.local_contracts import LocalWorkerGrant
from conscience_foundry.execution.local_executor import LocalExecutor
from conscience_foundry.execution.ports import (
    BudgetProof,
    ControlFacts,
    ControlProof,
    EvidenceAuthority,
    GrantFacts,
)
from conscience_foundry.storage.local import ObjectStore
from conscience_foundry.storage.local_attempt import LocalAttemptStore

_PRIVATE_LIMITS = frozenset(
    {
        "cfoundry.local-allocation-estimate.v1",
        "cf.local-process-observation.v1",
        "cfoundry.local-attempt-allocation.v1",
        "cfoundry.local-storage-allocation.v1",
    }
)


def build_local_services(config: RuntimeConfig) -> TrustedServices:
    if config.local_execution is None or config.live is not None:
        raise ContractError("config_invalid")
    limits = load_limits(config.limits_path)
    if not _PRIVATE_LIMITS <= limits.keys():
        raise ContractError("limits_missing")
    from pathlib import Path

    from conscience_foundry.cli.local_manifest import load_local_manifest

    pins = load_local_manifest(
        Path(config.local_execution.trusted_quote_manifest_path),
        project_id=config.project_id,
        limits_by_schema=limits,
        resource_policy_ref=config.local_execution.resource_policy_ref,
    )
    digest = read_runtime_identity(
        Path(config.local_execution.runtime_manifest_path),
        limits["cf.metadata-schema.v1"],
        tuple(model.image_digest for _, _, model in pins.configs),
    )
    return TrustedServices(local=LocalWiring(config, pins, digest))


class LocalOperatorDelegate:
    """Attest only the independently configured operator's narrow control facts."""

    def __init__(self, runtime: Runtime, authorization_ref: Ref) -> None:
        self.runtime = runtime
        self.authorization_ref = authorization_ref
        self.decoders: dict[str, Callable[[bytes, ContractLimits], object]] = {}

    def control(self, proof: ControlProof) -> ControlFacts:
        import hashlib

        from conscience_foundry.execution.evidence import current_policy
        from conscience_foundry.execution.ports import ControlFacts, ControlProof

        rt = self.runtime
        settings = rt.config.local_execution
        permission = "deadline_unknown" if proof.action == "mark_unknown_outcome" else proof.action
        if (
            type(proof) is not ControlProof
            or settings is None
            or proof.action not in settings.control_actions
            or proof.actor_id != rt.config.operator.actor_id
            or proof.binding.project_id != rt.config.project_id
            or proof.evidence_ref.project_id != rt.config.project_id
            or proof.binding.evidence_digest != proof.evidence_ref.digest
            or hashlib.sha256(proof.evidence_bytes).hexdigest() != proof.evidence_ref.digest
            or len(proof.evidence_bytes) != proof.evidence_ref.size_bytes
            or hashlib.sha256(proof.request_bytes).hexdigest() != proof.binding.request_digest
            or not rt.authorize(
                permission, proof.binding.project_id, proof.binding.run_id, proof.actor_id
            )
        ):
            raise ContractError("forbidden")
        current_policy(rt.control, proof.binding.project_id)
        return ControlFacts(
            proof.binding, proof.actor_id, proof.action, proof.snapshot_digest, (), False, False
        )

    def budget(self, proof: BudgetProof) -> GrantFacts:
        import hashlib

        from conscience_foundry.execution.evidence import current_policy, encoded
        from conscience_foundry.execution.ports import BudgetProof, EvidenceBinding, GrantFacts

        if type(proof) is not BudgetProof:
            raise ContractError("forbidden")
        claim = proof.claim
        rt = self.runtime
        if (
            claim.purpose != "install_run_authorization"
            or proof.binding != EvidenceBinding.from_budget(claim)
            or hashlib.sha256(claim.request_bytes).hexdigest() != claim.request_digest
            or claim.run_id != proof.authorization.run_id
            or claim.evidence_ref != self.authorization_ref
            or claim.authorization_ref != self.authorization_ref
            or hashlib.sha256(proof.evidence_bytes).hexdigest() != self.authorization_ref.digest
            or len(proof.evidence_bytes) != self.authorization_ref.size_bytes
            or proof.evidence_bytes != encoded(proof.authorization)
            or proof.authorization.project_id != rt.config.project_id
            or proof.authorization.actor_id != rt.config.operator.actor_id
            or claim.project_id != rt.config.project_id
            or not rt.authorize(
                claim.purpose, claim.project_id, claim.run_id, proof.authorization.actor_id
            )
        ):
            raise ContractError("forbidden")
        current_policy(rt.control, claim.project_id)
        return GrantFacts(
            proof.binding,
            self.authorization_ref.digest,
            proof.authorization.actor_id,
            claim.expected_previous_authorization_id,
        )


def read_runtime_identity(
    path: Path, limits: ContractLimits, expected: tuple[Digest, ...]
) -> Digest:
    import re

    from conscience_foundry.cli.local_manifest import _read_manifest
    from conscience_foundry.contracts.codec import load_json
    from conscience_foundry.execution.local_runtime import runtime_digest, verify_runtime

    value = load_json(
        _read_manifest(path, limits.max_json_bytes, reject_git_worktree=False), limits
    )
    system, files = value.get("os"), value.get("files")
    if (
        set(value) != {"os", "files"}
        or type(system) is not list
        or len(system) != 4
        or any(type(item) is not str or not item for item in system)
        or type(files) is not dict
        or not files
        or len(files) > limits.max_array_items
        or any(
            type(key) is not str
            or not (
                key == "interpreter" or key.startswith(("stdlib/", "package/", "distribution/"))
            )
            or type(digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            for key, digest in files.items()
        )
        or "interpreter" not in files
    ):
        raise ContractError("invalid_schema")
    digest = runtime_digest(value)
    if not expected or any(pin != digest for pin in expected):
        raise ContractError("hash_mismatch")
    verify_runtime(digest)
    return digest


class LocalWiring:
    """Trusted immutable pins; bind every callback to the current command runtime."""

    allocator: LocalAllocator
    executor: LocalExecutor
    committed: Callable[[Id, Id], tuple[StageAttempt, LocalPlanPin]]
    guard_for: Callable[[StageAttempt], LocalCommittedGuard]
    receipt_issuer: Callable[[StageAttempt], LocalReceiptIssuer]

    def __init__(self, config: RuntimeConfig, pins: LocalQuoteManifestPins, digest: Digest) -> None:
        self.config, self.pins, self.digest = config, pins, digest

    def close_storage(self, rt: Runtime, run: Id, candidate: Ref) -> BudgetEvent:
        """Verify retained evidence, close its allocation and settle or replay once."""
        import hashlib
        from uuid import uuid4

        from psycopg import sql

        from conscience_foundry.cli.local_authority import LocalClosureGuard, LocalControlAuthority
        from conscience_foundry.contracts.accounting import BudgetEvent
        from conscience_foundry.contracts.execution import RunAuthorization
        from conscience_foundry.execution.evidence import (
            budget_context,
            encoded,
            read_artifact,
            read_model,
        )
        from conscience_foundry.execution.ports import BudgetProof, EvidenceBinding
        from conscience_foundry.ledger.budget import BudgetEvidenceClaim, apply_budget_event

        control = rt.control
        if (
            rt.services.local is not self
            or type(cast(object, control.evidence_authority)) is not LocalControlAuthority
        ):
            raise ContractError("adapter_unavailable")
        project = rt.config.project_id
        with rt.ledger.transaction() as tx:
            tx.lock(project, run)
            rows = tx.connection.execute(
                sql.SQL(
                    "SELECT r.reservation_id::text, a.authorization_ref, r.final_billing "
                    "FROM {} r JOIN {} a ON (r.project_id,r.run_id,r.authorization_id)="
                    "(a.project_id,a.run_id,a.authorization_id) "
                    "WHERE r.project_id=%s AND r.run_id=%s AND r.scope='run_storage'"
                ).format(tx.table("reservations"), tx.table("authorizations")),
                (project, run),
            ).fetchall()
            if len(rows) != 1:
                raise ContractError("forbidden")
            reservation, auth_data, settled = rows[0]
            auth_ref = Ref.model_validate(auth_data)
            if auth_ref != self.pins.authorization_ref:
                raise ContractError("forbidden")
            prior = tx.connection.execute(
                sql.SQL(
                    "SELECT record_bytes FROM {} WHERE project_id=%s AND run_id=%s "
                    "AND reservation_id=%s"
                ).format(tx.table("budget_events")),
                (project, run, reservation),
            ).fetchall()
            final = [
                event
                for row in prior
                if (
                    event := BudgetEvent.from_wire(bytes(row[0]), rt.limit("cf.budget-event.v1"))
                ).event_type
                == "settle"
            ]
            if settled:
                if (
                    len(final) != 1
                    or final[0].evidence_ref != candidate
                    or final[0].amount_usd != self.allocator.policy.storage_price_usd
                ):
                    raise ContractError("determinism_conflict")
                event = final[0]
            else:
                if final:
                    raise ContractError("forbidden")
                event = BudgetEvent(
                    schema_version="cf.budget-event.v1",
                    project_id=project,
                    run_id=run,
                    reservation_id=reservation,
                    scope="run_storage",
                    event_id=str(uuid4()),
                    event_type="settle",
                    amount_usd=self.allocator.policy.storage_price_usd,
                    cost_status="actual",
                    evidence_ref=candidate,
                    created_at=rt.clock(),
                )
            raw, _ = read_artifact(candidate, control, evidence=True)
            _, auth = read_model(auth_ref, RunAuthorization, control)
            request = encoded(event)
            claim = BudgetEvidenceClaim(
                "final_billing",
                candidate,
                project,
                run,
                reservation,
                None,
                rt.clock(),
                auth_ref,
                None,
                None,
                request,
                hashlib.sha256(request).hexdigest(),
            )
            proof = BudgetProof(claim, EvidenceBinding.from_budget(claim), raw, auth, ())
            authority = cast(LocalControlAuthority, cast(object, control.evidence_authority))
            if settled:
                authority.budget(proof)
            else:
                authority.preclose_storage_candidate(proof)
        if not settled:
            self.allocator.closure_guard = LocalClosureGuard(
                ledger=rt.ledger, control=control, allocator=self.allocator, candidate=candidate
            )
            self.allocator.close_storage(run, self.allocator.durable_refs(project, run))
            with rt.ledger.transaction() as tx:
                apply_budget_event(
                    event, tx, event_bytes=encoded(event), context=budget_context(control, tx=tx)
                )
        return event

    def bind(self, rt: Runtime) -> TrustedServices:
        from dataclasses import replace
        from pathlib import Path

        from conscience_foundry.cli.local_authority import (
            LocalCommittedGuard,
            LocalControlAuthority,
            LocalEvidenceWriter,
            LocalGrantIssuer,
            LocalPlanPin,
            LocalReceiptIssuer,
            LocalRecoveryReader,
            LocalStagingSource,
            bootstrap_policy_reader,
        )
        from conscience_foundry.contracts.execution import StageAttempt
        from conscience_foundry.execution.evidence import read_model
        from conscience_foundry.execution.local_allocation import LocalAllocator
        from conscience_foundry.execution.local_executor import (
            LocalExecutor,
            _grant,
            _read,
            local_staged_refs,
        )
        from conscience_foundry.execution.local_worker import reconstruct_authority
        from conscience_foundry.ledger.attempts import load_attempt

        settings = rt.config.local_execution
        if (
            settings is None
            or rt.config != self.config
            or rt.services.live is not None
            or rt.services.transport_grants is not None
            or rt.services.executor is not None
            or rt.services.evidence_authority is not None
            or rt.services.local_grants is not None
            or rt.services.staged_reader is not None
            or rt.services.staged_writer is not None
            or rt.services.stage_inputs is not None
            or rt.services.issuer_scopes is not None
        ):
            raise ContractError("forbidden")
        _, bootstrap = reconstruct_authority(
            Path(settings.bootstrap_path), settings.bootstrap_digest, rt.clock
        )
        if (
            bootstrap.project_id != rt.config.project_id
            or bootstrap.actor_id != rt.config.operator.actor_id
            or bootstrap.allocator_root != settings.allocator_root
            or bootstrap.output_root != settings.attempt_root
            or bootstrap.operator_store_root != rt.config.object_store.root_path
            or bootstrap.operator_store_id != rt.config.object_store.store_id
            or bootstrap.policy_path != rt.config.policy_path
            or bootstrap.policy_limits != rt.limit("cf.policy.v1")
            or bootstrap.allocation_policy().attempt_price_usd != settings.attempt_price_usd
            or bootstrap.storage_price_usd != settings.storage_price_usd
            or bootstrap.run_storage_capacity_bytes != settings.run_storage_capacity_bytes
            or bootstrap.operator_storage_capacity_bytes != settings.operator_storage_capacity_bytes
            or bootstrap.resource_policy_ref != settings.resource_policy_ref
            or bootstrap.funded_from != settings.funded_from
            or bootstrap.funded_until != settings.funded_until
            or bootstrap.semantics != settings.semantics
        ):
            raise ContractError("forbidden")
        configs = {ref: config for ref, _, config in self.pins.configs}
        pins = tuple(
            LocalPlanPin(ref, plan, plan.execution_config_ref, configs[plan.execution_config_ref])
            for ref, _, plan in self.pins.plans
        )
        if any(pin.config.local_destination_id != settings.destination_id for pin in pins):
            raise ContractError("forbidden")
        delegate = LocalOperatorDelegate(rt, self.pins.authorization_ref)
        import hashlib

        from conscience_foundry.contracts.registry import registered_schema_ids

        pinned: dict[str, set[str]] = {}
        for pin in pins:
            ref = pin.config.tariff_ref
            if ref.artifact_schema not in registered_schema_ids():
                pinned.setdefault(ref.artifact_schema, set()).add(ref.digest)

        def decoder(allowed: frozenset[str]) -> Callable[[bytes, ContractLimits], object]:
            def decode(data: bytes, limits: ContractLimits) -> object:
                if type(data) is not bytes or len(data) > limits.max_json_bytes:
                    raise ContractError("limit_exceeded")
                digest = hashlib.sha256(data).hexdigest()
                if digest not in allowed:
                    raise ContractError("forbidden")
                return {"digest": digest}

            return decode

        delegate.decoders = {
            schema: decoder(frozenset(digests)) for schema, digests in pinned.items()
        }
        authority = LocalControlAuthority(
            policy=bootstrap.allocation_policy(),
            estimates=tuple((ref, raw) for ref, raw, _ in self.pins.estimates),
            plans=pins,
            limits=rt.limit("cfoundry.local-allocation-estimate.v1"),
            delegate=delegate,
            operator=rt.access,
        )
        rt.services = replace(rt.services, evidence_authority=cast(EvidenceAuthority, authority))
        control = rt.control

        def committed(project: Id, attempt_id: Id) -> tuple[StageAttempt, LocalPlanPin]:
            if project != rt.config.project_id:
                raise ContractError("forbidden")
            with rt.ledger.transaction() as tx:
                attempt_ref, run, plan_ref, auth_ref = load_attempt(tx, project, attempt_id)
                attempt = read_model(attempt_ref, StageAttempt, control)[1]
            matches = [pin for pin in pins if pin.ref == plan_ref and pin.plan.run_id == run]
            if (
                len(matches) != 1
                or auth_ref != self.pins.authorization_ref
                or attempt.attempt_id != attempt_id
            ):
                raise ContractError("forbidden")
            return attempt, matches[0]

        def guard(
            project: Id, run: Id, attempt_id: Id
        ) -> AbstractContextManager[LocalActivationFacts]:
            attempt, pin = committed(project, attempt_id)
            if pin.plan.run_id != run:
                raise ContractError("forbidden")
            return LocalCommittedGuard(
                rt.ledger,
                control,
                pin=pin,
                authorization_ref=self.pins.authorization_ref,
                attempt_root=Path(settings.attempt_root),
            )(project, run, attempt_id)

        allocator = LocalAllocator(
            Path(settings.allocator_root),
            bootstrap.allocation_policy(),
            rt.store,
            rt.clock,
            operator_store_id=bootstrap.operator_store_id,
            operator_store_root=Path(bootstrap.operator_store_root),
            activation_guard=guard,
            policy_reader=bootstrap_policy_reader(bootstrap, rt.clock),
        )
        allocator.verify_worker_bootstrap(Path(settings.bootstrap_path), settings.bootstrap_digest)
        authority.allocator = allocator

        def guard_for(attempt: StageAttempt) -> LocalCommittedGuard:
            actual, pin = committed(attempt.project_id, attempt.attempt_id)
            if actual.reservation_id != attempt.reservation_id:
                raise ContractError("forbidden")
            return LocalCommittedGuard(
                rt.ledger,
                control,
                pin=pin,
                authorization_ref=self.pins.authorization_ref,
                attempt_root=Path(settings.attempt_root),
            )

        class Clock:
            def now(self) -> Instant:
                return rt.clock()

        def store_factory(attempt: StageAttempt, grant: LocalWorkerGrant) -> LocalAttemptStore:
            pin = guard_for(attempt).pin
            source = LocalStagingSource(rt.store, rt.access, allocator, pin.plan, grant)
            return LocalAttemptStore(
                Path(settings.attempt_root),
                attempt.project_id,
                attempt.attempt_id,
                source,
                local_staged_refs(pin.plan),
                grant,
                Clock(),
                allocator,
            )

        def evidence(attempt: StageAttempt, schema: str, data: bytes) -> Ref:
            return LocalEvidenceWriter(
                guard=guard_for(attempt), allocator=allocator, executor=executor, operator=rt.access
            )(attempt, schema, data)

        executor = LocalExecutor(
            Path(settings.journal_root),
            settings.destination_id,
            self.digest,
            Clock(),
            evidence,
            store_factory,
            bootstrap_path=Path(settings.bootstrap_path),
            bootstrap_digest=settings.bootstrap_digest,
        )
        authority.executor = executor

        def issue(attempt: StageAttempt) -> LocalWorkerGrant:
            from conscience_foundry.execution.local_runtime import verify_runtime

            guard = guard_for(attempt)
            verify_runtime(self.digest)
            return LocalGrantIssuer(allocator=allocator, guard=guard)(attempt)

        def reader(project: Id, attempt_id: Id) -> ObjectStore:
            attempt, pin = committed(project, attempt_id)
            intent = _read(Path(settings.journal_root) / attempt_id, "intent.json")
            grant = _grant(intent["grant"])
            return LocalRecoveryReader(
                allocator=allocator,
                root=Path(settings.attempt_root),
                grant=grant,
                plan=pin.plan,
                operator=rt.access,
                limits_by_schema=rt.limits,
            )

        def writer(project: Id, attempt_id: Id) -> ObjectStore:
            _, pin = committed(project, attempt_id)
            return allocator.import_writer(project, pin.plan.run_id, attempt_id)

        bound = LocalWiring(self.config, self.pins, self.digest)
        bound.allocator, bound.executor, bound.committed, bound.guard_for = (
            allocator,
            executor,
            committed,
            guard_for,
        )
        bound.receipt_issuer = lambda attempt: LocalReceiptIssuer(
            guard=guard_for(attempt), allocator=allocator, executor=executor, operator=rt.access
        )
        return replace(
            rt.services,
            local=bound,
            executor=executor,
            local_grants=issue,
            staged_reader=reader,
            staged_writer=writer,
            stage_inputs=None,
        )
