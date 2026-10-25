"""Synthetic durable control flow; no provider or remote service is contacted."""

from __future__ import annotations

import hashlib
import io
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Event, current_thread
from types import MappingProxyType
from typing import Any, Literal
from uuid import uuid4

import pytest
from psycopg import sql
from test_ledger_db import ACTOR, ASSET, PROJECT, RUN, TIME, admission, encoded, limits, reference

from conscience_foundry.contracts.accounting import BillingAdjustment, BudgetEvent, ResourceUsage
from conscience_foundry.contracts.admission import IntakeManifest, SourceAsset
from conscience_foundry.contracts.canonical import DocumentRevision, ExtractionSpec, QualityCheck
from conscience_foundry.contracts.common import (
    ContractError,
    Reason,
    Ref,
    WireModel,
)
from conscience_foundry.contracts.execution import (
    ExecutionConfig,
    ExecutionPlan,
    ResultManifest,
    RunAuthorization,
)
from conscience_foundry.contracts.registry import export_schemas, registered_schema_ids
from conscience_foundry.core.identity import (
    F1Operation,
    RevisionInputs,
    operation_key,
    revision_id,
    structure_digest,
)
from conscience_foundry.execution.control import dispatch, reconcile, set_pause
from conscience_foundry.execution.evidence import budget_context
from conscience_foundry.execution.ports import (
    BillingFacts,
    CapabilityFacts,
    ControlContext,
    ControlFacts,
    CostAllocation,
    EstimateFacts,
    EvidenceBinding,
    GrantFacts,
    Observation,
    ObservationFacts,
    Submission,
    TransportFacts,
    TransportGrants,
    TransportProof,
)
from conscience_foundry.ledger.budget import (
    apply_billing_adjustment,
    apply_budget_event,
    install_run_authorization,
    reserve_storage,
)
from conscience_foundry.ledger.db import Ledger, register_admission
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.processing.text_utf8 import process_text
from conscience_foundry.storage.local import LocalObjectStore
from conscience_foundry.storage.locator import LocationRegistry

pytestmark = pytest.mark.database
EXPIRY = "2026-10-26T00:00:00.000Z"


def attempt_row(ledger: Ledger, attempt_id: str) -> Any:
    with ledger.transaction() as tx:
        return tx.connection.execute(
            sql.SQL(
                "SELECT state,result_ref,finished_at,remote_call_id FROM {} "
                "WHERE project_id=%s AND attempt_id=%s"
            ).format(tx.table("attempts")),
            (PROJECT, attempt_id),
        ).fetchone()


class SyntheticEvidence(WireModel):
    """An explicitly configured test adapter schema, never a core contract."""

    schema_version: Literal["test.control-evidence.v1"]
    nonce: str


class Authority:
    def __init__(self) -> None:
        self.decoders = MappingProxyType(
            {
                "test.control-evidence.v1": SyntheticEvidence.from_wire,
            }
        )
        self.grants: dict[str, tuple[str, str | None]] = {}
        self.estimates: dict[str, tuple[str, CapabilityFacts]] = {}
        self.observations: dict[str, tuple[str, str, str | None, bool, bool]] = {}
        self.billings: dict[str, tuple[str, str | None, bool, bool, bool]] = {}
        self.controls: dict[str, tuple[str, str | None, tuple[str, ...], bool, bool]] = {}
        self.storage_estimates: dict[
            str, tuple[str, tuple[Ref, ...], tuple[CapabilityFacts, ...]]
        ] = {}
        self.billing_plans: dict[str, tuple[str, ...]] = {}
        self.claims: list[Any] = []
        self.allowed = True
        self.transports: dict[tuple[bytes, ...], TransportFacts] = {}
        self.transport_calls = 0

    def authorize(self, action: str, project: str, run: str, actor: str) -> bool:
        return self.allowed and actor == ACTOR and project == PROJECT and bool(action)

    def budget(self, proof: Any) -> Any:
        claim = proof.claim
        self.claims.append(claim)
        binding = EvidenceBinding.from_budget(claim)
        if claim.purpose == "install_run_authorization":
            digest, previous = self.grants[claim.evidence_ref.digest]
            return GrantFacts(binding, digest, ACTOR, previous)
        if claim.purpose == "reserve_attempt":
            amount, capability = self.estimates[claim.evidence_ref.digest]
            return EstimateFacts(
                binding,
                amount,
                "USD",
                (claim.plan_ref,),
                (capability,),
                tuple(
                    CostAllocation(category, "4" if category == "cpu" else "0")
                    for category in ("cpu", "ram", "runtime", "transfer", "storage", "region")
                ),
                TIME,
                EXPIRY,
                None,
            )
        if claim.purpose == "reserve_storage":
            amount, plans, capabilities = self.storage_estimates[claim.evidence_ref.digest]
            return EstimateFacts(
                binding,
                amount,
                "USD",
                plans,
                capabilities,
                (CostAllocation("storage", amount),),
                TIME,
                EXPIRY,
                None,
            )
        if claim.purpose in {
            "record_usage",
            "final_billing",
            "billing_adjustment",
            "release_unspent",
            "final_no_effect",
        }:
            if claim.evidence_ref.digest in self.billing_plans:
                assert (
                    tuple(plan.ref.digest for plan in proof.plans)
                    == self.billing_plans[claim.evidence_ref.digest]
                )
            status, amount, final, no_liability, no_effect = self.billings[
                claim.evidence_ref.digest
            ]
            return BillingFacts(binding, status, amount, final, no_liability, no_effect)
        raise ContractError("forbidden")

    def observation(self, proof: Any) -> ObservationFacts:
        remote, state, result, no_effect, terminated = self.observations[proof.evidence_ref.digest]
        return ObservationFacts(
            proof.binding,
            remote,
            state,
            result,
            no_effect,
            terminated,
        )

    def control(self, proof: Any) -> Any:
        action, snapshot, unresolved, risk, resolved = self.controls[proof.evidence_ref.digest]
        return ControlFacts(proof.binding, ACTOR, action, snapshot, unresolved, risk, resolved)

    def transport(self, proof: TransportProof) -> TransportFacts:
        self.transport_calls += 1
        # Values were registered independently when the synthetic preparer minted
        # this specific material, not derived by echoing the incoming request.
        return self.transports[proof.material]


class Case:
    def __init__(self, tmp_path: Path) -> None:
        self.bound = limits()
        self.access = AccessContext(
            PROJECT,
            ACTOR,
            frozenset({"read", "extract", "remoteTransfer", "auditMetadataRead"}),
        )
        root = tmp_path / "objects"
        root.mkdir()

        def store_authority(ref: Ref, access: AccessContext, effect: str) -> None:
            if (
                ref.project_id != PROJECT
                or access != self.access
                or effect not in {"read", "write", "register_location"}
            ):
                raise ContractError("forbidden")

        self.store = LocalObjectStore(
            "synthetic",
            LocationRegistry(
                {"synthetic": root},
                self.bound,
                store_authority,
            ),
        )
        self.authority = Authority()
        self.data = admission()
        self.policy = self.data.evidence.pinned_policy.model_copy(
            update={
                "allowed_remote_destinations": ("synthetic.worker",),
            }
        )
        self.schemas = {schema: self.bound for schema in registered_schema_ids()}
        self.schemas["test.control-evidence.v1"] = self.bound
        self.control = ControlContext(
            access=self.access,
            clock=lambda: TIME,
            limits_by_schema=self.schemas,
            current_policy=lambda project: self.policy,
            authorize=self.authority.authorize,
            evidence_authority=self.authority,
            output_store_id="synthetic",
            store=self.store,
            transport_limits=self.bound,
        )
        for raw, ref in (
            (self.data.evidence.manifest_bytes, self.data.manifest_ref),
            (self.data.evidence.report_bytes, self.data.report_ref),
            (
                self.data.evidence.policy_bytes,
                IntakeManifest.from_wire(self.data.evidence.manifest_bytes, self.bound).policy_ref,
            ),
        ):
            self.store.put_verified(io.BytesIO(raw), ref, self.access)
        self.original = self.data.report.entries[0].snapshot_ref
        assert self.original is not None
        self.store.put_verified(io.BytesIO(b"Synthetic text"), self.original, self.access)
        self.limits_ref = self.put(self.bound)
        self.spec = ExtractionSpec(
            schema_version="kf.extraction-spec.v1",
            processor_id="text.utf8.v1",
            processor_version="synthetic.v1",
            code_version="synthetic.v1",
            image_digest="a" * 64,
            limits_ref=self.limits_ref,
            normalization="none",
            newline_policy="preserve",
            bom_policy="reject",
        )
        self.spec_ref = self.put(self.spec)
        tariff = self.proof()
        resource = self.proof()
        self.config = ExecutionConfig(
            schema_version="kf.execution-config.v1",
            adapter_id="synthetic.worker",
            deployment_version="synthetic.v1",
            image_digest="a" * 64,
            tariff_ref=tariff,
            resource_policy_ref=resource,
            remote_destination_id="synthetic.worker",
        )
        self.config_ref = self.put(self.config)
        contract_dir = tmp_path / "contracts"
        bundle = export_schemas(
            contract_dir,
            project_id=PROJECT,
            store_id="synthetic",
            version="synthetic.v1",
            limits_by_schema=self.schemas,
        )
        for binding in bundle.contracts:
            for ref in (binding.schema_ref, binding.semantic_rules_ref):
                self.store.put_verified(
                    io.BytesIO((contract_dir / ref.locations[0].object_key).read_bytes()),
                    ref,
                    self.access,
                )
        bundle_ref = self.put(bundle)
        manifest = IntakeManifest.from_wire(self.data.evidence.manifest_bytes, self.bound)
        key = operation_key(
            F1Operation(
                PROJECT,
                ASSET,
                manifest.items[0].source_id,
                (self.original.digest,),
                self.spec_ref.digest,
                manifest.profile_id,
                manifest.profile_version,
                manifest.policy_ref.digest,
                bundle_ref.digest,
                (self.limits_ref.digest,),
            ),
            limits=self.bound,
        )
        auth_id = str(uuid4())
        self.plan = ExecutionPlan.model_validate(
            {
                "schemaVersion": "kf.execution-plan.v1",
                "projectId": PROJECT,
                "runId": RUN,
                "planId": str(uuid4()),
                "executionConfigRef": self.config_ref,
                "admissionReportRef": self.data.report_ref,
                "extractionSpecRef": self.spec_ref,
                "policyRef": manifest.policy_ref,
                "profileId": manifest.profile_id,
                "profileVersion": manifest.profile_version,
                "contractSetRef": bundle_ref,
                "limitsRefs": (self.limits_ref,),
                "inputRefs": (self.original,),
                "operationKey": key,
                "resources": {
                    "cpuMilli": 100,
                    "memoryMiB": 64,
                    "gpuCount": 0,
                    "maxWallSeconds": 10,
                    "maxOutputBytes": 32768,
                    "maxConcurrentAttempts": 3,
                    "maxAttemptsPerOperation": 3,
                    "automaticRetries": 0,
                },
                "budget": {
                    "currency": "USD",
                    "maxRunCost": "10",
                    "maxAttemptCost": "4",
                    "tariffRef": tariff,
                    "authorizationId": auth_id,
                    "validUntil": EXPIRY,
                },
                "expiresAt": EXPIRY,
            }
        )
        self.plan_ref = self.put(self.plan)
        self.auth = RunAuthorization(
            schema_version="kf.run-authorization.v1",
            authorization_id=auth_id,
            project_id=PROJECT,
            run_id=RUN,
            admission_report_digest=self.data.report_ref.digest,
            allowed_plan_digests=(self.plan_ref.digest,),
            max_run_cost="10",
            max_concurrent_attempts=3,
            actor_id=ACTOR,
            authorized_at=TIME,
            expires_at=EXPIRY,
        )
        self.auth_ref = self.put(self.auth)
        self.authority.grants[self.auth_ref.digest] = self.auth_ref.digest, None
        self.estimate = self.proof()
        self.authority.estimates[self.estimate.digest] = (
            "4",
            CapabilityFacts(
                self.config_ref,
                tariff,
                resource,
                self.config.image_digest,
                self.config.remote_destination_id,
                self.plan.resources,
            ),
        )

    def put(self, value: WireModel) -> Ref:
        raw = encoded(value)
        ref = reference(raw, value.schema_version)
        self.store.put_verified(io.BytesIO(raw), ref, self.access)
        return ref

    def proof(self) -> Ref:
        return self.put(
            SyntheticEvidence(schema_version="test.control-evidence.v1", nonce=str(uuid4()))
        )

    def setup(self, ledger: Ledger) -> None:
        with ledger.transaction() as tx:
            register_admission(
                self.data.manifest_ref,
                self.data.report,
                self.data.report_ref,
                tx,
                evidence=self.data.evidence,
            )
            tx.create_run(PROJECT, RUN, self.data.report_ref.digest)
            install_run_authorization(
                self.auth,
                self.auth_ref,
                encoded(self.auth),
                tx,
                context=budget_context(self.control, tx=tx),
                expected_previous_authorization_id=None,
            )

    def grants(self, *, material: tuple[bytes, ...] | None = None) -> TransportGrants:
        attempt_id = str(uuid4())
        material = (
            material if material is not None else (b"synthetic-token-" + attempt_id.encode(),)
        )
        scope = b"synthetic-output-" + attempt_id.encode()
        grants = TransportGrants(
            PROJECT,
            self.plan_ref.digest,
            attempt_id,
            self.config.remote_destination_id,
            EXPIRY,
            material,
            scope,
        )
        digest = hashlib.sha256(b"kf.transport-material.internal.v1\n")
        digest.update(len(material).to_bytes(8, "big"))
        for piece in material:
            digest.update(len(piece).to_bytes(8, "big"))
            digest.update(piece)
        digest.update(len(scope).to_bytes(8, "big"))
        digest.update(scope)
        self.authority.transports[material] = TransportFacts(
            PROJECT,
            self.plan_ref.digest,
            attempt_id,
            self.config.remote_destination_id,
            EXPIRY,
            self.plan.input_refs,
            digest.hexdigest(),
            scope,
            attempt_id,
            True,
        )
        return grants

    def dispatch(self, ledger: Ledger, executor: Any) -> Any:
        grants = self.grants()
        return dispatch(
            self.plan,
            self.auth,
            self.access,
            ledger,
            executor,
            grants,
            control=self.control,
            plan_ref=self.plan_ref,
            authorization_ref=self.auth_ref,
            asset_id=ASSET,
            evidence_ref=self.estimate,
        )

    def result(self, attempt: Any, *, extra_check: bool = False) -> Ref:
        source = self.data.report.entries[0].source_id
        asset = SourceAsset(
            schema_version="kf.source-asset.v1",
            project_id=PROJECT,
            asset_id=ASSET,
            source_id=source,
            original_ref=self.original,
            admission_report_ref=self.data.report_ref,
            metadata=IntakeManifest.from_wire(self.data.evidence.manifest_bytes, self.bound)
            .items[0]
            .metadata,
        )
        output = process_text(
            asset,
            self.store.read_verified(self.original, self.access, 4096),
            self.spec,
            limits=self.bound,
            limits_bytes=encoded(self.bound),
        )
        quality = output.quality
        if extra_check:
            quality = quality.model_copy(
                update={
                    "checks": quality.checks
                    + (QualityCheck(check_id="synthetic.additional", outcome="pass"),)
                }
            )
        quality_ref, map_ref = self.put(quality), self.put(output.origin_map)
        text_ref = reference(output.text, "kf.canonical-text.v1").model_copy(
            update={"media_type": "text/plain"}
        )
        self.store.put_verified(io.BytesIO(output.text), text_ref, self.access)
        revision = DocumentRevision(
            schema_version="kf.document-revision.v1",
            project_id=PROJECT,
            source_id=source,
            asset_id=ASSET,
            revision_id=revision_id(
                RevisionInputs(
                    PROJECT,
                    source,
                    self.original.digest,
                    text_ref.digest,
                    self.spec_ref.digest,
                    structure_digest(output.sections, limits=self.bound),
                    map_ref.digest,
                ),
                limits=self.bound,
            ),
            original_ref=self.original,
            text_ref=text_ref,
            extraction_spec_ref=self.spec_ref,
            text_encoding="utf-8",
            offset_unit="unicode_scalar",
            sections=output.sections,
            origin_map_ref=map_ref,
            quality_report_ref=quality_ref,
        )
        revision_ref = self.put(revision)
        return self.put(
            ResultManifest(
                schema_version="kf.result.v1",
                project_id=PROJECT,
                plan_id=self.plan.plan_id,
                operation_key=self.plan.operation_key,
                attempt_id=attempt.attempt_id,
                input_digests=(self.original.digest,),
                status="succeeded",
                outputs=(revision_ref, quality_ref, map_ref, text_ref),
                document_revision_ref=revision_ref,
                quality_report_ref=quality_ref,
                errors=(),
                usage=ResourceUsage(
                    provider_request_ids=(),
                    cost_status="unknown",
                    tariff_ref=self.config.tariff_ref,
                ),
                completed_at=TIME,
            )
        )


class Executor:
    def __init__(self, case: Case, *, lost: bool = False) -> None:
        self.case, self.lost = case, lost
        self.calls = 0
        self.next: Observation | None = None

    def submit(self, plan: Any, attempt: Any, grants: Any) -> Submission:
        self.calls += 1
        if self.lost:
            raise TimeoutError
        return Submission("synthetic-call-" + attempt.attempt_id, True)

    def observe(self, attempt: Any) -> Observation:
        assert self.next is not None
        return self.next

    def cancel(self, attempt: Any) -> Observation:
        return self.observe(attempt)

    def success(self, attempt: Any, *, extra_check: bool = False) -> Ref:
        result = self.case.result(attempt, extra_check=extra_check)
        evidence = self.case.proof()
        self.next = Observation("succeeded", result, None, evidence)
        self.case.authority.observations[evidence.digest] = (
            attempt.remote_call_id or "synthetic-call-" + attempt.attempt_id,
            "succeeded",
            result.digest,
            False,
            True,
        )
        self.case.authority.billings[evidence.digest] = ("unknown", None, False, False, False)
        return result


def test_lost_submit_response_never_blindly_replays(ledger: Ledger, tmp_path: Path) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c, lost=True)
    first = c.dispatch(ledger, executor)
    assert first.state == "unknown_outcome"
    with pytest.raises(ContractError):
        c.dispatch(ledger, executor)
    assert executor.calls == 1
    with ledger.transaction() as tx:
        row = tx.connection.execute(
            sql.SQL("SELECT outstanding_usd FROM {} WHERE reservation_id=%s").format(
                tx.table("reservations")
            ),
            (first.reservation_id,),
        ).fetchone()
    assert row is not None and str(row[0]) == "4"


@pytest.mark.parametrize("path", ["observe_exception", "submit_response"])
def test_stale_network_completion_cannot_overwrite_terminal(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    import conscience_foundry.execution.control as control_module

    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c)
    captured: list[Any] = []
    if path == "observe_exception":
        first = c.dispatch(ledger, executor)
    else:

        def capture_submit(plan: Any, attempt: Any, grants: Any) -> Submission:
            captured.append(attempt)
            return Submission("synthetic-call-" + attempt.attempt_id, True)

        executor.submit = capture_submit
    loaded, release = Event(), Event()
    original = control_module._load
    reads = 0

    def paused_load(*args: Any, **kwargs: Any) -> Any:
        nonlocal reads
        result = original(*args, **kwargs)
        if current_thread().name.startswith("stale-writer"):
            reads += 1
            target = 2 if path == "observe_exception" else 1
            if reads == target:
                loaded.set()
                assert release.wait(5)
        return result

    monkeypatch.setattr(control_module, "_load", paused_load)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="stale-writer") as workers:
        if path == "observe_exception":
            failing = Executor(c)

            def unavailable(attempt: Any) -> Observation:
                raise TimeoutError

            failing.observe = unavailable
            future = workers.submit(
                reconcile, first.attempt_id, ledger, failing, c.store, control=c.control
            )
        else:
            future = workers.submit(c.dispatch, ledger, executor)
        try:
            assert loaded.wait(5)
            if path == "submit_response":
                first = captured[0]
            winner = Executor(c)
            winner.success(first)
            assert reconcile(first.attempt_id, ledger, winner, c.store, control=c.control)
            terminal = attempt_row(ledger, first.attempt_id)
            assert terminal[0] == "succeeded"
        finally:
            release.set()
        future.result()
    assert attempt_row(ledger, first.attempt_id) == terminal


def test_late_terminal_actual_usage_freezes_without_mutating_terminal(
    ledger: Ledger, tmp_path: Path
) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c)
    first = c.dispatch(ledger, executor)
    result = executor.success(first)
    assert reconcile(first.attempt_id, ledger, executor, c.store, control=c.control)
    terminal = attempt_row(ledger, first.attempt_id)
    proof = c.proof()
    c.authority.observations[proof.digest] = (
        first.remote_call_id,
        "succeeded",
        result.digest,
        False,
        True,
    )
    c.authority.billings[proof.digest] = ("actual", "12", False, False, False)
    executor.next = Observation(
        "succeeded",
        result,
        ResourceUsage(
            cost_status="actual",
            cost_usd="12",
            tariff_ref=c.config.tariff_ref,
            provider_request_ids=(),
        ),
        proof,
    )
    reconcile(first.attempt_id, ledger, executor, c.store, control=c.control)
    reconcile(first.attempt_id, ledger, executor, c.store, control=c.control)
    assert attempt_row(ledger, first.attempt_id) == terminal
    with ledger.transaction() as tx:
        assert tx.connection.execute(
            sql.SQL("SELECT frozen FROM {} WHERE project_id=%s AND run_id=%s").format(
                tx.table("runs")
            ),
            (PROJECT, RUN),
        ).fetchone() == (True,)
        events = tx.connection.execute(
            sql.SQL("SELECT record_bytes FROM {} WHERE project_id=%s").format(
                tx.table("budget_events")
            ),
            (PROJECT,),
        ).fetchall()
        actuals = [BudgetEvent.from_wire(bytes(row[0]), c.bound) for row in events]
        assert (
            sum(
                event.event_type == "record_usage" and event.cost_status == "actual"
                for event in actuals
            )
            == 1
        )
        assert (
            str(
                tx.connection.execute(
                    sql.SQL("SELECT outstanding_usd FROM {} WHERE reservation_id=%s").format(
                        tx.table("reservations")
                    ),
                    (first.reservation_id,),
                ).fetchone()[0]
            )
            == "4"
        )
    with pytest.raises(ContractError):
        c.dispatch(ledger, executor)
    assert executor.calls == 1


@pytest.mark.parametrize("kind", ["oversize", "count", "unattested"])
def test_transport_material_is_bounded_and_attested_before_allocation(
    ledger: Ledger, tmp_path: Path, kind: str
) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c)
    material = (b"unregistered-token",)
    if kind == "oversize":
        material = (b"x" * (c.bound.max_source_bytes + 1),)
    elif kind == "count":
        material = (b"",) * (c.bound.max_array_items + 1)
    grants = replace(c.grants(), material=material)
    authority_calls = c.authority.transport_calls
    with pytest.raises(ContractError):
        dispatch(
            c.plan,
            c.auth,
            c.access,
            ledger,
            executor,
            grants,
            control=c.control,
            plan_ref=c.plan_ref,
            authorization_ref=c.auth_ref,
            asset_id=ASSET,
            evidence_ref=c.estimate,
        )
    assert executor.calls == 0
    if kind in {"oversize", "count"}:
        assert c.authority.transport_calls == authority_calls
    with ledger.transaction() as tx:
        assert tx.connection.execute(
            sql.SQL("SELECT count(*) FROM {}").format(tx.table("reservations"))
        ).fetchone() == (0,)


@pytest.mark.parametrize(
    "kind",
    [
        "scope",
        "output_attempt",
        "not_isolated",
        "broader_input",
        "destination",
        "expiry",
        "fingerprint",
        "exception",
        "unknown",
        "oversize_scope",
        "aggregate",
        "tuple_subclass",
        "bytes_subclass",
    ],
)
def test_transport_attestation_rejects_actual_scope_mismatch_and_unknown(
    ledger: Ledger, tmp_path: Path, kind: str
) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c)
    grants = c.grants()
    registered = grants.material
    facts = c.authority.transports[grants.material]
    calls = c.authority.transport_calls
    hooks: list[str] = []
    if kind == "scope":
        facts = replace(facts, output_scope=b"broader-provider-scope")
    elif kind == "output_attempt":
        facts = replace(facts, output_attempt_id=str(uuid4()))
    elif kind == "not_isolated":
        facts = replace(facts, attempt_isolated=1)
    elif kind == "broader_input":
        facts = replace(facts, input_refs=facts.input_refs + (c.spec_ref,))
    elif kind == "destination":
        facts = replace(facts, destination_id="other-destination")
    elif kind == "expiry":
        facts = replace(facts, expires_at="2026-10-27T00:00:00.000Z")
    elif kind == "fingerprint":
        facts = replace(facts, material_fingerprint="a" * 64)
    elif kind == "exception":

        def unavailable(proof: TransportProof) -> TransportFacts:
            raise TimeoutError

        c.authority.transport = unavailable
    elif kind == "unknown":
        c.authority.transport = lambda proof: None
    elif kind == "oversize_scope":
        grants = replace(grants, output_scope=b"x" * (c.bound.max_source_bytes + 1))
    elif kind == "aggregate":
        grants = replace(grants, material=(b"x" * c.bound.max_source_bytes,))
    elif kind == "tuple_subclass":

        class MaliciousTuple(tuple):
            def __len__(self) -> int:
                hooks.append("length")
                raise AssertionError

        grants = replace(grants, material=MaliciousTuple(grants.material))
    elif kind == "bytes_subclass":

        class MaliciousBytes(bytes):
            def __len__(self) -> int:
                hooks.append("length")
                raise AssertionError

        grants = replace(grants, material=(MaliciousBytes(b"token"),))
    c.authority.transports[registered] = facts
    with pytest.raises(ContractError):
        dispatch(
            c.plan,
            c.auth,
            c.access,
            ledger,
            executor,
            grants,
            control=c.control,
            plan_ref=c.plan_ref,
            authorization_ref=c.auth_ref,
            asset_id=ASSET,
            evidence_ref=c.estimate,
        )
    assert executor.calls == 0 and not hooks
    if kind in {"oversize_scope", "aggregate", "tuple_subclass", "bytes_subclass"}:
        assert c.authority.transport_calls == calls
    with ledger.transaction() as tx:
        assert tx.connection.execute(
            sql.SQL("SELECT count(*) FROM {}").format(tx.table("reservations"))
        ).fetchone() == (0,)


@pytest.mark.parametrize("failure", ["exception", "expired"])
def test_transport_is_reattested_before_submit_without_releasing_money(
    ledger: Ledger, tmp_path: Path, failure: str
) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c)
    grants = c.grants()
    facts = c.authority.transports[grants.material]
    calls = 0
    now = TIME
    c.control = replace(c.control, clock=lambda: now)

    def attest(proof: TransportProof) -> TransportFacts:
        nonlocal calls, now
        calls += 1
        if calls == 2:
            if failure == "exception":
                raise TimeoutError
            now = EXPIRY
        return facts

    c.authority.transport = attest
    result = dispatch(
        c.plan,
        c.auth,
        c.access,
        ledger,
        executor,
        grants,
        control=c.control,
        plan_ref=c.plan_ref,
        authorization_ref=c.auth_ref,
        asset_id=ASSET,
        evidence_ref=c.estimate,
    )
    assert result.state == "failed" and executor.calls == 0 and calls == 2
    assert result.finished_at is not None
    assert grants.material[0].decode() not in repr(grants)
    assert facts.material_fingerprint not in repr(facts)
    with ledger.transaction() as tx:
        assert (
            str(
                tx.connection.execute(
                    sql.SQL("SELECT outstanding_usd FROM {} WHERE reservation_id=%s").format(
                        tx.table("reservations")
                    ),
                    (result.reservation_id,),
                ).fetchone()[0]
            )
            == "4"
        )
        rows = tx.connection.execute(
            sql.SQL("SELECT record_bytes FROM {} WHERE attempt_id=%s").format(
                tx.table("attempt_observations")
            ),
            (result.attempt_id,),
        ).fetchall()
    assert len(rows) == 1
    assert b'"submitInvoked":false' in bytes(rows[0][0])
    assert grants.material[0] not in bytes(rows[0][0])
    assert facts.material_fingerprint.encode() not in bytes(rows[0][0])


def test_terminal_snapshot_storage_rejects_a_stale_direct_write(
    ledger: Ledger, tmp_path: Path
) -> None:
    from conscience_foundry.execution.control import _load
    from conscience_foundry.ledger.attempts import save_attempt

    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c)
    running = c.dispatch(ledger, executor)
    executor.success(running)
    reconcile(running.attempt_id, ledger, executor, c.store, control=c.control)
    before = attempt_row(ledger, running.attempt_id)
    with ledger.transaction() as tx:
        tx.lock(PROJECT, RUN, running.operation_key)
        with pytest.raises(ContractError, match="determinism_conflict"):
            save_attempt(tx, running, c.control)
        current, _, _, _ = _load(tx, running.attempt_id, c.control)
        assert save_attempt(tx, current, c.control).artifact_schema == "kf.stage-attempt.v1"
    assert attempt_row(ledger, running.attempt_id) == before


def test_transport_fingerprint_frames_material_and_stays_transient(
    ledger: Ledger, tmp_path: Path
) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c)
    fingerprints: list[str] = []
    original = c.authority.transport

    def attest(proof: TransportProof) -> TransportFacts:
        assert proof.material_fingerprint not in repr(proof)
        assert all(piece.decode() not in repr(proof) for piece in proof.material)
        fingerprints.append(proof.material_fingerprint)
        return original(proof)

    c.authority.transport = attest
    for material in (
        (b"synthetic-sensitive-ab", b"synthetic-sensitive-c"),
        (b"synthetic-sensitive-a", b"bsynthetic-sensitive-c"),
    ):
        grants = c.grants(material=material)
        assert (
            dispatch(
                c.plan,
                c.auth,
                c.access,
                ledger,
                executor,
                grants,
                control=c.control,
                plan_ref=c.plan_ref,
                authorization_ref=c.auth_ref,
                asset_id=ASSET,
                evidence_ref=c.estimate,
            ).state
            == "running"
        )
    assert len(fingerprints) == 4 and fingerprints[0] != fingerprints[2]


def test_late_conflict_holds_descendants(ledger: Ledger, tmp_path: Path) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c)
    first, second = c.dispatch(ledger, executor), c.dispatch(ledger, executor)
    first_ref = executor.success(first)
    before = c.store.read_verified(first_ref, c.access, 65536).data
    selected = reconcile(first.attempt_id, ledger, executor, c.store, control=c.control)
    assert selected is not None and selected.outcome == "selected"
    executor.success(second, extra_check=True)
    conflict = reconcile(second.attempt_id, ledger, executor, c.store, control=c.control)
    assert conflict is not None and conflict.outcome == "conflict"
    with ledger.transaction() as tx:
        row = tx.connection.execute(
            sql.SQL("SELECT held FROM {} WHERE project_id=%s AND operation_key=%s").format(
                tx.table("operations")
            ),
            (PROJECT, c.plan.operation_key),
        ).fetchone()
    assert row == (True,)
    assert c.store.read_verified(first_ref, c.access, 65536).data == before
    with pytest.raises(ContractError):
        c.dispatch(ledger, executor)


def test_result_bytes_and_current_policy_are_required(ledger: Ledger, tmp_path: Path) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c)
    attempt = c.dispatch(ledger, executor)
    executor.success(attempt)
    c.policy = c.policy.model_copy(update={"sources": ()})
    with pytest.raises(ContractError):
        reconcile(attempt.attempt_id, ledger, executor, c.store, control=c.control)
    assert executor.calls == 1


def test_pause_serializes_after_claim_but_late_result_reconciles(
    ledger: Ledger, tmp_path: Path
) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    claimed, release = Event(), Event()
    executor = Executor(c)
    original_submit = executor.submit

    def submit(plan: Any, attempt: Any, grants: Any) -> Submission:
        claimed.set()
        assert release.wait(5)
        return original_submit(plan, attempt, grants)

    executor.submit = submit
    proof = c.proof()
    c.authority.controls[proof.digest] = ("pause", None, (), False, False)
    reason = Reason(code="unavailable", message="synthetic pause")
    with ThreadPoolExecutor(max_workers=1) as workers:
        future = workers.submit(c.dispatch, ledger, executor)
        try:
            assert claimed.wait(5)
            paused = set_pause(
                "run",
                PROJECT,
                RUN,
                True,
                0,
                c.access,
                ledger,
                control=c.control,
                reason=reason,
                evidence_ref=proof,
            )
            assert paused.paused and paused.version == 1
            with pytest.raises(ContractError):
                c.dispatch(ledger, executor)
        finally:
            release.set()
        attempt = future.result()
    executor.success(attempt)
    assert reconcile(attempt.attempt_id, ledger, executor, c.store, control=c.control) is not None
    resume = c.proof()
    c.authority.controls[resume.digest] = ("resume", None, (), False, False)
    with pytest.raises(ContractError):
        set_pause(
            "run",
            PROJECT,
            RUN,
            False,
            0,
            c.access,
            ledger,
            control=c.control,
            reason=reason,
            evidence_ref=resume,
        )
    c.authority.allowed = False
    with pytest.raises(ContractError):
        set_pause(
            "run",
            PROJECT,
            RUN,
            False,
            1,
            c.access,
            ledger,
            control=c.control,
            reason=reason,
            evidence_ref=resume,
        )
    c.authority.allowed = True
    assert (
        set_pause(
            "run",
            PROJECT,
            RUN,
            False,
            1,
            c.access,
            ledger,
            control=c.control,
            reason=reason,
            evidence_ref=resume,
        ).version
        == 2
    )


@pytest.mark.parametrize(
    "response",
    [
        Submission("synthetic-negative", False),
        Submission(None, True),
        Submission("", True),
        Submission(None, None),
    ],
)
def test_submission_does_not_infer_no_effect(
    ledger: Ledger, tmp_path: Path, response: Submission
) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c)
    executor.submit = lambda plan, attempt, grants: response
    attempt = c.dispatch(ledger, executor)
    assert attempt.state == "unknown_outcome" and attempt.finished_at is None
    if response.remote_call_id:
        assert attempt.remote_call_id == response.remote_call_id


def test_result_rejects_foreign_input_before_content_read(ledger: Ledger, tmp_path: Path) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c)
    attempt = c.dispatch(ledger, executor)
    result_ref = executor.success(attempt)
    result = ResultManifest.from_wire(
        c.store.read_verified(result_ref, c.access, 65536).data, c.bound
    )
    assert result.document_revision_ref is not None
    revision = DocumentRevision.from_wire(
        c.store.read_verified(result.document_revision_ref, c.access, 65536).data, c.bound
    )
    foreign_bytes = b"Unselected synthetic source"
    foreign = reference(foreign_bytes, "kf.raw-original.v1").model_copy(
        update={"media_type": "text/plain"}
    )
    c.store.put_verified(io.BytesIO(foreign_bytes), foreign, c.access)
    changed_ref = c.put(revision.model_copy(update={"original_ref": foreign}))
    changed = c.put(
        result.model_copy(
            update={
                "document_revision_ref": changed_ref,
                "outputs": tuple(
                    changed_ref if ref == result.document_revision_ref else ref
                    for ref in result.outputs
                ),
            }
        )
    )
    evidence = c.proof()
    executor.next = Observation("succeeded", changed, None, evidence)
    c.authority.observations[evidence.digest] = (
        attempt.remote_call_id,
        "succeeded",
        changed.digest,
        False,
        True,
    )
    reads: list[str] = []
    original = c.store.read_verified

    def read(ref: Ref, access: AccessContext, limit: int) -> Any:
        reads.append(ref.digest)
        return original(ref, access, limit)

    c.store.read_verified = read
    with pytest.raises(ContractError):
        reconcile(attempt.attempt_id, ledger, executor, c.store, control=c.control)
    assert foreign.digest not in reads


def test_cancel_needs_termination_and_terminal_corrections_create_hold(
    ledger: Ledger, tmp_path: Path
) -> None:
    from conscience_foundry.execution.control import cancel_attempt

    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c)
    attempt = c.dispatch(ledger, executor)
    command = c.proof()
    c.authority.controls[command.digest] = ("cancel_attempt", None, (), False, False)
    observed = c.proof()
    executor.next = Observation("cancelled", None, None, observed)
    c.authority.observations[observed.digest] = (
        attempt.remote_call_id,
        "cancelled",
        None,
        False,
        False,
    )
    with pytest.raises(ContractError):
        cancel_attempt(
            attempt.attempt_id,
            ledger,
            executor,
            control=c.control,
            reason=Reason(code="unavailable", message="synthetic cancellation"),
            evidence_ref=command,
        )
    c.authority.observations[observed.digest] = (
        attempt.remote_call_id,
        "cancelled",
        None,
        False,
        True,
    )
    assert reconcile(attempt.attempt_id, ledger, executor, c.store, control=c.control) is None
    executor.success(attempt)
    assert reconcile(attempt.attempt_id, ledger, executor, c.store, control=c.control) is None
    with ledger.transaction() as tx:
        state = tx.connection.execute(
            sql.SQL("SELECT state FROM {} WHERE attempt_id=%s").format(tx.table("attempts")),
            (attempt.attempt_id,),
        ).fetchone()
        held = tx.connection.execute(
            sql.SQL("SELECT held FROM {} WHERE operation_key=%s").format(tx.table("operations")),
            (attempt.operation_key,),
        ).fetchone()
        outstanding = tx.connection.execute(
            sql.SQL("SELECT outstanding_usd FROM {} WHERE reservation_id=%s").format(
                tx.table("reservations")
            ),
            (attempt.reservation_id,),
        ).fetchone()
    assert state == ("cancelled",) and held == (True,) and str(outstanding[0]) == "4"


def test_snapshot_and_explicit_financial_reconciliation_cas(ledger: Ledger, tmp_path: Path) -> None:
    from conscience_foundry.execution.control import control_snapshot, reconcile_budget

    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c)
    attempt = c.dispatch(ledger, executor)
    snapshot = control_snapshot(PROJECT, RUN, ledger, control=c.control)
    command = c.proof()
    c.authority.controls[command.digest] = ("reconcile_budget", snapshot, (), False, True)
    with pytest.raises(ContractError):
        reconcile_budget(
            PROJECT,
            RUN,
            snapshot,
            c.access,
            ledger,
            control=c.control,
            reason=Reason(code="unavailable", message="synthetic reconcile"),
            evidence_ref=command,
        )
    with ledger.transaction() as tx:
        assert (
            tx.connection.execute(
                sql.SQL("SELECT outstanding_usd FROM {} WHERE reservation_id=%s").format(
                    tx.table("reservations")
                ),
                (attempt.reservation_id,),
            ).fetchone()[0]
            == 4
        )
    executor.success(attempt)
    reconcile(attempt.attempt_id, ledger, executor, c.store, control=c.control)
    final_ref = c.proof()
    c.authority.billings[final_ref.digest] = ("actual", "4", True, True, False)
    settled = BudgetEvent(
        schema_version="kf.budget-event.v1",
        project_id=PROJECT,
        run_id=RUN,
        reservation_id=attempt.reservation_id,
        attempt_id=attempt.attempt_id,
        scope="attempt",
        event_id=str(uuid4()),
        event_type="settle",
        amount_usd="4",
        cost_status="actual",
        evidence_ref=final_ref,
        created_at=TIME,
    )
    with ledger.transaction() as tx:
        apply_budget_event(
            settled, tx, event_bytes=encoded(settled), context=budget_context(c.control, tx=tx)
        )
    adjustment_ref = c.proof()
    c.authority.billings[adjustment_ref.digest] = ("actual", "3", True, True, False)
    adjustment = BillingAdjustment(
        schema_version="kf.billing-adjustment.v1",
        project_id=PROJECT,
        run_id=RUN,
        reservation_id=attempt.reservation_id,
        adjustment_id=str(uuid4()),
        settlement_event_id=settled.event_id,
        expected_prior_actual_usd="4",
        revised_actual_usd="3",
        evidence_ref=adjustment_ref,
        created_at=TIME,
    )
    with ledger.transaction() as tx:
        apply_billing_adjustment(
            adjustment,
            tx,
            adjustment_bytes=encoded(adjustment),
            context=budget_context(c.control, tx=tx),
        )
    final_snapshot = control_snapshot(PROJECT, RUN, ledger, control=c.control)
    assert final_snapshot != snapshot
    c.authority.controls[command.digest] = ("reconcile_budget", final_snapshot, (), False, True)
    with pytest.raises(ContractError):
        reconcile_budget(
            PROJECT,
            RUN,
            snapshot,
            c.access,
            ledger,
            control=c.control,
            reason=Reason(code="unavailable", message="synthetic stale"),
            evidence_ref=command,
        )
    reconcile_budget(
        PROJECT,
        RUN,
        final_snapshot,
        c.access,
        ledger,
        control=c.control,
        reason=Reason(code="unavailable", message="synthetic complete"),
        evidence_ref=command,
    )
    with ledger.transaction() as tx:
        assert tx.connection.execute(
            sql.SQL("SELECT frozen FROM {} WHERE run_id=%s").format(tx.table("runs")), (RUN,)
        ).fetchone() == (False,)
        assert tx.connection.execute(
            sql.SQL("SELECT settled_usd,released_usd FROM {} WHERE reservation_id=%s").format(
                tx.table("reservations")
            ),
            (attempt.reservation_id,),
        ).fetchone() == (3, 0)


def test_final_bill_actual_and_release_residual_are_distinct(
    ledger: Ledger, tmp_path: Path
) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    attempt = c.dispatch(ledger, Executor(c))
    receipt = c.proof()
    c.authority.billings[receipt.digest] = ("actual", "3", True, True, False)
    settlement = BudgetEvent(
        schema_version="kf.budget-event.v1",
        project_id=PROJECT,
        run_id=RUN,
        reservation_id=attempt.reservation_id,
        attempt_id=attempt.attempt_id,
        scope="attempt",
        event_id=str(uuid4()),
        event_type="settle",
        amount_usd="3",
        cost_status="actual",
        evidence_ref=receipt,
        created_at=TIME,
    )
    release = settlement.model_copy(
        update={"event_id": str(uuid4()), "event_type": "release_unspent", "amount_usd": "1"}
    )
    forged = settlement.model_copy(update={"event_id": str(uuid4()), "amount_usd": "4"})
    with ledger.transaction() as tx, pytest.raises(ContractError):
        apply_budget_event(
            forged, tx, event_bytes=encoded(forged), context=budget_context(c.control, tx=tx)
        )
    with ledger.transaction() as tx:
        apply_budget_event(
            settlement,
            tx,
            event_bytes=encoded(settlement),
            context=budget_context(c.control, tx=tx),
        )
        apply_budget_event(
            release, tx, event_bytes=encoded(release), context=budget_context(c.control, tx=tx)
        )
    with ledger.transaction() as tx:
        assert tx.connection.execute(
            sql.SQL(
                "SELECT settled_usd,outstanding_usd,released_usd FROM {} WHERE reservation_id=%s"
            ).format(tx.table("reservations")),
            (attempt.reservation_id,),
        ).fetchone() == (3, 0, 1)


def test_observation_cannot_invent_running_without_remote_identity(
    ledger: Ledger, tmp_path: Path
) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c, lost=True)
    attempt = c.dispatch(ledger, executor)
    proof = c.proof()
    executor.next = Observation("running", None, None, proof)
    c.authority.observations[proof.digest] = (None, "running", None, False, False)
    with pytest.raises(ContractError):
        reconcile(attempt.attempt_id, ledger, executor, c.store, control=c.control)


def test_manual_retry_requires_exact_snapshot_and_cannot_bypass_cap(
    ledger: Ledger, tmp_path: Path
) -> None:
    from conscience_foundry.execution.control import control_snapshot
    from conscience_foundry.execution.ports import ManualRetry

    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c, lost=True)
    original = c.dispatch(ledger, executor)
    new_auth_id = str(uuid4())
    budget = c.plan.budget.model_copy(update={"authorization_id": new_auth_id})
    c.plan = c.plan.model_copy(update={"plan_id": str(uuid4()), "budget": budget})
    c.plan_ref = c.put(c.plan)
    c.auth = c.auth.model_copy(
        update={"authorization_id": new_auth_id, "allowed_plan_digests": (c.plan_ref.digest,)}
    )
    previous = c.auth_ref
    c.auth_ref = c.put(c.auth)
    old_auth_id = RunAuthorization.from_wire(
        c.store.read_verified(previous, c.access, 65536).data, c.bound
    ).authorization_id
    c.authority.grants[c.auth_ref.digest] = c.auth_ref.digest, old_auth_id
    with ledger.transaction() as tx:
        install_run_authorization(
            c.auth,
            c.auth_ref,
            encoded(c.auth),
            tx,
            context=budget_context(c.control, tx=tx),
            expected_previous_authorization_id=old_auth_id,
        )
    with pytest.raises(ContractError):
        c.dispatch(ledger, executor)
    snap = control_snapshot(
        PROJECT, RUN, ledger, control=c.control, operation_key=c.plan.operation_key
    )
    proof = c.proof()
    c.authority.controls[proof.digest] = ("manual_retry", snap, (original.attempt_id,), True, False)
    retry = ManualRetry(proof, snap, (original.attempt_id,))
    executor.lost = False
    grants = c.grants()
    replacement = dispatch(
        c.plan,
        c.auth,
        c.access,
        ledger,
        executor,
        grants,
        control=c.control,
        plan_ref=c.plan_ref,
        authorization_ref=c.auth_ref,
        asset_id=ASSET,
        evidence_ref=c.estimate,
        manual_retry=retry,
    )
    assert replacement.attempt_number == 2 and executor.calls == 2
    with ledger.transaction() as tx:
        assert (
            tx.connection.execute(
                sql.SQL("SELECT sum(outstanding_usd) FROM {}").format(tx.table("reservations"))
            ).fetchone()[0]
            == 8
        )
    with pytest.raises(ContractError):
        dispatch(
            c.plan,
            c.auth,
            c.access,
            ledger,
            executor,
            replace(grants, attempt_id=str(uuid4())),
            control=c.control,
            plan_ref=c.plan_ref,
            authorization_ref=c.auth_ref,
            asset_id=ASSET,
            evidence_ref=c.estimate,
            manual_retry=retry,
        )
    previous_id = c.auth.authorization_id
    next_id = str(uuid4())
    c.plan = c.plan.model_copy(
        update={
            "plan_id": str(uuid4()),
            "budget": c.plan.budget.model_copy(update={"authorization_id": next_id}),
        }
    )
    c.plan_ref = c.put(c.plan)
    c.auth = c.auth.model_copy(
        update={"authorization_id": next_id, "allowed_plan_digests": (c.plan_ref.digest,)}
    )
    c.auth_ref = c.put(c.auth)
    c.authority.grants[c.auth_ref.digest] = c.auth_ref.digest, previous_id
    with ledger.transaction() as tx:
        install_run_authorization(
            c.auth,
            c.auth_ref,
            encoded(c.auth),
            tx,
            context=budget_context(c.control, tx=tx),
            expected_previous_authorization_id=previous_id,
        )
    fresh = control_snapshot(
        PROJECT, RUN, ledger, control=c.control, operation_key=c.plan.operation_key
    )
    fresh_proof = c.proof()
    c.authority.controls[fresh_proof.digest] = (
        "manual_retry",
        fresh,
        (original.attempt_id,),
        True,
        False,
    )
    with pytest.raises(ContractError) as exhausted:
        dispatch(
            c.plan,
            c.auth,
            c.access,
            ledger,
            executor,
            c.grants(),
            control=c.control,
            plan_ref=c.plan_ref,
            authorization_ref=c.auth_ref,
            asset_id=ASSET,
            evidence_ref=c.estimate,
            manual_retry=ManualRetry(fresh_proof, fresh, (original.attempt_id,)),
        )
    assert exhausted.value.code == "budget_exhausted" and executor.calls == 2


def test_storage_billing_resolves_original_funding_plans_after_amendment(
    ledger: Ledger, tmp_path: Path
) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    storage = c.proof()
    c.authority.storage_estimates[storage.digest] = (
        "3",
        (c.plan_ref,),
        (c.authority.estimates[c.estimate.digest][1],),
    )
    with ledger.transaction() as tx:
        reservation = reserve_storage(
            RUN, "3", storage, tx, context=budget_context(c.control, tx=tx)
        )
    previous = c.auth.authorization_id
    amended = c.auth.model_copy(
        update={
            "authorization_id": str(uuid4()),
            "allowed_plan_digests": ("b" * 64,),
            "expires_at": "2026-10-27T00:00:00.000Z",
        }
    )
    amended_ref = c.put(amended)
    c.authority.grants[amended_ref.digest] = amended_ref.digest, previous
    with ledger.transaction() as tx:
        install_run_authorization(
            amended,
            amended_ref,
            encoded(amended),
            tx,
            context=budget_context(c.control, tx=tx),
            expected_previous_authorization_id=previous,
        )
    c.control = replace(c.control, clock=lambda: "2026-10-26T01:00:00.000Z")
    receipt = c.proof()
    c.authority.billings[receipt.digest] = ("actual", "2", True, True, False)
    c.authority.billing_plans[receipt.digest] = (c.plan_ref.digest,)
    settlement = BudgetEvent(
        schema_version="kf.budget-event.v1",
        project_id=PROJECT,
        run_id=RUN,
        reservation_id=reservation,
        scope="run_storage",
        event_id=str(uuid4()),
        event_type="settle",
        amount_usd="2",
        cost_status="actual",
        evidence_ref=receipt,
        created_at="2026-10-26T01:00:00.000Z",
    )
    release = settlement.model_copy(
        update={"event_id": str(uuid4()), "event_type": "release_unspent", "amount_usd": "1"}
    )
    with ledger.transaction() as tx:
        apply_budget_event(
            settlement,
            tx,
            event_bytes=encoded(settlement),
            context=budget_context(c.control, tx=tx),
        )
        apply_budget_event(
            release, tx, event_bytes=encoded(release), context=budget_context(c.control, tx=tx)
        )
    with ledger.transaction() as tx:
        assert tx.connection.execute(
            sql.SQL(
                "SELECT settled_usd,outstanding_usd,released_usd FROM {} WHERE reservation_id=%s"
            ).format(tx.table("reservations")),
            (reservation,),
        ).fetchone() == (2, 0, 1)


def test_storage_cannot_omit_an_authorized_plan(ledger: Ledger, tmp_path: Path) -> None:
    c = Case(tmp_path)
    c.auth = c.auth.model_copy(update={"allowed_plan_digests": (c.plan_ref.digest, "b" * 64)})
    c.auth_ref = c.put(c.auth)
    c.authority.grants[c.auth_ref.digest] = c.auth_ref.digest, None
    c.setup(ledger)
    proof = c.proof()
    c.authority.storage_estimates[proof.digest] = (
        "3",
        (c.plan_ref,),
        (c.authority.estimates[c.estimate.digest][1],),
    )
    with ledger.transaction() as tx, pytest.raises(ContractError):
        reserve_storage(RUN, "3", proof, tx, context=budget_context(c.control, tx=tx))


def test_replayed_attempt_id_and_missing_trusted_decoder_are_fail_closed(
    ledger: Ledger, tmp_path: Path
) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    executor = Executor(c)
    decoders = c.authority.decoders
    c.authority.decoders = MappingProxyType({})
    with pytest.raises(ContractError):
        c.dispatch(ledger, executor)
    assert executor.calls == 0
    c.authority.decoders = decoders
    grants = c.grants(material=(b"synthetic-opaque-material",))
    assert "synthetic-opaque-material" not in repr(grants)
    kwargs = dict(
        control=c.control,
        plan_ref=c.plan_ref,
        authorization_ref=c.auth_ref,
        asset_id=ASSET,
        evidence_ref=c.estimate,
    )
    for invalid in (
        replace(grants, plan_digest="b" * 64),
        replace(grants, destination_id="other"),
        replace(grants, expires_at=TIME),
    ):
        with pytest.raises(ContractError):
            dispatch(c.plan, c.auth, c.access, ledger, executor, invalid, **kwargs)
    first = dispatch(c.plan, c.auth, c.access, ledger, executor, grants, **kwargs)
    second = dispatch(c.plan, c.auth, c.access, ledger, executor, grants, **kwargs)
    assert first == second and executor.calls == 1
    with ledger.transaction() as tx:
        assert tx.connection.execute(
            sql.SQL("SELECT count(*) FROM {}").format(tx.table("reservations"))
        ).fetchone() == (1,)


@pytest.mark.parametrize("scope", ["run", "project"])
def test_resume_requires_current_grant_even_with_operator_evidence(
    ledger: Ledger, tmp_path: Path, scope: str
) -> None:
    c = Case(tmp_path)
    c.setup(ledger)
    c.dispatch(ledger, Executor(c, lost=True))
    pause = c.proof()
    c.authority.controls[pause.digest] = ("pause", None, (), False, False)
    target_run = RUN if scope == "run" else None
    reason = Reason(code="unavailable", message="synthetic stop")
    set_pause(
        scope,
        PROJECT,
        target_run,
        True,
        0,
        c.access,
        ledger,
        control=c.control,
        reason=reason,
        evidence_ref=pause,
    )
    c.control = replace(c.control, clock=lambda: "2026-10-26T01:00:00.000Z")
    resume = c.proof()
    c.authority.controls[resume.digest] = ("resume", None, (), False, False)
    with pytest.raises(ContractError):
        set_pause(
            scope,
            PROJECT,
            target_run,
            False,
            1,
            c.access,
            ledger,
            control=c.control,
            reason=reason,
            evidence_ref=resume,
        )
