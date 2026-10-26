"""Stub SDK and in-memory doubles exercise the bounded remote worker and capability gate.

No network, credential, provider payload or Modal SDK is used; every identifier,
token and byte string below is synthetic. Real platform restart, startup,
scheduling and cancellation behavior of a deployment is live capability
evidence, never asserted by these offline tests.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import io
import json
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from conscience_foundry.contracts.admission import AdmissionEntry, AdmissionReport
from conscience_foundry.contracts.canonical import (
    DocumentRevision,
    ExtractionSpec,
    OriginMap,
    QualityReport,
)
from conscience_foundry.contracts.common import (
    ArtifactRef,
    ContractError,
    ContractLimits,
    Instant,
)
from conscience_foundry.contracts.execution import ExecutionPlan, ResultManifest, StageAttempt
from conscience_foundry.core.identity import RevisionInputs, revision_id, structure_digest
from conscience_foundry.execution import worker as worker_module
from conscience_foundry.execution.capabilities import (
    PLATFORM_RETRY_CAVEAT,
    CapabilityRecord,
    validate_capabilities,
)
from conscience_foundry.execution.evidence import encoded
from conscience_foundry.execution.modal_adapter import (
    ModalExecutor,
    ModalPin,
    ModalPoll,
)
from conscience_foundry.execution.ports import Submission, TransportGrants
from conscience_foundry.execution.worker import run_worker
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.local import VerifiedBytes

PROJECT = "00000000-0000-0000-0000-000000000001"
SOURCE = "00000000-0000-0000-0000-000000000002"
ASSET = "00000000-0000-0000-0000-000000000003"
RUN = "00000000-0000-0000-0000-000000000004"
PLAN_ID = "00000000-0000-0000-0000-000000000005"
ATTEMPT = "00000000-0000-0000-0000-000000000006"
RESERVATION = "00000000-0000-0000-0000-000000000007"
AUTHORIZATION = "00000000-0000-0000-0000-000000000008"
ACTOR = "00000000-0000-0000-0000-000000000009"
BATCH = "00000000-0000-0000-0000-00000000000a"
START = datetime(2030, 1, 1, tzinfo=UTC)
NOW = "2030-01-01T00:00:00.000Z"
LATER = "2030-01-01T01:00:00.000Z"
GRANT_EXPIRY = "2030-01-01T00:30:00.000Z"
PAST = "2031-01-01T00:00:00.000Z"
SOURCE_BYTES = "A😀é\r\nB".encode()
SECRET = b"synthetic-secret-token-material"
DESTINATION = "synthetic.destination"
IMAGE = "a" * 64
CODE = "b" * 64


def instant(seconds: float) -> Instant:
    moment = START + timedelta(seconds=seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def make_ref(
    data: bytes, schema: str, media: str = "application/json", project: str = PROJECT
) -> ArtifactRef:
    return ArtifactRef(
        schema_version="kf.artifact-ref.v1",
        project_id=project,
        digest=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        media_type=media,
        artifact_schema=schema,
        locations=(),
    )


def make_limits(**changes: object) -> ContractLimits:
    return ContractLimits.model_validate(
        {
            "schemaVersion": "kf.contract-limits.v1",
            "version": "synthetic.worker-limits.v1",
            "maxJsonBytes": 65536,
            "maxStringScalars": 4096,
            "maxArrayItems": 128,
            "maxDepth": 16,
            "maxManifestItems": 4,
            "maxSourceBytes": 65536,
            "maxOutputBytes": 65536,
            "maxErrorMessageScalars": 80,
        }
        | changes
    )


class MemoryStore:
    """ObjectStore double that logs every effect by operation and schema, never payloads."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.log: list[tuple[str, str]] = []
        self.contexts: list[AccessContext] = []

    def put_verified(
        self, stream: Any, expected: ArtifactRef, context: AccessContext
    ) -> ArtifactRef:
        self.log.append(("write", expected.artifact_schema))
        self.contexts.append(context)
        data = stream.read()
        assert hashlib.sha256(data).hexdigest() == expected.digest
        self.objects[expected.digest] = data
        return expected

    def open_verified(self, ref: ArtifactRef, context: AccessContext) -> Any:
        return io.BytesIO(self.read_verified(ref, context, ref.size_bytes).data)

    def read_verified(self, ref: ArtifactRef, context: AccessContext, limit: int) -> VerifiedBytes:
        self.log.append(("read", ref.artifact_schema))
        self.contexts.append(context)
        if ref.size_bytes > limit:
            raise ContractError("limit_exceeded")
        data = self.objects.get(ref.digest)
        if data is None:
            raise ContractError("artifact_missing")
        return VerifiedBytes(data, ref.digest)

    def writes(self) -> list[str]:
        return [schema for operation, schema in self.log if operation == "write"]


class StepClock:
    """Instant source that counts calls and can report an expired time from a given call."""

    def __init__(self, expire_at_call: int | None = None, base: str = NOW) -> None:
        self.calls = 0
        self.expire_at_call = expire_at_call
        self.base = base

    def now(self) -> Instant:
        self.calls += 1
        if self.expire_at_call is not None and self.calls >= self.expire_at_call:
            return PAST
        return self.base


@dataclass
class Scenario:
    plan: ExecutionPlan
    plan_bytes: bytes
    attempt: StageAttempt
    attempt_bytes: bytes
    grants: TransportGrants
    store: MemoryStore
    limits: ContractLimits
    spec_ref: ArtifactRef
    source_ref: ArtifactRef
    limits_ref: ArtifactRef
    report_ref: ArtifactRef
    extras: dict[str, Any] = field(default_factory=dict)


def build(
    *,
    source: bytes = SOURCE_BYTES,
    limits: ContractLimits | None = None,
    resources: dict[str, Any] | None = None,
    grant_expiry: str = GRANT_EXPIRY,
    plan_expiry: str = LATER,
    attempt_state: str = "dispatching",
    store_source: bool = True,
) -> Scenario:
    bound = limits if limits is not None else make_limits()
    store = MemoryStore()
    limits_raw = bound.model_dump_json(by_alias=True).encode()
    limits_ref = make_ref(limits_raw, "kf.contract-limits.v1")
    spec = ExtractionSpec.model_validate(
        {
            "schema_version": "kf.extraction-spec.v1",
            "processor_id": "text.utf8.v1",
            "processor_version": "synthetic.processor.v1",
            "code_version": "synthetic.code.v1",
            "image_digest": IMAGE,
            "limits_ref": limits_ref,
            "normalization": "none",
            "newline_policy": "preserve",
            "bom_policy": "reject",
        }
    )
    spec_raw = encoded(spec)
    spec_ref = make_ref(spec_raw, "kf.extraction-spec.v1")
    source_ref = make_ref(source, "kf.raw-original.v1", "text/plain")
    report = AdmissionReport(
        schema_version="kf.admission-report.v1",
        project_id=PROJECT,
        batch_id=BATCH,
        manifest_digest="c" * 64,
        policy_version="synthetic.policy.v1",
        checked_at=NOW,
        entries=(
            AdmissionEntry(
                asset_id=ASSET,
                source_id=SOURCE,
                status="admitted",
                reasons=(),
                snapshot_ref=source_ref,
            ),
        ),
    )
    report_raw = encoded(report)
    report_ref = make_ref(report_raw, "kf.admission-report.v1")
    tariff_ref = make_ref(b"synthetic tariff", "kf.tariff.v1")
    values: dict[str, Any] = {
        "cpu_milli": 1000,
        "memory_mib": 512,
        "gpu_count": 0,
        "max_wall_seconds": 600,
        "max_output_bytes": 65536,
        "max_concurrent_attempts": 1,
        "max_attempts_per_operation": 1,
        "automatic_retries": 0,
    } | (resources or {})
    plan = ExecutionPlan.model_validate(
        {
            "schema_version": "kf.execution-plan.v1",
            "project_id": PROJECT,
            "run_id": RUN,
            "plan_id": PLAN_ID,
            "execution_config_ref": make_ref(b"synthetic config", "kf.execution-config.v1"),
            "admission_report_ref": report_ref,
            "extraction_spec_ref": spec_ref,
            "policy_ref": make_ref(b"synthetic policy", "kf.policy.v1"),
            "profile_id": "technical_minimal",
            "profile_version": "synthetic.profile.v1",
            "contract_set_ref": make_ref(b"synthetic contracts", "kf.contract-set.v1"),
            "limits_refs": (limits_ref,),
            "input_refs": (source_ref,),
            "operation_key": "d" * 64,
            "resources": values,
            "budget": {
                "currency": "USD",
                "max_run_cost": "10",
                "max_attempt_cost": "4",
                "tariff_ref": tariff_ref,
                "authorization_id": AUTHORIZATION,
                "valid_until": plan_expiry,
            },
            "expires_at": plan_expiry,
        }
    )
    plan_bytes = encoded(plan)
    attempt = StageAttempt.model_validate(
        {
            "schema_version": "kf.stage-attempt.v1",
            "project_id": PROJECT,
            "plan_id": PLAN_ID,
            "operation_key": "d" * 64,
            "attempt_id": ATTEMPT,
            "attempt_number": 1,
            "reservation_id": RESERVATION,
            "state": attempt_state,
            "created_at": NOW,
            **({"dispatched_at": NOW} if attempt_state != "reserved" else {}),
        }
    )
    grants = TransportGrants(
        project_id=PROJECT,
        plan_digest=hashlib.sha256(plan_bytes).hexdigest(),
        attempt_id=ATTEMPT,
        destination_id=DESTINATION,
        expires_at=grant_expiry,
        material=(SECRET,),
        output_scope=b"synthetic-bucket/staging/attempts/",
    )
    for ref, raw in (
        (limits_ref, limits_raw),
        (spec_ref, spec_raw),
        (report_ref, report_raw),
    ):
        store.objects[ref.digest] = raw
    if store_source:
        store.objects[source_ref.digest] = source
    return Scenario(
        plan,
        plan_bytes,
        attempt,
        encoded(attempt),
        grants,
        store,
        bound,
        spec_ref,
        source_ref,
        limits_ref,
        report_ref,
    )


def execute(scenario: Scenario, clock: StepClock | None = None) -> ArtifactRef:
    return run_worker(
        scenario.plan_bytes,
        scenario.attempt_bytes,
        scenario.grants,
        scenario.store,
        clock or StepClock(),
    )


def read_manifest(scenario: Scenario, ref: ArtifactRef) -> ResultManifest:
    return ResultManifest.from_wire(scenario.store.objects[ref.digest], scenario.limits)


# -- worker -----------------------------------------------------------------------------


def test_worker_has_no_ledger_or_model_dependency() -> None:
    # worker_receives_no_database_credentials: nothing database-shaped enters or is read
    parameters = set(inspect.signature(run_worker).parameters)
    assert parameters == {"plan_bytes", "attempt_bytes", "grants", "store", "clock"}
    assert not {"dsn", "database", "connection", "ledger", "credentials"} & parameters
    tree = ast.parse(Path(inspect.getfile(worker_module)).read_text())
    imported = {
        alias.name.split(".")[0] if isinstance(node, ast.Import) else (node.module or "")
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not {"os", "psycopg", "modal", "boto3", "anthropic", "pydantic_ai"} & imported
    probe = (
        "import sys, conscience_foundry.execution.worker as w;"
        "bad=[m for m in sys.modules if m.split('.')[0] in "
        "{'psycopg','modal','boto3','anthropic','pydantic_ai','dagster'} "
        "or m.startswith('conscience_foundry.ledger')];"
        "print(','.join(sorted(bad)))"
    )
    loaded = subprocess.run(
        [sys.executable, "-I", "-c", probe], capture_output=True, text=True, check=True
    )
    assert loaded.stdout.strip() == ""

    # the result is the verified canonical output and the manifest is the last write
    scenario = build()
    manifest_ref = execute(scenario)
    assert manifest_ref.artifact_schema == "kf.result.v1"
    assert scenario.store.writes()[-1] == "kf.result.v1"
    assert scenario.store.writes().count("kf.result.v1") == 1
    assert scenario.store.writes() == [
        "kf.canonical-text.v1",
        "kf.origin-map.v1",
        "kf.quality-report.v1",
        "kf.document-revision.v1",
        "kf.result.v1",
    ]
    manifest = read_manifest(scenario, manifest_ref)
    assert manifest.status == "succeeded"
    assert (manifest.project_id, manifest.attempt_id) == (PROJECT, ATTEMPT)
    assert manifest.operation_key == scenario.plan.operation_key
    assert manifest.input_digests == (scenario.source_ref.digest,)
    assert manifest.usage.cost_status == "unknown"
    assert manifest.usage.cost_usd is None
    assert manifest.usage.tariff_ref == scenario.plan.budget.tariff_ref
    for output in manifest.outputs:
        assert hashlib.sha256(scenario.store.objects[output.digest]).hexdigest() == output.digest
    text = next(o for o in manifest.outputs if o.artifact_schema == "kf.canonical-text.v1")
    assert scenario.store.objects[text.digest] == SOURCE_BYTES
    revision = DocumentRevision.from_wire(
        scenario.store.objects[manifest.document_revision_ref.digest],  # type: ignore[union-attr]
        scenario.limits,
    )
    revision.validate_f1(len(SOURCE_BYTES.decode("utf-8")))
    assert (revision.source_id, revision.asset_id) == (SOURCE, ASSET)
    origin = OriginMap.from_wire(
        scenario.store.objects[revision.origin_map_ref.digest], scenario.limits
    )
    quality = QualityReport.from_wire(
        scenario.store.objects[revision.quality_report_ref.digest], scenario.limits
    )
    assert quality.disposition == "valid"
    assert revision.revision_id == revision_id(
        RevisionInputs(
            PROJECT,
            SOURCE,
            scenario.source_ref.digest,
            revision.text_ref.digest,
            scenario.spec_ref.digest,
            structure_digest(revision.sections, limits=scenario.limits),
            revision.origin_map_ref.digest,
        ),
        limits=scenario.limits,
    )
    assert origin.original_digest == scenario.source_ref.digest
    # the worker acts as the attempt with read-only plus transfer/extract scope
    assert {context.project_id for context in scenario.store.contexts} == {PROJECT}
    assert all("publish" not in context.scopes for context in scenario.store.contexts)


def test_function_retry_zero_does_not_prove_platform_bounds() -> None:
    scenario = build()
    complete = capability(scenario.plan)
    validate_capabilities(complete, scenario.plan)

    # retries=0 with finite function timeouts, but no evidenced crash-restart bound: blocked
    for unproven in (
        replace_record(complete, platform_restart_bound="unknown", max_platform_restarts=None),
        replace_record(complete, platform_restart_bound="unbounded", max_platform_restarts=None),
        replace_record(complete, total_bound_seconds=None),
    ):
        assert unproven.function_retries == 0
        with pytest.raises(ContractError) as blocked:
            validate_capabilities(unproven, scenario.plan)
        assert blocked.value.code == "unsupported_capability"
    assert "retries=0" in PLATFORM_RETRY_CAVEAT and "restart" in PLATFORM_RETRY_CAVEAT

    # the executor never reaches the SDK on a blocked record
    sdk = FakeModal()
    executor = make_executor(
        scenario,
        sdk,
        record=replace_record(
            complete, platform_restart_bound="unknown", max_platform_restarts=None
        ),
    )
    with pytest.raises(ContractError) as refused:
        executor.submit(scenario.plan, scenario.attempt, scenario.grants)
    assert refused.value.code == "unsupported_capability"
    assert sdk.spawned == []

    # an expired envelope has no application effects: nothing is read, written or listed
    expired = build()
    clock = StepClock(expire_at_call=1)
    with pytest.raises(ContractError) as late:
        execute(expired, clock)
    assert late.value.code == "authorization_expired"
    assert expired.store.log == []
    assert clock.calls == 1


@pytest.mark.parametrize("expired_call", range(1, 11))
def test_deadline_is_checked_at_entry_and_before_every_bounded_step(expired_call: int) -> None:
    scenario = build()
    clock = StepClock(expire_at_call=expired_call)
    with pytest.raises(ContractError) as late:
        execute(scenario, clock)
    assert late.value.code == "authorization_expired"
    # call 1 is the entry check; each of the nine bounded external steps is preceded by one more
    assert len(scenario.store.log) == max(expired_call - 2, 0)
    assert "kf.result.v1" not in scenario.store.writes()
    assert clock.calls == expired_call


def test_a_run_that_stays_in_time_makes_one_check_per_step() -> None:
    scenario = build()
    clock = StepClock()
    execute(scenario, clock)
    assert clock.calls == 1 + len(scenario.store.log) == 10


@pytest.mark.parametrize(
    "case",
    ["grant_expired", "plan_digest", "attempt_id", "project", "state", "operation", "garbage"],
)
def test_untrusted_envelope_is_refused_before_any_effect(case: str) -> None:
    scenario = build()
    plan_bytes, attempt_bytes, grants = scenario.plan_bytes, scenario.attempt_bytes, scenario.grants
    if case == "grant_expired":
        grants = replace(grants, expires_at=NOW)
    elif case == "plan_digest":
        grants = replace(grants, plan_digest="e" * 64)
    elif case == "attempt_id":
        grants = replace(grants, attempt_id="00000000-0000-0000-0000-0000000000ff")
    elif case == "project":
        grants = replace(grants, project_id="00000000-0000-0000-0000-0000000000ff")
    elif case == "state":
        other = build(attempt_state="reserved")
        attempt_bytes = other.attempt_bytes
    elif case == "operation":
        attempt_bytes = attempt_bytes.replace(b"d" * 64, b"f" * 64)
    else:
        plan_bytes = b"{not json"
        grants = replace(grants, plan_digest=hashlib.sha256(plan_bytes).hexdigest())
    with pytest.raises(ContractError):
        run_worker(plan_bytes, attempt_bytes, grants, scenario.store, StepClock())
    assert scenario.store.log == []


def test_output_ceiling_is_enforced_before_any_write() -> None:
    # large enough to read every pinned input, too small for the outputs plus the manifest
    scenario = build(resources={"max_output_bytes": 1024})
    with pytest.raises(ContractError) as over:
        execute(scenario)
    assert over.value.code == "limit_exceeded"
    assert [operation for operation, _ in scenario.store.log] == ["read"] * 4
    assert scenario.store.writes() == []


def test_memory_ceiling_bounds_the_working_set() -> None:
    # memoryMiB is positive; a source that cannot fit the working set is refused before reading it
    big = b"x" * (2 * 1024 * 1024)
    scenario = build(
        source=big,
        limits=make_limits(maxSourceBytes=4 * 1024 * 1024, maxOutputBytes=64 * 1024 * 1024),
        resources={"memory_mib": 1, "max_output_bytes": 64 * 1024 * 1024},
    )
    with pytest.raises(ContractError) as over:
        execute(scenario)
    assert over.value.code == "limit_exceeded"
    assert ("read", "kf.raw-original.v1") not in scenario.store.log
    assert scenario.store.writes() == []


def test_wall_ceiling_is_part_of_the_deadline() -> None:
    scenario = build(resources={"max_wall_seconds": 5})

    class Drifting:
        def __init__(self) -> None:
            self.calls = 0

        def now(self) -> Instant:
            self.calls += 1
            return instant(0 if self.calls == 1 else 6)

    with pytest.raises(ContractError) as late:
        execute(scenario, Drifting())  # type: ignore[arg-type]
    assert late.value.code == "authorization_expired"
    assert "kf.result.v1" not in scenario.store.writes()


def test_content_failure_is_a_failed_manifest_written_last_and_infrastructure_is_not() -> None:
    scenario = build(source=b"\xef\xbb\xbfbom")
    manifest_ref = execute(scenario)
    manifest = read_manifest(scenario, manifest_ref)
    assert manifest.status == "failed"
    assert [error.code for error in manifest.errors] == ["bom_rejected"]
    assert manifest.outputs == ()
    assert scenario.store.writes() == ["kf.result.v1"]

    # a missing source is an unavailable input, not a proven content failure: no manifest
    missing = build(store_source=False)
    with pytest.raises(ContractError):
        execute(missing)
    assert missing.store.writes() == []


# -- capability record -------------------------------------------------------------------


def capability(plan: ExecutionPlan, **changes: Any) -> CapabilityRecord:
    values: dict[str, Any] = {
        "schema_version": "kf.modal-capability-record.v1",
        "project_id": PROJECT,
        "execution_config_ref": plan.execution_config_ref,
        "sdk_version": "synthetic-sdk.1",
        "deployment_version": "synthetic.deployment.v1",
        "image_digest": IMAGE,
        "code_digest": CODE,
        "cpu_milli": 1000,
        "memory_mib": 512,
        "gpu_count": 0,
        "function_retries": 0,
        "startup_timeout_seconds": 60,
        "scheduling_timeout_seconds": 120,
        "execution_timeout_seconds": 300,
        "platform_restart_bound": "bounded",
        "max_platform_restarts": 0,
        "total_bound_seconds": 480,
        "cancellation": "terminates_containers",
        "deadline_enforcement": "entry_and_every_bounded_step",
        "valid_until": plan.budget.valid_until,
        "source_evidence_refs": (make_ref(b"synthetic evidence", "kf.capability-source.v1"),),
    }
    return CapabilityRecord.model_validate(values | changes)


def replace_record(record: CapabilityRecord, **changes: Any) -> CapabilityRecord:
    value = record.model_dump(exclude_none=True) | changes
    if value.get("max_platform_restarts", 0) is None:
        value.pop("max_platform_restarts", None)
    if value.get("total_bound_seconds", 0) is None:
        value.pop("total_bound_seconds", None)
    return CapabilityRecord.model_validate(value)


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"gpu_count": 1}, "unsupported_capability"),
        ({"function_retries": 1}, "unsupported_capability"),
        ({"cancellation": "request_only"}, "unsupported_capability"),
        ({"cancellation": "unsupported"}, "unsupported_capability"),
        ({"deadline_enforcement": "entry_only"}, "unsupported_capability"),
        ({"deadline_enforcement": "none"}, "unsupported_capability"),
        ({"cpu_milli": 1001}, "limit_exceeded"),
        ({"memory_mib": 513}, "limit_exceeded"),
        ({"total_bound_seconds": 601}, "limit_exceeded"),
        # the declared total cannot be smaller than its own components allow
        ({"total_bound_seconds": 479}, "unsupported_capability"),
        (
            {"max_platform_restarts": 1, "total_bound_seconds": 600},
            "unsupported_capability",
        ),
        ({"project_id": "00000000-0000-0000-0000-0000000000ff"}, "forbidden"),
        ({"valid_until": "2029-12-31T00:00:00.000Z"}, "authorization_expired"),
    ],
)
def test_capability_record_must_cover_the_plan(changes: dict[str, Any], code: str) -> None:
    scenario = build()
    record = capability(scenario.plan, **changes)
    with pytest.raises(ContractError) as blocked:
        validate_capabilities(record, scenario.plan)
    assert blocked.value.code == code


def test_capability_record_binds_the_plan_config_and_cites_evidence() -> None:
    scenario = build()
    other = make_ref(b"another config", "kf.execution-config.v1")
    with pytest.raises(ContractError) as swapped:
        validate_capabilities(capability(scenario.plan, execution_config_ref=other), scenario.plan)
    assert swapped.value.code == "forbidden"
    with pytest.raises(ContractError) as foreign:
        validate_capabilities(
            capability(
                scenario.plan,
                source_evidence_refs=(
                    make_ref(
                        b"e",
                        "kf.capability-source.v1",
                        project="00000000-0000-0000-0000-0000000000ff",
                    ),
                ),
            ),
            scenario.plan,
        )
    assert foreign.value.code == "forbidden"
    with pytest.raises(ValueError):
        capability(scenario.plan, source_evidence_refs=())
    with pytest.raises(ValueError):
        capability(scenario.plan, platform_restart_bound="bounded", max_platform_restarts=None)
    with pytest.raises(ValueError):
        capability(scenario.plan, unexpected_field=1)
    with pytest.raises(ContractError) as untyped:
        validate_capabilities("not a record", scenario.plan)  # type: ignore[arg-type]
    assert untyped.value.code == "invalid_schema"


# -- executor ----------------------------------------------------------------------------


class FakeModal:
    """Stub SDK: spawn/poll/cancel with scriptable outcomes; no network, no deployment."""

    def __init__(self) -> None:
        self.spawned: list[tuple[str, dict[str, Any]]] = []
        self.polled: list[str] = []
        self.cancelled: list[str] = []
        self.spawn_error: Exception | None = None
        self.call_id: Any = "synthetic-call-1"
        self.polls: list[ModalPoll | Exception] = []
        self.cancel_error: Exception | None = None

    def spawn(self, function: str, payload: Any) -> str:
        self.spawned.append((function, dict(payload)))
        if self.spawn_error is not None:
            raise self.spawn_error
        return self.call_id  # type: ignore[no-any-return]

    def poll(self, call_id: str) -> ModalPoll:
        self.polled.append(call_id)
        outcome = self.polls.pop(0) if self.polls else ModalPoll("pending")
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def cancel(self, call_id: str) -> None:
        self.cancelled.append(call_id)
        if self.cancel_error is not None:
            raise self.cancel_error


def make_executor(
    scenario: Scenario,
    sdk: FakeModal,
    *,
    record: CapabilityRecord | None = None,
    pin: ModalPin | None = None,
    clock: Callable[[], Instant] | None = None,
    evidence: list[tuple[str, bytes]] | None = None,
) -> ModalExecutor:
    log = evidence if evidence is not None else []

    def sink(schema: str, data: bytes) -> ArtifactRef:
        log.append((schema, data))
        return make_ref(data, schema)

    return ModalExecutor(
        sdk=sdk,
        pin=pin
        or ModalPin(
            app_name="synthetic-app",
            function_name="synthetic-worker",
            deployment_version="synthetic.deployment.v1",
            image_digest=IMAGE,
            code_digest=CODE,
            sdk_version="synthetic-sdk.1",
            destination_id=DESTINATION,
        ),
        record=record or capability(scenario.plan),
        execution_config_digest=scenario.plan.execution_config_ref.digest,
        store=scenario.store,
        access=AccessContext(PROJECT, ACTOR, frozenset({"read"})),
        limits=scenario.limits,
        clock=clock or (lambda: NOW),
        evidence=sink,
    )


def running(scenario: Scenario, call_id: str = "synthetic-call-1") -> StageAttempt:
    return StageAttempt.model_validate(
        scenario.attempt.model_dump(by_alias=True, exclude_none=True)
        | {"state": "running", "remoteCallId": call_id}
    )


def test_submit_spawns_once_with_a_bounded_payload_and_returns_the_call_id() -> None:
    scenario = build()
    sdk = FakeModal()
    executor = make_executor(scenario, sdk)
    submission = executor.submit(scenario.plan, scenario.attempt, scenario.grants)
    assert submission == Submission("synthetic-call-1", True)
    ((function, payload),) = sdk.spawned
    assert function == "synthetic-worker"
    assert payload["plan_bytes"] == scenario.plan_bytes
    assert payload["attempt_bytes"] == scenario.attempt_bytes
    assert set(payload) == {"plan_bytes", "attempt_bytes", "grants"}
    # no database or ledger material rides along
    assert "dsn" not in json.dumps(sorted(payload), default=str).lower()
    # a second submit of the same attempt never spawns again
    with pytest.raises(ContractError) as repeat:
        executor.submit(scenario.plan, scenario.attempt, scenario.grants)
    assert repeat.value.code == "dispatch_unknown"
    assert len(sdk.spawned) == 1
    assert SECRET not in repr(executor).encode() and SECRET not in repr(submission).encode()


@pytest.mark.parametrize("failure", ["raises", "no_call_id", "empty_call_id"])
def test_ambiguous_spawn_is_unknown_and_is_never_retried(failure: str) -> None:
    scenario = build()
    sdk = FakeModal()
    if failure == "raises":
        sdk.spawn_error = TimeoutError("synthetic lost response")
    elif failure == "no_call_id":
        sdk.call_id = None
    else:
        sdk.call_id = ""
    executor = make_executor(scenario, sdk)
    submission = executor.submit(scenario.plan, scenario.attempt, scenario.grants)
    assert submission == Submission(None, None)
    with pytest.raises(ContractError) as repeat:
        executor.submit(scenario.plan, scenario.attempt, scenario.grants)
    assert repeat.value.code == "dispatch_unknown"
    assert len(sdk.spawned) == 1


def test_submit_fails_closed_before_any_spawn() -> None:
    scenario = build()

    def refused(**kwargs: Any) -> None:
        sdk = FakeModal()
        grants = kwargs.pop("grants", scenario.grants)
        attempt = kwargs.pop("attempt", scenario.attempt)
        executor = make_executor(scenario, sdk, **kwargs)
        with pytest.raises(ContractError):
            executor.submit(scenario.plan, attempt, grants)
        assert sdk.spawned == []

    pin = ModalPin(
        "synthetic-app",
        "synthetic-worker",
        "synthetic.deployment.v1",
        IMAGE,
        CODE,
        "synthetic-sdk.1",
        DESTINATION,
    )
    refused(pin=replace(pin, image_digest="9" * 64))
    refused(pin=replace(pin, code_digest="9" * 64))
    refused(pin=replace(pin, deployment_version="other.deployment"))
    refused(pin=replace(pin, sdk_version="other-sdk"))
    refused(pin=replace(pin, destination_id="other.destination"))
    refused(grants=replace(scenario.grants, destination_id="other.destination"))
    refused(grants=replace(scenario.grants, plan_digest="e" * 64))
    refused(grants=replace(scenario.grants, expires_at=NOW))
    refused(clock=lambda: PAST)
    refused(attempt=build(attempt_state="reserved").attempt)
    # capability evidence for another image is not evidence for this deployment
    refused(record=capability(scenario.plan, image_digest="9" * 64))
    refused(record=capability(scenario.plan, function_retries=1))


def poll_executor(
    scenario: Scenario, *polls: ModalPoll | Exception
) -> tuple[ModalExecutor, FakeModal, list[tuple[str, bytes]]]:
    sdk = FakeModal()
    sdk.polls = list(polls)
    evidence: list[tuple[str, bytes]] = []
    return make_executor(scenario, sdk, evidence=evidence), sdk, evidence


def test_observe_maps_sdk_outcomes_without_inventing_failure_or_absence() -> None:
    scenario = build()
    manifest_ref = execute(scenario)
    result = manifest_ref.model_dump_json(by_alias=True, exclude_none=True).encode()
    attempt = running(scenario)

    executor, sdk, evidence = poll_executor(scenario, ModalPoll("pending"))
    observed = executor.observe(attempt)
    assert (observed.state, observed.result_ref, observed.usage) == ("running", None, None)
    assert sdk.polled == ["synthetic-call-1"]
    ((schema, raw),) = evidence
    assert observed.evidence.artifact_schema == schema
    assert observed.evidence.digest == hashlib.sha256(raw).hexdigest()
    assert SECRET not in raw and b"planBytes" not in raw and b"plan_bytes" not in raw
    assert json.loads(raw)["remoteCallId"] == "synthetic-call-1"

    executor, _, _ = poll_executor(scenario, ModalPoll("completed", result))
    done = executor.observe(attempt)
    assert (done.state, done.result_ref) == ("succeeded", manifest_ref)

    failed_scenario = build(source=b"\xef\xbb\xbfbom")
    failed_ref = execute(failed_scenario)
    executor, _, _ = poll_executor(
        failed_scenario,
        ModalPoll(
            "completed", failed_ref.model_dump_json(by_alias=True, exclude_none=True).encode()
        ),
    )
    assert executor.observe(running(failed_scenario)).state == "failed"

    executor, _, _ = poll_executor(scenario, ModalPoll("remote_error"))
    assert executor.observe(attempt).state == "failed"
    executor, _, _ = poll_executor(scenario, ModalPoll("cancelled"))
    assert executor.observe(attempt).state == "cancelled"

    # a timeout, expired output, an SDK failure or an unreadable result prove nothing
    for outcome in (
        ModalPoll("timed_out"),
        ModalPoll("output_expired"),
        ModalPoll("completed", b"{broken"),
        ModalPoll("completed", None),
        ModalPoll("surprising"),  # type: ignore[arg-type]
        TimeoutError("synthetic poll timeout"),
        ConnectionError("synthetic reset"),
    ):
        executor, _, _ = poll_executor(scenario, outcome)
        unresolved = executor.observe(attempt)
        assert unresolved.state == "unknown_outcome", outcome
        assert unresolved.result_ref is None

    # a manifest that cannot be verified from the store is unknown, never failed or absent
    scenario.store.objects.pop(manifest_ref.digest)
    executor, _, _ = poll_executor(scenario, ModalPoll("completed", result))
    assert executor.observe(attempt).state == "unknown_outcome"

    # a result nominating another project's manifest is not accepted as this attempt's result
    foreign = make_ref(b"x", "kf.result.v1", project="00000000-0000-0000-0000-0000000000ff")
    executor, _, _ = poll_executor(
        scenario,
        ModalPoll("completed", foreign.model_dump_json(by_alias=True, exclude_none=True).encode()),
    )
    assert executor.observe(attempt).state == "unknown_outcome"


def test_observe_without_a_call_id_cannot_query_and_reports_unknown() -> None:
    scenario = build()
    executor, sdk, _ = poll_executor(scenario)
    observed = executor.observe(scenario.attempt)
    assert observed.state == "unknown_outcome"
    assert sdk.polled == []


def test_evidence_failure_surfaces_instead_of_claiming_an_outcome() -> None:
    scenario = build()
    sdk = FakeModal()

    def broken(_schema: str, _data: bytes) -> ArtifactRef:
        raise OSError("synthetic evidence store outage")

    executor = make_executor(scenario, sdk)
    executor.evidence = broken
    with pytest.raises(ContractError) as unavailable:
        executor.observe(running(scenario))
    assert unavailable.value.code == "unavailable"


def test_cancel_request_is_not_confirmed_termination() -> None:
    scenario = build()
    attempt = running(scenario)

    # cancel accepted, the call still reports pending: only a request, funds stay reserved
    executor, sdk, _ = poll_executor(scenario, ModalPoll("pending"))
    observed = executor.cancel(attempt)
    assert sdk.cancelled == ["synthetic-call-1"]
    assert observed.state == "cancel_requested"

    # cancel accepted and the SDK reports the call cancelled
    executor, _, _ = poll_executor(scenario, ModalPoll("cancelled"))
    assert executor.cancel(attempt).state == "cancelled"

    # the call finished anyway: report what the provider says, never "cancelled"
    manifest_ref = execute(scenario)
    result = manifest_ref.model_dump_json(by_alias=True, exclude_none=True).encode()
    executor, _, _ = poll_executor(scenario, ModalPoll("completed", result))
    assert executor.cancel(attempt).state == "succeeded"

    # a post-cancel poll that cannot settle is still just a request
    executor, _, _ = poll_executor(scenario, TimeoutError("synthetic"))
    assert executor.cancel(attempt).state == "cancel_requested"

    # a cancel the SDK rejected stays uncertain: raised, never reported as cancelled
    executor, sdk, _ = poll_executor(scenario)
    sdk.cancel_error = ConnectionError("synthetic reset")
    with pytest.raises(ContractError) as uncertain:
        executor.cancel(attempt)
    assert uncertain.value.code == "dispatch_unknown"

    # no call id means nothing to cancel remotely, and nothing is claimed
    executor, sdk, _ = poll_executor(scenario)
    assert executor.cancel(scenario.attempt).state == "unknown_outcome"
    assert sdk.cancelled == []


def test_importing_the_adapter_never_imports_or_deploys_the_sdk() -> None:
    probe = (
        "import sys, conscience_foundry.execution.modal_adapter as m;"
        "import conscience_foundry.execution.capabilities;"
        "print('modal' in sys.modules, hasattr(m, 'deploy'), hasattr(m, 'app'))"
    )
    loaded = subprocess.run(
        [sys.executable, "-I", "-c", probe], capture_output=True, text=True, check=True
    )
    assert loaded.stdout.split() == ["False", "False", "False"]
    source = Path(inspect.getfile(sys.modules["conscience_foundry.execution.modal_adapter"]))
    names = {
        node.module or ""
        for node in ast.walk(ast.parse(source.read_text()))
        if isinstance(node, ast.ImportFrom)
    } | {
        alias.name
        for node in ast.walk(ast.parse(source.read_text()))
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert not {"modal", "os", "subprocess", "socket", "requests", "httpx"} & names
