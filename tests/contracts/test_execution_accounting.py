"""Synthetic wire contracts and authorization checks; no ledger or provider calls."""

import copy
import hashlib
import json

import pytest
from pydantic import ValidationError

from conscience_foundry.contracts.accounting import (
    BillingAdjustment,
    BudgetEvent,
    OperationResultRecord,
    ResourceUsage,
    RunReport,
)
from conscience_foundry.contracts.admission import AdmissionReport, IntakeManifest
from conscience_foundry.contracts.common import ContractError, ContractLimits
from conscience_foundry.contracts.execution import (
    BudgetEnvelope,
    ExecutionConfig,
    ExecutionPlan,
    ResourceEnvelope,
    ResultManifest,
    RunAuthorization,
    StageAttempt,
    validate_plan_authorization,
)
from conscience_foundry.contracts.project import PolicyArtifact

PROJECT = "00000000-0000-0000-0000-000000000001"
RUN = "00000000-0000-0000-0000-000000000002"
PLAN = "00000000-0000-0000-0000-000000000003"
AUTH = "00000000-0000-0000-0000-000000000004"
ATTEMPT = "00000000-0000-0000-0000-000000000005"
RESERVATION = "00000000-0000-0000-0000-000000000006"
EVENT = "00000000-0000-0000-0000-000000000007"
ACTOR = "00000000-0000-0000-0000-000000000008"
ASSET = "00000000-0000-0000-0000-000000000009"
OTHER_PROJECT = "00000000-0000-0000-0000-000000000010"
TIME = "2026-10-25T00:00:00.000Z"
LATER = "2026-10-25T01:00:00.000Z"
EXPIRES = "2026-10-25T02:00:00.000Z"
AFTER = "2026-10-25T03:00:00.000Z"


def limits() -> ContractLimits:
    return ContractLimits.model_validate(
        {
            "schemaVersion": "kf.contract-limits.v1",
            "version": "synthetic.v1",
            "maxJsonBytes": 131072,
            "maxStringScalars": 256,
            "maxArrayItems": 64,
            "maxDepth": 24,
            "maxManifestItems": 4,
            "maxSourceBytes": 4096,
            "maxOutputBytes": 8192,
            "maxErrorMessageScalars": 80,
        }
    )


def ref(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.artifact-ref.v1",
        "projectId": PROJECT,
        "digest": "a" * 64,
        "sizeBytes": 17,
        "mediaType": "application/json",
        "artifactSchema": "synthetic.v1",
        "locations": [{"storeId": "synthetic", "objectKey": "sha256/synthetic"}],
    } | updates


def reason() -> dict[str, str]:
    return {"code": "remote_failed", "message": "Synthetic failure"}


def resources(**updates: object) -> dict[str, object]:
    return {
        "cpuMilli": 1000,
        "memoryMiB": 256,
        "gpuCount": 0,
        "maxWallSeconds": 30,
        "maxOutputBytes": 4096,
        "maxConcurrentAttempts": 1,
        "maxAttemptsPerOperation": 1,
        "automaticRetries": 0,
    } | updates


def budget(**updates: object) -> dict[str, object]:
    return {
        "currency": "USD",
        "maxRunCost": "10.00",
        "maxAttemptCost": "4.00",
        "tariffRef": ref(),
        "authorizationId": AUTH,
        "validUntil": EXPIRES,
    } | updates


def plan(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.execution-plan.v1",
        "projectId": PROJECT,
        "runId": RUN,
        "planId": PLAN,
        "executionConfigRef": ref(),
        "admissionReportRef": ref(),
        "extractionSpecRef": ref(),
        "policyRef": ref(),
        "profileId": "technical_minimal",
        "profileVersion": "1",
        "contractSetRef": ref(),
        "limitsRefs": [ref()],
        "inputRefs": [ref()],
        "operationKey": "b" * 64,
        "resources": resources(),
        "budget": budget(),
        "expiresAt": EXPIRES,
    } | updates


def authorization(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.run-authorization.v1",
        "authorizationId": AUTH,
        "projectId": PROJECT,
        "runId": RUN,
        "admissionReportDigest": "a" * 64,
        "allowedPlanDigests": ["c" * 64],
        "maxRunCost": "10.00",
        "maxConcurrentAttempts": 1,
        "actorId": ACTOR,
        "authorizedAt": TIME,
        "expiresAt": EXPIRES,
    } | updates


def usage(**updates: object) -> dict[str, object]:
    return {
        "providerRequestIds": [],
        "costStatus": "unknown",
        "tariffRef": ref(),
    } | updates


def event(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.budget-event.v1",
        "projectId": PROJECT,
        "runId": RUN,
        "reservationId": RESERVATION,
        "scope": "attempt",
        "attemptId": ATTEMPT,
        "eventId": EVENT,
        "eventType": "reserve",
        "amountUsd": "4.00",
        "costStatus": "estimated",
        "evidenceRef": ref(),
        "createdAt": TIME,
    } | updates


def attempt(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.stage-attempt.v1",
        "projectId": PROJECT,
        "planId": PLAN,
        "operationKey": "b" * 64,
        "attemptId": ATTEMPT,
        "attemptNumber": 1,
        "reservationId": RESERVATION,
        "state": "planned",
        "createdAt": TIME,
    } | updates


def result(**updates: object) -> dict[str, object]:
    revision = ref(artifactSchema="kf.document-revision.v1", digest="d" * 64)
    quality = ref(artifactSchema="kf.quality-report.v1", digest="e" * 64)
    return {
        "schemaVersion": "kf.result.v1",
        "projectId": PROJECT,
        "planId": PLAN,
        "operationKey": "b" * 64,
        "attemptId": ATTEMPT,
        "inputDigests": ["a" * 64],
        "status": "succeeded",
        "outputs": [revision, quality],
        "documentRevisionRef": revision,
        "qualityReportRef": quality,
        "errors": [],
        "usage": usage(),
        "completedAt": LATER,
    } | updates


def test_run_storage_and_unknown_cost_shapes() -> None:
    storage = event(scope="run_storage")
    with pytest.raises(ValidationError):
        BudgetEvent.model_validate(storage)
    storage.pop("attemptId")
    assert BudgetEvent.model_validate(storage).scope == "run_storage"
    missing_attempt = event()
    missing_attempt.pop("attemptId")
    with pytest.raises(ValidationError):
        BudgetEvent.model_validate(missing_attempt)
    unknown = event(eventType="record_usage", costStatus="unknown")
    with pytest.raises(ValidationError):
        BudgetEvent.model_validate(unknown)
    unknown.pop("amountUsd")
    observed = BudgetEvent.model_validate(unknown)
    assert "amountUsd" not in json.loads(observed.model_dump_json(by_alias=True))
    with pytest.raises(ValidationError):
        BudgetEvent.model_validate(event(eventType="settle", costStatus="estimated"))
    with pytest.raises(ValidationError):
        BudgetEvent.model_validate(event(eventType="release_unspent", costStatus="unknown"))
    with pytest.raises(ValidationError):
        BudgetEvent.model_validate(event(amountUsd="0"))


@pytest.mark.parametrize("status", ["actual", "estimated"])
def test_resource_usage_requires_observed_cost_for_known_status(status: str) -> None:
    with pytest.raises(ValidationError):
        ResourceUsage.model_validate(usage(costStatus=status))
    assert ResourceUsage.model_validate(usage(costStatus=status, costUsd="0")).cost_usd == "0"
    with pytest.raises(ValidationError):
        ResourceUsage.model_validate(usage(costUsd="0"))


def test_resource_quantities_and_safe_integer_coercions() -> None:
    measured = ResourceUsage.model_validate(usage(cpuSeconds="0.0000000001", transferBytes=0))
    assert measured.cpu_seconds == "0.0000000001"
    for updates in ({"cpuSeconds": "-1"}, {"wallSeconds": 1.0}, {"transferBytes": True}):
        with pytest.raises(ValidationError):
            ResourceUsage.model_validate(usage(**updates))
    for updates in (
        {"gpuCount": 1},
        {"gpuCount": False},
        {"automaticRetries": 1},
        {"automaticRetries": False},
        {"memoryMiB": 0},
        {"cpuMilli": True},
    ):
        with pytest.raises(ValidationError):
            ResourceEnvelope.model_validate(resources(**updates))


def test_budget_envelope_exact_decimal_order_and_positive_bounds() -> None:
    assert BudgetEnvelope.model_validate(budget(maxRunCost="00010", maxAttemptCost="9.999999999"))
    for updates in (
        {"maxRunCost": "0"},
        {"maxAttemptCost": "0.0"},
        {"maxAttemptCost": "10.000000001"},
        {"maxRunCost": "-1"},
        {"maxAttemptCost": "0.0000000001"},
    ):
        with pytest.raises(ValidationError):
            BudgetEnvelope.model_validate(budget(**updates))


def test_execution_plan_project_pins_and_finite_f1_inputs() -> None:
    assert ExecutionPlan.model_validate(plan()).resources.gpu_count == 0
    for updates in (
        {"policyRef": ref(projectId=OTHER_PROJECT)},
        {"limitsRefs": []},
        {"inputRefs": []},
        {"inputRefs": [ref(), ref()]},
        {"expiresAt": LATER},
    ):
        with pytest.raises(ValidationError):
            ExecutionPlan.model_validate(plan(**updates))


def test_stage_attempt_terminal_and_timestamp_conditions() -> None:
    assert StageAttempt.model_validate(attempt()).state == "planned"
    succeeded = attempt(
        state="succeeded",
        dispatchedAt=TIME,
        finishedAt=LATER,
        resultManifestRef=ref(artifactSchema="kf.result.v1"),
    )
    assert StageAttempt.model_validate(succeeded).state == "succeeded"
    for updates in (
        {"state": "succeeded", "finishedAt": LATER},
        {"state": "succeeded", "resultManifestRef": ref()},
        {"state": "planned", "remoteCallId": "synthetic-call"},
        {"state": "unknown_outcome", "finishedAt": LATER},
        {"state": "running", "dispatchedAt": "2026-10-24T23:00:00.000Z"},
    ):
        with pytest.raises(ValidationError):
            StageAttempt.model_validate(attempt(**updates))
    cancelled = StageAttempt.model_validate(attempt(state="cancelled", finishedAt=LATER))
    assert cancelled.dispatched_at is None
    assert "dispatchedAt" not in json.loads(cancelled.model_dump_json(by_alias=True))


def test_result_success_requires_unique_correlated_outputs() -> None:
    assert ResultManifest.model_validate(result()).status == "succeeded"
    for updates in (
        {"errors": [reason()]},
        {"outputs": []},
        {"outputs": [ref(artifactSchema="kf.document-revision.v1")]},
        {"qualityReportRef": ref(projectId=OTHER_PROJECT)},
        {"inputDigests": []},
    ):
        with pytest.raises(ValidationError):
            ResultManifest.model_validate(result(**updates))
    missing = result()
    missing.pop("documentRevisionRef")
    with pytest.raises(ValidationError):
        ResultManifest.model_validate(missing)
    failure = result(status="failed", errors=[reason()], outputs=[])
    failure.pop("documentRevisionRef")
    failure.pop("qualityReportRef")
    assert ResultManifest.model_validate(failure).status == "failed"
    with pytest.raises(ValidationError):
        ResultManifest.model_validate(result(status="failed", errors=[reason()]))


def test_operation_result_initial_selection_and_later_outcomes() -> None:
    selected_ref = ref(artifactSchema="kf.result.v1")
    selected = {
        "schemaVersion": "kf.operation-result-record.v1",
        "projectId": PROJECT,
        "operationKey": "b" * 64,
        "eventId": EVENT,
        "attemptId": ATTEMPT,
        "resultRef": selected_ref,
        "comparisonDigest": "c" * 64,
        "outcome": "selected",
        "selectedResultRef": selected_ref,
        "evidenceRef": ref(),
        "recordedAt": TIME,
    }
    first = OperationResultRecord.model_validate(selected)
    assert "previousEventId" not in json.loads(first.model_dump_json(by_alias=True))
    for updates in (
        {"outcome": "equivalent"},
        {"outcome": "selected", "previousEventId": ACTOR},
        {"selectedResultRef": ref(digest="f" * 64)},
        {"evidenceRef": ref(projectId=OTHER_PROJECT)},
        {"resultRef": ref(), "selectedResultRef": ref()},
    ):
        with pytest.raises(ValidationError):
            OperationResultRecord.model_validate(selected | updates)


def test_billing_adjustment_replacement_amounts_preserve_original_events() -> None:
    adjustment = {
        "schemaVersion": "kf.billing-adjustment.v1",
        "projectId": PROJECT,
        "runId": RUN,
        "reservationId": RESERVATION,
        "adjustmentId": EVENT,
        "settlementEventId": ACTOR,
        "expectedPriorActualUsd": "4.000",
        "revisedActualUsd": "3.00",
        "evidenceRef": ref(),
        "createdAt": TIME,
    }
    parsed = BillingAdjustment.model_validate(adjustment)
    assert parsed.expected_prior_actual_usd == "4.000"
    assert parsed.revised_actual_usd == "3.00"
    with pytest.raises(ValidationError):
        BillingAdjustment.model_validate(adjustment | {"revisedActualUsd": "-1"})
    with pytest.raises(ValidationError):
        BillingAdjustment.model_validate(adjustment | {"evidenceRef": ref(projectId=OTHER_PROJECT)})


def test_report_retains_every_outcome_and_unknown_cost_flag() -> None:
    payload = {
        "schemaVersion": "kf.run-report.v1",
        "projectId": PROJECT,
        "runId": RUN,
        "batchId": PLAN,
        "admissionReportRef": ref(),
        "attempts": [],
        "itemOutcomes": [{"assetId": ASSET, "status": "blocked", "reasons": [reason()]}],
        "costSummary": {
            "settledActualUsd": "0",
            "reservedOutstandingUsd": "4",
            "estimatedUsd": "0",
            "hasUnknownCost": True,
        },
        "reportAt": TIME,
    }
    report = RunReport.model_validate(payload)
    assert report.cost_summary.has_unknown_cost is True
    assert report.item_outcomes[0].asset_id == ASSET
    assert "revisionRef" not in json.loads(report.model_dump_json(by_alias=True))["itemOutcomes"][0]
    duplicate = copy.deepcopy(payload)
    duplicate["itemOutcomes"] = payload["itemOutcomes"] * 2
    with pytest.raises(ValidationError):
        RunReport.model_validate(duplicate)
    accepted = copy.deepcopy(payload)
    accepted["itemOutcomes"] = [{"assetId": ASSET, "status": "accepted", "reasons": []}]
    with pytest.raises(ValidationError):
        RunReport.model_validate(accepted)


def test_execution_config_exact_fields_and_no_project_invention() -> None:
    payload = {
        "schemaVersion": "kf.execution-config.v1",
        "adapterId": "synthetic-modal",
        "deploymentVersion": "synthetic.v1",
        "imageDigest": "a" * 64,
        "tariffRef": ref(),
        "resourcePolicyRef": ref(),
        "remoteDestinationId": "synthetic-remote",
    }
    assert ExecutionConfig.model_validate(payload).adapter_id == "synthetic-modal"
    with pytest.raises(ValidationError):
        ExecutionConfig.model_validate(payload | {"credential": "not-a-real-credential"})


def test_collections_are_immutable_and_wire_shapes_roundtrip() -> None:
    for model, payload in (
        (ExecutionPlan, plan()),
        (RunAuthorization, authorization()),
        (StageAttempt, attempt()),
        (ResultManifest, result()),
        (BudgetEvent, event()),
    ):
        parsed = model.model_validate(payload)
        assert model.from_wire(parsed.model_dump_json(by_alias=True).encode(), limits()) == parsed
    parsed_plan = ExecutionPlan.model_validate(plan())
    assert isinstance(parsed_plan.input_refs, tuple)
    assert isinstance(parsed_plan.limits_refs, tuple)
    with pytest.raises(AttributeError):
        parsed_plan.input_refs.append(ref())


def test_run_report_context_requires_complete_manifest_universe_and_pinned_policy() -> None:
    manifest = IntakeManifest.model_validate(
        {
            "schemaVersion": "kf.intake.v1",
            "projectId": PROJECT,
            "batchId": PLAN,
            "profileId": "technical_minimal",
            "profileVersion": "1",
            "policyRef": ref(),
            "createdAt": TIME,
            "items": [
                {
                    "assetId": ASSET,
                    "sourceId": ACTOR,
                    "originalDigest": "a" * 64,
                    "sizeBytes": 17,
                    "mediaType": "text/plain",
                    "custodyRef": {"rootId": "synthetic", "relativePath": "manual.txt"},
                    "metadata": {},
                }
            ],
        }
    )
    policy = PolicyArtifact.model_validate(
        {
            "schemaVersion": "kf.policy.v1",
            "projectId": PROJECT,
            "policyVersion": "1",
            "sources": [
                {
                    "sourceId": ACTOR,
                    "read": "allow",
                    "remoteTransfer": "allow",
                    "extract": "allow",
                    "enrich": "allow",
                    "embed": "allow",
                    "train": "allow",
                    "publish": "allow",
                    "auditMetadataRead": "allow",
                }
            ],
            "allowedRemoteDestinations": [],
            "effectiveAt": TIME,
        }
    )
    admission = AdmissionReport.model_validate(
        {
            "schemaVersion": "kf.admission-report.v1",
            "projectId": PROJECT,
            "batchId": PLAN,
            "manifestDigest": "a" * 64,
            "policyVersion": "1",
            "checkedAt": TIME,
            "entries": [
                {
                    "assetId": ASSET,
                    "sourceId": ACTOR,
                    "status": "blocked",
                    "reasons": [reason()],
                }
            ],
        }
    )
    payload = {
        "schemaVersion": "kf.run-report.v1",
        "projectId": PROJECT,
        "runId": RUN,
        "batchId": PLAN,
        "admissionReportRef": ref(),
        "attempts": [],
        "itemOutcomes": [{"assetId": ASSET, "status": "blocked", "reasons": [reason()]}],
        "costSummary": {
            "settledActualUsd": "0",
            "reservedOutstandingUsd": "0",
            "estimatedUsd": "0",
            "hasUnknownCost": True,
        },
        "reportAt": TIME,
    }
    report = RunReport.model_validate(payload)
    report.validate_manifest(manifest, admission, policy)
    for changes in (
        {"itemOutcomes": []},
        {"batchId": ACTOR},
        {"projectId": OTHER_PROJECT, "admissionReportRef": ref(projectId=OTHER_PROJECT)},
    ):
        with pytest.raises(ContractError):
            RunReport.model_validate(payload | changes).validate_manifest(
                manifest, admission, policy
            )
    changed_policy = policy.model_dump(by_alias=True) | {"policyVersion": "2"}
    with pytest.raises(ContractError):
        report.validate_manifest(manifest, admission, PolicyArtifact.model_validate(changed_policy))


def test_optional_usage_fields_schema_and_wire_roundtrip() -> None:
    measured = ResourceUsage.model_validate(usage())
    dumped = measured.model_dump_json(by_alias=True).encode()
    assert ResourceUsage.from_wire(dumped, limits()) == measured
    assert "null" not in dumped.decode()
    for field in ("costUsd", "cpuSeconds", "transferBytes"):
        schema = ResourceUsage.model_json_schema()["properties"][field]
        assert schema.get("type") != "null"
        assert not any(item.get("type") == "null" for item in schema.get("anyOf", []))
        with pytest.raises(ContractError):
            ResourceUsage.from_wire(json.dumps(usage(**{field: None})).encode(), limits())


def test_exact_plan_allowlist_and_shared_cap() -> None:
    raw = json.dumps(plan()).encode()
    digest = hashlib.sha256(raw).hexdigest()
    parsed = ExecutionPlan.from_wire(raw, limits())
    grant = RunAuthorization.model_validate(authorization(allowedPlanDigests=[digest]))
    validate_plan_authorization(parsed, grant, LATER, plan_bytes=raw, limits=limits())
    for changes in (
        {"allowedPlanDigests": ["f" * 64]},
        {"maxRunCost": "11"},
        {"runId": ACTOR},
        {"projectId": OTHER_PROJECT},
        {"authorizationId": ACTOR},
        {"admissionReportDigest": "f" * 64},
        {"expiresAt": LATER},
    ):
        changed = RunAuthorization.model_validate(
            authorization(**({"allowedPlanDigests": [digest]} | changes))
        )
        with pytest.raises(ContractError):
            validate_plan_authorization(parsed, changed, LATER, plan_bytes=raw, limits=limits())
    with pytest.raises(ContractError, match="authorization_expired"):
        validate_plan_authorization(parsed, grant, EXPIRES, plan_bytes=raw, limits=limits())
    with pytest.raises(ContractError):
        validate_plan_authorization(parsed, grant, LATER, plan_bytes=raw + b" ", limits=limits())
    with pytest.raises(ContractError):
        validate_plan_authorization(
            ExecutionPlan.model_validate(plan(operationKey="f" * 64)),
            grant,
            LATER,
            plan_bytes=raw,
            limits=limits(),
        )
    duplicate_keys = raw.replace(b'"runId":', b'"runId": "' + RUN.encode() + b'", "runId":', 1)
    with pytest.raises(ContractError):
        validate_plan_authorization(
            parsed, grant, LATER, plan_bytes=duplicate_keys, limits=limits()
        )


def test_authorization_shape_cannot_supply_empty_or_duplicate_plan_allowlist() -> None:
    for changes in (
        {"allowedPlanDigests": []},
        {"allowedPlanDigests": ["c" * 64, "c" * 64]},
        {"maxRunCost": "0"},
        {"maxConcurrentAttempts": 0},
        {"authorizedAt": AFTER},
    ):
        with pytest.raises(ValidationError):
            RunAuthorization.model_validate(authorization(**changes))
