"""Synthetic enrichment registration contracts and static schema exports."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from conscience_foundry.contracts.common import ContractLimits

P = "00000000-0000-0000-0000-000000000001"
Q = "00000000-0000-0000-0000-000000000002"
TIME = "2026-10-25T00:00:00.000Z"
LATER = "2026-10-25T01:00:00.000Z"


def ref(role: str, digest: str = "a", project: str = P) -> dict:
    return {
        "schemaVersion": "cf.artifact-ref.v1",
        "projectId": project,
        "digest": digest * 64,
        "sizeBytes": 1,
        "mediaType": "application/json",
        "artifactSchema": role,
        "locations": [],
    }


def limits() -> ContractLimits:
    return ContractLimits.model_validate(
        {
            "schemaVersion": "cf.contract-limits.v1",
            "version": "v1",
            "maxJsonBytes": 65536,
            "maxStringScalars": 1024,
            "maxArrayItems": 64,
            "maxDepth": 16,
            "maxManifestItems": 8,
            "maxSourceBytes": 4096,
            "maxOutputBytes": 65536,
            "maxErrorMessageScalars": 80,
        }
    )


def operation(**updates: object) -> dict:
    return {
        "schemaVersion": "cf.enrichment-operation.v1",
        "projectId": P,
        "assetId": Q,
        "canonicalRevisionRef": ref("cf.document-revision.v1"),
        "specRef": ref("cf.enrichment-spec.v1"),
        "policyRef": ref("cf.policy.v1"),
        "inputRef": ref("cf.enrichment-payload.v1"),
        "contextSpans": [],
        "omittedContextRefs": [],
    } | updates


def test_operation_identity_and_reference_guards() -> None:
    from conscience_foundry.contracts.enrichment import (
        EnrichmentOperation,
        enrichment_operation_key,
    )

    obj = EnrichmentOperation.model_validate(operation())
    key = enrichment_operation_key(obj, limits=limits())
    assert key == enrichment_operation_key(
        EnrichmentOperation.model_validate(operation()), limits=limits()
    )
    changed = EnrichmentOperation.model_validate(
        operation(inputRef=ref("cf.enrichment-payload.v1", "b"))
    )
    assert key != enrichment_operation_key(changed, limits=limits())
    for bad in (
        operation(operationKey="b" * 64),
        operation(specRef=ref("cf.enrichment-spec.v1", project=Q)),
        operation(canonicalRevisionRef=ref("cf.result.v1")),
        operation(
            omittedContextRefs=[ref("cf.document-revision.v1"), ref("cf.document-revision.v1")]
        ),
    ):
        with pytest.raises(ValidationError):
            EnrichmentOperation.model_validate(bad)


def test_payload_attempt_and_installation_enforce_shape() -> None:
    from conscience_foundry.contracts.enrichment import (
        EnrichmentAttempt,
        EnrichmentPayload,
        TaskSchemaInstallation,
    )

    payload = {
        "schemaVersion": "cf.enrichment-payload.v1",
        "projectId": P,
        "schemaRef": ref("json-schema.2020-12"),
        "value": {"claim": "example"},
    }
    EnrichmentPayload.model_validate(payload)
    for bad in (
        payload | {"value": []},
        payload | {"schemaRef": ref("cf.result.v1")},
        payload | {"value": {"bad": object()}},
    ):
        with pytest.raises(ValidationError):
            EnrichmentPayload.model_validate(bad)
    attempt = {
        "schemaVersion": "cf.enrichment-attempt.v1",
        "projectId": P,
        "planId": Q,
        "operationKey": "b" * 64,
        "attemptId": Q,
        "attemptNumber": 1,
        "reservationId": Q,
        "state": "succeeded",
        "createdAt": TIME,
        "finishedAt": LATER,
        "attemptReportRef": ref("cf.enrichment-attempt-report.v1"),
    }
    EnrichmentAttempt.model_validate(attempt)
    for bad in (
        attempt | {"attemptReportRef": ref("cf.result.v1")},
        attempt | {"resultManifestRef": ref("cf.result.v1")},
        {k: v for k, v in attempt.items() if k != "attemptReportRef"},
    ):
        with pytest.raises(ValidationError):
            EnrichmentAttempt.model_validate(bad)
    install = {
        "schemaVersion": "cf.enrichment-schema-installation.v1",
        "projectId": P,
        "specRef": ref("cf.enrichment-spec.v1"),
        "inputSchemaRef": ref("json-schema.2020-12"),
        "outputSchemaRef": ref("json-schema.2020-12"),
        "policyRef": ref("cf.policy.v1"),
        "actorId": Q,
        "evidenceRef": ref("synthetic.evidence.v1"),
        "installedAt": TIME,
    }
    TaskSchemaInstallation.model_validate(install)
    with pytest.raises(ValidationError):
        TaskSchemaInstallation.model_validate(
            install | {"outputSchemaRef": ref("json-schema.2020-12", project=Q)}
        )


def test_all_six_schemas_are_registered_and_match_exported_files() -> None:
    from conscience_foundry.contracts.registry import (
        _rules_bytes,
        _schema_bytes,
        registered_schema_ids,
    )
    from conscience_foundry.release.edges import _RULES

    ids = [
        "cf.enrichment-" + n + ".v1"
        for n in (
            "allocation-policy",
            "operation",
            "plan",
            "payload",
            "attempt",
            "attempt-report",
            "schema-installation",
        )
    ]
    for name in ids:
        assert name in registered_schema_ids()
        assert name in _RULES
        assert (Path("schemas") / (name + ".schema.json")).read_bytes() == _schema_bytes(name)
        assert (Path("schemas") / (name + ".rules.json")).read_bytes() == _rules_bytes(name)


def test_plan_reference_roles_project_limits_and_expiry() -> None:
    from conscience_foundry.contracts.enrichment import EnrichmentPlan

    plan = {
        "schemaVersion": "cf.enrichment-plan.v1",
        "projectId": P,
        "runId": Q,
        "planId": Q,
        "operationRef": ref("cf.enrichment-operation.v1"),
        "operationKey": "b" * 64,
        "admissionReportRef": ref("cf.admission-report.v1"),
        "contractSetRef": ref("cf.contract-set.v1"),
        "limitsRefs": [ref("cf.contract-limits.v1")],
        "allocationPolicyRef": ref("cf.enrichment-allocation-policy.v1"),
        "taskSchemaInstallationRef": ref("cf.enrichment-schema-installation.v1"),
        "resources": {
            "cpuMilli": 1,
            "memoryMiB": 1,
            "gpuCount": 0,
            "maxWallSeconds": 1,
            "maxOutputBytes": 1,
            "maxConcurrentAttempts": 1,
            "maxAttemptsPerOperation": 1,
            "automaticRetries": 0,
        },
        "budget": {
            "currency": "USD",
            "maxRunCost": "1",
            "maxAttemptCost": "1",
            "tariffRef": ref("cf.tariff.v1"),
            "authorizationId": Q,
            "validUntil": TIME,
        },
        "expiresAt": LATER,
    }
    EnrichmentPlan.model_validate(plan)
    for bad in (
        plan | {"limitsRefs": []},
        plan | {"operationRef": ref("cf.result.v1")},
        plan
        | {"taskSchemaInstallationRef": ref("cf.enrichment-schema-installation.v1", project=Q)},
        plan | {"limitsRefs": [ref("cf.contract-limits.v1"), ref("cf.contract-limits.v1")]},
        plan
        | {
            "limitsRefs": [
                ref("cf.contract-limits.v1"),
                ref("cf.contract-limits.v1") | {"sizeBytes": 2},
            ]
        },
        plan | {"expiresAt": "2026-10-24T00:00:00.000Z"},
        plan | {"extractionSpecRef": ref("cf.extraction-spec.v1")},
    ):
        with pytest.raises(ValidationError):
            EnrichmentPlan.model_validate(bad)


def test_attempt_report_pins_roles_and_rejects_cycles() -> None:
    from conscience_foundry.contracts.enrichment import EnrichmentAttemptReport

    report = {
        "schemaVersion": "cf.enrichment-attempt-report.v1",
        "projectId": P,
        "operationKey": "b" * 64,
        "attemptId": Q,
        "reservationId": Q,
        "requestRef": ref("cf.enrichment-request.v1"),
        "allocationEvidenceRef": ref("synthetic.allocation.v1"),
        "observedState": "succeeded",
        "observedAt": TIME,
        "reasons": [],
    }
    EnrichmentAttemptReport.model_validate(report)
    for bad in (
        report | {"requestRef": ref("cf.result.v1")},
        report | {"allocationEvidenceRef": ref("synthetic.allocation.v1", project=Q)},
        report | {"resultRef": ref("cf.enrichment-result.v1")},
        report | {"observedState": "accepted"},
    ):
        with pytest.raises(ValidationError):
            EnrichmentAttemptReport.model_validate(bad)


def test_operation_rejects_mixed_span_revisions_and_preserves_span_order() -> None:
    from conscience_foundry.contracts.enrichment import (
        EnrichmentOperation,
        enrichment_operation_key,
    )

    span = {
        "schemaVersion": "cf.document-span.v1",
        "projectId": P,
        "sourceId": Q,
        "revisionId": "b" * 64,
        "sectionId": "s",
        "start": 0,
        "end": 1,
        "offsetUnit": "unicode_scalar",
    }
    second = span | {"start": 1, "end": 2}
    first_obj = EnrichmentOperation.model_validate(operation(contextSpans=[span, second]))
    reverse_obj = EnrichmentOperation.model_validate(operation(contextSpans=[second, span]))
    assert enrichment_operation_key(first_obj, limits=limits()) != enrichment_operation_key(
        reverse_obj, limits=limits()
    )
    with pytest.raises(ValidationError):
        EnrichmentOperation.model_validate(
            operation(contextSpans=[span, second | {"revisionId": "c" * 64}])
        )


def test_each_registered_fixture_has_fully_classified_reference_edges() -> None:
    from conscience_foundry.contracts.registry import SCHEMA_MODELS
    from conscience_foundry.release.edges import edge_roles

    fixtures = json.loads(Path("tests/fixtures/public/schema_parity.json").read_text())
    cases = [
        case
        for case in fixtures["shapeCases"]
        if case["caseId"].startswith("cf.enrichment-") and case["kind"] == "valid"
    ]
    assert len(cases) == 7
    for case in cases:
        model = SCHEMA_MODELS[case["schemaId"]].model_validate(case["instance"])
        edge_roles(case["schemaId"], model)


def test_parent_contract_set_remains_valid_without_new_limits(tmp_path: Path) -> None:
    from conscience_foundry.contracts.common import ContractError
    from conscience_foundry.contracts.registry import (
        ContractSet,
        export_schemas,
        registered_schema_ids,
        validate_contract_set,
    )

    fixture = json.loads(Path("tests/fixtures/public/schema_parity.json").read_text())[
        "preEnrichmentContractSet"
    ]
    assert fixture["parentCommit"] == "338716495b1ed6ccd9b2cfae5e36e8728bfdd62e"
    bundle = ContractSet.model_validate(fixture["contractSet"])
    old_ids = [item.schema_id for item in bundle.contracts]
    old_limits = {name: ContractLimits.model_validate(fixture["limits"]) for name in old_ids}
    validate_contract_set(bundle, project_id=P, limits_by_schema=old_limits)
    for excluded in (old_ids[0], old_ids[-1]):
        partial = bundle.model_copy(
            update={
                "contracts": tuple(item for item in bundle.contracts if item.schema_id != excluded)
            }
        )
        with pytest.raises(ContractError, match="unsupported_schema"):
            validate_contract_set(partial, project_id=P, limits_by_schema=old_limits)
    absent = dict(old_limits)
    absent.pop(old_ids[0])
    with pytest.raises(ContractError, match="limits_missing"):
        validate_contract_set(bundle, project_id=P, limits_by_schema=absent)
    first = bundle.contracts[0]
    tampered = first.model_copy(
        update={"schema_ref": first.schema_ref.model_copy(update={"digest": "0" * 64})}
    )
    changed = bundle.model_copy(update={"contracts": (tampered, *bundle.contracts[1:])})
    with pytest.raises(ContractError, match="hash_mismatch"):
        validate_contract_set(changed, project_id=P, limits_by_schema=old_limits)
    all_limits = {name: limits() for name in registered_schema_ids()}
    current = export_schemas(
        tmp_path, project_id=P, store_id="test", version="test.v1", limits_by_schema=all_limits
    )
    validate_contract_set(current, project_id=P, limits_by_schema=all_limits)
    added = next(item for item in current.contracts if item.schema_id not in old_ids)
    hybrid = bundle.model_copy(
        update={
            "contracts": tuple(sorted((*bundle.contracts, added), key=lambda item: item.schema_id))
        }
    )
    with pytest.raises(ContractError, match="unsupported_schema"):
        validate_contract_set(hybrid, project_id=P, limits_by_schema=all_limits)
    unknown = first.model_copy(update={"schema_id": "unregistered.example.v1"})
    forged = bundle.model_copy(update={"contracts": (unknown, *bundle.contracts[1:])})
    with pytest.raises(ContractError, match="unsupported_schema"):
        validate_contract_set(forged, project_id=P, limits_by_schema=all_limits)
    altered_rules = first.model_copy(
        update={
            "semantic_rules_ref": first.semantic_rules_ref.model_copy(update={"digest": "0" * 64})
        }
    )
    forged_rules = bundle.model_copy(update={"contracts": (altered_rules, *bundle.contracts[1:])})
    with pytest.raises(ContractError, match="hash_mismatch"):
        validate_contract_set(forged_rules, project_id=P, limits_by_schema=old_limits)
    missing_new = dict(all_limits)
    missing_new.pop("cf.enrichment-allocation-policy.v1")
    with pytest.raises(ContractError, match="limits_missing"):
        validate_contract_set(current, project_id=P, limits_by_schema=missing_new)


def test_allocation_policy_shape_and_plan_role() -> None:
    from conscience_foundry.contracts.enrichment import EnrichmentAllocationPolicy, EnrichmentPlan

    policy = {
        "schemaVersion": "cf.enrichment-allocation-policy.v1",
        "projectId": P,
        "tariffRef": ref("custom.operator-tariff.v1"),
        "fixedChargeUsd": "0.005",
        "fundedFrom": TIME,
        "fundedUntil": LATER,
    }
    EnrichmentAllocationPolicy.model_validate(policy)
    for bad in (
        policy | {"fixedChargeUsd": "0"},
        policy | {"fixedChargeUsd": "-1"},
        policy | {"fundedUntil": TIME},
        policy | {"tariffRef": ref("custom.operator-tariff.v1", project=Q)},
        policy | {"unbounded": True},
    ):
        with pytest.raises(ValidationError):
            EnrichmentAllocationPolicy.model_validate(bad)
    fixtures = json.loads(Path("tests/fixtures/public/schema_parity.json").read_text())
    valid = next(
        c["instance"]
        for c in fixtures["shapeCases"]
        if c["caseId"] == "cf.enrichment-plan.v1-valid"
    )
    valid["allocationPolicyRef"] = ref("cf.enrichment-allocation-policy.v1")
    EnrichmentPlan.model_validate(valid)
    with pytest.raises(ValidationError):
        EnrichmentPlan.model_validate(
            valid | {"allocationPolicyRef": ref("cf.local-resource-policy.v1")}
        )
