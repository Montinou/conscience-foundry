"""Synthetic versioned extension envelopes; no model runtime or provider calls."""

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from conscience_foundry.contracts.common import ContractError, ContractLimits
from conscience_foundry.contracts.extensions import (
    AnnotationSet,
    DecisionRelease,
    DecisionRequest,
    DecisionResult,
    DecisionTaskSpec,
    DecisionValidationContext,
    EnrichmentRequest,
    EnrichmentResult,
    EnrichmentSpec,
    EnrichmentValidationContext,
    Probability,
    correlate_decision,
    correlate_enrichment,
)

PROJECT = "00000000-0000-0000-0000-000000000001"
OTHER = "00000000-0000-0000-0000-000000000002"
ATTEMPT = "00000000-0000-0000-0000-000000000003"
RESERVATION = "00000000-0000-0000-0000-000000000004"
RELEASE = "00000000-0000-0000-0000-000000000005"
DEADLINE = "2026-10-25T01:00:00.000Z"


def limits(**updates: int) -> ContractLimits:
    return ContractLimits.model_validate(
        {
            "schemaVersion": "kf.contract-limits.v1",
            "version": "synthetic.v1",
            "maxJsonBytes": 1048576,
            "maxStringScalars": 4096,
            "maxArrayItems": 256,
            "maxDepth": 32,
            "maxManifestItems": 16,
            "maxSourceBytes": 8192,
            "maxOutputBytes": 65536,
            "maxErrorMessageScalars": 128,
        }
        | updates
    )


def ref(schema: str = "synthetic.payload.v1", **updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.artifact-ref.v1",
        "projectId": PROJECT,
        "digest": "a" * 64,
        "sizeBytes": 17,
        "mediaType": "application/json",
        "artifactSchema": schema,
        "locations": [{"storeId": "synthetic", "objectKey": "objects/synthetic"}],
    } | updates


def reason() -> dict[str, str]:
    return {"code": "unavailable", "message": "Synthetic diagnostic"}


def enrichment_spec(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.enrichment-spec.v1",
        "specId": "synthetic.v1",
        "taskId": "synthetic",
        "profileId": "technical_minimal",
        "profileVersion": "v1",
        **{
            field: ref()
            for field in (
                "inputSchemaRef",
                "outputSchemaRef",
                "promptRef",
                "contextPolicyRef",
                "modelRouteRef",
                "generationSettingsRef",
                "validationPolicyRef",
                "reviewPolicyRef",
                "executionLimitsRef",
                "runtimeRef",
            )
        },
        "inputSchemaRef": ref("json-schema.2020-12"),
        "outputSchemaRef": ref("json-schema.2020-12"),
    } | updates


def enrichment_request(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.enrichment-request.v1",
        "projectId": PROJECT,
        "operationKey": "b" * 64,
        "attemptId": ATTEMPT,
        "specRef": ref("kf.enrichment-spec.v1"),
        "policyRef": ref("kf.policy.v1"),
        "canonicalRevisionRefs": [ref("kf.document-revision.v1")],
        "contextSpans": [],
        "omittedContextRefs": [],
        "inputRef": ref(),
        "reservationId": RESERVATION,
        "deadline": DEADLINE,
    } | updates


def enrichment_result(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.enrichment-result.v1",
        "projectId": PROJECT,
        "operationKey": "b" * 64,
        "attemptId": ATTEMPT,
        "specRef": ref("kf.enrichment-spec.v1"),
        "schemaStatus": "not_run",
        "anchorStatus": "not_run",
        "semanticStatus": "pending",
        "disposition": "needs_review",
        "validationReportRef": ref(),
        "attemptReportRef": ref(),
        "reasons": [reason()],
    } | updates


def task_spec(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.decision-task.v1",
        "taskId": "synthetic.categorical",
        "version": "synthetic.v1",
        "inputSchemaRef": ref("json-schema.2020-12"),
        "outputSchemaRef": ref("json-schema.2020-12"),
        "options": ["first", "second"],
        "optionOrderVersion": "synthetic.v1",
        "fallbackPolicyRef": ref(),
    } | updates


def decision_release(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.decision-release.v1",
        "releaseId": RELEASE,
        "implementation": "rules",
        "taskSpecRefs": [ref("kf.decision-task.v1")],
        "runtimeRef": ref(),
        "stateBuilderRef": ref(),
        "datasetProvenanceRef": ref(),
        "decisionPolicyRef": ref(),
        "certifiedCohorts": [],
        "evaluationRef": ref(),
    } | updates


def decision_request(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.decision-request.v1",
        "projectId": PROJECT,
        "taskSpecRef": ref("kf.decision-task.v1"),
        "decisionReleaseRef": ref("kf.decision-release.v1"),
        "inputRef": ref(),
        "policyRef": ref("kf.policy.v1"),
        "contextRevisionRefs": [],
        "operationKey": "c" * 64,
        "attemptId": ATTEMPT,
        "reservationId": RESERVATION,
        "deadline": DEADLINE,
    } | updates


def decision_result(**updates: object) -> dict[str, object]:
    raw = json.dumps(decision_request()).encode()
    return {
        "schemaVersion": "kf.decision-result.v1",
        "projectId": PROJECT,
        "operationKey": "c" * 64,
        "attemptId": ATTEMPT,
        "requestDigest": hashlib.sha256(raw).hexdigest(),
        "taskSpecRef": ref("kf.decision-task.v1"),
        "decisionReleaseRef": ref("kf.decision-release.v1"),
        "status": "unavailable",
        "cohortStatus": "not_applicable",
        "policyOutcome": "needs_review",
        "reason": reason(),
        "traceRef": ref(),
    } | updates


def test_missing_response_is_not_run() -> None:
    missing = EnrichmentResult.model_validate(enrichment_result())
    assert missing.schema_status == "not_run"
    assert missing.disposition != "accepted"
    for update in (
        {"anchorStatus": "valid"},
        {"candidateAnnotationsRef": ref()},
        {"rawResponseRef": ref()},
        {"reasons": []},
        {"disposition": "accepted"},
    ):
        with pytest.raises(ValidationError):
            EnrichmentResult.model_validate(enrichment_result(**update))
    with pytest.raises(ValidationError):
        EnrichmentResult.model_validate(enrichment_result(schemaStatus="invalid", reasons=[]))


def test_enrichment_shape_and_optional_wire_parity() -> None:
    spec = EnrichmentSpec.model_validate(enrichment_spec())
    assert "graphSpecRef" not in spec.model_dump(mode="json", by_alias=True)
    assert EnrichmentSpec.from_wire(spec.model_dump_json(by_alias=True).encode(), limits()) == spec
    for update in ({"graphSpecRef": None}, {"unknown": "x"}, {"runtimeRef": ref(projectId=OTHER)}):
        with pytest.raises(ValidationError):
            EnrichmentSpec.model_validate(enrichment_spec(**update))
    req = EnrichmentRequest.model_validate(enrichment_request())
    assert isinstance(req.canonical_revision_refs, tuple)
    for update in (
        {"inputRef": ref(projectId=OTHER)},
        {"canonicalRevisionRefs": [ref("kf.document-revision.v1")] * 2},
        {"specRef": ref("wrong.v1")},
    ):
        with pytest.raises(ValidationError):
            EnrichmentRequest.model_validate(enrichment_request(**update))
    accepted = enrichment_result(
        schemaStatus="valid",
        anchorStatus="valid",
        semanticStatus="supported",
        disposition="accepted",
        rawResponseRef=ref(),
        candidateAnnotationsRef=ref("kf.annotation-set.v1"),
        reasons=[],
    )
    EnrichmentResult.model_validate(accepted)
    for update in (
        {"candidateAnnotationsRef": None},
        {"schemaStatus": "invalid"},
        {"anchorStatus": "invalid"},
        {"semanticStatus": "disputed"},
    ):
        with pytest.raises(ValidationError):
            EnrichmentResult.model_validate(accepted | update)


def test_annotation_membership_does_not_assert_acceptance() -> None:
    data = {
        "schemaVersion": "kf.annotation-set.v1",
        "projectId": PROJECT,
        "specRef": ref("kf.enrichment-spec.v1"),
        "canonicalRevisionRefs": [ref("kf.document-revision.v1")],
        "results": [ref("kf.enrichment-result.v1")],
        "coverageReportRef": ref(),
    }
    model = AnnotationSet.model_validate(data)
    assert model.results[0].artifact_schema == "kf.enrichment-result.v1"
    with pytest.raises(ValidationError):
        AnnotationSet.model_validate(data | {"results": [ref(projectId=OTHER)]})


def test_probability_and_categorical_conditional_shapes() -> None:
    for valid in ("0", "1", "0.000000001", "0.5", "1.000000000"):
        Probability.model_validate({"option": "first", "probability": valid})
    for invalid in ("1.1", "-0.1", "0.0000000001", "NaN", 0.5):
        with pytest.raises(ValidationError):
            Probability.model_validate({"option": "first", "probability": invalid})
    DecisionTaskSpec.model_validate(task_spec())
    for update in ({"options": ["first", "first"]}, {"options": []}):
        with pytest.raises(ValidationError):
            DecisionTaskSpec.model_validate(task_spec(**update))
    DecisionRelease.model_validate(decision_release())
    for status in ("abstain", "unavailable", "invalid"):
        for field, value in (
            ("prediction", "first"),
            ("distribution", [{"option": "first", "probability": "1"}]),
        ):
            with pytest.raises(ValidationError):
                DecisionResult.model_validate(decision_result(status=status, **{field: value}))
        with pytest.raises(ValidationError):
            DecisionResult.model_validate(
                decision_result(status=status, policyOutcome="use_prediction")
            )
    with pytest.raises(ValidationError):
        DecisionResult.model_validate(decision_result(status="prediction"))
    with pytest.raises(ValidationError):
        DecisionResult.model_validate(
            decision_result(status="invalid", policyOutcome="use_baseline")
        )
    good = DecisionResult.model_validate(decision_result())
    assert "prediction" not in good.model_dump(mode="json", by_alias=True)
    assert "distribution" not in good.model_dump(mode="json", by_alias=True)
    assert DecisionResult.from_wire(good.model_dump_json(by_alias=True).encode(), limits()) == good


def decision_context(**updates: object) -> DecisionValidationContext:
    from conscience_foundry.contracts.common import ArtifactRef

    data = {
        "request_digest": hashlib.sha256(json.dumps(decision_request()).encode()).hexdigest(),
        "project_id": PROJECT,
        "operation_key": "c" * 64,
        "attempt_id": ATTEMPT,
        "applicable_cohort": None,
        "expected_cohort_status": "not_applicable",
        "task_spec_ref": ArtifactRef.model_validate(ref("kf.decision-task.v1")),
        "decision_release_ref": ArtifactRef.model_validate(ref("kf.decision-release.v1")),
        "output_schema_ref": ArtifactRef.model_validate(ref("json-schema.2020-12")),
        "policy_ref": ArtifactRef.model_validate(ref("kf.policy.v1")),
        "decision_policy_ref": ArtifactRef.model_validate(ref()),
        "fallback_policy_ref": ArtifactRef.model_validate(ref()),
        "implementation": "rules",
        "probabilistic": False,
        "calibration_required": False,
        "probability_tolerance": "0.000000001",
        "expected_policy_outcome": "needs_review",
        "baseline_authorized": False,
    } | updates
    return DecisionValidationContext(**data)


def enrichment_context(**updates: object) -> EnrichmentValidationContext:
    from conscience_foundry.contracts.common import ArtifactRef

    data = {
        "request_digest": hashlib.sha256(json.dumps(enrichment_request()).encode()).hexdigest(),
        "project_id": PROJECT,
        "operation_key": "b" * 64,
        "attempt_id": ATTEMPT,
        "spec_ref": ArtifactRef.model_validate(ref("kf.enrichment-spec.v1")),
        "validation_policy_ref": ArtifactRef.model_validate(ref()),
        "review_policy_ref": ArtifactRef.model_validate(ref()),
        "anchors_applicable": True,
        "attributed_claims": True,
        "inference_allowed": False,
        "expected_schema_status": "not_run",
        "expected_anchor_status": "not_run",
        "expected_semantic_status": "pending",
        "expected_disposition": "needs_review",
    } | updates
    return EnrichmentValidationContext(**data)


def test_wrong_attempt_and_uncertified_prediction_rejected() -> None:
    request = EnrichmentRequest.model_validate(enrichment_request())
    result = EnrichmentResult.model_validate(enrichment_result())
    spec = EnrichmentSpec.model_validate(enrichment_spec())
    correlate_enrichment(
        request,
        result,
        request_bytes=json.dumps(enrichment_request()).encode(),
        limits=limits(),
        spec=spec,
        context=enrichment_context(),
    )
    for changed in (
        result.model_copy(update={"attempt_id": OTHER}),
        result.model_copy(update={"project_id": OTHER}),
        result.model_copy(update={"operation_key": "d" * 64}),
    ):
        with pytest.raises(ContractError):
            correlate_enrichment(
                request,
                changed,
                request_bytes=json.dumps(enrichment_request()).encode(),
                limits=limits(),
                spec=spec,
                context=enrichment_context(),
            )
    raw = json.dumps(decision_request()).encode()
    prediction = DecisionResult.model_validate(
        decision_result(
            status="prediction",
            prediction="first",
            cohortStatus="uncertified",
            policyOutcome="needs_review",
            distribution=[
                {"option": "first", "probability": "0.6"},
                {"option": "second", "probability": "0.4"},
            ],
        )
    )
    laya = DecisionRelease.model_validate(
        decision_release(
            implementation="laya",
            modelRef=ref(),
            tokenizerRef=ref(),
            calibrationRef=ref(),
            certifiedCohorts=["synthetic"],
        )
    )
    context = decision_context(
        implementation="laya",
        probabilistic=True,
        calibration_required=True,
        applicable_cohort="synthetic",
        expected_cohort_status="certified",
        expected_policy_outcome="use_prediction",
    )
    with pytest.raises(ContractError):
        correlate_decision(
            raw,
            prediction,
            limits=limits(),
            task_spec=DecisionTaskSpec.model_validate(task_spec()),
            decision_release=laya,
            context=context,
        )


def test_decision_exact_request_bytes_and_independent_policy_outcome() -> None:
    raw = json.dumps(decision_request()).encode()
    result = DecisionResult.model_validate(decision_result())
    task = DecisionTaskSpec.model_validate(task_spec())
    release = DecisionRelease.model_validate(decision_release())
    correlate_decision(
        raw,
        result,
        limits=limits(),
        task_spec=task,
        decision_release=release,
        context=decision_context(),
    )
    for changed_raw in (
        raw + b" ",
        raw.replace(b'"projectId":', b'"projectId": null, "projectId":'),
    ):
        with pytest.raises(ContractError):
            correlate_decision(
                changed_raw,
                result,
                limits=limits(),
                task_spec=task,
                decision_release=release,
                context=decision_context(),
            )
    with pytest.raises(ContractError):
        correlate_decision(
            raw,
            result,
            limits=limits(maxJsonBytes=2),
            task_spec=task,
            decision_release=release,
            context=decision_context(),
        )
    for changed in (
        result.model_copy(update={"attempt_id": OTHER}),
        result.model_copy(update={"project_id": OTHER}),
        result.model_copy(update={"policy_outcome": "use_baseline"}),
    ):
        with pytest.raises(ContractError):
            correlate_decision(
                raw,
                changed,
                limits=limits(),
                task_spec=task,
                decision_release=release,
                context=decision_context(),
            )
    baseline = DecisionResult.model_validate(decision_result(policyOutcome="use_baseline"))
    for allowed in (False, True):
        context = decision_context(
            expected_policy_outcome="use_baseline", baseline_authorized=allowed
        )
        if allowed:
            correlate_decision(
                raw,
                baseline,
                limits=limits(),
                task_spec=task,
                decision_release=release,
                context=context,
            )
        else:
            with pytest.raises(ContractError):
                correlate_decision(
                    raw,
                    baseline,
                    limits=limits(),
                    task_spec=task,
                    decision_release=release,
                    context=context,
                )
    with pytest.raises(ContractError):
        correlate_decision(
            raw,
            result,
            limits=limits(),
            task_spec=task,
            decision_release=release,
            context=decision_context(implementation="laya"),
        )


def test_distribution_exact_option_order_tolerance_and_certification() -> None:
    raw = json.dumps(decision_request()).encode()
    task = DecisionTaskSpec.model_validate(task_spec())
    release = DecisionRelease.model_validate(
        decision_release(
            implementation="laya",
            modelRef=ref(),
            tokenizerRef=ref(),
            calibrationRef=ref(),
            certifiedCohorts=["synthetic"],
        )
    )
    context = decision_context(
        implementation="laya",
        probabilistic=True,
        calibration_required=True,
        applicable_cohort="synthetic",
        expected_cohort_status="certified",
        expected_policy_outcome="use_prediction",
    )
    payload = decision_result(
        status="prediction",
        prediction="first",
        cohortStatus="certified",
        policyOutcome="use_prediction",
        distribution=[
            {"option": "first", "probability": "0.6"},
            {"option": "second", "probability": "0.4"},
        ],
    )
    correlate_decision(
        raw,
        DecisionResult.model_validate(payload),
        limits=limits(),
        task_spec=task,
        decision_release=release,
        context=context,
    )
    for update in (
        {"distribution": list(reversed(payload["distribution"]))},
        {"distribution": [{"option": "first", "probability": "1"}]},
        {"distribution": [{"option": "first", "probability": "0.6"}] * 2},
        {
            "distribution": [
                {"option": "first", "probability": "0.6"},
                {"option": "second", "probability": "0.3"},
            ]
        },
        {"prediction": "unknown"},
        {"distribution": None},
    ):
        with pytest.raises((ContractError, ValidationError)):
            correlate_decision(
                raw,
                DecisionResult.model_validate(payload | update),
                limits=limits(),
                task_spec=task,
                decision_release=release,
                context=context,
            )
    for field in ("modelRef", "tokenizerRef", "calibrationRef"):
        changed = decision_release(
            implementation="laya",
            modelRef=ref(),
            tokenizerRef=ref(),
            calibrationRef=ref(),
            certifiedCohorts=["synthetic"],
        )
        del changed[field]
        with pytest.raises(ContractError):
            correlate_decision(
                raw,
                DecisionResult.model_validate(payload),
                limits=limits(),
                task_spec=task,
                decision_release=DecisionRelease.model_validate(changed),
                context=context,
            )
    with pytest.raises(ContractError):
        correlate_decision(
            raw,
            DecisionResult.model_validate(payload),
            limits=limits(),
            task_spec=task,
            decision_release=release,
            context=decision_context(
                implementation="laya", expected_policy_outcome="use_prediction"
            ),
        )
    rules = DecisionResult.model_validate(
        decision_result(
            status="prediction",
            prediction="first",
            cohortStatus="not_applicable",
            policyOutcome="use_prediction",
        )
    )
    correlate_decision(
        raw,
        rules,
        limits=limits(),
        task_spec=task,
        decision_release=DecisionRelease.model_validate(decision_release()),
        context=decision_context(expected_policy_outcome="use_prediction"),
    )


def test_enrichment_trusted_evidence_and_registered_pins() -> None:
    from conscience_foundry.contracts.common import ArtifactRef

    req = EnrichmentRequest.model_validate(enrichment_request())
    spec = EnrichmentSpec.model_validate(enrichment_spec())
    payload = enrichment_result(
        schemaStatus="valid",
        anchorStatus="valid",
        semanticStatus="supported",
        disposition="accepted",
        rawResponseRef=ref(),
        candidateAnnotationsRef=ref(),
        reasons=[],
    )
    result = EnrichmentResult.model_validate(payload)
    context = enrichment_context(
        expected_schema_status="valid",
        expected_anchor_status="valid",
        expected_semantic_status="supported",
        expected_disposition="accepted",
    )
    correlate_enrichment(
        req,
        result,
        request_bytes=json.dumps(enrichment_request()).encode(),
        limits=limits(),
        spec=spec,
        context=context,
    )
    for changed in (
        enrichment_context(),
        enrichment_context(
            expected_schema_status="valid",
            expected_anchor_status="valid",
            expected_semantic_status="pending",
            expected_disposition="accepted",
        ),
        enrichment_context(
            spec_ref=ArtifactRef.model_validate(ref("kf.enrichment-spec.v1", digest="f" * 64))
        ),
        enrichment_context(validation_policy_ref=ArtifactRef.model_validate(ref(digest="f" * 64))),
    ):
        with pytest.raises(ContractError):
            correlate_enrichment(
                req,
                result,
                request_bytes=json.dumps(enrichment_request()).encode(),
                limits=limits(),
                spec=spec,
                context=changed,
            )
    nonattributed = EnrichmentResult.model_validate(
        payload | {"anchorStatus": "not_applicable", "semanticStatus": "not_applicable"}
    )
    with pytest.raises(ContractError):
        correlate_enrichment(
            req,
            nonattributed,
            request_bytes=json.dumps(enrichment_request()).encode(),
            limits=limits(),
            spec=spec,
            context=context,
        )
    inference_context = enrichment_context(
        anchors_applicable=False,
        attributed_claims=False,
        inference_allowed=True,
        expected_schema_status="valid",
        expected_anchor_status="not_applicable",
        expected_semantic_status="not_applicable",
        expected_disposition="accepted",
    )
    correlate_enrichment(
        req,
        nonattributed,
        request_bytes=json.dumps(enrichment_request()).encode(),
        limits=limits(),
        spec=spec,
        context=inference_context,
    )
    with pytest.raises(ContractError):
        correlate_enrichment(
            req,
            nonattributed,
            request_bytes=json.dumps(enrichment_request()).encode(),
            limits=limits(),
            spec=spec,
            context=enrichment_context(
                anchors_applicable=False,
                attributed_claims=False,
                inference_allowed=False,
                expected_schema_status="valid",
                expected_anchor_status="not_applicable",
                expected_semantic_status="not_applicable",
                expected_disposition="accepted",
            ),
        )


def test_payload_schema_references_require_schema_artifacts() -> None:
    for model, payload in ((EnrichmentSpec, enrichment_spec()), (DecisionTaskSpec, task_spec())):
        for field in ("inputSchemaRef", "outputSchemaRef"):
            with pytest.raises(ValidationError):
                model.model_validate(payload | {field: ref("unregistered.payload.v1")})


def test_extension_schema_registry_and_explicit_edge_roles(tmp_path: Path) -> None:
    from conscience_foundry.contracts.common import ArtifactRef
    from conscience_foundry.contracts.registry import (
        export_schemas,
        registered_schema_ids,
        validate_artifact,
    )
    from conscience_foundry.release.edges import edge_roles

    cases = (
        (EnrichmentSpec, enrichment_spec(graphSpecRef=ref())),
        (EnrichmentRequest, enrichment_request()),
        (EnrichmentResult, enrichment_result()),
        (
            AnnotationSet,
            {
                "schemaVersion": "kf.annotation-set.v1",
                "projectId": PROJECT,
                "specRef": ref("kf.enrichment-spec.v1"),
                "canonicalRevisionRefs": [ref("kf.document-revision.v1")],
                "results": [ref("kf.enrichment-result.v1")],
                "coverageReportRef": ref(),
            },
        ),
        (DecisionTaskSpec, task_spec()),
        (
            DecisionRelease,
            decision_release(
                implementation="laya", modelRef=ref(), tokenizerRef=ref(), calibrationRef=ref()
            ),
        ),
        (DecisionRequest, decision_request()),
        (DecisionResult, decision_result()),
    )
    for model, payload in cases:
        assert payload["schemaVersion"] in registered_schema_ids()
        instance = model.model_validate(payload)
        raw = instance.model_dump_json(by_alias=True).encode()
        artifact = ArtifactRef.model_validate(
            ref(
                str(payload["schemaVersion"]),
                digest=hashlib.sha256(raw).hexdigest(),
                sizeBytes=len(raw),
            )
        )
        admitted = validate_artifact(
            artifact, raw, limits_by_schema={key: limits() for key in registered_schema_ids()}
        )
        assert admitted == instance
        assert edge_roles(str(payload["schemaVersion"]), admitted)
    spec = EnrichmentSpec.model_validate(enrichment_spec(graphSpecRef=ref()))
    edges = edge_roles(spec.schema_version, spec)
    assert tuple(edge.role for edge in edges) == (
        "content",
        "content",
        "content",
        "content",
        "audit",
        "audit",
        "audit",
        "audit",
        "audit",
        "audit",
        "audit",
    )
    selected_result = EnrichmentResult.model_validate(
        enrichment_result(
            schemaStatus="valid",
            anchorStatus="valid",
            semanticStatus="supported",
            disposition="accepted",
            rawResponseRef=ref(),
            candidateAnnotationsRef=ref(),
            reasons=[],
        )
    )
    assert tuple(
        edge.role for edge in edge_roles(selected_result.schema_version, selected_result)
    ) == ("content", "content", "audit", "audit", "audit")
    release = DecisionRelease.model_validate(cases[5][1])
    assert tuple(edge.role for edge in edge_roles(release.schema_version, release)) == (
        "content",
        "content",
        "audit",
        "audit",
        "audit",
        "audit",
        "audit",
        "audit",
        "audit",
    )
    for model, payload in (
        (EnrichmentRequest, enrichment_request()),
        (DecisionRequest, decision_request()),
        (DecisionResult, decision_result()),
    ):
        instance = model.model_validate(payload)
        assert all(
            edge.role == "audit" for edge in edge_roles(str(payload["schemaVersion"]), instance)
        )
    bundle = export_schemas(
        tmp_path,
        project_id=PROJECT,
        store_id="synthetic",
        version="synthetic.v1",
        limits_by_schema={key: limits() for key in registered_schema_ids()},
    )
    assert {binding.schema_id for binding in bundle.contracts} >= {
        str(payload["schemaVersion"]) for _, payload in cases
    }


def test_trusted_contexts_are_immutable_and_require_explicit_valid_values() -> None:
    from dataclasses import FrozenInstanceError

    with pytest.raises(FrozenInstanceError):
        decision_context().baseline_authorized = True
    with pytest.raises(FrozenInstanceError):
        enrichment_context().expected_disposition = "accepted"
    for update in (
        {"baseline_authorized": 1},
        {"probability_tolerance": "-1"},
        {"probability_tolerance": "NaN"},
        {"implementation": "unknown"},
    ):
        with pytest.raises(ContractError):
            decision_context(**update)
    with pytest.raises(ContractError):
        enrichment_context(anchors_applicable=1)


def test_request_schema_and_policy_pins_are_independently_bound() -> None:
    from conscience_foundry.contracts.common import ArtifactRef

    raw = json.dumps(decision_request()).encode()
    result = DecisionResult.model_validate(decision_result())
    task = DecisionTaskSpec.model_validate(task_spec())
    release = DecisionRelease.model_validate(decision_release())
    for field, schema in (
        ("task_spec_ref", "kf.decision-task.v1"),
        ("decision_release_ref", "kf.decision-release.v1"),
        ("output_schema_ref", "json-schema.2020-12"),
        ("policy_ref", "kf.policy.v1"),
        ("decision_policy_ref", "synthetic.payload.v1"),
        ("fallback_policy_ref", "synthetic.payload.v1"),
    ):
        context = decision_context(
            **{field: ArtifactRef.model_validate(ref(schema, digest="f" * 64))}
        )
        with pytest.raises(ContractError):
            correlate_decision(
                raw,
                result,
                limits=limits(),
                task_spec=task,
                decision_release=release,
                context=context,
            )


def test_core_envelopes_import_without_model_runtimes() -> None:
    import sys

    for prefix in ("pydantic_ai", "pydantic_graph", "laya", "modal", "dagster"):
        assert not any(name == prefix or name.startswith(prefix + ".") for name in sys.modules)


def test_missing_response_cannot_claim_completed_semantics() -> None:
    for status in ("supported", "disputed", "insufficient_context"):
        with pytest.raises(ValidationError):
            EnrichmentResult.model_validate(enrichment_result(semanticStatus=status))
    # Revalidation in the correlator also rejects a forged already-built model.
    forged = EnrichmentResult.model_validate(enrichment_result()).model_copy(
        update={"semantic_status": "supported"}
    )
    with pytest.raises(ContractError):
        correlate_enrichment(
            EnrichmentRequest.model_validate(enrichment_request()),
            forged,
            request_bytes=json.dumps(enrichment_request()).encode(),
            limits=limits(),
            spec=EnrichmentSpec.model_validate(enrichment_spec()),
            context=enrichment_context(expected_semantic_status="supported"),
        )


def test_decision_evidence_context_cannot_cross_request_boundary() -> None:
    request_b = decision_request(attemptId=OTHER, inputRef=ref(digest="e" * 64))
    raw_b = json.dumps(request_b).encode()
    result_b = DecisionResult.model_validate(
        decision_result(attemptId=OTHER, requestDigest=hashlib.sha256(raw_b).hexdigest())
    )
    with pytest.raises(ContractError):
        correlate_decision(
            raw_b,
            result_b,
            limits=limits(),
            task_spec=DecisionTaskSpec.model_validate(task_spec()),
            decision_release=DecisionRelease.model_validate(decision_release()),
            context=decision_context(),
        )


def test_enrichment_evidence_context_cannot_cross_request_boundary() -> None:
    request_b = EnrichmentRequest.model_validate(
        enrichment_request(attemptId=OTHER, inputRef=ref(digest="e" * 64))
    )
    with pytest.raises(ContractError):
        correlate_enrichment(
            request_b,
            EnrichmentResult.model_validate(enrichment_result(attemptId=OTHER)),
            request_bytes=json.dumps(
                enrichment_request(attemptId=OTHER, inputRef=ref(digest="e" * 64))
            ).encode(),
            limits=limits(),
            spec=EnrichmentSpec.model_validate(enrichment_spec()),
            context=enrichment_context(),
        )


def test_laya_prediction_requires_request_specific_certification() -> None:
    release = DecisionRelease.model_validate(
        decision_release(
            implementation="laya",
            modelRef=ref(),
            tokenizerRef=ref(),
            calibrationRef=ref(),
            certifiedCohorts=["unrelated"],
        )
    )
    result = DecisionResult.model_validate(
        decision_result(
            status="prediction",
            prediction="first",
            cohortStatus="certified",
            policyOutcome="use_prediction",
            distribution=[
                {"option": "first", "probability": "0.6"},
                {"option": "second", "probability": "0.4"},
            ],
        )
    )
    with pytest.raises(ContractError):
        correlate_decision(
            json.dumps(decision_request()).encode(),
            result,
            limits=limits(),
            task_spec=DecisionTaskSpec.model_validate(task_spec()),
            decision_release=release,
            context=decision_context(
                implementation="laya",
                probabilistic=True,
                calibration_required=True,
                applicable_cohort="synthetic",
                expected_cohort_status="certified",
                expected_policy_outcome="use_prediction",
            ),
        )


@pytest.mark.parametrize(
    "updates",
    [
        {"request_digest": "f" * 64},
        {"project_id": OTHER},
        {"operation_key": "f" * 64},
        {"attempt_id": OTHER},
    ],
)
def test_trusted_context_binds_every_request_identity(updates: dict[str, str]) -> None:
    with pytest.raises(ContractError):
        correlate_decision(
            json.dumps(decision_request()).encode(),
            DecisionResult.model_validate(decision_result()),
            limits=limits(),
            task_spec=DecisionTaskSpec.model_validate(task_spec()),
            decision_release=DecisionRelease.model_validate(decision_release()),
            context=decision_context(**updates),
        )
    with pytest.raises(ContractError):
        correlate_enrichment(
            EnrichmentRequest.model_validate(enrichment_request()),
            EnrichmentResult.model_validate(enrichment_result()),
            request_bytes=json.dumps(enrichment_request()).encode(),
            limits=limits(),
            spec=EnrichmentSpec.model_validate(enrichment_spec()),
            context=enrichment_context(**updates),
        )


def test_exact_request_serialization_requires_new_independent_context() -> None:
    raw = json.dumps(decision_request()).encode() + b" "
    digest = hashlib.sha256(raw).hexdigest()
    result = DecisionResult.model_validate(decision_result(requestDigest=digest))
    kwargs = {
        "limits": limits(),
        "task_spec": DecisionTaskSpec.model_validate(task_spec()),
        "decision_release": DecisionRelease.model_validate(decision_release()),
    }
    with pytest.raises(ContractError):
        correlate_decision(raw, result, context=decision_context(), **kwargs)
    correlate_decision(raw, result, context=decision_context(request_digest=digest), **kwargs)

    request = EnrichmentRequest.model_validate(enrichment_request())
    enrichment = EnrichmentResult.model_validate(enrichment_result())
    spec = EnrichmentSpec.model_validate(enrichment_spec())
    raw = json.dumps(enrichment_request()).encode() + b" "
    with pytest.raises(ContractError):
        correlate_enrichment(
            request,
            enrichment,
            request_bytes=raw,
            limits=limits(),
            spec=spec,
            context=enrichment_context(),
        )
    correlate_enrichment(
        request,
        enrichment,
        request_bytes=raw,
        limits=limits(),
        spec=spec,
        context=enrichment_context(request_digest=hashlib.sha256(raw).hexdigest()),
    )
    for invalid_bytes, bounded in (
        (raw, limits(maxJsonBytes=2)),
        (raw.replace(b'"projectId":', b'"projectId": null, "projectId":'), limits()),
        (json.dumps(enrichment_request(inputRef=ref(digest="e" * 64))).encode(), limits()),
    ):
        with pytest.raises(ContractError):
            correlate_enrichment(
                request,
                enrichment,
                request_bytes=invalid_bytes,
                limits=bounded,
                spec=spec,
                context=enrichment_context(
                    request_digest=hashlib.sha256(invalid_bytes).hexdigest()
                ),
            )


@pytest.mark.parametrize(
    "cohort,status",
    [(None, "certified"), ("unrelated", "certified"), ("synthetic", "uncertified")],
)
def test_laya_cannot_select_its_own_certification(cohort: str | None, status: str) -> None:
    release = DecisionRelease.model_validate(
        decision_release(
            implementation="laya",
            modelRef=ref(),
            tokenizerRef=ref(),
            calibrationRef=ref(),
            certifiedCohorts=["synthetic"],
        )
    )
    result = DecisionResult.model_validate(
        decision_result(
            status="prediction",
            prediction="first",
            cohortStatus="certified",
            policyOutcome="use_prediction",
            distribution=[
                {"option": "first", "probability": "0.6"},
                {"option": "second", "probability": "0.4"},
            ],
        )
    )
    with pytest.raises(ContractError):
        correlate_decision(
            json.dumps(decision_request()).encode(),
            result,
            limits=limits(),
            task_spec=DecisionTaskSpec.model_validate(task_spec()),
            decision_release=release,
            context=decision_context(
                implementation="laya",
                probabilistic=True,
                calibration_required=True,
                expected_policy_outcome="use_prediction",
                applicable_cohort=cohort,
                expected_cohort_status=status,
            ),
        )


def test_trusted_request_context_requires_well_formed_explicit_values() -> None:
    for updates in (
        {"request_digest": "invalid"},
        {"project_id": "invalid"},
        {"operation_key": "invalid"},
        {"attempt_id": "invalid"},
    ):
        with pytest.raises(ContractError):
            decision_context(**updates)
        with pytest.raises(ContractError):
            enrichment_context(**updates)
    for updates in (
        {"expected_cohort_status": "unknown"},
        {"applicable_cohort": ""},
        {"expected_cohort_status": "certified"},
        {"applicable_cohort": "synthetic"},
    ):
        with pytest.raises(ContractError):
            decision_context(**updates)
