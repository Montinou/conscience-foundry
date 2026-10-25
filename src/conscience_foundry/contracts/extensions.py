"""Versioned extension envelopes; no generation, inference or policy authority."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from decimal import Decimal
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, BeforeValidator, Field, StringConstraints, model_validator
from pydantic.json_schema import SkipJsonSchema

from conscience_foundry.contracts.canonical import DocumentSpan
from conscience_foundry.contracts.common import (
    ContractError,
    ContractLimits,
    Digest,
    Id,
    Instant,
    Reason,
    Ref,
    ScalarString,
    Version,
    WireModel,
)

NonemptyString = Annotated[ScalarString, Field(min_length=1)]


def _array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _refs_project(refs: tuple[Ref, ...], project_id: str | None = None) -> None:
    projects = {ref.project_id for ref in refs}
    if len(projects) > 1 or (project_id is not None and projects - {project_id}):
        raise ValueError("cross-project reference")


def _unique_refs(refs: tuple[Ref, ...]) -> None:
    identities = {(ref.project_id, ref.artifact_schema, ref.digest, ref.size_bytes) for ref in refs}
    if len(identities) != len(refs):
        raise ValueError("duplicate reference")


def _ref_role(ref: Ref, role: str) -> None:
    if ref.artifact_schema != role:
        raise ValueError("wrong reference schema")


class EnrichmentSpec(WireModel):
    schema_version: Literal["kf.enrichment-spec.v1"]
    spec_id: Version
    task_id: NonemptyString
    profile_id: NonemptyString
    profile_version: Version
    input_schema_ref: Ref
    output_schema_ref: Ref
    prompt_ref: Ref
    context_policy_ref: Ref
    model_route_ref: Ref
    generation_settings_ref: Ref
    validation_policy_ref: Ref
    review_policy_ref: Ref
    execution_limits_ref: Ref
    runtime_ref: Ref
    graph_spec_ref: Ref | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def correlated_dependencies(self) -> Self:
        _ref_role(self.input_schema_ref, "json-schema.2020-12")
        _ref_role(self.output_schema_ref, "json-schema.2020-12")
        _refs_project(
            tuple(
                value
                for value in (
                    self.input_schema_ref,
                    self.output_schema_ref,
                    self.prompt_ref,
                    self.context_policy_ref,
                    self.model_route_ref,
                    self.generation_settings_ref,
                    self.validation_policy_ref,
                    self.review_policy_ref,
                    self.execution_limits_ref,
                    self.runtime_ref,
                    self.graph_spec_ref,
                )
                if value is not None
            )
        )
        return self


class EnrichmentRequest(WireModel):
    schema_version: Literal["kf.enrichment-request.v1"]
    project_id: Id
    operation_key: Digest
    attempt_id: Id
    spec_ref: Ref
    policy_ref: Ref
    canonical_revision_refs: Annotated[tuple[Ref, ...], BeforeValidator(_array)]
    context_spans: Annotated[tuple[DocumentSpan, ...], BeforeValidator(_array)]
    omitted_context_refs: Annotated[tuple[Ref, ...], BeforeValidator(_array)]
    input_ref: Ref
    reservation_id: Id
    deadline: Instant

    @model_validator(mode="after")
    def context_shapes(self) -> Self:
        _refs_project(
            (
                self.spec_ref,
                self.policy_ref,
                self.input_ref,
                *self.canonical_revision_refs,
                *self.omitted_context_refs,
            ),
            self.project_id,
        )
        _ref_role(self.spec_ref, "kf.enrichment-spec.v1")
        _ref_role(self.policy_ref, "kf.policy.v1")
        for ref in self.canonical_revision_refs:
            _ref_role(ref, "kf.document-revision.v1")
        _unique_refs(self.canonical_revision_refs)
        _unique_refs(self.omitted_context_refs)
        if any(span.project_id != self.project_id for span in self.context_spans):
            raise ValueError("cross-project span")
        return self


class EnrichmentResult(WireModel):
    schema_version: Literal["kf.enrichment-result.v1"]
    project_id: Id
    operation_key: Digest
    attempt_id: Id
    spec_ref: Ref
    raw_response_ref: Ref | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    candidate_annotations_ref: Ref | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    schema_status: Literal["valid", "invalid", "not_run"]
    anchor_status: Literal["valid", "invalid", "not_applicable", "not_run"]
    semantic_status: Literal[
        "pending", "supported", "disputed", "insufficient_context", "not_applicable"
    ]
    disposition: Literal["candidate", "accepted", "needs_review", "rejected"]
    validation_report_ref: Ref
    attempt_report_ref: Ref
    reasons: Annotated[tuple[Reason, ...], BeforeValidator(_array)]

    @model_validator(mode="after")
    def validation_dimensions(self) -> Self:
        _refs_project(
            tuple(
                ref
                for ref in (
                    self.spec_ref,
                    self.raw_response_ref,
                    self.candidate_annotations_ref,
                    self.validation_report_ref,
                    self.attempt_report_ref,
                )
                if ref is not None
            ),
            self.project_id,
        )
        _ref_role(self.spec_ref, "kf.enrichment-spec.v1")
        if self.schema_status == "not_run":
            if (
                self.anchor_status != "not_run"
                or self.semantic_status not in {"pending", "not_applicable"}
                or self.raw_response_ref is not None
                or self.candidate_annotations_ref is not None
                or not self.reasons
                or self.disposition == "accepted"
            ):
                raise ValueError("absent response requires explicit unperformed evidence")
        if self.schema_status == "invalid" and not self.reasons:
            raise ValueError("invalid schema requires a reason")
        if self.disposition == "accepted" and (
            self.candidate_annotations_ref is None
            or self.schema_status != "valid"
            or self.anchor_status not in {"valid", "not_applicable"}
            or self.semantic_status not in {"supported", "not_applicable"}
        ):
            raise ValueError("accepted shape requires completed applicable validation")
        return self


class AnnotationSet(WireModel):
    schema_version: Literal["kf.annotation-set.v1"]
    project_id: Id
    spec_ref: Ref
    canonical_revision_refs: Annotated[tuple[Ref, ...], BeforeValidator(_array)]
    results: Annotated[tuple[Ref, ...], BeforeValidator(_array)]
    coverage_report_ref: Ref

    @model_validator(mode="after")
    def correlated_membership(self) -> Self:
        _refs_project(
            (self.spec_ref, self.coverage_report_ref, *self.canonical_revision_refs, *self.results),
            self.project_id,
        )
        _ref_role(self.spec_ref, "kf.enrichment-spec.v1")
        for ref in self.canonical_revision_refs:
            _ref_role(ref, "kf.document-revision.v1")
        for ref in self.results:
            _ref_role(ref, "kf.enrichment-result.v1")
        _unique_refs(self.canonical_revision_refs)
        _unique_refs(self.results)
        return self


def _probability(value: str) -> str:
    if not Decimal("0") <= Decimal(value) <= Decimal("1"):
        raise ValueError("probability outside unit interval")
    return value


ProbabilityValue = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[0-9]+(?:\.[0-9]{1,9})?$"),
    AfterValidator(_probability),
]


class Probability(WireModel):
    option: NonemptyString
    probability: ProbabilityValue


class DecisionTaskSpec(WireModel):
    schema_version: Literal["kf.decision-task.v1"]
    task_id: NonemptyString
    version: Version
    input_schema_ref: Ref
    output_schema_ref: Ref
    options: Annotated[tuple[NonemptyString, ...], BeforeValidator(_array), Field(min_length=1)]
    option_order_version: Version
    fallback_policy_ref: Ref

    @model_validator(mode="after")
    def registered_options(self) -> Self:
        _ref_role(self.input_schema_ref, "json-schema.2020-12")
        _ref_role(self.output_schema_ref, "json-schema.2020-12")
        _refs_project((self.input_schema_ref, self.output_schema_ref, self.fallback_policy_ref))
        if len(set(self.options)) != len(self.options):
            raise ValueError("duplicate option")
        return self


class DecisionRelease(WireModel):
    schema_version: Literal["kf.decision-release.v1"]
    release_id: Id
    implementation: Literal["rules", "classifier", "laya"]
    task_spec_refs: Annotated[tuple[Ref, ...], BeforeValidator(_array), Field(min_length=1)]
    model_ref: Ref | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    tokenizer_ref: Ref | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    runtime_ref: Ref
    state_builder_ref: Ref
    dataset_provenance_ref: Ref
    calibration_ref: Ref | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    decision_policy_ref: Ref
    certified_cohorts: Annotated[tuple[NonemptyString, ...], BeforeValidator(_array)]
    evaluation_ref: Ref

    @model_validator(mode="after")
    def release_dependencies(self) -> Self:
        _refs_project(
            tuple(
                ref
                for ref in (
                    *self.task_spec_refs,
                    self.model_ref,
                    self.tokenizer_ref,
                    self.runtime_ref,
                    self.state_builder_ref,
                    self.dataset_provenance_ref,
                    self.calibration_ref,
                    self.decision_policy_ref,
                    self.evaluation_ref,
                )
                if ref is not None
            )
        )
        for ref in self.task_spec_refs:
            _ref_role(ref, "kf.decision-task.v1")
        _unique_refs(self.task_spec_refs)
        if len(set(self.certified_cohorts)) != len(self.certified_cohorts):
            raise ValueError("duplicate certified cohort")
        return self


class DecisionRequest(WireModel):
    schema_version: Literal["kf.decision-request.v1"]
    project_id: Id
    task_spec_ref: Ref
    decision_release_ref: Ref
    input_ref: Ref
    policy_ref: Ref
    context_revision_refs: Annotated[tuple[Ref, ...], BeforeValidator(_array)]
    operation_key: Digest
    attempt_id: Id
    reservation_id: Id
    deadline: Instant

    @model_validator(mode="after")
    def request_dependencies(self) -> Self:
        _refs_project(
            (
                self.task_spec_ref,
                self.decision_release_ref,
                self.input_ref,
                self.policy_ref,
                *self.context_revision_refs,
            ),
            self.project_id,
        )
        _ref_role(self.task_spec_ref, "kf.decision-task.v1")
        _ref_role(self.decision_release_ref, "kf.decision-release.v1")
        _ref_role(self.policy_ref, "kf.policy.v1")
        for ref in self.context_revision_refs:
            _ref_role(ref, "kf.document-revision.v1")
        _unique_refs(self.context_revision_refs)
        return self


class DecisionResult(WireModel):
    schema_version: Literal["kf.decision-result.v1"]
    project_id: Id
    operation_key: Digest
    attempt_id: Id
    request_digest: Digest
    task_spec_ref: Ref
    decision_release_ref: Ref
    status: Literal["prediction", "abstain", "unavailable", "invalid"]
    prediction: NonemptyString | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    distribution: (
        Annotated[tuple[Probability, ...], BeforeValidator(_array)] | SkipJsonSchema[None]
    ) = Field(default=None, exclude_if=lambda value: value is None)
    cohort_status: Literal["certified", "uncertified", "not_applicable"]
    policy_outcome: Literal["use_prediction", "use_baseline", "needs_review", "stop"]
    reason: Reason
    trace_ref: Ref

    @model_validator(mode="after")
    def conditional_prediction(self) -> Self:
        _refs_project(
            (self.task_spec_ref, self.decision_release_ref, self.trace_ref), self.project_id
        )
        _ref_role(self.task_spec_ref, "kf.decision-task.v1")
        _ref_role(self.decision_release_ref, "kf.decision-release.v1")
        if self.status == "prediction":
            if self.prediction is None:
                raise ValueError("prediction status requires a prediction")
        elif (
            self.prediction is not None
            or self.distribution is not None
            or self.policy_outcome == "use_prediction"
        ):
            raise ValueError("nonprediction status cannot carry actionable prediction")
        if self.status == "invalid" and self.policy_outcome != "stop":
            raise ValueError("integrity failure stops protected action")
        if self.policy_outcome == "use_prediction" and self.cohort_status == "uncertified":
            raise ValueError("uncertified result cannot drive prediction")
        return self


def _identity(ref: Ref) -> tuple[str, str, str, int, str]:
    """Artifact identity is independent of mutable verified physical locators."""
    return (ref.project_id, ref.artifact_schema, ref.digest, ref.size_bytes, ref.media_type)


def _match(left: Ref, right: Ref) -> None:
    if _identity(left) != _identity(right):
        raise ContractError("schema_incompatible")


@dataclass(frozen=True)
class EnrichmentValidationContext:
    """Trusted registered task/policy binding and independently observed evidence.

    This is control-plane context, never constructed from a model response.
    Callers verify the pinned spec/policy artifact bytes and compute each expected
    validation dimension independently. No envelope field proves source support.
    """

    request_digest: Digest
    project_id: Id
    operation_key: Digest
    attempt_id: Id
    spec_ref: Ref
    validation_policy_ref: Ref
    review_policy_ref: Ref
    anchors_applicable: bool
    attributed_claims: bool
    inference_allowed: bool
    expected_schema_status: Literal["valid", "invalid", "not_run"]
    expected_anchor_status: Literal["valid", "invalid", "not_applicable", "not_run"]
    expected_semantic_status: Literal[
        "pending", "supported", "disputed", "insufficient_context", "not_applicable"
    ]
    expected_disposition: Literal["candidate", "accepted", "needs_review", "rejected"]

    def __post_init__(self) -> None:
        _validate_context_identity(
            self.request_digest, self.project_id, self.operation_key, self.attempt_id
        )
        if any(
            type(value) is not bool
            for value in (self.anchors_applicable, self.attributed_claims, self.inference_allowed)
        ):
            raise ContractError("invalid_schema")
        if any(
            not isinstance(ref, Ref)
            for ref in (self.spec_ref, self.validation_policy_ref, self.review_policy_ref)
        ):
            raise ContractError("invalid_schema")


@dataclass(frozen=True)
class DecisionValidationContext:
    """Trusted static schema/policy binding, not a wire grant or a policy engine.

    The caller resolves and verifies task/release/output/policy artifacts before
    supplying this context. The expected outcome is computed independently under
    current policy; it is not an allowlist from which a response may choose.
    """

    request_digest: Digest
    project_id: Id
    operation_key: Digest
    attempt_id: Id
    task_spec_ref: Ref
    decision_release_ref: Ref
    output_schema_ref: Ref
    policy_ref: Ref
    decision_policy_ref: Ref
    fallback_policy_ref: Ref
    implementation: Literal["rules", "classifier", "laya"]
    probabilistic: bool
    calibration_required: bool
    probability_tolerance: str
    expected_policy_outcome: Literal["use_prediction", "use_baseline", "needs_review", "stop"]
    baseline_authorized: bool
    applicable_cohort: str | None
    expected_cohort_status: Literal["certified", "uncertified", "not_applicable"]

    def __post_init__(self) -> None:
        from pydantic import TypeAdapter, ValidationError

        _validate_context_identity(
            self.request_digest, self.project_id, self.operation_key, self.attempt_id
        )
        if any(
            type(value) is not bool
            for value in (self.probabilistic, self.calibration_required, self.baseline_authorized)
        ):
            raise ContractError("invalid_schema")
        if any(
            not isinstance(ref, Ref)
            for ref in (
                self.task_spec_ref,
                self.decision_release_ref,
                self.output_schema_ref,
                self.policy_ref,
                self.decision_policy_ref,
                self.fallback_policy_ref,
            )
        ):
            raise ContractError("invalid_schema")
        try:
            TypeAdapter(ProbabilityValue).validate_python(self.probability_tolerance)
        except ValidationError:
            raise ContractError("invalid_schema") from None
        if self.implementation not in {"rules", "classifier", "laya"}:
            raise ContractError("unsupported_schema")
        if self.expected_policy_outcome not in {
            "use_prediction",
            "use_baseline",
            "needs_review",
            "stop",
        }:
            raise ContractError("invalid_schema")
        if self.expected_cohort_status not in {"certified", "uncertified", "not_applicable"}:
            raise ContractError("invalid_schema")
        if self.applicable_cohort is not None:
            try:
                TypeAdapter(NonemptyString).validate_python(self.applicable_cohort)
            except ValidationError:
                raise ContractError("invalid_schema") from None
        if self.implementation == "rules" and (
            self.expected_cohort_status != "not_applicable" or self.applicable_cohort is not None
        ):
            raise ContractError("invalid_schema")


def _validate_context_identity(
    request_digest: str, project_id: str, operation_key: str, attempt_id: str
) -> None:
    from pydantic import TypeAdapter, ValidationError

    try:
        TypeAdapter(tuple[Digest, Id, Digest, Id]).validate_python(
            (request_digest, project_id, operation_key, attempt_id)
        )
    except ValidationError:
        raise ContractError("invalid_schema") from None


def _bind_request_context(
    context: EnrichmentValidationContext | DecisionValidationContext,
    request_bytes: bytes,
    project_id: str,
    operation_key: str,
    attempt_id: str,
) -> None:
    if (context.request_digest, context.project_id, context.operation_key, context.attempt_id) != (
        hashlib.sha256(request_bytes).hexdigest(),
        project_id,
        operation_key,
        attempt_id,
    ):
        raise ContractError("revision_mismatch")


def correlate_enrichment(
    request: EnrichmentRequest,
    result: EnrichmentResult,
    *,
    request_bytes: bytes,
    limits: ContractLimits,
    spec: EnrichmentSpec,
    context: EnrichmentValidationContext,
) -> None:
    """Correlate shape and trusted evidence; never infer truth from a response.

    The exact bounded request bytes are parsed, compared and hashed here.
    Spec/ref byte integrity, context revision resolution, exact anchoring,
    permissions and semantic review are separately established by the caller.
    This method validates the independently supplied outcomes and their pins.
    """
    from pydantic import ValidationError

    try:
        request = EnrichmentRequest.model_validate(request.model_dump(mode="json", by_alias=True))
        result = EnrichmentResult.model_validate(result.model_dump(mode="json", by_alias=True))
        spec = EnrichmentSpec.model_validate(spec.model_dump(mode="json", by_alias=True))
    except ValidationError:
        raise ContractError("invalid_schema") from None
    if EnrichmentRequest.from_wire(request_bytes, limits) != request:
        raise ContractError("revision_mismatch")
    _bind_request_context(
        context, request_bytes, request.project_id, request.operation_key, request.attempt_id
    )
    if (request.project_id, request.operation_key, request.attempt_id) != (
        result.project_id,
        result.operation_key,
        result.attempt_id,
    ):
        raise ContractError("revision_mismatch")
    _match(request.spec_ref, result.spec_ref)
    _match(request.spec_ref, context.spec_ref)
    _match(spec.validation_policy_ref, context.validation_policy_ref)
    _match(spec.review_policy_ref, context.review_policy_ref)
    if spec.input_schema_ref.project_id != request.project_id:
        raise ContractError("forbidden")
    if (result.schema_status, result.anchor_status, result.semantic_status, result.disposition) != (
        context.expected_schema_status,
        context.expected_anchor_status,
        context.expected_semantic_status,
        context.expected_disposition,
    ):
        raise ContractError("invalid_schema")
    if result.anchor_status == "not_applicable" and context.anchors_applicable:
        raise ContractError("invalid_span")
    if result.semantic_status == "not_applicable" and context.attributed_claims:
        raise ContractError("invalid_schema")
    if result.disposition == "accepted":
        if context.anchors_applicable and result.anchor_status != "valid":
            raise ContractError("invalid_span")
        if context.attributed_claims:
            if not context.anchors_applicable or result.semantic_status != "supported":
                raise ContractError("invalid_schema")
        elif not context.inference_allowed:
            raise ContractError("forbidden")


def correlate_decision(
    request_bytes: bytes,
    result: DecisionResult,
    *,
    limits: ContractLimits,
    task_spec: DecisionTaskSpec,
    decision_release: DecisionRelease,
    context: DecisionValidationContext,
) -> None:
    """Bind the exact bounded request bytes and trusted categorical policy.

    SHA-256 is computed over original bytes, never reserialization or a response
    claim. Task/release/output schema artifact integrity is verified separately
    by the registry/custody caller. This function performs no model or policy
    evaluation and cannot grant permissions, funding or fallback authorization.
    """
    from pydantic import ValidationError

    request = DecisionRequest.from_wire(request_bytes, limits)
    _bind_request_context(
        context, request_bytes, request.project_id, request.operation_key, request.attempt_id
    )
    try:
        result = DecisionResult.model_validate(result.model_dump(mode="json", by_alias=True))
        task_spec = DecisionTaskSpec.model_validate(
            task_spec.model_dump(mode="json", by_alias=True)
        )
        decision_release = DecisionRelease.model_validate(
            decision_release.model_dump(mode="json", by_alias=True)
        )
    except ValidationError:
        raise ContractError("invalid_schema") from None
    if (request.project_id, request.operation_key, request.attempt_id) != (
        result.project_id,
        result.operation_key,
        result.attempt_id,
    ) or result.request_digest != hashlib.sha256(request_bytes).hexdigest():
        raise ContractError("revision_mismatch")
    for actual, expected in (
        (request.task_spec_ref, result.task_spec_ref),
        (request.decision_release_ref, result.decision_release_ref),
        (request.task_spec_ref, context.task_spec_ref),
        (request.decision_release_ref, context.decision_release_ref),
        (request.policy_ref, context.policy_ref),
        (task_spec.output_schema_ref, context.output_schema_ref),
        (task_spec.fallback_policy_ref, context.fallback_policy_ref),
        (decision_release.decision_policy_ref, context.decision_policy_ref),
    ):
        _match(actual, expected)
    if not any(
        _identity(ref) == _identity(request.task_spec_ref)
        for ref in decision_release.task_spec_refs
    ):
        raise ContractError("schema_incompatible")
    if (
        task_spec.input_schema_ref.project_id != request.project_id
        or decision_release.runtime_ref.project_id != request.project_id
    ):
        raise ContractError("forbidden")
    if context.implementation != decision_release.implementation:
        raise ContractError("schema_incompatible")
    if result.policy_outcome != context.expected_policy_outcome:
        raise ContractError("forbidden")
    if result.cohort_status != context.expected_cohort_status:
        raise ContractError("forbidden")
    if result.policy_outcome == "use_baseline" and not context.baseline_authorized:
        raise ContractError("forbidden")
    if decision_release.implementation == "rules":
        if (
            context.probabilistic
            or context.calibration_required
            or result.distribution is not None
            or result.cohort_status != "not_applicable"
        ):
            raise ContractError("invalid_schema")
    elif decision_release.implementation == "laya" and (
        not context.probabilistic or not context.calibration_required
    ):
        raise ContractError("schema_incompatible")
    if result.status == "prediction":
        if result.prediction not in task_spec.options:
            raise ContractError("invalid_schema")
        if result.distribution is not None:
            if (
                not context.probabilistic
                or tuple(item.option for item in result.distribution) != task_spec.options
            ):
                raise ContractError("invalid_schema")
            total = sum((Decimal(item.probability) for item in result.distribution), Decimal(0))
            if abs(total - Decimal(1)) > Decimal(context.probability_tolerance):
                raise ContractError("invalid_schema")
        if result.policy_outcome == "use_prediction":
            if context.probabilistic and result.distribution is None:
                raise ContractError("invalid_schema")
            if context.calibration_required and (
                context.expected_cohort_status != "certified"
                or context.applicable_cohort is None
                or context.applicable_cohort not in decision_release.certified_cohorts
                or decision_release.calibration_ref is None
            ):
                raise ContractError("forbidden")
            if decision_release.implementation == "laya" and (
                decision_release.model_ref is None or decision_release.tokenizer_ref is None
            ):
                raise ContractError("invalid_schema")
