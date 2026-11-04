"""Immutable enrichment registration and transport evidence contracts."""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, Field, model_validator
from pydantic.json_schema import SkipJsonSchema

from conscience_foundry.contracts.canonical import DocumentSpan
from conscience_foundry.contracts.codec import hash_jcs
from conscience_foundry.contracts.common import (
    ContractError,
    ContractLimits,
    Digest,
    Id,
    Instant,
    Money,
    PositiveInteger,
    Reason,
    Ref,
    ScalarString,
    WireModel,
)
from conscience_foundry.contracts.execution import AttemptState, BudgetEnvelope, ResourceEnvelope


def _array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _references(project: Id, refs: tuple[Ref, ...]) -> None:
    if any(ref.project_id != project for ref in refs):
        raise ValueError("cross-project reference")


def _role(ref: Ref, role: str) -> None:
    if ref.artifact_schema != role:
        raise ValueError("wrong reference role")


def _identity(ref: Ref) -> str:
    return json.dumps(
        ref.model_dump(by_alias=True), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


class EnrichmentOperation(WireModel):
    schema_version: Literal["cf.enrichment-operation.v1"]
    project_id: Id
    asset_id: Id
    canonical_revision_ref: Ref
    spec_ref: Ref
    policy_ref: Ref
    input_ref: Ref
    context_spans: Annotated[tuple[DocumentSpan, ...], BeforeValidator(_array)]
    omitted_context_refs: Annotated[tuple[Ref, ...], BeforeValidator(_array)]

    @model_validator(mode="after")
    def correlated(self) -> Self:
        _references(
            self.project_id,
            (
                self.canonical_revision_ref,
                self.spec_ref,
                self.policy_ref,
                self.input_ref,
                *self.omitted_context_refs,
            ),
        )
        for ref, role in (
            (self.canonical_revision_ref, "cf.document-revision.v1"),
            (self.spec_ref, "cf.enrichment-spec.v1"),
            (self.policy_ref, "cf.policy.v1"),
            (self.input_ref, "cf.enrichment-payload.v1"),
        ):
            _role(ref, role)
        if any(span.project_id != self.project_id for span in self.context_spans):
            raise ValueError("cross-project span")
        if len({(span.source_id, span.revision_id) for span in self.context_spans}) > 1:
            raise ValueError("context spans must share one revision")
        identities = tuple(_identity(ref) for ref in self.omitted_context_refs)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("omitted references must be sorted and unique")
        return self


def enrichment_operation_key(operation: EnrichmentOperation, *, limits: ContractLimits) -> Digest:
    if not isinstance(operation, EnrichmentOperation) or not isinstance(limits, ContractLimits):
        raise ContractError("invalid_schema")
    data = operation.model_dump_json(by_alias=True).encode("utf-8")
    bounded = EnrichmentOperation.from_wire(data, limits)
    return hash_jcs("cf.enrichment-operation.v1", bounded.model_dump(by_alias=True, mode="json"))


class EnrichmentAllocationPolicy(WireModel):
    """Operator-pinned internal allocation; it is not storage or process evidence."""

    schema_version: Literal["cf.enrichment-allocation-policy.v1"]
    project_id: Id
    tariff_ref: Ref
    fixed_charge_usd: Money
    funded_from: Instant
    funded_until: Instant

    @model_validator(mode="after")
    def valid_allocation(self) -> Self:
        _references(self.project_id, (self.tariff_ref,))
        if Decimal(self.fixed_charge_usd) <= 0 or self.funded_from >= self.funded_until:
            raise ValueError("invalid allocation policy bounds")
        return self


class EnrichmentPlan(WireModel):
    schema_version: Literal["cf.enrichment-plan.v1"]
    project_id: Id
    run_id: Id
    plan_id: Id
    operation_ref: Ref
    operation_key: Digest
    admission_report_ref: Ref
    contract_set_ref: Ref
    limits_refs: Annotated[tuple[Ref, ...], BeforeValidator(_array), Field(min_length=1)]
    allocation_policy_ref: Ref
    task_schema_installation_ref: Ref
    resources: ResourceEnvelope
    budget: BudgetEnvelope
    expires_at: Instant

    @model_validator(mode="after")
    def correlated(self) -> Self:
        _references(
            self.project_id,
            (
                self.operation_ref,
                self.admission_report_ref,
                self.contract_set_ref,
                self.allocation_policy_ref,
                self.task_schema_installation_ref,
                self.budget.tariff_ref,
                *self.limits_refs,
            ),
        )
        for ref, role in (
            (self.operation_ref, "cf.enrichment-operation.v1"),
            (self.admission_report_ref, "cf.admission-report.v1"),
            (self.contract_set_ref, "cf.contract-set.v1"),
            (self.allocation_policy_ref, "cf.enrichment-allocation-policy.v1"),
            (self.task_schema_installation_ref, "cf.enrichment-schema-installation.v1"),
        ):
            _role(ref, role)
        if any(ref.artifact_schema != "cf.contract-limits.v1" for ref in self.limits_refs):
            raise ValueError("wrong limits role")
        if len({ref.digest for ref in self.limits_refs}) != len(self.limits_refs):
            raise ValueError("duplicate limits reference")
        if self.budget.valid_until > self.expires_at:
            raise ValueError("budget expiry exceeds plan expiry")
        return self


class EnrichmentPayload(WireModel):
    schema_version: Literal["cf.enrichment-payload.v1"]
    project_id: Id
    schema_ref: Ref
    value: dict[str, object]

    @model_validator(mode="after")
    def correlated(self) -> Self:
        _references(self.project_id, (self.schema_ref,))
        _role(self.schema_ref, "json-schema.2020-12")
        return self


class EnrichmentAttempt(WireModel):
    schema_version: Literal["cf.enrichment-attempt.v1"]
    project_id: Id
    plan_id: Id
    operation_key: Digest
    attempt_id: Id
    attempt_number: PositiveInteger
    reservation_id: Id
    state: AttemptState
    created_at: Instant
    dispatched_at: Instant | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda v: v is None
    )
    finished_at: Instant | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda v: v is None
    )
    remote_call_id: Annotated[ScalarString, Field(min_length=1)] | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda v: v is None
    )
    attempt_report_ref: Ref | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda v: v is None
    )
    reason: Reason | SkipJsonSchema[None] = Field(default=None, exclude_if=lambda v: v is None)

    @model_validator(mode="after")
    def state_evidence_shape(self) -> Self:
        terminal = self.state in {"succeeded", "failed", "cancelled"}
        if terminal != (self.finished_at is not None) or (
            terminal and self.attempt_report_ref is None
        ):
            raise ValueError("terminal attempt requires completion and report")
        if self.dispatched_at is not None and self.dispatched_at < self.created_at:
            raise ValueError("dispatch predates attempt")
        if self.finished_at is not None and self.finished_at < (
            self.dispatched_at or self.created_at
        ):
            raise ValueError("completion predates attempt")
        if self.state in {"planned", "reserved"} and any(
            v is not None
            for v in (self.dispatched_at, self.remote_call_id, self.attempt_report_ref)
        ):
            raise ValueError("undispatched attempt has external evidence")
        if self.attempt_report_ref is not None:
            _references(self.project_id, (self.attempt_report_ref,))
            _role(self.attempt_report_ref, "cf.enrichment-attempt-report.v1")
        return self


class EnrichmentAttemptReport(WireModel):
    schema_version: Literal["cf.enrichment-attempt-report.v1"]
    project_id: Id
    operation_key: Digest
    attempt_id: Id
    reservation_id: Id
    request_ref: Ref
    allocation_evidence_ref: Ref
    observed_state: Literal["running", "succeeded", "failed", "cancelled", "unknown_outcome"]
    observed_at: Instant
    raw_response_ref: Ref | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda v: v is None
    )
    reasons: Annotated[tuple[Reason, ...], BeforeValidator(_array)]

    @model_validator(mode="after")
    def correlated(self) -> Self:
        _references(
            self.project_id,
            tuple(
                ref
                for ref in (self.request_ref, self.allocation_evidence_ref, self.raw_response_ref)
                if ref is not None
            ),
        )
        _role(self.request_ref, "cf.enrichment-request.v1")
        return self


class TaskSchemaInstallation(WireModel):
    schema_version: Literal["cf.enrichment-schema-installation.v1"]
    project_id: Id
    spec_ref: Ref
    input_schema_ref: Ref
    output_schema_ref: Ref
    policy_ref: Ref
    actor_id: Id
    evidence_ref: Ref
    installed_at: Instant

    @model_validator(mode="after")
    def correlated(self) -> Self:
        _references(
            self.project_id,
            (
                self.spec_ref,
                self.input_schema_ref,
                self.output_schema_ref,
                self.policy_ref,
                self.evidence_ref,
            ),
        )
        for ref, role in (
            (self.spec_ref, "cf.enrichment-spec.v1"),
            (self.input_schema_ref, "json-schema.2020-12"),
            (self.output_schema_ref, "json-schema.2020-12"),
            (self.policy_ref, "cf.policy.v1"),
        ):
            _role(ref, role)
        return self
