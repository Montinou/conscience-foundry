"""Immutable F1 execution records; parsing never dispatches or grants authority."""

from __future__ import annotations

import hashlib
from decimal import Decimal
from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, Field, TypeAdapter, model_validator
from pydantic.json_schema import SkipJsonSchema

from conscience_foundry.contracts.accounting import ResourceUsage
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
    Version,
    WireModel,
)


def _json_array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _zero(value: object) -> object:
    if type(value) is not int or value != 0:
        raise ValueError("F1 requires integer zero")
    return value


F1Zero = Annotated[Literal[0], BeforeValidator(_zero)]
NonemptyString = Annotated[ScalarString, Field(min_length=1)]


class ExecutionConfig(WireModel):
    schema_version: Literal["kf.execution-config.v1"]
    adapter_id: NonemptyString
    deployment_version: Version
    image_digest: Digest
    tariff_ref: Ref
    resource_policy_ref: Ref
    remote_destination_id: NonemptyString

    @model_validator(mode="after")
    def reference_project(self) -> Self:
        if self.tariff_ref.project_id != self.resource_policy_ref.project_id:
            raise ValueError("cross-project execution configuration")
        return self


class ResourceEnvelope(WireModel):
    cpu_milli: PositiveInteger
    memory_mib: PositiveInteger = Field(alias="memoryMiB")
    gpu_count: F1Zero
    max_wall_seconds: PositiveInteger
    max_output_bytes: PositiveInteger
    max_concurrent_attempts: PositiveInteger
    max_attempts_per_operation: PositiveInteger
    automatic_retries: F1Zero


class BudgetEnvelope(WireModel):
    currency: Literal["USD"]
    max_run_cost: Money
    max_attempt_cost: Money
    tariff_ref: Ref
    authorization_id: Id
    valid_until: Instant

    @model_validator(mode="after")
    def positive_and_bounded(self) -> Self:
        if not Decimal("0") < Decimal(self.max_attempt_cost) <= Decimal(self.max_run_cost):
            raise ValueError("invalid budget envelope")
        return self


class ExecutionPlan(WireModel):
    schema_version: Literal["kf.execution-plan.v1"]
    project_id: Id
    run_id: Id
    plan_id: Id
    execution_config_ref: Ref
    admission_report_ref: Ref
    extraction_spec_ref: Ref
    policy_ref: Ref
    profile_id: NonemptyString
    profile_version: Version
    contract_set_ref: Ref
    limits_refs: Annotated[tuple[Ref, ...], BeforeValidator(_json_array), Field(min_length=1)]
    input_refs: Annotated[
        tuple[Ref, ...], BeforeValidator(_json_array), Field(min_length=1, max_length=1)
    ]
    operation_key: Digest
    resources: ResourceEnvelope
    budget: BudgetEnvelope
    expires_at: Instant

    @model_validator(mode="after")
    def correlated_references_and_expiry(self) -> Self:
        references = (
            self.execution_config_ref,
            self.admission_report_ref,
            self.extraction_spec_ref,
            self.policy_ref,
            self.contract_set_ref,
            self.budget.tariff_ref,
            *self.limits_refs,
            *self.input_refs,
        )
        if any(reference.project_id != self.project_id for reference in references):
            raise ValueError("cross-project plan reference")
        if self.budget.valid_until > self.expires_at:
            raise ValueError("budget expiry exceeds plan expiry")
        if len({reference.digest for reference in self.limits_refs}) != len(self.limits_refs):
            raise ValueError("duplicate limits reference")
        return self


class RunAuthorization(WireModel):
    schema_version: Literal["kf.run-authorization.v1"]
    authorization_id: Id
    project_id: Id
    run_id: Id
    admission_report_digest: Digest
    allowed_plan_digests: Annotated[
        tuple[Digest, ...], BeforeValidator(_json_array), Field(min_length=1)
    ]
    max_run_cost: Money
    max_concurrent_attempts: PositiveInteger
    actor_id: Id
    authorized_at: Instant
    expires_at: Instant

    @model_validator(mode="after")
    def immutable_grant_shape(self) -> Self:
        if Decimal(self.max_run_cost) <= 0 or self.authorized_at >= self.expires_at:
            raise ValueError("invalid authorization bounds")
        if len(set(self.allowed_plan_digests)) != len(self.allowed_plan_digests):
            raise ValueError("duplicate allowed plan digest")
        return self


def validate_plan_authorization(
    plan: ExecutionPlan,
    authorization: RunAuthorization,
    now: Instant,
    *,
    plan_bytes: bytes,
    limits: ContractLimits,
) -> None:
    """Bind complete immutable plan bytes to a separately trusted operator grant.

    This pure check does not authenticate the grant's actor, establish current
    policy, or read ledger balances. Dispatch must establish those authorities
    and atomically retain settled/outstanding liabilities across amendments.
    """
    try:
        TypeAdapter(Instant).validate_python(now)
    except ValueError:
        raise ContractError("invalid_schema") from None
    parsed = ExecutionPlan.from_wire(plan_bytes, limits)
    if parsed != plan:
        raise ContractError("hash_mismatch")
    digest = hashlib.sha256(plan_bytes).hexdigest()
    if digest not in authorization.allowed_plan_digests:
        raise ContractError("forbidden")
    if (
        plan.project_id != authorization.project_id
        or plan.run_id != authorization.run_id
        or plan.budget.authorization_id != authorization.authorization_id
        or plan.admission_report_ref.digest != authorization.admission_report_digest
        or Decimal(plan.budget.max_run_cost) != Decimal(authorization.max_run_cost)
        or plan.resources.max_concurrent_attempts > authorization.max_concurrent_attempts
        or plan.expires_at > authorization.expires_at
    ):
        raise ContractError("forbidden")
    if (
        now < authorization.authorized_at
        or now >= authorization.expires_at
        or now >= plan.expires_at
        or now >= plan.budget.valid_until
    ):
        raise ContractError("authorization_expired")


AttemptState = Literal[
    "planned",
    "reserved",
    "dispatching",
    "running",
    "succeeded",
    "failed",
    "unknown_outcome",
    "cancel_requested",
    "cancelled",
]


class StageAttempt(WireModel):
    schema_version: Literal["kf.stage-attempt.v1"]
    project_id: Id
    plan_id: Id
    operation_key: Digest
    attempt_id: Id
    attempt_number: PositiveInteger
    reservation_id: Id
    state: AttemptState
    created_at: Instant
    dispatched_at: Instant | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    finished_at: Instant | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    remote_call_id: NonemptyString | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    result_manifest_ref: Ref | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    reason: Reason | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def state_evidence_shape(self) -> Self:
        terminal = self.state in {"succeeded", "failed", "cancelled"}
        if terminal != (self.finished_at is not None):
            raise ValueError("terminal attempt requires completion timestamp only")
        if self.dispatched_at is not None and self.dispatched_at < self.created_at:
            raise ValueError("dispatch predates attempt")
        if self.finished_at is not None and self.finished_at < (
            self.dispatched_at or self.created_at
        ):
            raise ValueError("completion predates attempt")
        if self.state in {"planned", "reserved"} and any(
            value is not None
            for value in (self.dispatched_at, self.remote_call_id, self.result_manifest_ref)
        ):
            raise ValueError("undispatched attempt has external evidence")
        if self.state == "succeeded" and self.result_manifest_ref is None:
            raise ValueError("successful attempt requires verified result reference")
        if self.result_manifest_ref is not None and (
            self.result_manifest_ref.project_id != self.project_id
            or self.result_manifest_ref.artifact_schema != "kf.result.v1"
        ):
            raise ValueError("invalid result manifest reference")
        return self


class ResultManifest(WireModel):
    schema_version: Literal["kf.result.v1"]
    project_id: Id
    plan_id: Id
    operation_key: Digest
    attempt_id: Id
    input_digests: Annotated[
        tuple[Digest, ...], BeforeValidator(_json_array), Field(min_length=1, max_length=1)
    ]
    status: Literal["succeeded", "failed"]
    outputs: Annotated[tuple[Ref, ...], BeforeValidator(_json_array)]
    document_revision_ref: Ref | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    quality_report_ref: Ref | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    errors: Annotated[tuple[Reason, ...], BeforeValidator(_json_array)]
    usage: ResourceUsage
    completed_at: Instant

    @model_validator(mode="after")
    def result_shape(self) -> Self:
        references = (*self.outputs, self.usage.tariff_ref)
        if any(reference.project_id != self.project_id for reference in references):
            raise ValueError("cross-project result reference")
        if len({(r.digest, r.artifact_schema) for r in self.outputs}) != len(self.outputs):
            raise ValueError("duplicate output artifact")
        for reference, schema in (
            (self.document_revision_ref, "kf.document-revision.v1"),
            (self.quality_report_ref, "kf.quality-report.v1"),
        ):
            if reference is not None and (
                reference.project_id != self.project_id
                or reference.artifact_schema != schema
                or reference not in self.outputs
            ):
                raise ValueError("invalid nominated output")
        if self.status == "succeeded":
            if self.errors or self.document_revision_ref is None or self.quality_report_ref is None:
                raise ValueError("successful result requires complete outputs and no errors")
            for schema in ("kf.document-revision.v1", "kf.quality-report.v1"):
                if sum(output.artifact_schema == schema for output in self.outputs) != 1:
                    raise ValueError(
                        "successful result requires unique document and quality report"
                    )
        elif not self.errors or self.document_revision_ref is not None:
            raise ValueError("failed result requires error and cannot nominate revision")
        return self
