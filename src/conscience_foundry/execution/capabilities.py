"""Fail-closed provider capability evidence for the bounded remote worker."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, Field, model_validator
from pydantic.json_schema import SkipJsonSchema

from conscience_foundry.contracts.common import (
    ContractError,
    Digest,
    Id,
    Instant,
    PositiveInteger,
    Ref,
    SafeInteger,
    Version,
    WireModel,
)
from conscience_foundry.contracts.execution import ExecutionPlan

PLATFORM_RETRY_CAVEAT = (
    "Function retries=0 and a finite function timeout do not bound platform container-crash "
    "restarts (rescheduling), startup or scheduling time; readiness needs those bounds "
    "evidenced for the exact deployment."
)


def _json_array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class CapabilityRecord(WireModel):
    """Private operator-supplied evidence about one exact remote deployment."""

    schema_version: Literal["kf.modal-capability-record.v1"]
    project_id: Id
    execution_config_ref: Ref
    sdk_version: Version
    deployment_version: Version
    image_digest: Digest
    code_digest: Digest
    cpu_milli: PositiveInteger
    memory_mib: PositiveInteger = Field(alias="memoryMiB")
    gpu_count: SafeInteger
    function_retries: SafeInteger
    startup_timeout_seconds: PositiveInteger
    scheduling_timeout_seconds: PositiveInteger
    execution_timeout_seconds: PositiveInteger
    platform_restart_bound: Literal["bounded", "unbounded", "unknown"]
    max_platform_restarts: SafeInteger | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    total_bound_seconds: PositiveInteger | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    cancellation: Literal["terminates_containers", "request_only", "unsupported"]
    deadline_enforcement: Literal["entry_and_every_bounded_step", "entry_only", "none"]
    valid_until: Instant
    source_evidence_refs: Annotated[
        tuple[Ref, ...], BeforeValidator(_json_array), Field(min_length=1)
    ]

    @model_validator(mode="after")
    def restart_bound_shape(self) -> Self:
        if (self.platform_restart_bound == "bounded") != (self.max_platform_restarts is not None):
            raise ValueError("restart count contradicts restart bound")
        return self


def _identity(ref: Ref) -> tuple[object, ...]:
    return ref.project_id, ref.artifact_schema, ref.digest, ref.size_bytes, ref.media_type


def validate_capabilities(record: CapabilityRecord, plan: ExecutionPlan) -> None:
    """Block unless the record evidences every bound the plan relies on; never infer one.

    ``function_retries == 0`` and a finite function timeout are necessary but never
    sufficient: without an evidenced crash-restart bound and an evidenced total bound
    (scheduling plus every startup/execution attempt) the platform could keep
    rescheduling and billing after the application has stopped caring.
    """
    if type(record) is not CapabilityRecord or type(plan) is not ExecutionPlan:
        raise ContractError("invalid_schema")
    resources = plan.resources
    if (
        record.project_id != plan.project_id
        or _identity(record.execution_config_ref) != _identity(plan.execution_config_ref)
        or any(ref.project_id != plan.project_id for ref in record.source_evidence_refs)
    ):
        raise ContractError("forbidden")
    if record.valid_until < plan.budget.valid_until:
        raise ContractError("authorization_expired")
    if (
        record.gpu_count != 0
        or record.function_retries != 0
        or resources.gpu_count != 0
        or resources.automatic_retries != 0
    ):
        raise ContractError("unsupported_capability")
    if (
        record.platform_restart_bound != "bounded"
        or record.max_platform_restarts is None
        or record.total_bound_seconds is None
    ):
        raise ContractError("unsupported_capability")
    if record.cancellation != "terminates_containers":
        raise ContractError("unsupported_capability")
    if record.deadline_enforcement != "entry_and_every_bounded_step":
        raise ContractError("unsupported_capability")
    if record.cpu_milli > resources.cpu_milli or record.memory_mib > resources.memory_mib:
        raise ContractError("limit_exceeded")
    # Each platform restart repeats startup and execution; scheduling is bounded once.
    minimum_total = record.scheduling_timeout_seconds + (record.max_platform_restarts + 1) * (
        record.startup_timeout_seconds + record.execution_timeout_seconds
    )
    if record.total_bound_seconds < minimum_total:
        raise ContractError("unsupported_capability")
    if record.total_bound_seconds > resources.max_wall_seconds:
        raise ContractError("limit_exceeded")
