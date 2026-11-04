"""Explicit cooperative resource policy for trusted local execution."""

from typing import Literal

from conscience_foundry.contracts.common import ContractError, PositiveInteger, WireModel
from conscience_foundry.contracts.execution import ResourceEnvelope


class LocalResourcePolicy(WireModel):
    schema_version: Literal["cf.local-resource-policy.v1"]
    semantics: Literal["cooperative", "hard"]
    max_cpu_milli: PositiveInteger
    max_memory_mib: PositiveInteger
    max_wall_seconds: PositiveInteger
    max_output_bytes: PositiveInteger
    max_concurrent_attempts: PositiveInteger
    max_attempts_per_operation: PositiveInteger


def validate_local_resources(policy: LocalResourcePolicy, resources: ResourceEnvelope) -> None:
    if policy.semantics != "cooperative" or any(
        (
            resources.cpu_milli > policy.max_cpu_milli,
            resources.memory_mib > policy.max_memory_mib,
            resources.max_wall_seconds > policy.max_wall_seconds,
            resources.max_output_bytes > policy.max_output_bytes,
            resources.max_concurrent_attempts > policy.max_concurrent_attempts,
            resources.max_attempts_per_operation > policy.max_attempts_per_operation,
            resources.gpu_count != 0,
            resources.automatic_retries != 0,
        )
    ):
        raise ContractError("unsupported_capability")
