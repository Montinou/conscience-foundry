"""Immutable, explicitly supplied view of authenticated task schema installation."""

from __future__ import annotations

from dataclasses import dataclass

from conscience_foundry.contracts.common import ContractError, Id, Ref


@dataclass(frozen=True)
class TaskSchemaRegistry:
    project_id: Id
    spec_ref: Ref
    installation_ref: Ref
    schemas: tuple[tuple[Ref, bytes], ...]

    def __post_init__(self) -> None:
        if (
            type(self.spec_ref) is not Ref
            or type(self.installation_ref) is not Ref
            or self.spec_ref.project_id != self.project_id
            or self.installation_ref.project_id != self.project_id
            or self.spec_ref.artifact_schema != "cf.enrichment-spec.v1"
            or self.installation_ref.artifact_schema != "cf.enrichment-schema-installation.v1"
            or type(self.schemas) is not tuple
            or not self.schemas
        ):
            raise ContractError("invalid_schema")
        if any(
            type(ref) is not Ref
            or ref.project_id != self.project_id
            or ref.artifact_schema != "json-schema.2020-12"
            or type(data) is not bytes
            for ref, data in self.schemas
        ):
            raise ContractError("invalid_schema")

    def permits(self, ref: Ref, data: bytes) -> bool:
        return ref.project_id == self.project_id and any(
            ref == pin and data == raw for pin, raw in self.schemas
        )
