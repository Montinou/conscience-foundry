"""Domain-neutral project, profile and explicit source-policy wire contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, Field, ValidationError, model_validator
from pydantic.json_schema import SkipJsonSchema

from conscience_foundry.contracts.common import (
    ContractError,
    Id,
    Instant,
    Ref,
    ScalarString,
    Version,
    WireModel,
)

NonemptyString = Annotated[ScalarString, Field(min_length=1)]
Permission = Literal["allow", "deny", "unknown"]
EFFECT_NAMES = frozenset(
    {
        "read",
        "remoteTransfer",
        "extract",
        "enrich",
        "embed",
        "train",
        "publish",
        "auditMetadataRead",
    }
)


def _json_array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _unique(values: tuple[object, ...]) -> None:
    if len(values) != len(set(values)):
        raise ValueError("duplicate values")


class ProjectConfig(WireModel):
    schema_version: Literal["kf.project.v1"]
    project_id: Id
    profile_id: NonemptyString
    profile_version: Version
    policy_ref: Ref
    limits_refs: Annotated[tuple[Ref, ...], BeforeValidator(_json_array), Field(min_length=1)]
    contract_set_ref: Ref
    storage_config_ref: Ref
    execution_config_ref: Ref

    @model_validator(mode="after")
    def project_references(self) -> Self:
        references = (
            self.policy_ref,
            *self.limits_refs,
            self.contract_set_ref,
            self.storage_config_ref,
            self.execution_config_ref,
        )
        if any(reference.project_id != self.project_id for reference in references):
            raise ValueError("cross-project reference")
        return self


class StorageConfig(WireModel):
    schema_version: Literal["kf.storage-config.v1"]
    project_id: Id
    local_store_id: NonemptyString
    staging_store_id: NonemptyString
    backup_store_id: NonemptyString
    retention_policy_ref: Ref

    @model_validator(mode="after")
    def project_reference(self) -> Self:
        if self.retention_policy_ref.project_id != self.project_id:
            raise ValueError("cross-project reference")
        return self


class ProfileDescriptor(WireModel):
    schema_version: Literal["kf.profile.v1"]
    profile_id: NonemptyString
    version: Version
    metadata_schema_ref: Ref
    allowed_processor_ids: Annotated[
        tuple[NonemptyString, ...], BeforeValidator(_json_array), Field(min_length=1)
    ]
    extension_schema_refs: Annotated[tuple[Ref, ...], BeforeValidator(_json_array)]
    export_adapters: Annotated[tuple[NonemptyString, ...], BeforeValidator(_json_array)]

    @model_validator(mode="after")
    def unique_names(self) -> Self:
        _unique(self.allowed_processor_ids)
        _unique(self.export_adapters)
        return self


class SourcePolicy(WireModel):
    source_id: Id
    read: Permission
    remote_transfer: Permission
    extract: Permission
    enrich: Permission
    embed: Permission
    train: Permission
    publish: Permission
    audit_metadata_read: Permission

    def permission(self, effect: str) -> Permission:
        """Resolve only fixed public field aliases, never arbitrary attributes."""
        effects: dict[str, Permission] = {
            "read": self.read,
            "remoteTransfer": self.remote_transfer,
            "extract": self.extract,
            "enrich": self.enrich,
            "embed": self.embed,
            "train": self.train,
            "publish": self.publish,
            "auditMetadataRead": self.audit_metadata_read,
        }
        if effect not in effects:
            raise ValueError("unknown policy effect")
        return effects[effect]


class PolicyArtifact(WireModel):
    schema_version: Literal["kf.policy.v1"]
    project_id: Id
    policy_version: Version
    sources: Annotated[tuple[SourcePolicy, ...], BeforeValidator(_json_array)]
    allowed_remote_destinations: Annotated[tuple[NonemptyString, ...], BeforeValidator(_json_array)]
    effective_at: Instant

    @model_validator(mode="after")
    def unique_sources_and_destinations(self) -> Self:
        _unique(tuple(source.source_id for source in self.sources))
        _unique(self.allowed_remote_destinations)
        return self


class TechnicalMetadata(WireModel):
    """The built-in synthetic profile's metadata; generic records stay extensible."""

    title: ScalarString | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    language: ScalarString | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )


@dataclass(frozen=True)
class TechnicalMetadataBinding:
    """Trusted registry pin for the static technical validator, never wire input.

    The operator/registry supplies this expected reference independently of the
    profile descriptor. Custody must verify the referenced schema bytes first.
    Locations can change through the locator registry without changing identity.
    """

    expected_schema_ref: Ref

    def validate(self, schema_ref: Ref, metadata: dict[str, object]) -> None:
        expected = self.expected_schema_ref
        if (
            schema_ref.project_id,
            schema_ref.artifact_schema,
            schema_ref.digest,
            schema_ref.size_bytes,
        ) != (
            expected.project_id,
            expected.artifact_schema,
            expected.digest,
            expected.size_bytes,
        ):
            raise ContractError("unsupported_schema")
        try:
            TechnicalMetadata.model_validate(metadata)
        except ValidationError:
            raise ContractError("invalid_schema") from None
