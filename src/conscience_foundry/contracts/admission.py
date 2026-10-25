"""Immutable intake descriptions and explicit cross-record admission validation."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Literal, Self, cast

from pydantic import (
    AfterValidator,
    BeforeValidator,
    Field,
    PlainSerializer,
    ValidationInfo,
    model_validator,
)
from pydantic.json_schema import SkipJsonSchema

from conscience_foundry.contracts.common import (
    ContractError,
    ContractLimits,
    Digest,
    Id,
    Instant,
    Reason,
    Ref,
    SafeInteger,
    ScalarString,
    Version,
    WireModel,
    safe_object_key,
)
from conscience_foundry.contracts.project import (
    PolicyArtifact,
    ProfileDescriptor,
    ProjectConfig,
    TechnicalMetadataBinding,
)


def _json_array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(child) for child in value)
    return value


def _metadata(value: Mapping[str, object]) -> Mapping[str, object]:
    return cast(Mapping[str, object], _freeze(dict(value)))


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw(child) for child in value]
    return value


Metadata = Annotated[
    Mapping[str, object],
    AfterValidator(_metadata),
    PlainSerializer(_thaw, return_type=dict[str, object]),
]
NonemptyString = Annotated[ScalarString, Field(min_length=1)]


class CustodyRef(WireModel):
    root_id: NonemptyString
    relative_path: Annotated[ScalarString, AfterValidator(safe_object_key)]


class _MetadataRecord(WireModel):
    @model_validator(mode="before")
    @classmethod
    def trusted_metadata_composition(cls, value: object) -> object:
        if isinstance(value, dict) and isinstance(value.get("metadata"), MappingProxyType):
            return value | {"metadata": _thaw(value["metadata"])}
        return value


class IntakeItem(_MetadataRecord):
    asset_id: Id
    source_id: Id
    original_digest: Digest
    size_bytes: SafeInteger
    media_type: Literal["text/plain"]
    custody_ref: CustodyRef
    metadata: Metadata

    @model_validator(mode="after")
    def source_limit(self, info: ValidationInfo) -> Self:
        if info.context and isinstance(info.context.get("limits"), ContractLimits):
            if self.size_bytes > info.context["limits"].max_source_bytes:
                raise ValueError("source exceeds configured bound")
        return self


class IntakeManifest(WireModel):
    schema_version: Literal["kf.intake.v1"]
    project_id: Id
    batch_id: Id
    profile_id: NonemptyString
    profile_version: Version
    policy_ref: Ref
    created_at: Instant
    items: Annotated[tuple[IntakeItem, ...], BeforeValidator(_json_array), Field(min_length=1)]

    @model_validator(mode="after")
    def manifest_invariants(self, info: ValidationInfo) -> Self:
        asset_ids = [item.asset_id for item in self.items]
        if len(asset_ids) != len(set(asset_ids)):
            raise ValueError("duplicate asset identity")
        if self.policy_ref.project_id != self.project_id:
            raise ValueError("cross-project reference")
        if info.context and isinstance(info.context.get("limits"), ContractLimits):
            if len(self.items) > info.context["limits"].max_manifest_items:
                raise ValueError("manifest exceeds configured bound")
        return self

    def validate_project(
        self,
        project: ProjectConfig,
        profile: ProfileDescriptor,
        policy: PolicyArtifact,
        metadata_binding: TechnicalMetadataBinding,
    ) -> None:
        """Apply an explicitly supplied trusted allowlisted profile and current policy."""
        if (
            self.project_id != project.project_id
            or policy.project_id != self.project_id
            or profile.metadata_schema_ref.project_id != self.project_id
            or self.profile_id != project.profile_id
            or self.profile_id != profile.profile_id
            or self.profile_version != project.profile_version
            or self.profile_version != profile.version
            or self.policy_ref != project.policy_ref
            or any(
                reference.project_id != self.project_id
                for reference in profile.extension_schema_refs
            )
        ):
            raise ContractError("invalid_schema")
        if profile.profile_id != "technical_minimal":
            raise ContractError("unsupported_schema")
        policy_sources = {source.source_id for source in policy.sources}
        if any(item.source_id not in policy_sources for item in self.items):
            raise ContractError("forbidden")
        for item in self.items:
            metadata_binding.validate(profile.metadata_schema_ref, dict(item.metadata))


class AdmissionEntry(WireModel):
    asset_id: Id
    source_id: Id
    status: Literal["admitted", "blocked", "withdrawn"]
    reasons: Annotated[tuple[Reason, ...], BeforeValidator(_json_array)]
    snapshot_ref: Ref | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def status_fields(self) -> Self:
        if self.status == "admitted":
            if self.snapshot_ref is None or self.reasons:
                raise ValueError("admitted entry requires snapshot and no blocking reasons")
        elif not self.reasons:
            raise ValueError("nonadmitted entry requires a reason")
        return self


class AdmissionReport(WireModel):
    schema_version: Literal["kf.admission-report.v1"]
    project_id: Id
    batch_id: Id
    manifest_digest: Digest
    policy_version: Version
    checked_at: Instant
    entries: Annotated[tuple[AdmissionEntry, ...], BeforeValidator(_json_array)]

    @model_validator(mode="after")
    def report_invariants(self) -> Self:
        assets = [entry.asset_id for entry in self.entries]
        if len(assets) != len(set(assets)):
            raise ValueError("duplicate report asset")
        if any(
            entry.snapshot_ref is not None and entry.snapshot_ref.project_id != self.project_id
            for entry in self.entries
        ):
            raise ValueError("cross-project snapshot")
        return self

    def validate_manifest(self, manifest: IntakeManifest, pinned_policy: PolicyArtifact) -> None:
        """Check rows against pinned historical admission policy, not current access.

        Custody separately verifies raw manifest/policy bytes and their references;
        parsed records alone cannot establish their raw digests.
        """
        if (
            self.project_id != manifest.project_id
            or self.batch_id != manifest.batch_id
            or pinned_policy.project_id != self.project_id
            or pinned_policy.policy_version != self.policy_version
        ):
            raise ContractError("invalid_schema")
        items = {item.asset_id: item for item in manifest.items}
        if set(items) != {entry.asset_id for entry in self.entries}:
            raise ContractError("invalid_schema")
        for entry in self.entries:
            item = items[entry.asset_id]
            if entry.source_id != item.source_id:
                raise ContractError("invalid_schema")
            if entry.status == "admitted":
                snapshot = entry.snapshot_ref
                if snapshot is None or (
                    snapshot.digest != item.original_digest
                    or snapshot.size_bytes != item.size_bytes
                    or snapshot.media_type != item.media_type
                ):
                    raise ContractError("hash_mismatch")


class SourceAsset(_MetadataRecord):
    schema_version: Literal["kf.source-asset.v1"]
    project_id: Id
    asset_id: Id
    source_id: Id
    original_ref: Ref
    admission_report_ref: Ref
    metadata: Metadata

    @model_validator(mode="after")
    def project_references(self) -> Self:
        if (
            self.original_ref.project_id != self.project_id
            or self.admission_report_ref.project_id != self.project_id
        ):
            raise ValueError("cross-project reference")
        return self

    def validate_admission(
        self, manifest: IntakeManifest, report: AdmissionReport, pinned_policy: PolicyArtifact
    ) -> None:
        """Require admitted identity/content pins; custody separately verifies raw report bytes."""
        report.validate_manifest(manifest, pinned_policy)
        if self.project_id != manifest.project_id:
            raise ContractError("invalid_schema")
        item = next((item for item in manifest.items if item.asset_id == self.asset_id), None)
        row = next((entry for entry in report.entries if entry.asset_id == self.asset_id), None)
        if item is None or row is None or row.status != "admitted":
            raise ContractError("forbidden")
        if (
            self.source_id != item.source_id
            or self.original_ref.digest != item.original_digest
            or self.original_ref.size_bytes != item.size_bytes
            or self.original_ref.media_type != item.media_type
            or self.metadata != item.metadata
        ):
            raise ContractError("invalid_schema")
