"""Immutable C03 artifact sidecars; provenance does not authorize traversal."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, Field, model_validator

from conscience_foundry.contracts.common import (
    Digest,
    Id,
    Instant,
    Ref,
    ScalarString,
    Version,
    WireModel,
)


class ArtifactProducer(WireModel):
    code_version: Version
    image_digest: Digest
    processor_id: Annotated[ScalarString, Field(min_length=1)]
    processor_version: Version


class ArtifactManifest(WireModel):
    schema_version: Literal["kf.artifact-manifest.v1"]
    project_id: Id
    artifact: Ref
    producer: ArtifactProducer
    input_refs: Annotated[
        tuple[Ref, ...],
        BeforeValidator(lambda value: tuple(value) if isinstance(value, list) else value),
    ]
    operation_key: Digest
    attempt_id: Id
    created_at: Instant

    @model_validator(mode="after")
    def project_provenance(self) -> Self:
        if any(ref.project_id != self.project_id for ref in (self.artifact, *self.input_refs)):
            raise ValueError("cross-project artifact provenance")
        return self
