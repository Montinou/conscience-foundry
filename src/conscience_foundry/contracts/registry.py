"""Static trusted schema bootstrap; artifacts describe rules but never load code.

Raw roles have reject-all JSON-instance schemas because raw bytes are not JSON
instances. Their installed byte/media validators are the acceptance mechanism.
The JSON-Schema artifact role accepts only exact installed exported schemas;
its coarse JSON shape alone never establishes schema validity or trust.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, Field, model_validator

from conscience_foundry.contracts.accounting import (
    BillingAdjustment,
    BudgetEvent,
    OperationResultRecord,
    RunReport,
)
from conscience_foundry.contracts.admission import AdmissionReport, IntakeManifest, SourceAsset
from conscience_foundry.contracts.artifacts import ArtifactManifest
from conscience_foundry.contracts.canonical import (
    DocumentRevision,
    DocumentSpan,
    ExtractionSpec,
    OriginMap,
    QualityReport,
    RevisionReview,
)
from conscience_foundry.contracts.codec import load_json
from conscience_foundry.contracts.common import (
    ArtifactLocation,
    ArtifactRef,
    ContractError,
    ContractLimits,
    Id,
    Ref,
    Version,
    WireModel,
)
from conscience_foundry.contracts.execution import (
    ExecutionConfig,
    ExecutionPlan,
    ResultManifest,
    RunAuthorization,
    StageAttempt,
)
from conscience_foundry.contracts.project import (
    PolicyArtifact,
    ProfileDescriptor,
    ProjectConfig,
    StorageConfig,
    TechnicalMetadata,
    TechnicalMetadataBinding,
)
from conscience_foundry.contracts.release import (
    ActivationRecord,
    CoverageReport,
    ImportReceipt,
    LibraryRelease,
    ProvenanceReport,
    PublicationAuthorization,
    PublicationRecord,
    RetentionPolicy,
)

JSON_SCHEMA_ID = "json-schema.2020-12"
JSON_SCHEMA_URI = "https://json-schema.org/draft/2020-12/schema"
SEMANTIC_RULES_ID: Literal["kf.semantic-rules.v1"] = "kf.semantic-rules.v1"
VALIDATOR_VERSION = "conscience-foundry.f1.contracts.v1"
RAW_SCHEMA_IDS = frozenset({"kf.raw-original.v1", "kf.canonical-text.v1"})


def _array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class ContractBinding(WireModel):
    schema_id: Version
    schema_ref: Ref
    semantic_rules_ref: Ref

    @model_validator(mode="after")
    def pinned_roles(self) -> Self:
        if self.schema_ref.artifact_schema != JSON_SCHEMA_ID:
            raise ValueError("schema ref requires JSON Schema role")
        if self.semantic_rules_ref.artifact_schema != SEMANTIC_RULES_ID:
            raise ValueError("semantic rules ref requires descriptive role")
        if self.schema_ref.project_id != self.semantic_rules_ref.project_id:
            raise ValueError("cross-project contract binding")
        return self


class SchemaPair(WireModel):
    writer_schema_id: Version
    reader_schema_id: Version
    compatibility_evidence_ref: Ref


class ContractSet(WireModel):
    schema_version: Literal["kf.contract-set.v1"]
    version: Version
    contracts: Annotated[tuple[ContractBinding, ...], BeforeValidator(_array), Field(min_length=1)]
    compatible_pairs: Annotated[tuple[SchemaPair, ...], BeforeValidator(_array)]

    @model_validator(mode="after")
    def registered_unique_bindings(self) -> Self:
        ids = tuple(binding.schema_id for binding in self.contracts)
        if len(set(ids)) != len(ids) or ids != tuple(sorted(ids)):
            raise ValueError("bindings must be unique and sorted")
        pairs = tuple(
            (pair.writer_schema_id, pair.reader_schema_id) for pair in self.compatible_pairs
        )
        if len(set(pairs)) != len(pairs) or any(
            writer not in ids or reader not in ids for writer, reader in pairs
        ):
            raise ValueError("invalid compatibility pair")
        projects = {
            ref.project_id
            for binding in self.contracts
            for ref in (binding.schema_ref, binding.semantic_rules_ref)
        } | {pair.compatibility_evidence_ref.project_id for pair in self.compatible_pairs}
        if len(projects) != 1:
            raise ValueError("cross-project contract set")
        return self


class SemanticRulesDescriptor(WireModel):
    schema_version: Literal["kf.semantic-rules.v1"]
    schema_id: Version
    validator_version: Version
    edge_policy_id: Version


SCHEMA_MODELS: Mapping[str, type[WireModel]] = MappingProxyType(
    {
        "kf.artifact-ref.v1": ArtifactRef,
        "kf.contract-limits.v1": ContractLimits,
        "kf.project.v1": ProjectConfig,
        "kf.storage-config.v1": StorageConfig,
        "kf.profile.v1": ProfileDescriptor,
        "kf.policy.v1": PolicyArtifact,
        "kf.technical-metadata.v1": TechnicalMetadata,
        "kf.intake.v1": IntakeManifest,
        "kf.admission-report.v1": AdmissionReport,
        "kf.source-asset.v1": SourceAsset,
        "kf.artifact-manifest.v1": ArtifactManifest,
        "kf.extraction-spec.v1": ExtractionSpec,
        "kf.document-revision.v1": DocumentRevision,
        "kf.document-span.v1": DocumentSpan,
        "kf.origin-map.v1": OriginMap,
        "kf.quality-report.v1": QualityReport,
        "kf.revision-review.v1": RevisionReview,
        "kf.execution-config.v1": ExecutionConfig,
        "kf.execution-plan.v1": ExecutionPlan,
        "kf.run-authorization.v1": RunAuthorization,
        "kf.stage-attempt.v1": StageAttempt,
        "kf.result.v1": ResultManifest,
        "kf.budget-event.v1": BudgetEvent,
        "kf.billing-adjustment.v1": BillingAdjustment,
        "kf.operation-result-record.v1": OperationResultRecord,
        "kf.run-report.v1": RunReport,
        "kf.library-release.v1": LibraryRelease,
        "kf.coverage-report.v1": CoverageReport,
        "kf.provenance-report.v1": ProvenanceReport,
        "kf.import-receipt.v1": ImportReceipt,
        "kf.retention.v1": RetentionPolicy,
        "kf.publication-record.v1": PublicationRecord,
        "kf.publication-authorization.v1": PublicationAuthorization,
        "kf.activation.v1": ActivationRecord,
        "kf.contract-set.v1": ContractSet,
        SEMANTIC_RULES_ID: SemanticRulesDescriptor,
    }
)


def registered_schema_ids() -> tuple[str, ...]:
    """Installed roles only; descriptors cannot expand this immutable allowlist."""
    return tuple(sorted((*SCHEMA_MODELS, *RAW_SCHEMA_IDS, JSON_SCHEMA_ID)))


def _limits(schema_id: str, configured: Mapping[str, ContractLimits]) -> ContractLimits:
    limits = configured.get(schema_id)
    if not isinstance(limits, ContractLimits):
        raise ContractError("limits_missing")
    return limits


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _schema_bytes(schema_id: str) -> bytes:
    if schema_id in SCHEMA_MODELS:
        schema = SCHEMA_MODELS[schema_id].model_json_schema(by_alias=True)
    elif schema_id in RAW_SCHEMA_IDS:
        schema = {"$schema": JSON_SCHEMA_URI, "not": {}}
    elif schema_id == JSON_SCHEMA_ID:
        # Exact-byte trusted bootstrap validation below, not a general metaschema interpreter.
        schema = {
            "$schema": JSON_SCHEMA_URI,
            "type": "object",
            "required": ["$schema"],
            "properties": {"$schema": {"const": JSON_SCHEMA_URI}},
        }
    else:
        raise ContractError("unsupported_schema")
    return _json_bytes(schema | {"$id": schema_id})


def _rules(schema_id: str) -> SemanticRulesDescriptor:
    return SemanticRulesDescriptor(
        schema_version=SEMANTIC_RULES_ID,
        schema_id=schema_id,
        validator_version=VALIDATOR_VERSION,
        edge_policy_id=f"{schema_id}.edges.v1",
    )


def _rules_bytes(schema_id: str) -> bytes:
    return _json_bytes(_rules(schema_id).model_dump(mode="json", by_alias=True))


def _artifact_ref(data: bytes, schema_id: str, project_id: str, store_id: str) -> Ref:
    digest = hashlib.sha256(data).hexdigest()
    return ArtifactRef(
        schema_version="kf.artifact-ref.v1",
        project_id=project_id,
        digest=digest,
        size_bytes=len(data),
        media_type="application/json",
        artifact_schema=schema_id,
        locations=(ArtifactLocation(store_id=store_id, object_key=f"sha256/{digest}"),),
    )


def _check_byte_ceiling(data: bytes, schema_id: str, limits: ContractLimits) -> None:
    ceiling = (
        limits.max_source_bytes if schema_id == "kf.raw-original.v1" else limits.max_output_bytes
    )
    if len(data) > ceiling:
        raise ContractError("limit_exceeded")


def export_schemas(
    output_dir: Path,
    *,
    project_id: Id,
    store_id: str,
    version: Version,
    limits_by_schema: Mapping[str, ContractLimits],
) -> ContractSet:
    """Export the installed bundle using explicit private scope and finite limits.

    No local paths enter references. Raw-role JSON schemas reject JSON instances;
    only the static raw validators below can validate their actual byte bodies.
    """
    for schema_id in registered_schema_ids():
        _limits(schema_id, limits_by_schema)
    objects: dict[str, bytes] = {}
    bindings: list[ContractBinding] = []
    for schema_id in registered_schema_ids():
        schema_data = _schema_bytes(schema_id)
        semantic_data = _rules_bytes(schema_id)
        _check_byte_ceiling(schema_data, JSON_SCHEMA_ID, _limits(JSON_SCHEMA_ID, limits_by_schema))
        _check_byte_ceiling(
            semantic_data, SEMANTIC_RULES_ID, _limits(SEMANTIC_RULES_ID, limits_by_schema)
        )
        load_json(schema_data, _limits(JSON_SCHEMA_ID, limits_by_schema))
        SemanticRulesDescriptor.from_wire(
            semantic_data, _limits(SEMANTIC_RULES_ID, limits_by_schema)
        )
        schema_ref = _artifact_ref(schema_data, JSON_SCHEMA_ID, project_id, store_id)
        rules_ref = _artifact_ref(semantic_data, SEMANTIC_RULES_ID, project_id, store_id)
        objects[schema_ref.locations[0].object_key] = schema_data
        objects[rules_ref.locations[0].object_key] = semantic_data
        bindings.append(
            ContractBinding(
                schema_id=schema_id, schema_ref=schema_ref, semantic_rules_ref=rules_ref
            )
        )
    bundle = ContractSet(
        schema_version="kf.contract-set.v1",
        version=version,
        contracts=tuple(bindings),
        compatible_pairs=(),
    )
    ContractSet.from_wire(
        bundle.model_dump_json(by_alias=True).encode(),
        _limits("kf.contract-set.v1", limits_by_schema),
    )
    for key, data in objects.items():
        destination = output_dir / key
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with destination.open("xb") as stream:
                stream.write(data)
        except FileExistsError:
            if destination.read_bytes() != data:
                raise ContractError("hash_mismatch") from None
    return bundle


def validate_contract_set(
    bundle: ContractSet, *, project_id: Id, limits_by_schema: Mapping[str, ContractLimits]
) -> None:
    """Verify installed bootstrap pins, never trust a registry on its own claim.

    No cross-version reader compatibility is installed in F1. New compatibility
    evidence requires a trusted code revision; its presence in JSON is no grant.
    """
    if tuple(binding.schema_id for binding in bundle.contracts) != registered_schema_ids():
        raise ContractError("unsupported_schema")
    if bundle.compatible_pairs:
        raise ContractError("schema_incompatible")
    for schema_id in registered_schema_ids():
        _limits(schema_id, limits_by_schema)
    for binding in bundle.contracts:
        for artifact, data, role in (
            (binding.schema_ref, _schema_bytes(binding.schema_id), JSON_SCHEMA_ID),
            (binding.semantic_rules_ref, _rules_bytes(binding.schema_id), SEMANTIC_RULES_ID),
        ):
            _check_byte_ceiling(data, role, _limits(role, limits_by_schema))
            if role == JSON_SCHEMA_ID:
                load_json(data, _limits(JSON_SCHEMA_ID, limits_by_schema))
            else:
                SemanticRulesDescriptor.from_wire(
                    data, _limits(SEMANTIC_RULES_ID, limits_by_schema)
                )
            if (
                artifact.project_id,
                artifact.artifact_schema,
                artifact.media_type,
                artifact.digest,
                artifact.size_bytes,
            ) != (
                project_id,
                role,
                "application/json",
                hashlib.sha256(data).hexdigest(),
                len(data),
            ):
                raise ContractError("hash_mismatch")


def technical_metadata_binding(
    bundle: ContractSet, *, project_id: Id, limits_by_schema: Mapping[str, ContractLimits]
) -> TechnicalMetadataBinding:
    """Return the trusted static validator pin from a verified installed bundle."""
    validate_contract_set(bundle, project_id=project_id, limits_by_schema=limits_by_schema)
    binding = next(
        binding for binding in bundle.contracts if binding.schema_id == "kf.technical-metadata.v1"
    )
    return TechnicalMetadataBinding(binding.schema_ref)


def validate_artifact(
    artifact: Ref, data: bytes, *, limits_by_schema: Mapping[str, ContractLimits]
) -> WireModel | dict[str, object] | bytes:
    """Validate bytes against installed rules; no traversal or authority claim.

    Raw original is bounded text/plain input awaiting the processor's UTF-8
    quality checks. Canonical text is separately strict UTF-8 scalar content.
    JSON Schema/semantic descriptors must match exact installed bootstrap bytes.
    """
    schema_id = artifact.artifact_schema
    if schema_id not in registered_schema_ids():
        raise ContractError("unsupported_schema")
    limits = _limits(schema_id, limits_by_schema)
    if not isinstance(data, bytes) or len(data) != artifact.size_bytes:
        raise ContractError("hash_mismatch")
    _check_byte_ceiling(data, schema_id, limits)
    if hashlib.sha256(data).hexdigest() != artifact.digest:
        raise ContractError("hash_mismatch")
    if schema_id in RAW_SCHEMA_IDS:
        if artifact.media_type != "text/plain":
            raise ContractError("unsupported_format")
        if schema_id == "kf.canonical-text.v1":
            try:
                data.decode("utf-8")
            except UnicodeError:
                raise ContractError("invalid_encoding") from None
        return data
    if artifact.media_type != "application/json":
        raise ContractError("unsupported_format")
    if schema_id == JSON_SCHEMA_ID:
        parsed = load_json(data, limits)
        if data not in {_schema_bytes(key) for key in registered_schema_ids()}:
            raise ContractError("unsupported_schema")
        return parsed
    model = SCHEMA_MODELS[schema_id].from_wire(data, limits)
    if getattr(model, "project_id", artifact.project_id) != artifact.project_id:
        raise ContractError("forbidden")
    from conscience_foundry.release.edges import edge_roles

    if any(edge.ref.project_id != artifact.project_id for edge in edge_roles(schema_id, model)):
        raise ContractError("forbidden")
    if isinstance(model, ContractSet):
        validate_contract_set(
            model, project_id=artifact.project_id, limits_by_schema=limits_by_schema
        )
    if isinstance(model, SemanticRulesDescriptor):
        if model.schema_id not in registered_schema_ids() or data != _rules_bytes(model.schema_id):
            raise ContractError("unsupported_schema")
    return model
