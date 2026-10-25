"""Trusted field-based content/audit traversal; producers never choose edge roles."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from pydantic import ValidationError

from conscience_foundry.contracts.common import ArtifactRef, ContractError, Ref, Version, WireModel
from conscience_foundry.contracts.registry import JSON_SCHEMA_ID, RAW_SCHEMA_IDS, SCHEMA_MODELS


@dataclass(frozen=True)
class ReferenceEdge:
    ref: Ref
    role: Literal["content", "audit"]


# Paths are Python field names in installed models, not executable corpus data.
_RULES: Mapping[str, tuple[tuple[str, Literal["content", "audit"]], ...]] = MappingProxyType(
    {
        "kf.project.v1": (
            ("policy_ref", "content"),
            ("limits_refs.*", "content"),
            ("contract_set_ref", "content"),
            ("storage_config_ref", "content"),
            ("execution_config_ref", "content"),
        ),
        "kf.storage-config.v1": (("retention_policy_ref", "content"),),
        "kf.profile.v1": (
            ("metadata_schema_ref", "content"),
            ("extension_schema_refs.*", "content"),
        ),
        "kf.intake.v1": (("policy_ref", "audit"),),
        "kf.admission-report.v1": (("entries.*.snapshot_ref", "audit"),),
        "kf.source-asset.v1": (("original_ref", "content"), ("admission_report_ref", "audit")),
        "kf.artifact-manifest.v1": (("artifact", "audit"), ("input_refs.*", "audit")),
        "kf.extraction-spec.v1": (("limits_ref", "content"),),
        "kf.document-revision.v1": (
            ("original_ref", "content"),
            ("text_ref", "content"),
            ("extraction_spec_ref", "content"),
            ("origin_map_ref", "content"),
            ("quality_report_ref", "content"),
        ),
        "kf.execution-config.v1": (("tariff_ref", "audit"), ("resource_policy_ref", "audit")),
        "kf.execution-plan.v1": (
            ("execution_config_ref", "audit"),
            ("admission_report_ref", "audit"),
            ("extraction_spec_ref", "audit"),
            ("policy_ref", "audit"),
            ("contract_set_ref", "audit"),
            ("limits_refs.*", "audit"),
            ("input_refs.*", "audit"),
            ("budget.tariff_ref", "audit"),
        ),
        "kf.stage-attempt.v1": (("result_manifest_ref", "audit"),),
        "kf.result.v1": (
            ("outputs.*", "audit"),
            ("document_revision_ref", "audit"),
            ("quality_report_ref", "audit"),
            ("usage.tariff_ref", "audit"),
        ),
        "kf.budget-event.v1": (("evidence_ref", "audit"),),
        "kf.billing-adjustment.v1": (("evidence_ref", "audit"),),
        "kf.operation-result-record.v1": (
            ("result_ref", "audit"),
            ("selected_result_ref", "audit"),
            ("evidence_ref", "audit"),
        ),
        "kf.run-report.v1": (
            ("admission_report_ref", "audit"),
            ("attempts.*", "audit"),
            ("item_outcomes.*.revision_ref", "audit"),
        ),
        "kf.library-release.v1": (
            ("source_entries.*.revision_ref", "content"),
            ("source_entries.*.review_ref", "content"),
            ("component_refs.*.artifact_ref", "content"),
            ("coverage_report_ref", "content"),
            ("provenance_report_ref", "content"),
        ),
        "kf.provenance-report.v1": (
            ("entries.*.revision_ref", "content"),
            ("entries.*.review_ref", "content"),
            ("entries.*.operation_result_ref", "audit"),
            ("entries.*.attempt_refs.*", "audit"),
            ("entries.*.run_report_refs.*", "audit"),
        ),
        "kf.import-receipt.v1": (("release_ref", "audit"), ("verified_artifacts.*", "audit")),
        "kf.publication-record.v1": (
            ("policy_ref", "audit"),
            ("evidence_refs.*", "audit"),
            ("publication_authorization_ref", "audit"),
        ),
        "kf.publication-authorization.v1": (("policy_ref", "audit"),),
        "kf.contract-set.v1": (
            ("contracts.*.schema_ref", "content"),
            ("contracts.*.semantic_rules_ref", "content"),
            ("compatible_pairs.*.compatibility_evidence_ref", "content"),
        ),
        # Explicit no-reference registrations; an added Ref is detected below.
        "kf.artifact-ref.v1": (),
        "kf.contract-limits.v1": (),
        "kf.policy.v1": (),
        "kf.technical-metadata.v1": (),
        "kf.document-span.v1": (),
        "kf.origin-map.v1": (),
        "kf.quality-report.v1": (),
        "kf.revision-review.v1": (),
        "kf.run-authorization.v1": (),
        "kf.retention.v1": (),
        "kf.activation.v1": (),
        "kf.semantic-rules.v1": (),
    }
)


def _all_refs(value: object, prefix: str = "") -> list[tuple[str, Ref]]:
    if isinstance(value, ArtifactRef):
        return [(prefix, value)]
    if isinstance(value, WireModel):
        return [
            item
            for name in type(value).model_fields
            for item in _all_refs(getattr(value, name), f"{prefix}.{name}")
        ]
    if isinstance(value, tuple):
        return [
            item
            for index, child in enumerate(value)
            for item in _all_refs(child, f"{prefix}.{index}")
        ]
    return []


def _path_refs(value: object, path: tuple[str, ...], prefix: str = "") -> list[tuple[str, Ref]]:
    if value is None:
        return []
    if not path:
        if not isinstance(value, ArtifactRef):
            raise ContractError("unsupported_schema")
        return [(prefix, value)]
    step, *rest = path
    if step == "*" and isinstance(value, tuple):
        return [
            item
            for index, child in enumerate(value)
            for item in _path_refs(child, tuple(rest), f"{prefix}.{index}")
        ]
    if isinstance(value, WireModel) and step in type(value).model_fields:
        return _path_refs(getattr(value, step), tuple(rest), f"{prefix}.{step}")
    raise ContractError("unsupported_schema")


def edge_roles(schema_id: Version, record: object) -> tuple[ReferenceEdge, ...]:
    """Classify an already validated record; this never fetches or grants access.

    Wire bytes must first pass the bounded registry/codec admission boundary.
    Unknown schemas, wrong model types and any unclassified typed Ref fail closed.
    Metadata JSON is data, not a way to declare new reference-bearing fields.
    """
    if schema_id in RAW_SCHEMA_IDS:
        if not isinstance(record, bytes):
            raise ContractError("invalid_schema")
        return ()
    if schema_id == JSON_SCHEMA_ID:
        # Registry already pins the exact installed schema bytes. JSON Schema
        # $ref strings are schema syntax and never arbitrary ArtifactRef edges.
        if not isinstance(record, dict):
            raise ContractError("invalid_schema")
        return ()
    model = SCHEMA_MODELS.get(schema_id)
    if model is None:
        raise ContractError("unsupported_schema")
    if type(record) is not model:
        raise ContractError("invalid_schema")
    try:
        checked = model.model_validate(record.model_dump(mode="json", by_alias=True))
    except ValidationError:
        raise ContractError("invalid_schema") from None
    all_refs = _all_refs(checked) if not isinstance(checked, ArtifactRef) else []
    classified: list[tuple[str, ReferenceEdge]] = []
    if schema_id == "kf.coverage-report.v1":
        from conscience_foundry.contracts.release import CoverageReport

        if not isinstance(checked, CoverageReport):
            raise ContractError("invalid_schema")
        classified.extend(
            (path, ReferenceEdge(ref, "audit"))
            for path, ref in _path_refs(checked, ("admission_report_refs", "*"))
        )
        for index, entry in enumerate(checked.entries):
            prefix = f".entries.{index}"
            classified.extend(
                (path, ReferenceEdge(ref, "audit"))
                for path, ref in _path_refs(entry, ("outcome_evidence_refs", "*"), prefix)
            )
            classified.extend(
                (path, ReferenceEdge(ref, "content" if entry.selected else "audit"))
                for path, ref in _path_refs(entry, ("revision_ref",), prefix)
            )
    else:
        rules = _RULES.get(schema_id)
        if rules is None:
            raise ContractError("unsupported_schema")
        for path, role in rules:
            classified.extend(
                (actual, ReferenceEdge(ref, role))
                for actual, ref in _path_refs(checked, tuple(path.split(".")))
            )
    if {path for path, _ in all_refs} != {path for path, _ in classified} or len(all_refs) != len(
        classified
    ):
        raise ContractError("unsupported_schema")
    return tuple(edge for _, edge in classified)
