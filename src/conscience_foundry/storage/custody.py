"""Stateless, authorized inspection of exact input paths into immutable snapshots."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

from pydantic import TypeAdapter, ValidationError

from conscience_foundry.contracts.admission import (
    AdmissionEntry,
    AdmissionReport,
    IntakeManifest,
    SourceAsset,
)
from conscience_foundry.contracts.common import (
    ArtifactRef,
    ContractError,
    ContractLimits,
    Id,
    Instant,
    Reason,
    Ref,
    WireModel,
)
from conscience_foundry.contracts.project import (
    PolicyArtifact,
    ProfileDescriptor,
    ProjectConfig,
    TechnicalMetadataBinding,
)
from conscience_foundry.policy.access import AccessContext, require_permission
from conscience_foundry.storage.local import ObjectStore
from conscience_foundry.storage.locator import LocationRegistry


def _limits(configured: Mapping[str, ContractLimits], schema: str) -> ContractLimits:
    value = configured.get(schema)
    if not isinstance(value, ContractLimits):
        raise ContractError("limits_missing")
    return value


def _parsed_match(data: bytes, model: WireModel, limits: ContractLimits) -> None:
    if not isinstance(data, bytes):
        raise ContractError("invalid_schema")
    if len(data) > limits.max_output_bytes:
        raise ContractError("limit_exceeded")
    if type(model).from_wire(data, limits) != model:
        raise ContractError("hash_mismatch")


def _verify_reference(data: bytes, reference: Ref, schema: str, project_id: Id) -> None:
    if (
        reference.project_id != project_id
        or reference.artifact_schema != schema
        or reference.media_type != "application/json"
    ):
        raise ContractError("invalid_schema")
    if len(data) != reference.size_bytes or hashlib.sha256(data).hexdigest() != reference.digest:
        raise ContractError("hash_mismatch")


def _verify_context(
    manifest: IntakeManifest,
    manifest_bytes: bytes,
    policy: PolicyArtifact,
    policy_bytes: bytes,
    limits_by_schema: Mapping[str, ContractLimits],
    context: AccessContext,
) -> None:
    _parsed_match(manifest_bytes, manifest, _limits(limits_by_schema, "kf.intake.v1"))
    _parsed_match(policy_bytes, policy, _limits(limits_by_schema, "kf.policy.v1"))
    _verify_reference(policy_bytes, manifest.policy_ref, "kf.policy.v1", manifest.project_id)
    if context.project_id != manifest.project_id or policy.project_id != manifest.project_id:
        raise ContractError("forbidden")


def _reason(error: ContractError, limits: ContractLimits) -> Reason:
    code = "source_missing" if error.code == "artifact_missing" else error.code
    try:
        return Reason.model_validate(
            {"code": code, "message": code[: limits.max_error_message_scalars]},
            context={"limits": limits},
        )
    except ValidationError:
        return Reason(code="unavailable", message="unavailable"[: limits.max_error_message_scalars])


def _require_report_access(
    manifest: IntakeManifest, policy: PolicyArtifact, context: AccessContext
) -> None:
    if not isinstance(policy, PolicyArtifact):
        raise ContractError("unavailable")
    if policy.project_id != manifest.project_id or context.project_id != manifest.project_id:
        raise ContractError("forbidden")
    for source_id in sorted({item.source_id for item in manifest.items}):
        require_permission(context, policy, source_id, "auditMetadataRead")


def _deny_unscoped_input(_ref: Ref, _context: AccessContext, _effect: str) -> None:
    raise ContractError("forbidden")


def inspect_intake(
    manifest: IntakeManifest,
    config: ProjectConfig,
    policy: PolicyArtifact,
    context: AccessContext,
    store: ObjectStore,
    *,
    manifest_bytes: bytes,
    policy_bytes: bytes,
    profile: ProfileDescriptor,
    metadata_binding: TechnicalMetadataBinding,
    input_roots: Mapping[str, Path],
    limits_by_schema: Mapping[str, ContractLimits],
    checked_at: Instant,
) -> AdmissionReport:
    """Propose a report from exact bounded input bytes; no durable admission state.

    Profile, binding, input roots and limits are independently trusted operator
    configuration. The binding is produced by the installed schema registry;
    policy bytes are checked against the manifest and project reference here.
    The caller must use the current policy and cannot treat this report as a
    database registration, a revision acceptance or a dispatch authorization.
    """
    _verify_context(manifest, manifest_bytes, policy, policy_bytes, limits_by_schema, context)
    report_limits = _limits(limits_by_schema, "kf.admission-report.v1")
    source_limits = _limits(limits_by_schema, "kf.raw-original.v1")
    try:
        TypeAdapter(Instant).validate_python(checked_at)
    except ValidationError:
        raise ContractError("invalid_schema") from None
    manifest.validate_project(config, profile, policy, metadata_binding)
    _require_report_access(manifest, policy, context)
    # Validate operator configuration before processing any item. This registry
    # cannot read content; each item below creates its own source-bound authority.
    with LocationRegistry(input_roots, source_limits, _deny_unscoped_input):
        pass
    rows: list[AdmissionEntry] = []
    for item in manifest.items:
        try:
            require_permission(context, policy, item.source_id, "read")
            require_permission(context, policy, item.source_id, "extract")
            expected = ArtifactRef(
                schema_version="kf.artifact-ref.v1",
                project_id=manifest.project_id,
                digest=item.original_digest,
                size_bytes=item.size_bytes,
                media_type=item.media_type,
                artifact_schema="kf.raw-original.v1",
                locations=(),
            )

            def authorize(
                ref: Ref,
                actor: AccessContext,
                effect: str,
                *,
                selected: Ref = expected,
                source_id: Id = item.source_id,
            ) -> None:
                if ref != selected or actor != context or effect != "read":
                    raise ContractError("forbidden")
                require_permission(actor, policy, source_id, "read")
                require_permission(actor, policy, source_id, "extract")

            with LocationRegistry(input_roots, source_limits, authorize) as inputs:
                with inputs.open_location_verified(
                    expected, item.custody_ref.root_id, item.custody_ref.relative_path, context
                ) as snapshot:
                    stored = store.put_verified(snapshot, expected, context)
            if stored != expected:
                raise ContractError("hash_mismatch")
            rows.append(
                AdmissionEntry(
                    asset_id=item.asset_id,
                    source_id=item.source_id,
                    status="admitted",
                    reasons=(),
                    snapshot_ref=stored,
                )
            )
        except ContractError as error:
            rows.append(
                AdmissionEntry(
                    asset_id=item.asset_id,
                    source_id=item.source_id,
                    status="blocked",
                    reasons=(_reason(error, report_limits),),
                )
            )
        except Exception:
            rows.append(
                AdmissionEntry(
                    asset_id=item.asset_id,
                    source_id=item.source_id,
                    status="blocked",
                    reasons=(_reason(ContractError("unavailable"), report_limits),),
                )
            )
    report = AdmissionReport(
        schema_version="kf.admission-report.v1",
        project_id=manifest.project_id,
        batch_id=manifest.batch_id,
        manifest_digest=hashlib.sha256(manifest_bytes).hexdigest(),
        policy_version=policy.policy_version,
        checked_at=checked_at,
        entries=tuple(rows),
    )
    report.validate_manifest(manifest, policy)
    _parsed_match(report.model_dump_json(by_alias=True).encode(), report, report_limits)
    return report


def source_asset(
    manifest: IntakeManifest,
    report: AdmissionReport,
    report_ref: Ref,
    asset_id: Id,
    *,
    manifest_bytes: bytes,
    report_bytes: bytes,
    pinned_policy: PolicyArtifact,
    policy_bytes: bytes,
    limits_by_schema: Mapping[str, ContractLimits],
    context: AccessContext,
    current_policy: PolicyArtifact,
) -> SourceAsset:
    """Build a provisional asset after exact report/manifest/policy byte checks.

    The independently supplied current policy gates report metadata and selected
    content access; pinned policy bytes establish historical evidence only.
    This does not prove snapshot content, durable batch registration or dispatch
    eligibility. T11/T13 must establish those independent facts.
    """
    asset_limits = _limits(limits_by_schema, "kf.source-asset.v1")
    _verify_context(
        manifest, manifest_bytes, pinned_policy, policy_bytes, limits_by_schema, context
    )
    _parsed_match(report_bytes, report, _limits(limits_by_schema, "kf.admission-report.v1"))
    _verify_reference(report_bytes, report_ref, "kf.admission-report.v1", manifest.project_id)
    if report.manifest_digest != hashlib.sha256(manifest_bytes).hexdigest():
        raise ContractError("hash_mismatch")
    report.validate_manifest(manifest, pinned_policy)
    _require_report_access(manifest, current_policy, context)
    item = next((item for item in manifest.items if item.asset_id == asset_id), None)
    row = next((row for row in report.entries if row.asset_id == asset_id), None)
    if item is None or row is None or row.status != "admitted" or row.snapshot_ref is None:
        raise ContractError("forbidden")
    if row.snapshot_ref.artifact_schema != "kf.raw-original.v1":
        raise ContractError("unsupported_schema")
    require_permission(context, current_policy, item.source_id, "read")
    require_permission(context, current_policy, item.source_id, "extract")
    asset = SourceAsset(
        schema_version="kf.source-asset.v1",
        project_id=manifest.project_id,
        asset_id=item.asset_id,
        source_id=item.source_id,
        original_ref=row.snapshot_ref,
        admission_report_ref=report_ref,
        metadata=item.metadata,
    )
    asset.validate_admission(manifest, report, pinned_policy)
    _parsed_match(asset.model_dump_json(by_alias=True).encode(), asset, asset_limits)
    return asset
