"""Synthetic project/policy/admission contract tests without storage or services."""

import copy
import json
from dataclasses import FrozenInstanceError

import pytest
from pydantic import ValidationError

from conscience_foundry.contracts.admission import (
    AdmissionReport,
    CustodyRef,
    IntakeItem,
    IntakeManifest,
    SourceAsset,
)
from conscience_foundry.contracts.common import ArtifactRef, ContractError, ContractLimits
from conscience_foundry.contracts.project import (
    PolicyArtifact,
    ProfileDescriptor,
    ProjectConfig,
    SourcePolicy,
    StorageConfig,
    TechnicalMetadata,
    TechnicalMetadataBinding,
)
from conscience_foundry.policy.access import AccessContext, require_permission

PROJECT = "00000000-0000-0000-0000-000000000001"
OTHER_PROJECT = "00000000-0000-0000-0000-000000000002"
ASSET = "00000000-0000-0000-0000-000000000003"
SOURCE = "00000000-0000-0000-0000-000000000004"
BATCH = "00000000-0000-0000-0000-000000000005"
ACTOR = "00000000-0000-0000-0000-000000000006"
TIME = "2026-10-25T00:00:00.000Z"
PERMISSIONS = (
    "read",
    "remoteTransfer",
    "extract",
    "enrich",
    "embed",
    "train",
    "publish",
    "auditMetadataRead",
)


def limits(**overrides: int) -> ContractLimits:
    values = {
        "schemaVersion": "kf.contract-limits.v1",
        "version": "synthetic.limits.v1",
        "maxJsonBytes": 65536,
        "maxStringScalars": 256,
        "maxArrayItems": 32,
        "maxDepth": 16,
        "maxManifestItems": 2,
        "maxSourceBytes": 1024,
        "maxOutputBytes": 2048,
        "maxErrorMessageScalars": 80,
    }
    values.update(overrides)
    return ContractLimits.model_validate(values)


def ref(project: str = PROJECT, **updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.artifact-ref.v1",
        "projectId": project,
        "digest": "a" * 64,
        "sizeBytes": 17,
        "mediaType": "application/json",
        "artifactSchema": "synthetic.v1",
        "locations": [{"storeId": "synthetic", "objectKey": "sha256/synthetic"}],
    } | updates


def source_policy(**updates: object) -> dict[str, object]:
    return {"sourceId": SOURCE, **dict.fromkeys(PERMISSIONS, "allow")} | updates


def policy(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.policy.v1",
        "projectId": PROJECT,
        "policyVersion": "synthetic.policy.v1",
        "sources": [source_policy()],
        "allowedRemoteDestinations": ["synthetic-remote"],
        "effectiveAt": TIME,
    } | updates


def item(**updates: object) -> dict[str, object]:
    return {
        "assetId": ASSET,
        "sourceId": SOURCE,
        "originalDigest": "a" * 64,
        "sizeBytes": 17,
        "mediaType": "text/plain",
        "custodyRef": {"rootId": "synthetic-input", "relativePath": "a.txt"},
        "metadata": {"title": "Synthetic manual"},
    } | updates


def manifest(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.intake.v1",
        "projectId": PROJECT,
        "batchId": BATCH,
        "profileId": "technical_minimal",
        "profileVersion": "synthetic.profile.v1",
        "policyRef": ref(artifactSchema="kf.policy.v1"),
        "createdAt": TIME,
        "items": [item()],
    } | updates


def report(manifest_value: IntakeManifest, **updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.admission-report.v1",
        "projectId": PROJECT,
        "batchId": BATCH,
        "manifestDigest": "a" * 64,
        "policyVersion": "synthetic.policy.v1",
        "checkedAt": TIME,
        "entries": [
            {
                "assetId": ASSET,
                "sourceId": SOURCE,
                "status": "admitted",
                "reasons": [],
                "snapshotRef": ref(mediaType="text/plain", artifactSchema="raw.utf8.v1"),
            }
        ],
    } | updates


def test_unknown_permission_and_cross_project_fail() -> None:
    context = AccessContext(PROJECT, ACTOR, frozenset(PERMISSIONS))
    require_permission(context, PolicyArtifact.model_validate(policy()), SOURCE, "read")
    for changed, effect, expected in [
        (policy(sources=[source_policy(read="unknown")]), "read", "permission_unknown"),
        (policy(projectId=OTHER_PROJECT), "read", "forbidden"),
        (
            policy(sources=[source_policy(auditMetadataRead="unknown")]),
            "auditMetadataRead",
            "permission_unknown",
        ),
        (policy(sources=[source_policy(read="deny")]), "read", "forbidden"),
    ]:
        with pytest.raises(ContractError) as exc:
            require_permission(context, PolicyArtifact.model_validate(changed), SOURCE, effect)
        assert exc.value.code == expected
    for effect in ("invented", "audit_metadata_read", "", "__dict__"):
        with pytest.raises(ContractError):
            require_permission(context, PolicyArtifact.model_validate(policy()), SOURCE, effect)
    with pytest.raises(ContractError):
        require_permission(
            AccessContext(PROJECT, ACTOR, frozenset()),
            PolicyArtifact.model_validate(policy()),
            SOURCE,
            "read",
        )
    with pytest.raises(ContractError):
        require_permission(context, PolicyArtifact.model_validate(policy()), ASSET, "read")
    with pytest.raises(FrozenInstanceError):
        context.actor_id = ASSET  # type: ignore[misc]


def test_audit_and_content_scopes_are_independent() -> None:
    value = PolicyArtifact.model_validate(policy(sources=[source_policy(read="deny")]))
    audit = AccessContext(PROJECT, ACTOR, frozenset({"auditMetadataRead"}))
    require_permission(audit, value, SOURCE, "auditMetadataRead")
    with pytest.raises(ContractError):
        require_permission(audit, value, SOURCE, "read")
    with pytest.raises(ContractError):
        require_permission(
            AccessContext(PROJECT, ACTOR, frozenset({"read"})), value, SOURCE, "auditMetadataRead"
        )


def test_technical_profile_has_no_domain_requirements() -> None:
    value = IntakeManifest.from_wire(json.dumps(manifest()).encode(), limits())
    assert dict(value.items[0].metadata) == {"title": "Synthetic manual"}
    assert (
        dict(IntakeManifest.model_validate(manifest(items=[item(metadata={})])).items[0].metadata)
        == {}
    )
    assert IntakeManifest.model_validate(manifest(items=[item(metadata={"language": "en"})]))
    for metadata in ({"author": "Synthetic"}, {"philosopher": "Synthetic"}, {"title": None}):
        with pytest.raises(ValidationError):
            TechnicalMetadata.model_validate(metadata)
    with pytest.raises(ValidationError):
        IntakeManifest.model_validate(manifest(items=[item(), item()]))
    with pytest.raises(ValidationError):
        IntakeManifest.model_validate(manifest(items=[]))
    # Equal bytes under distinct editorial identities remain separate intake rows.
    other = item(assetId=ACTOR, sourceId=OTHER_PROJECT)
    assert len(IntakeManifest.model_validate(manifest(items=[item(), other])).items) == 2


def test_manifest_limits_and_nested_immutability() -> None:
    with pytest.raises(ContractError):
        IntakeManifest.from_wire(json.dumps(manifest()).encode(), limits(maxSourceBytes=16))
    with pytest.raises(ContractError):
        IntakeManifest.from_wire(
            json.dumps(manifest(items=[item(), item(assetId=ACTOR)])).encode(),
            limits(maxManifestItems=1),
        )
    value = IntakeManifest.model_validate(manifest())
    assert isinstance(value.items, tuple)
    with pytest.raises(AttributeError):
        value.items.append(item())  # type: ignore[attr-defined]
    with pytest.raises(TypeError):
        value.items[0].metadata["title"] = "Changed"  # type: ignore[index]


def test_policy_requires_explicit_audit_and_unique_sources() -> None:
    missing = source_policy()
    missing.pop("auditMetadataRead")
    for update in (
        {"sources": [missing]},
        {"sources": [source_policy(), source_policy()]},
        {"sources": [source_policy(read=True)]},
    ):
        with pytest.raises(ValidationError):
            PolicyArtifact.model_validate(policy(**update))
    assert isinstance(PolicyArtifact.model_validate(policy()).sources, tuple)
    with pytest.raises(ValidationError):
        SourcePolicy.model_validate(source_policy(extra="unknown"))


def test_custody_paths_are_strict_relative_json_strings() -> None:
    for path in ("/a", "../a", "a/../b", "a//b", "a/./b", "a\\b", "C:/a", "a\x00b", ""):
        with pytest.raises(ValidationError):
            CustodyRef.model_validate({"rootId": "synthetic", "relativePath": path})
    value = CustodyRef.from_wire(b'{"rootId":"synthetic","relativePath":"a\\u002fb.txt"}', limits())
    assert value.relative_path == "a/b.txt"
    with pytest.raises(ValidationError):
        CustodyRef.model_validate({"rootId": "", "relativePath": "a.txt"})


def test_project_storage_and_profile_pins_are_project_scoped() -> None:
    config = {
        "schemaVersion": "kf.project.v1",
        "projectId": PROJECT,
        "profileId": "technical_minimal",
        "profileVersion": "synthetic.profile.v1",
        "policyRef": ref(artifactSchema="kf.policy.v1"),
        "limitsRefs": [ref(artifactSchema="kf.contract-limits.v1")],
        "contractSetRef": ref(artifactSchema="kf.contract-set.v1"),
        "storageConfigRef": ref(artifactSchema="kf.storage-config.v1"),
        "executionConfigRef": ref(artifactSchema="kf.execution-config.v1"),
    }
    assert ProjectConfig.model_validate(config)
    for name in ("policyRef", "contractSetRef", "storageConfigRef", "executionConfigRef"):
        with pytest.raises(ValidationError):
            ProjectConfig.model_validate(config | {name: ref(OTHER_PROJECT)})
    with pytest.raises(ValidationError):
        ProjectConfig.model_validate(config | {"limitsRefs": []})
    storage = {
        "schemaVersion": "kf.storage-config.v1",
        "projectId": PROJECT,
        "localStoreId": "local",
        "stagingStoreId": "staging",
        "backupStoreId": "backup",
        "retentionPolicyRef": ref(artifactSchema="kf.retention-policy.v1"),
    }
    assert StorageConfig.model_validate(storage)
    with pytest.raises(ValidationError):
        StorageConfig.model_validate(storage | {"retentionPolicyRef": ref(OTHER_PROJECT)})
    profile = {
        "schemaVersion": "kf.profile.v1",
        "profileId": "technical_minimal",
        "version": "synthetic.profile.v1",
        "metadataSchemaRef": ref(),
        "allowedProcessorIds": ["text.utf8.v1"],
        "extensionSchemaRefs": [],
        "exportAdapters": [],
    }
    assert ProfileDescriptor.model_validate(profile).export_adapters == ()
    with pytest.raises(ValidationError):
        ProfileDescriptor.model_validate(profile | {"allowedProcessorIds": ["text.utf8.v1"] * 2})


def test_admission_conditional_rows_and_project_pins() -> None:
    admitted = IntakeManifest.model_validate(manifest())
    value = AdmissionReport.model_validate(report(admitted))
    value.validate_manifest(admitted, PolicyArtifact.model_validate(policy()))
    base = report(admitted)
    for changes in (
        {"status": "admitted", "snapshotRef": None},
        {"status": "admitted", "reasons": [{"code": "forbidden", "message": "Denied"}]},
        {"status": "blocked", "reasons": []},
        {"snapshotRef": ref(OTHER_PROJECT)},
    ):
        changed = copy.deepcopy(base)
        changed["entries"][0].update(changes)
        with pytest.raises(ValidationError):
            AdmissionReport.model_validate(changed)
    for status in ("blocked", "withdrawn"):
        changed = copy.deepcopy(base)
        changed["entries"][0] = {
            "assetId": ASSET,
            "sourceId": SOURCE,
            "status": status,
            "reasons": [{"code": "forbidden", "message": "Denied"}],
        }
        AdmissionReport.model_validate(changed).validate_manifest(
            admitted, PolicyArtifact.model_validate(policy())
        )


def test_admission_matches_manifest_universe_and_immutable_bytes() -> None:
    admitted = IntakeManifest.model_validate(manifest())
    base = report(admitted)
    for update in ({"batchId": ACTOR}, {"projectId": OTHER_PROJECT}, {"entries": []}):
        with pytest.raises((ContractError, ValidationError)):
            AdmissionReport.model_validate(base | update).validate_manifest(
                admitted, PolicyArtifact.model_validate(policy())
            )
    for update in (
        {"sourceId": ACTOR},
        {"assetId": ACTOR},
        {"snapshotRef": ref(sizeBytes=18)},
        {"snapshotRef": ref(digest="b" * 64)},
    ):
        changed = copy.deepcopy(base)
        changed["entries"][0].update(update)
        with pytest.raises((ContractError, ValidationError)):
            AdmissionReport.model_validate(changed).validate_manifest(
                admitted, PolicyArtifact.model_validate(policy())
            )


def test_source_asset_is_bound_to_admitted_item_and_report() -> None:
    admitted = IntakeManifest.model_validate(manifest())
    admission = AdmissionReport.model_validate(report(admitted))
    admission_ref = ref(artifactSchema="kf.admission-report.v1")
    value = {
        "schemaVersion": "kf.source-asset.v1",
        "projectId": PROJECT,
        "assetId": ASSET,
        "sourceId": SOURCE,
        "originalRef": ref(mediaType="text/plain", artifactSchema="raw.utf8.v1"),
        "admissionReportRef": admission_ref,
        "metadata": {"title": "Synthetic manual"},
    }
    asset = SourceAsset.model_validate(value)
    asset.validate_admission(admitted, admission, PolicyArtifact.model_validate(policy()))
    for update in (
        {"sourceId": ACTOR},
        {"originalRef": ref(sizeBytes=18)},
        {"originalRef": ref(OTHER_PROJECT)},
        {"metadata": {"title": "Changed"}},
    ):
        with pytest.raises((ContractError, ValidationError)):
            SourceAsset.model_validate(value | update).validate_admission(
                admitted, admission, PolicyArtifact.model_validate(policy())
            )


def test_generic_metadata_is_preserved_but_technical_profile_is_checked_at_boundary() -> None:
    config_value = {
        "schemaVersion": "kf.project.v1",
        "projectId": PROJECT,
        "profileId": "technical_minimal",
        "profileVersion": "synthetic.profile.v1",
        "policyRef": ref(artifactSchema="kf.policy.v1"),
        "limitsRefs": [ref()],
        "contractSetRef": ref(),
        "storageConfigRef": ref(),
        "executionConfigRef": ref(),
    }
    profile_value = {
        "schemaVersion": "kf.profile.v1",
        "profileId": "technical_minimal",
        "version": "synthetic.profile.v1",
        "metadataSchemaRef": ref(),
        "allowedProcessorIds": ["text.utf8.v1"],
        "extensionSchemaRefs": [],
        "exportAdapters": [],
    }
    project = ProjectConfig.model_validate(config_value)
    descriptor = ProfileDescriptor.model_validate(profile_value)
    source_permissions = PolicyArtifact.model_validate(policy())
    IntakeManifest.model_validate(manifest()).validate_project(
        project,
        descriptor,
        source_permissions,
        TechnicalMetadataBinding(ArtifactRef.model_validate(ref())),
    )
    generic = IntakeManifest.model_validate(
        manifest(items=[item(metadata={"nested": ["generic"]})])
    )
    assert generic.model_dump(mode="json", by_alias=True)["items"][0]["metadata"] == {
        "nested": ["generic"]
    }
    with pytest.raises(TypeError):
        generic.items[0].metadata["extra"] = "mutation"
    with pytest.raises(AttributeError):
        generic.items[0].metadata["nested"].append("mutation")
    with pytest.raises(ContractError):
        generic.validate_project(
            project,
            descriptor,
            source_permissions,
            TechnicalMetadataBinding(ArtifactRef.model_validate(ref())),
        )
    for update in (
        {"projectId": OTHER_PROJECT},
        {"profileVersion": "other.v1"},
        {"profileId": "other"},
        {"policyRef": ref(digest="b" * 64)},
    ):
        with pytest.raises((ContractError, ValidationError)):
            IntakeManifest.model_validate(manifest(**update)).validate_project(
                project,
                descriptor,
                source_permissions,
                TechnicalMetadataBinding(ArtifactRef.model_validate(ref())),
            )
    unknown = ProfileDescriptor.model_validate(profile_value | {"profileId": "unknown"})
    with pytest.raises(ContractError):
        IntakeManifest.model_validate(manifest()).validate_project(
            project,
            unknown,
            source_permissions,
            TechnicalMetadataBinding(ArtifactRef.model_validate(ref())),
        )


def test_contextual_validation_does_not_claim_verification_of_raw_artifact_digests() -> None:
    value = IntakeManifest.model_validate(manifest())
    # These helpers receive parsed records only. Exact bytes/digests are verified by custody.
    different_pin = AdmissionReport.model_validate(report(value, manifestDigest="b" * 64))
    different_pin.validate_manifest(value, PolicyArtifact.model_validate(policy()))
    assert different_pin.manifest_digest == "b" * 64


def test_generic_metadata_trusted_composition_and_optional_schema() -> None:
    value = IntakeManifest.model_validate(
        manifest(items=[item(metadata={"nested": [{"a": ["b"]}]})])
    )
    copied = IntakeItem.model_validate(item(metadata=value.items[0].metadata))
    assert copied.metadata == value.items[0].metadata
    with pytest.raises(TypeError):
        copied.metadata["nested"][0]["a"] = "changed"
    schema = TechnicalMetadata.model_json_schema()
    assert schema["properties"]["title"]["type"] == "string"
    assert schema["properties"]["language"]["type"] == "string"


def test_optional_fields_omit_absent_values_and_roundtrip() -> None:
    from conscience_foundry.contracts.admission import AdmissionEntry

    entry = AdmissionEntry.model_validate(
        {
            "assetId": ASSET,
            "sourceId": SOURCE,
            "status": "blocked",
            "reasons": [{"code": "forbidden", "message": "Denied"}],
        }
    )
    serialized = entry.model_dump_json(by_alias=True)
    assert "snapshotRef" not in json.loads(serialized)
    assert AdmissionEntry.from_wire(serialized.encode(), limits()) == entry
    metadata = TechnicalMetadata.model_validate({"title": "Synthetic manual"})
    metadata_json = metadata.model_dump_json(by_alias=True)
    assert json.loads(metadata_json) == {"title": "Synthetic manual"}
    assert TechnicalMetadata.from_wire(metadata_json.encode(), limits()) == metadata
    snapshot_schema = AdmissionEntry.model_json_schema()["properties"]["snapshotRef"]
    assert "anyOf" not in snapshot_schema
    assert snapshot_schema["$ref"].endswith("/ArtifactRef")
    with pytest.raises(ContractError):
        AdmissionEntry.from_wire(
            json.dumps(
                entry.model_dump(mode="json", by_alias=True) | {"snapshotRef": None}
            ).encode(),
            limits(),
        )


def test_admission_policy_version_requires_pinned_context() -> None:
    admitted = IntakeManifest.model_validate(manifest())
    mismatched = AdmissionReport.model_validate(report(admitted, policyVersion="other.policy.v1"))
    pinned = PolicyArtifact.model_validate(policy())
    with pytest.raises(ContractError):
        mismatched.validate_manifest(admitted, pinned)
    valid = AdmissionReport.model_validate(report(admitted))
    valid.validate_manifest(admitted, pinned)
    with pytest.raises(ContractError):
        valid.validate_manifest(
            admitted, PolicyArtifact.model_validate(policy(projectId=OTHER_PROJECT))
        )
    asset = SourceAsset.model_validate(
        {
            "schemaVersion": "kf.source-asset.v1",
            "projectId": PROJECT,
            "assetId": ASSET,
            "sourceId": SOURCE,
            "originalRef": ref(mediaType="text/plain", artifactSchema="raw.utf8.v1"),
            "admissionReportRef": ref(artifactSchema="kf.admission-report.v1"),
            "metadata": {"title": "Synthetic manual"},
        }
    )
    with pytest.raises(ContractError):
        asset.validate_admission(admitted, mismatched, pinned)
    # Admission evidence uses its historical pinned policy, distinct from current access.
    current = PolicyArtifact.model_validate(policy(policyVersion="current.policy.v2"))
    with pytest.raises(ContractError):
        valid.validate_manifest(admitted, current)


def test_profile_schema_pin_is_bound_to_static_validator() -> None:
    project = ProjectConfig.model_validate(
        {
            "schemaVersion": "kf.project.v1",
            "projectId": PROJECT,
            "profileId": "technical_minimal",
            "profileVersion": "synthetic.profile.v1",
            "policyRef": ref(artifactSchema="kf.policy.v1"),
            "limitsRefs": [ref()],
            "contractSetRef": ref(),
            "storageConfigRef": ref(),
            "executionConfigRef": ref(),
        }
    )
    descriptor = ProfileDescriptor.model_validate(
        {
            "schemaVersion": "kf.profile.v1",
            "profileId": "technical_minimal",
            "version": "synthetic.profile.v1",
            "metadataSchemaRef": ref(digest="b" * 64),
            "allowedProcessorIds": ["text.utf8.v1"],
            "extensionSchemaRefs": [],
            "exportAdapters": [],
        }
    )
    with pytest.raises(ContractError):
        IntakeManifest.model_validate(manifest()).validate_project(
            project,
            descriptor,
            PolicyArtifact.model_validate(policy()),
            TechnicalMetadataBinding(ArtifactRef.model_validate(ref())),
        )


def test_trusted_metadata_binding_uses_content_identity_not_locations() -> None:
    binding = TechnicalMetadataBinding(ArtifactRef.model_validate(ref()))
    relocated = ArtifactRef.model_validate(
        ref(locations=[{"storeId": "relocated", "objectKey": "sha256/other"}])
    )
    binding.validate(relocated, {"title": "Synthetic"})
    for update in (
        {"projectId": OTHER_PROJECT},
        {"artifactSchema": "other.v1"},
        {"digest": "b" * 64},
        {"sizeBytes": 18},
    ):
        with pytest.raises(ContractError):
            binding.validate(ArtifactRef.model_validate(ref(**update)), {"title": "Synthetic"})
    with pytest.raises(FrozenInstanceError):
        binding.expected_schema_ref = relocated  # type: ignore[misc]
