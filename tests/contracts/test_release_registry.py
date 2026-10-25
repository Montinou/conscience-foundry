"""Synthetic release contracts and static registry tests; no stores or services."""

import copy
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from conscience_foundry.contracts.codec import hash_jcs
from conscience_foundry.contracts.common import ArtifactRef, ContractError, ContractLimits
from conscience_foundry.contracts.registry import (
    ContractSet,
    SemanticRulesDescriptor,
    export_schemas,
    registered_schema_ids,
    technical_metadata_binding,
    validate_artifact,
    validate_contract_set,
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
from conscience_foundry.release.edges import edge_roles

PROJECT = "00000000-0000-0000-0000-000000000001"
OTHER_PROJECT = "00000000-0000-0000-0000-000000000002"
SOURCE = "00000000-0000-0000-0000-000000000003"
OTHER_SOURCE = "00000000-0000-0000-0000-000000000004"
ASSET = "00000000-0000-0000-0000-000000000005"
OTHER_ASSET = "00000000-0000-0000-0000-000000000006"
BATCH = "00000000-0000-0000-0000-000000000007"
RELEASE = "00000000-0000-0000-0000-000000000008"
ACTOR = "00000000-0000-0000-0000-000000000009"
EVENT = "00000000-0000-0000-0000-000000000010"
PREVIOUS = "00000000-0000-0000-0000-000000000011"
TIME = "2026-10-25T00:00:00.000Z"
LATER = "2026-10-25T01:00:00.000Z"


def limits(**updates: int) -> ContractLimits:
    return ContractLimits.model_validate(
        {
            "schemaVersion": "kf.contract-limits.v1",
            "version": "synthetic.limits.v1",
            "maxJsonBytes": 1048576,
            "maxStringScalars": 4096,
            "maxArrayItems": 256,
            "maxDepth": 32,
            "maxManifestItems": 16,
            "maxSourceBytes": 8192,
            "maxOutputBytes": 16384,
            "maxErrorMessageScalars": 128,
        }
        | updates
    )


def ref(schema: str = "kf.document-revision.v1", **updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.artifact-ref.v1",
        "projectId": PROJECT,
        "digest": "a" * 64,
        "sizeBytes": 17,
        "mediaType": "application/json",
        "artifactSchema": schema,
        "locations": [{"storeId": "synthetic", "objectKey": f"objects/{schema}"}],
    } | updates


def reason() -> dict[str, str]:
    return {"code": "forbidden", "message": "Synthetic excluded source"}


def source(source_id: str = SOURCE, **updates: object) -> dict[str, object]:
    return {
        "sourceId": source_id,
        "revisionRef": ref(digest="b" * 64 if source_id == SOURCE else "c" * 64),
        "reviewRef": ref("kf.revision-review.v1"),
    } | updates


def release(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.library-release.v1",
        "projectId": PROJECT,
        "releaseId": RELEASE,
        "profileId": "technical_minimal",
        "profileVersion": "synthetic.v1",
        "capabilities": ["canonical_text"],
        "sourceEntries": [source()],
        "componentRefs": [],
        "coverageReportRef": ref("kf.coverage-report.v1"),
        "provenanceReportRef": ref("kf.provenance-report.v1"),
        "createdAt": TIME,
    } | updates


def selection_digest(entries: list[dict[str, object]]) -> str:
    return hash_jcs("kf.release-selection.v1", entries)


def coverage_entry(**updates: object) -> dict[str, object]:
    return {
        "batchId": BATCH,
        "assetId": ASSET,
        "sourceId": SOURCE,
        "status": "accepted",
        "selected": True,
        "revisionRef": source()["revisionRef"],
        "outcomeEvidenceRefs": [ref("kf.run-report.v1")],
        "reasons": [],
    } | updates


def coverage(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.coverage-report.v1",
        "projectId": PROJECT,
        "selectionDigest": selection_digest([source()]),
        "admissionReportRefs": [ref("kf.admission-report.v1")],
        "entries": [coverage_entry()],
        "reportAt": TIME,
    } | updates


def provenance(**updates: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.provenance-report.v1",
        "projectId": PROJECT,
        "selectionDigest": selection_digest([source()]),
        "entries": [
            source()
            | {
                "operationResultRef": ref("kf.operation-result-record.v1"),
                "attemptRefs": [ref("kf.stage-attempt.v1")],
                "runReportRefs": [ref("kf.run-report.v1")],
            }
        ],
        "reportAt": TIME,
    } | updates


def test_unknown_edge_role_fails_closed() -> None:
    with pytest.raises(ContractError):
        edge_roles("unknown.v1", {})
    value = release() | {"unregisteredRef": ref()}
    with pytest.raises(ContractError):
        edge_roles("kf.library-release.v1", value)
    with pytest.raises(ValidationError):
        LibraryRelease.model_validate(value)
    report = CoverageReport.model_validate(coverage())
    roles = edge_roles("kf.coverage-report.v1", report)
    assert [(edge.ref.artifact_schema, edge.role) for edge in roles] == [
        ("kf.admission-report.v1", "audit"),
        ("kf.run-report.v1", "audit"),
        ("kf.document-revision.v1", "content"),
    ]


def test_selection_digest_has_no_parent_cycle() -> None:
    selected = LibraryRelease.model_validate(release())
    report = CoverageReport.model_validate(coverage())
    lineage = ProvenanceReport.model_validate(provenance())
    report.validate_selection(selected)
    lineage.validate_selection(selected)
    assert report.selection_digest == hash_jcs(
        "kf.release-selection.v1", selected.model_dump(mode="json", by_alias=True)["sourceEntries"]
    )
    for model in (report, lineage):
        assert "releaseRef" not in model.model_dump(by_alias=True)
        with pytest.raises(ValidationError):
            type(model).model_validate(
                model.model_dump(mode="json", by_alias=True) | {"releaseRef": ref()}
            )
    for entries in ([source(OTHER_SOURCE), source()], [source(), source()]):
        with pytest.raises(ValidationError):
            LibraryRelease.model_validate(release(sourceEntries=entries))
    changed = copy.deepcopy(coverage())
    changed["selectionDigest"] = "d" * 64
    with pytest.raises(ContractError):
        CoverageReport.model_validate(changed).validate_selection(selected)
    changed = copy.deepcopy(provenance())
    changed["entries"][0]["reviewRef"] = ref("kf.revision-review.v1", digest="d" * 64)
    with pytest.raises(ContractError):
        ProvenanceReport.model_validate(changed).validate_selection(selected)


def test_excluded_revision_is_only_audit_and_rows_remain() -> None:
    excluded = coverage_entry(
        assetId=OTHER_ASSET,
        sourceId=OTHER_SOURCE,
        selected=False,
        status="withdrawn",
        revisionRef=ref(digest="e" * 64),
        reasons=[reason()],
    )
    report = CoverageReport.model_validate(coverage(entries=[coverage_entry(), excluded]))
    report.validate_selection(LibraryRelease.model_validate(release()))
    assert len(report.entries) == 2
    assert [
        edge.role
        for edge in edge_roles("kf.coverage-report.v1", report)
        if edge.ref.digest == "e" * 64
    ] == ["audit"]
    lineage_roles = edge_roles(
        "kf.provenance-report.v1", ProvenanceReport.model_validate(provenance())
    )
    assert [edge.role for edge in lineage_roles] == [
        "content",
        "content",
        "audit",
        "audit",
        "audit",
    ]
    for update in (
        {"selected": True, "status": "withdrawn"},
        {"selected": False, "reasons": []},
        {"selected": True, "revisionRef": None},
        {"outcomeEvidenceRefs": []},
    ):
        with pytest.raises(ValidationError):
            CoverageReport.model_validate(coverage(entries=[coverage_entry(**update)]))
    with pytest.raises(ValidationError):
        CoverageReport.model_validate(coverage(entries=[excluded, coverage_entry()]))


def test_release_references_and_f1_capabilities() -> None:
    value = LibraryRelease.model_validate(release())
    value.validate_f1()
    assert all(edge.role == "content" for edge in edge_roles("kf.library-release.v1", value))
    assert len(edge_roles("kf.library-release.v1", value)) == 4
    for update in (
        {"coverageReportRef": ref("kf.coverage-report.v1", projectId=OTHER_PROJECT)},
        {"coverageReportRef": ref("kf.run-report.v1")},
        {"capabilities": ["canonical_text", "canonical_text"]},
    ):
        with pytest.raises(ValidationError):
            LibraryRelease.model_validate(release(**update))
    with pytest.raises(ContractError):
        LibraryRelease.model_validate(release(capabilities=["search"])).validate_f1()


def test_publication_conditional_fields_and_no_implicit_grants() -> None:
    base = {
        "schemaVersion": "kf.publication-record.v1",
        "projectId": PROJECT,
        "releaseDigest": "a" * 64,
        "eventId": EVENT,
        "stage": "candidate",
        "actorId": ACTOR,
        "policyRef": ref("kf.policy.v1"),
        "evidenceRefs": [ref("kf.library-release.v1")],
        "recordedAt": TIME,
    }
    candidate = PublicationRecord.model_validate(base)
    assert "previousEventId" not in candidate.model_dump(mode="json", by_alias=True)
    assert "publicationAuthorizationRef" not in candidate.model_dump(mode="json", by_alias=True)
    PublicationRecord.from_wire(candidate.model_dump_json(by_alias=True).encode(), limits())
    for update in (
        {"stage": "published", "previousEventId": PREVIOUS},
        {"stage": "validated"},
        {"evidenceRefs": []},
        {"stage": "candidate", "previousEventId": PREVIOUS},
        {"publicationAuthorizationRef": ref("kf.publication-authorization.v1")},
        {"policyRef": ref("kf.policy.v1", projectId=OTHER_PROJECT)},
    ):
        with pytest.raises(ValidationError):
            PublicationRecord.model_validate(base | update)
    published = PublicationRecord.model_validate(
        base
        | {
            "stage": "published",
            "previousEventId": PREVIOUS,
            "publicationAuthorizationRef": ref("kf.publication-authorization.v1"),
        }
    )
    assert all(edge.role == "audit" for edge in edge_roles("kf.publication-record.v1", published))
    grant = {
        "schemaVersion": "kf.publication-authorization.v1",
        "projectId": PROJECT,
        "releaseDigest": "a" * 64,
        "actorId": ACTOR,
        "policyRef": ref("kf.policy.v1"),
        "authorizedAt": TIME,
        "expiresAt": LATER,
    }
    PublicationAuthorization.model_validate(grant)
    with pytest.raises(ValidationError):
        PublicationAuthorization.model_validate(grant | {"expiresAt": TIME})
    activation = ActivationRecord.model_validate(
        {
            "schemaVersion": "kf.activation.v1",
            "projectId": PROJECT,
            "nextReleaseDigest": "a" * 64,
            "actorId": ACTOR,
            "activatedAt": TIME,
        }
    )
    assert "expectedPreviousReleaseDigest" not in activation.model_dump(by_alias=True)
    assert (
        ActivationRecord.model_json_schema()["properties"]["expectedPreviousReleaseDigest"]["type"]
        == "string"
    )


def test_import_and_retention_shapes_do_not_claim_runtime_success() -> None:
    receipt = {
        "schemaVersion": "kf.import-receipt.v1",
        "projectId": PROJECT,
        "importId": EVENT,
        "releaseRef": ref("kf.library-release.v1"),
        "verifiedArtifacts": [ref()],
        "status": "local_verified",
        "checkedAt": TIME,
        "reasons": [],
    }
    ImportReceipt.model_validate(receipt)
    for update in (
        {"verifiedArtifacts": []},
        {"reasons": [reason()]},
        {"status": "failed", "reasons": []},
        {"verifiedArtifacts": [ref(projectId=OTHER_PROJECT)]},
    ):
        with pytest.raises(ValidationError):
            ImportReceipt.model_validate(receipt | update)
    retention = {
        "schemaVersion": "kf.retention.v1",
        "policyVersion": "synthetic.v1",
        "minStagingAgeSeconds": 1,
        "fundedStagingHorizonSeconds": 20,
        "escalationLeadSeconds": 5,
        "backupRequired": True,
        "auditRetentionSeconds": 30,
    }
    RetentionPolicy.model_validate(retention)
    for update in (
        {"escalationLeadSeconds": 20},
        {"fundedStagingHorizonSeconds": 0},
        {"minStagingAgeSeconds": 21},
        {"backupRequired": 1},
    ):
        with pytest.raises(ValidationError):
            RetentionPolicy.model_validate(retention | update)


def export_bundle(output: Path) -> ContractSet:
    return export_schemas(
        output,
        project_id=PROJECT,
        store_id="synthetic-schema-store",
        version="synthetic.bundle.v1",
        limits_by_schema={schema_id: limits() for schema_id in registered_schema_ids()},
    )


def test_schema_exports_pin_actual_bytes_and_semantic_descriptors(tmp_path: Path) -> None:
    bundle = export_bundle(tmp_path)
    assert tuple(binding.schema_id for binding in bundle.contracts) == tuple(
        sorted(registered_schema_ids())
    )
    assert "kf.artifact-manifest.v1" in registered_schema_ids()
    assert "kf.execution-config.v1" in registered_schema_ids()
    for binding in bundle.contracts:
        for artifact in (binding.schema_ref, binding.semantic_rules_ref):
            body = (tmp_path / artifact.locations[0].object_key).read_bytes()
            assert hashlib.sha256(body).hexdigest() == artifact.digest
            assert len(body) == artifact.size_bytes
            assert artifact.project_id == PROJECT
            assert artifact.locations[0].store_id == "synthetic-schema-store"
        schema = json.loads((tmp_path / binding.schema_ref.locations[0].object_key).read_bytes())
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert binding.schema_ref.artifact_schema == "json-schema.2020-12"
        semantic = SemanticRulesDescriptor.from_wire(
            (tmp_path / binding.semantic_rules_ref.locations[0].object_key).read_bytes(), limits()
        )
        assert semantic.schema_id == binding.schema_id
        assert set(semantic.model_dump(by_alias=True)) == {
            "schemaVersion",
            "schemaId",
            "validatorVersion",
            "edgePolicyId",
        }
    validate_contract_set(
        bundle,
        project_id=PROJECT,
        limits_by_schema={key: limits() for key in registered_schema_ids()},
    )
    again = export_bundle(tmp_path)
    assert again == bundle
    altered = bundle.model_dump(mode="json", by_alias=True)
    altered["contracts"][0]["schemaRef"]["digest"] = "f" * 64
    with pytest.raises(ContractError):
        validate_contract_set(
            ContractSet.model_validate(altered),
            project_id=PROJECT,
            limits_by_schema={key: limits() for key in registered_schema_ids()},
        )
    with pytest.raises(ContractError):
        export_schemas(
            tmp_path / "missing",
            project_id=PROJECT,
            store_id="synthetic",
            version="synthetic.v1",
            limits_by_schema={},
        )
    with pytest.raises(ValidationError):
        ContractSet.model_validate(
            bundle.model_dump(mode="json", by_alias=True)
            | {
                "contracts": list(
                    reversed(bundle.model_dump(mode="json", by_alias=True)["contracts"])
                )
            }
        )


def test_registry_static_validators_and_technical_schema_pin(tmp_path: Path) -> None:
    bundle = export_bundle(tmp_path)
    binding = technical_metadata_binding(
        bundle,
        project_id=PROJECT,
        limits_by_schema={key: limits() for key in registered_schema_ids()},
    )
    schema_binding = next(
        item for item in bundle.contracts if item.schema_id == "kf.technical-metadata.v1"
    )
    binding.validate(schema_binding.schema_ref, {"title": "Synthetic manual"})
    with pytest.raises(ContractError):
        binding.validate(schema_binding.schema_ref.model_copy(update={"digest": "f" * 64}), {})
    payload = json.dumps(release()).encode()
    artifact = ArtifactRef.model_validate(
        ref(
            "kf.library-release.v1",
            digest=hashlib.sha256(payload).hexdigest(),
            sizeBytes=len(payload),
        )
    )
    parsed = validate_artifact(
        artifact, payload, limits_by_schema={key: limits() for key in registered_schema_ids()}
    )
    assert isinstance(parsed, LibraryRelease)
    for changed in (
        artifact.model_copy(update={"digest": "f" * 64}),
        artifact.model_copy(update={"artifact_schema": "unregistered.v1"}),
    ):
        with pytest.raises(ContractError):
            validate_artifact(
                changed,
                payload,
                limits_by_schema={key: limits() for key in registered_schema_ids()},
            )
    with pytest.raises(ContractError):
        validate_artifact(artifact, payload, limits_by_schema={})


def test_raw_roles_never_parse_json_and_have_finite_media_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    export_bundle(tmp_path)
    payload = b"not JSON\xff"
    raw = ArtifactRef.model_validate(
        ref(
            "kf.raw-original.v1",
            mediaType="text/plain",
            digest=hashlib.sha256(payload).hexdigest(),
            sizeBytes=len(payload),
        )
    )

    def denied_json(*args: object, **kwargs: object) -> object:
        raise AssertionError("raw bytes must not use JSON parser")

    monkeypatch.setattr("conscience_foundry.contracts.codec.load_json", denied_json)
    monkeypatch.setattr("conscience_foundry.contracts.registry.load_json", denied_json)
    assert (
        validate_artifact(
            raw, payload, limits_by_schema={key: limits() for key in registered_schema_ids()}
        )
        == payload
    )
    canonical = raw.model_copy(update={"artifact_schema": "kf.canonical-text.v1"})
    with pytest.raises(ContractError):
        validate_artifact(
            canonical, payload, limits_by_schema={key: limits() for key in registered_schema_ids()}
        )
    with pytest.raises(ContractError):
        validate_artifact(
            raw.model_copy(update={"media_type": "application/json"}),
            payload,
            limits_by_schema={key: limits() for key in registered_schema_ids()},
        )
    with pytest.raises(ContractError):
        validate_artifact(
            raw, payload, limits_by_schema={"kf.raw-original.v1": limits(maxSourceBytes=2)}
        )


def test_static_registry_rejects_unregistered_reference_field_in_a_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from conscience_foundry.contracts import registry
    from conscience_foundry.contracts.common import Ref

    class AddedReference(LibraryRelease):
        unregistered_ref: Ref

    extended = AddedReference.model_validate(release() | {"unregisteredRef": ref()})
    monkeypatch.setattr(
        registry,
        "SCHEMA_MODELS",
        dict(registry.SCHEMA_MODELS) | {"kf.library-release.v1": AddedReference},
    )
    monkeypatch.setattr("conscience_foundry.release.edges.SCHEMA_MODELS", registry.SCHEMA_MODELS)
    with pytest.raises(ContractError, match="unsupported_schema"):
        edge_roles("kf.library-release.v1", extended)


def test_descriptor_cannot_select_code_and_current_schema_pins_are_required(tmp_path: Path) -> None:
    bundle = export_bundle(tmp_path)
    bindings = {item.schema_id: item for item in bundle.contracts}
    descriptor_ref = bindings["kf.library-release.v1"].semantic_rules_ref
    descriptor = json.loads((tmp_path / descriptor_ref.locations[0].object_key).read_bytes())
    for change in ({"edgePolicyId": "untrusted.module:run"}, {"validatorVersion": "different.v1"}):
        data = json.dumps(descriptor | change, sort_keys=True, separators=(",", ":")).encode()
        changed_ref = descriptor_ref.model_copy(
            update={"digest": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
        )
        with pytest.raises(ContractError, match="unsupported_schema"):
            validate_artifact(
                changed_ref,
                data,
                limits_by_schema={key: limits() for key in registered_schema_ids()},
            )
    with pytest.raises(ValidationError):
        SemanticRulesDescriptor.model_validate(descriptor | {"loader": "untrusted.module:run"})
    changed = bundle.model_dump(mode="json", by_alias=True)
    changed["contracts"][0]["semanticRulesRef"]["digest"] = "f" * 64
    with pytest.raises(ContractError, match="hash_mismatch"):
        validate_contract_set(
            ContractSet.model_validate(changed),
            project_id=PROJECT,
            limits_by_schema={key: limits() for key in registered_schema_ids()},
        )
    with pytest.raises(ContractError):
        technical_metadata_binding(
            bundle,
            project_id=OTHER_PROJECT,
            limits_by_schema={key: limits() for key in registered_schema_ids()},
        )


def test_reports_wire_roundtrip_and_exact_selected_universe() -> None:
    selected = LibraryRelease.model_validate(release())
    for cls, value in (
        (LibraryRelease, release()),
        (CoverageReport, coverage()),
        (ProvenanceReport, provenance()),
    ):
        model = cls.model_validate(value)
        assert cls.from_wire(model.model_dump_json(by_alias=True).encode(), limits()) == model
    row = coverage_entry(assetId=OTHER_ASSET)
    report = CoverageReport.model_validate(coverage(entries=[coverage_entry(), row]))
    with pytest.raises(ContractError):
        report.validate_selection(selected)
    with pytest.raises(ContractError):
        ProvenanceReport.model_validate(provenance(entries=[])).validate_selection(selected)
    omitted = coverage_entry(selected=False, status="withdrawn", reasons=[reason()])
    del omitted["revisionRef"]
    report = CoverageReport.model_validate(coverage(entries=[omitted]))
    assert "revisionRef" not in report.model_dump(mode="json", by_alias=True)["entries"][0]
    assert (
        CoverageReport.from_wire(report.model_dump_json(by_alias=True).encode(), limits()) == report
    )
    with pytest.raises(ValidationError):
        CoverageReport.model_validate(coverage(entries=[omitted | {"revisionRef": None}]))


def test_generated_schema_fixtures_are_reproducible(tmp_path: Path) -> None:
    bundle = export_bundle(tmp_path)
    fixture_root = Path(__file__).resolve().parents[2] / "schemas"
    expected_paths: set[Path] = set()
    for binding in bundle.contracts:
        for suffix, artifact in (
            ("schema", binding.schema_ref),
            ("rules", binding.semantic_rules_ref),
        ):
            target = fixture_root / f"{binding.schema_id}.{suffix}.json"
            expected_paths.add(target)
            assert target.read_bytes() == (tmp_path / artifact.locations[0].object_key).read_bytes()
    assert set(fixture_root.glob("*.json")) == expected_paths


def test_trusted_bootstrap_still_obeys_configured_descriptor_bounds(tmp_path: Path) -> None:
    bundle = export_bundle(tmp_path)
    configured = {key: limits() for key in registered_schema_ids()}
    configured["json-schema.2020-12"] = limits(maxJsonBytes=2)
    with pytest.raises(ContractError, match="limit_exceeded"):
        validate_contract_set(bundle, project_id=PROJECT, limits_by_schema=configured)


@pytest.mark.parametrize("role", ["json-schema.2020-12", "kf.semantic-rules.v1"])
@pytest.mark.parametrize("action", ["export", "bootstrap"])
def test_export_and_bootstrap_obey_artifact_output_ceiling(
    tmp_path: Path, role: str, action: str
) -> None:
    bundle = export_bundle(tmp_path / "valid")
    configured = {key: limits() for key in registered_schema_ids()}
    configured[role] = limits(maxOutputBytes=2)
    output = tmp_path / "rejected"

    with pytest.raises(ContractError, match="limit_exceeded"):
        if action == "export":
            export_schemas(
                output,
                project_id=PROJECT,
                store_id="synthetic-schema-store",
                version="synthetic.bundle.v1",
                limits_by_schema=configured,
            )
        else:
            validate_contract_set(bundle, project_id=PROJECT, limits_by_schema=configured)
    assert not output.exists()


def test_registry_admission_binds_envelope_project_and_bootstrap_pins(tmp_path: Path) -> None:
    configured = {key: limits() for key in registered_schema_ids()}
    payload = json.dumps(release()).encode()
    envelope = ArtifactRef.model_validate(
        ref(
            "kf.library-release.v1",
            projectId=OTHER_PROJECT,
            digest=hashlib.sha256(payload).hexdigest(),
            sizeBytes=len(payload),
        )
    )
    with pytest.raises(ContractError, match="forbidden"):
        validate_artifact(envelope, payload, limits_by_schema=configured)
    configured["kf.contract-set.v1"] = limits(maxOutputBytes=1048576)
    bundle = export_bundle(tmp_path).model_dump(mode="json", by_alias=True)
    bundle["contracts"][0]["schemaRef"]["digest"] = "f" * 64
    payload = json.dumps(bundle).encode()
    envelope = ArtifactRef.model_validate(
        ref(
            "kf.contract-set.v1", digest=hashlib.sha256(payload).hexdigest(), sizeBytes=len(payload)
        )
    )
    with pytest.raises(ContractError, match="hash_mismatch"):
        validate_artifact(envelope, payload, limits_by_schema=configured)
