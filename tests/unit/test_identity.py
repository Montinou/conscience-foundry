"""Synthetic verified bytes exercise exact F1 projections, not attempt wrappers."""

from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, replace

import pytest
from pydantic import ValidationError

from conscience_foundry.contracts.accounting import ResourceUsage
from conscience_foundry.contracts.admission import SourceAsset
from conscience_foundry.contracts.canonical import (
    DocumentRevision,
    ExtractionSpec,
    QualityCheck,
    QualityReport,
    Section,
)
from conscience_foundry.contracts.common import (
    ArtifactLocation,
    ArtifactRef,
    ContractError,
    ContractLimits,
    Reason,
)
from conscience_foundry.contracts.execution import ResultManifest
from conscience_foundry.core.comparison import (
    F1Comparison,
    comparison_digest,
    quality_projection_digest,
)
from conscience_foundry.core.identity import (
    F1Operation,
    RevisionInputs,
    operation_key,
    revision_id,
    structure_digest,
)
from conscience_foundry.processing.text_utf8 import process_text
from conscience_foundry.storage.local import VerifiedBytes

PROJECT = "00000000-0000-0000-0000-000000000001"
SOURCE = "00000000-0000-0000-0000-000000000002"
ASSET = "00000000-0000-0000-0000-000000000003"
OTHER = "00000000-0000-0000-0000-000000000004"
ATTEMPT_A = "00000000-0000-0000-0000-000000000005"
ATTEMPT_B = "00000000-0000-0000-0000-000000000006"
TEXT = "A😀e\u0301\r\nB".encode()


VALID_QUALITY_JCS = (
    b'{"checks":[{"checkId":"bounds","outcome":"pass"},'
    b'{"checkId":"encoding","outcome":"pass"},{"checkId":"hash","outcome":"pass"},'
    b'{"checkId":"identity_mapping","outcome":"pass"},'
    b'{"checkId":"no_BOM","outcome":"pass"},{"checkId":"no_NUL","outcome":"pass"},'
    b'{"checkId":"non_whitespace","outcome":"pass"},'
    b'{"checkId":"nonempty","outcome":"pass"}],"disposition":"valid"}'
)

def limits(**changes: object) -> ContractLimits:
    return ContractLimits.model_validate({
        "schemaVersion": "kf.contract-limits.v1", "version": "synthetic.identity.v1",
        "maxJsonBytes": 65536, "maxStringScalars": 1024, "maxArrayItems": 128,
        "maxDepth": 16, "maxManifestItems": 4, "maxSourceBytes": 65536,
        "maxOutputBytes": 65536, "maxErrorMessageScalars": 80,
    } | changes)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ref(data: bytes, schema: str, location: str = "synthetic/a") -> ArtifactRef:
    return ArtifactRef(
        schema_version="kf.artifact-ref.v1", project_id=PROJECT, digest=digest(data),
        size_bytes=len(data), media_type="text/plain" if schema.startswith("kf.raw")
        or schema == "kf.canonical-text.v1" else "application/json",
        artifact_schema=schema,
        locations=(ArtifactLocation(store_id="synthetic", object_key=location),),
    )


def operation(**changes: object) -> F1Operation:
    return F1Operation(**({
        "project_id": PROJECT, "asset_id": ASSET, "source_id": SOURCE,
        "input_digests": ("a" * 64,), "extraction_spec_digest": "b" * 64,
        "profile_id": "technical_minimal", "profile_version": "synthetic.v1",
        "policy_digest": "c" * 64, "contract_set_digest": "d" * 64,
        "limits_digests": ("e" * 64, "f" * 64),
    } | changes))


def test_operation_domain_and_exact_projection() -> None:
    projection = operation()
    # Literal canonical bytes are independent of the production projection builder.
    canonical = (
        '{"assetId":"' + ASSET + '","contractSetDigest":"' + "d" * 64
        + '","extractionSpecDigest":"' + "b" * 64 + '","inputDigests":["' + "a" * 64
        + '"],"limitsDigests":["' + "e" * 64 + '","' + "f" * 64
        + '"],"policyDigest":"' + "c" * 64
        + '","profileId":"technical_minimal","profileVersion":"synthetic.v1",'
        + '"projectId":"' + PROJECT + '","sourceId":"' + SOURCE + '"}'
    ).encode()
    assert operation_key(projection, limits=limits()) == digest(b"kf.operation.v1\n" + canonical)
    assert operation_key(projection, limits=limits()) != digest(
        b"kf.operation.v1\\n" + canonical
    )
    assert operation_key(replace(projection, asset_id=OTHER), limits=limits()) != operation_key(
        projection, limits=limits()
    )
    assert operation_key(replace(projection, profile_id="é"), limits=limits()) != operation_key(
        replace(projection, profile_id="e\u0301"), limits=limits()
    )
    with pytest.raises(FrozenInstanceError):
        projection.asset_id = OTHER  # type: ignore[misc]



def test_limits_digest_set_is_canonical_but_inputs_are_not_deduplicated() -> None:
    canonical = operation()
    repeated = operation(limits_digests=("f" * 64, "e" * 64, "f" * 64))
    assert operation_key(repeated, limits=limits()) == operation_key(canonical, limits=limits())
    with pytest.raises((ContractError, ValueError)):
        operation_key(operation(input_digests=("a" * 64, "a" * 64)), limits=limits())

def test_ordered_structure_and_revision_projection() -> None:
    sections = (Section(section_id="body", start=0, end=7),)
    expected_structure = digest(b'kf.structure.v1\n[{"end":7,"sectionId":"body","start":0}]')
    assert structure_digest(sections, limits=limits()) == expected_structure
    inputs = RevisionInputs(
        project_id=PROJECT, source_id=SOURCE, original_digest="a" * 64,
        text_digest="b" * 64, extraction_spec_digest="c" * 64,
        structure_digest=expected_structure, origin_map_digest="d" * 64,
    )
    canonical = (
        '{"extractionSpecDigest":"' + "c" * 64 + '","originMapDigest":"' + "d" * 64
        + '","originalDigest":"' + "a" * 64 + '","projectId":"' + PROJECT
        + '","sourceId":"' + SOURCE + '","structureDigest":"' + expected_structure
        + '","textDigest":"' + "b" * 64 + '"}'
    ).encode()
    expected = digest(b"kf.revision.v1\n" + canonical)
    assert revision_id(inputs, limits=limits()) == expected
    for name in (
        "original_digest", "text_digest", "extraction_spec_digest", "structure_digest",
        "origin_map_digest",
    ):
        assert revision_id(replace(inputs, **{name: "f" * 64}), limits=limits()) != expected
    ordered = (Section(section_id="first", start=0, end=1),
               Section(section_id="second", start=1, end=2))
    assert structure_digest(ordered, limits=limits()) != structure_digest(
        ordered[::-1], limits=limits()
    )


def processed():
    bound = limits()
    limits_bytes = bound.model_dump_json(by_alias=True).encode()
    recipe = ExtractionSpec(
        schema_version="kf.extraction-spec.v1", processor_id="text.utf8.v1",
        processor_version="synthetic.processor.v1", code_version="synthetic.code.v1",
        image_digest="a" * 64, limits_ref=ref(limits_bytes, "kf.contract-limits.v1"),
        normalization="none", newline_policy="preserve", bom_policy="reject",
    )
    asset = SourceAsset(
        schema_version="kf.source-asset.v1", project_id=PROJECT, asset_id=ASSET,
        source_id=SOURCE, original_ref=ref(TEXT, "kf.raw-original.v1"),
        admission_report_ref=ref(b"synthetic evidence", "kf.admission-report.v1"), metadata={},
    )
    output = process_text(
        asset, VerifiedBytes(TEXT, digest(TEXT)), recipe, limits=bound, limits_bytes=limits_bytes,
    )
    return asset, recipe, output


def test_retry_wrappers_compare_equal() -> None:
    bound = limits()
    asset, recipe, output = processed()
    recipe_ref = ref(recipe.model_dump_json(by_alias=True).encode(), "kf.extraction-spec.v1")
    map_bytes = output.origin_map.model_dump_json(by_alias=True).encode()
    quality_bytes = output.quality.model_dump_json(by_alias=True).encode()
    section_hash = structure_digest(output.sections, limits=bound)
    rev_hash = revision_id(RevisionInputs(
        project_id=PROJECT, source_id=SOURCE, original_digest=asset.original_ref.digest,
        text_digest=digest(output.text), extraction_spec_digest=recipe_ref.digest,
        structure_digest=section_hash, origin_map_digest=digest(map_bytes),
    ), limits=bound)
    op_hash = operation_key(operation(
        input_digests=(asset.original_ref.digest,), extraction_spec_digest=recipe_ref.digest,
        limits_digests=(recipe.limits_ref.digest,),
    ), limits=bound)
    wrappers = []
    comparisons = []
    for attempt, location, completed in (
        (ATTEMPT_A, "synthetic/a", "2026-10-25T00:00:00.000Z"),
        (ATTEMPT_B, "synthetic/b", "2026-10-25T00:01:00.000Z"),
    ):
        text_ref = ref(output.text, "kf.canonical-text.v1", location)
        map_ref = ref(map_bytes, "kf.origin-map.v1", location)
        quality_ref = ref(quality_bytes, "kf.quality-report.v1", location)
        revision = DocumentRevision(
            schema_version="kf.document-revision.v1", project_id=PROJECT, source_id=SOURCE,
            asset_id=ASSET, revision_id=rev_hash, original_ref=asset.original_ref,
            text_ref=text_ref, extraction_spec_ref=recipe_ref, text_encoding="utf-8",
            offset_unit="unicode_scalar", sections=output.sections,
            origin_map_ref=map_ref, quality_report_ref=quality_ref,
        )
        revision.validate_f1(len(output.text.decode()))
        revision_ref = ref(revision.model_dump_json(by_alias=True).encode(),
                           "kf.document-revision.v1", location)
        wrapper = ResultManifest(
            schema_version="kf.result.v1", project_id=PROJECT, plan_id=ASSET,
            operation_key=op_hash, attempt_id=attempt, input_digests=(asset.original_ref.digest,),
            status="succeeded", outputs=(revision_ref, quality_ref),
            document_revision_ref=revision_ref, quality_report_ref=quality_ref, errors=(),
            usage=ResourceUsage(provider_request_ids=(attempt,), cost_status="unknown",
                                tariff_ref=ref(b"synthetic tariff", "synthetic.tariff.v1")),
            completed_at=completed,
        )
        wrappers.append(wrapper.model_dump_json(by_alias=True).encode())
        comparisons.append(F1Comparison(
            project_id=PROJECT, asset_id=ASSET, source_id=SOURCE, operation_key=op_hash,
            revision_id=revision.revision_id, original_digest=asset.original_ref.digest,
            text_digest=text_ref.digest, extraction_spec_digest=recipe_ref.digest,
            structure_digest=section_hash, origin_map_digest=map_ref.digest,
            quality_projection_digest=quality_projection_digest(output.quality, limits=bound),
        ))
    assert digest(wrappers[0]) != digest(wrappers[1])
    assert comparison_digest(comparisons[0], limits=bound) == comparison_digest(
        comparisons[1], limits=bound
    )
    assert comparison_digest(replace(comparisons[0], asset_id=OTHER), limits=bound) != (
        comparison_digest(comparisons[0], limits=bound)
    )


def test_all_quality_checks_and_disposition_affect_identity() -> None:
    _, _, output = processed()
    report = output.quality
    base = quality_projection_digest(report, limits=limits())
    extra = QualityCheck(check_id="synthetic_extra", outcome="pass")
    extended = QualityReport(
        schema_version="kf.quality-report.v1", source_id=SOURCE,
        checks=(*report.checks, extra), disposition="valid",
    )
    assert quality_projection_digest(extended, limits=limits()) != base
    changed = extended.model_copy(update={
        "checks": (*report.checks, extra.model_copy(update={"outcome": "not_run"}))
    })
    assert quality_projection_digest(changed, limits=limits()) != quality_projection_digest(
        extended, limits=limits()
    )
    assert quality_projection_digest(extended.model_copy(update={
        "checks": extended.checks[::-1]
    }), limits=limits()) == quality_projection_digest(extended, limits=limits())
    assert quality_projection_digest(report.model_copy(update={
        "disposition": "needs_review"
    }), limits=limits()) != base
    with_reason = report.model_copy(update={"checks": (*report.checks, QualityCheck(
        check_id="synthetic_extra", outcome="fail",
        reason=Reason(code="source_changed", message="Synthetic message A"),
    ))})
    other_message = with_reason.model_copy(update={"checks": (*report.checks, QualityCheck(
        check_id="synthetic_extra", outcome="fail",
        reason=Reason(code="source_changed", message="Synthetic message B"),
    ))})
    assert quality_projection_digest(with_reason, limits=limits()) == quality_projection_digest(
        other_message, limits=limits()
    )
    other_code = with_reason.model_copy(update={"checks": (*report.checks, QualityCheck(
        check_id="synthetic_extra", outcome="fail",
        reason=Reason(code="remote_failed", message="Synthetic message A"),
    ))})
    assert quality_projection_digest(with_reason, limits=limits()) != quality_projection_digest(
        other_code, limits=limits()
    )
    for checks in (report.checks[:-1], (*report.checks, report.checks[0])):
        with pytest.raises((ContractError, ValidationError)):
            quality_projection_digest(report.model_copy(update={"checks": checks}), limits=limits())


def test_pins_and_limits_fail_closed() -> None:
    projection = operation()
    for changes in (
        {"input_digests": ()}, {"input_digests": ("a" * 64, "b" * 64)},
        {"limits_digests": ()}, {"project_id": "invalid"}, {"policy_digest": "missing"},
        {"profile_version": ""},
    ):
        with pytest.raises((ContractError, ValidationError, ValueError)):
            operation_key(operation(**changes), limits=limits())
    with pytest.raises(ContractError, match="limit_exceeded"):
        operation_key(projection, limits=limits(maxJsonBytes=16))
    with pytest.raises(ContractError, match="limit_exceeded"):
        operation_key(projection, limits=limits(maxArrayItems=1))
    with pytest.raises(ContractError, match="limit_exceeded"):
        operation_key(projection, limits=limits(maxStringScalars=4))
    with pytest.raises(ContractError, match="limit_exceeded"):
        quality_projection_digest(processed()[2].quality, limits=limits(maxArrayItems=7))


def test_quality_and_comparison_domains_match_literal_canonical_vectors() -> None:
    report = processed()[2].quality

    assert quality_projection_digest(report, limits=limits()) == digest(
        b"kf.quality-projection.v1\n" + VALID_QUALITY_JCS
    )
    projection = F1Comparison(
        project_id=PROJECT, asset_id=ASSET, source_id=SOURCE, operation_key="a" * 64,
        revision_id="b" * 64, original_digest="c" * 64, text_digest="d" * 64,
        extraction_spec_digest="e" * 64, structure_digest="f" * 64,
        origin_map_digest="0" * 64, quality_projection_digest="1" * 64,
    )
    canonical = (
        '{"assetId":"' + ASSET + '","extractionSpecDigest":"' + "e" * 64
        + '","operationKey":"' + "a" * 64 + '","originMapDigest":"' + "0" * 64
        + '","originalDigest":"' + "c" * 64 + '","projectId":"' + PROJECT
        + '","qualityProjectionDigest":"' + "1" * 64 + '","revisionId":"' + "b" * 64
        + '","sourceId":"' + SOURCE + '","structureDigest":"' + "f" * 64
        + '","textDigest":"' + "d" * 64 + '"}'
    ).encode()
    assert comparison_digest(projection, limits=limits()) == digest(
        b"kf.f1-comparison.v1\n" + canonical
    )
    for field in (
        "operation_key", "revision_id", "original_digest", "text_digest",
        "extraction_spec_digest", "structure_digest", "origin_map_digest",
        "quality_projection_digest",
    ):
        assert comparison_digest(replace(projection, **{field: "9" * 64}), limits=limits()) != (
            comparison_digest(projection, limits=limits())
        )


def test_projection_ceiling_fails_before_hashing(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden_hash(*args: object, **kwargs: object) -> str:
        pytest.fail("oversized projection reached canonical hashing")

    monkeypatch.setattr("conscience_foundry.core.identity.hash_jcs", forbidden_hash)
    for bound in (limits(maxJsonBytes=16), limits(maxOutputBytes=16),
                  limits(maxArrayItems=1), limits(maxStringScalars=4), limits(maxDepth=1)):
        with pytest.raises(ContractError, match="limit_exceeded"):
            operation_key(operation(), limits=bound)


def test_quality_projection_rejects_wrong_version_in_copied_model() -> None:
    report = processed()[2].quality.model_copy(update={"schema_version": "synthetic.wrong.v1"})
    with pytest.raises(ContractError, match="invalid_schema"):
        quality_projection_digest(report, limits=limits())



def test_quality_check_ids_use_explicit_utf16_order() -> None:
    report = processed()[2].quality
    extra = (
        QualityCheck(check_id="\ue000", outcome="pass"),
        QualityCheck(check_id="\U00010000", outcome="pass"),
    )
    extended = QualityReport(
        schema_version="kf.quality-report.v1", source_id=SOURCE,
        checks=(*report.checks, *extra), disposition="valid",
    )
    suffix = (
        ',{"checkId":"\U00010000","outcome":"pass"},'
        '{"checkId":"\ue000","outcome":"pass"}],"disposition"'
    ).encode()
    expected_bytes = VALID_QUALITY_JCS.replace(b'],"disposition"', suffix)
    assert quality_projection_digest(extended, limits=limits()) == digest(
        b"kf.quality-projection.v1\n" + expected_bytes
    )
    forged = report.model_copy(update={"checks": (*report.checks, extra[0].model_copy(
        update={"check_id": "\ud800"}
    ))})
    with pytest.raises(ContractError, match="invalid_schema"):
        quality_projection_digest(forged, limits=limits())
