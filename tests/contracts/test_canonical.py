"""Synthetic canonical-contract checks; bytes and operator authority are later gates."""

import json

import pytest
from pydantic import ValidationError

from conscience_foundry.contracts.canonical import (
    DocumentRevision,
    DocumentSpan,
    ExtractionSpec,
    OriginMap,
    QualityCheck,
    QualityReport,
    RevisionReview,
    Section,
    validate_span_shape,
)
from conscience_foundry.contracts.common import ContractError, ContractLimits

PROJECT = "00000000-0000-0000-0000-000000000001"
SOURCE = "00000000-0000-0000-0000-000000000002"
ASSET = "00000000-0000-0000-0000-000000000003"
ACTOR = "00000000-0000-0000-0000-000000000004"
OTHER = "00000000-0000-0000-0000-000000000005"
REQUIRED = (
    "hash",
    "encoding",
    "nonempty",
    "no_NUL",
    "no_BOM",
    "bounds",
    "identity_mapping",
    "non_whitespace",
)


def limits() -> ContractLimits:
    return ContractLimits.model_validate(
        {
            "schemaVersion": "kf.contract-limits.v1",
            "version": "synthetic.v1",
            "maxJsonBytes": 65536,
            "maxStringScalars": 256,
            "maxArrayItems": 32,
            "maxDepth": 16,
            "maxManifestItems": 4,
            "maxSourceBytes": 1024,
            "maxOutputBytes": 1024,
            "maxErrorMessageScalars": 80,
        }
    )


def ref(**changes: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.artifact-ref.v1",
        "projectId": PROJECT,
        "digest": "a" * 64,
        "sizeBytes": 11,
        "mediaType": "application/json",
        "artifactSchema": "synthetic.v1",
        "locations": [],
    } | changes


def revision(**changes: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.document-revision.v1",
        "projectId": PROJECT,
        "sourceId": SOURCE,
        "assetId": ASSET,
        "revisionId": "b" * 64,
        "originalRef": ref(),
        "textRef": ref(),
        "extractionSpecRef": ref(),
        "textEncoding": "utf-8",
        "offsetUnit": "unicode_scalar",
        "sections": [{"sectionId": "body", "start": 0, "end": 7}],
        "originMapRef": ref(),
        "qualityReportRef": ref(),
    } | changes


def span(**changes: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.document-span.v1",
        "projectId": PROJECT,
        "sourceId": SOURCE,
        "revisionId": "b" * 64,
        "sectionId": "body",
        "start": 1,
        "end": 2,
        "offsetUnit": "unicode_scalar",
    } | changes


def quality(**changes: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.quality-report.v1",
        "sourceId": SOURCE,
        "checks": [{"checkId": check, "outcome": "pass"} for check in REQUIRED],
        "disposition": "valid",
    } | changes


def review(**changes: object) -> dict[str, object]:
    return {
        "schemaVersion": "kf.revision-review.v1",
        "projectId": PROJECT,
        "revisionId": "b" * 64,
        "decision": "accepted",
        "actorId": ACTOR,
        "policyVersion": "synthetic.policy.v1",
        "reviewedAt": "2026-10-25T00:00:00.000Z",
        "reason": {"code": "invalid_schema", "message": "Synthetic operator review"},
    } | changes


def test_absolute_span_containment() -> None:
    value = DocumentRevision.model_validate(revision())
    validate_span_shape(DocumentSpan.model_validate(span()), value, 7)
    validate_span_shape(DocumentSpan.model_validate(span(start=0, end=7)), value, 7)
    for changes in (
        {"start": 1, "end": 1},
        {"start": 0, "end": 8},
        {"start": -1},
        {"start": True},
        {"end": 2.0},
    ):
        with pytest.raises((ValidationError, ContractError)):
            validate_span_shape(DocumentSpan.model_validate(span(**changes)), value, 7)


def test_span_identity_and_verified_length_context() -> None:
    value = DocumentRevision.model_validate(revision())
    for changes in (
        {"projectId": OTHER},
        {"sourceId": OTHER},
        {"revisionId": "c" * 64},
        {"sectionId": "missing"},
    ):
        with pytest.raises(ContractError):
            validate_span_shape(DocumentSpan.model_validate(span(**changes)), value, 7)
    for length in (6, -1, True, 7.0):
        with pytest.raises(ContractError):
            validate_span_shape(DocumentSpan.model_validate(span()), value, length)


def test_f1_revision_requires_single_body_and_same_project_refs() -> None:
    for sections in (
        [],
        [{"sectionId": "body", "start": 1, "end": 7}],
        [{"sectionId": "other", "start": 0, "end": 7}],
        [{"sectionId": "body", "start": 0, "end": 7, "heading": "x"}],
        [{"sectionId": "body", "start": 0, "end": 7, "parentSectionId": "body"}],
        [{"sectionId": "body", "start": 0, "end": 7}] * 2,
    ):
        with pytest.raises((ValidationError, ContractError)):
            DocumentRevision.model_validate(revision(sections=sections)).validate_f1(7)
    with pytest.raises(ValidationError):
        DocumentRevision.model_validate(revision(textRef=ref(projectId=OTHER)))
    with pytest.raises(ValidationError):
        Section.model_validate({"sectionId": "body", "start": 2, "end": 1})


def test_optional_fields_are_omitted_and_explicit_null_rejected() -> None:
    section = Section.model_validate({"sectionId": "body", "start": 0, "end": 7})
    assert json.loads(section.model_dump_json(by_alias=True)) == {
        "sectionId": "body",
        "start": 0,
        "end": 7,
    }
    check = QualityCheck.model_validate({"checkId": "hash", "outcome": "pass"})
    assert "reason" not in json.loads(check.model_dump_json(by_alias=True))
    Section.from_wire(section.model_dump_json(by_alias=True).encode(), limits())
    QualityCheck.from_wire(check.model_dump_json(by_alias=True).encode(), limits())
    for key in ("parentSectionId", "heading"):
        with pytest.raises(ValidationError):
            Section.model_validate({"sectionId": "body", "start": 0, "end": 7, key: None})
    with pytest.raises(ValidationError):
        QualityCheck.model_validate({"checkId": "hash", "outcome": "pass", "reason": None})
    assert "anyOf" not in Section.model_json_schema()["properties"]["heading"]
    assert "anyOf" not in QualityCheck.model_json_schema()["properties"]["reason"]


def test_required_quality_checks_are_unique_and_extras_preserved() -> None:
    valid = quality()
    checks = valid["checks"]
    assert isinstance(checks, list)
    for changed in (checks[:-1], checks + [checks[0]]):
        with pytest.raises(ValidationError):
            QualityReport.model_validate(quality(checks=changed))
    enriched = QualityReport.model_validate(
        quality(checks=checks + [{"checkId": "synthetic_extra", "outcome": "not_run"}])
    )
    assert enriched.checks[-1].check_id == "synthetic_extra"
    assert json.loads(enriched.model_dump_json(by_alias=True))["checks"][-1]["outcome"] == "not_run"
    with pytest.raises((AttributeError, TypeError)):
        enriched.checks[0] = enriched.checks[-1]


def test_review_cannot_override_integrity() -> None:
    value = DocumentRevision.model_validate(revision())
    accepted = RevisionReview.model_validate(review())
    accepted.validate_quality(value, QualityReport.model_validate(quality()))
    checks = [
        {"checkId": check, "outcome": "fail" if check == "hash" else "pass"} for check in REQUIRED
    ]
    broken = QualityReport.model_validate(quality(checks=checks, disposition="quarantined"))
    with pytest.raises(ContractError):
        accepted.validate_quality(value, broken)
    for identity in ({"projectId": OTHER}, {"revisionId": "c" * 64}):
        with pytest.raises(ContractError):
            RevisionReview.model_validate(review(**identity)).validate_quality(
                value, QualityReport.model_validate(quality())
            )
    with pytest.raises(ContractError):
        accepted.validate_quality(value, QualityReport.model_validate(quality(sourceId=OTHER)))
    with pytest.raises(ContractError):
        accepted.validate_quality(
            DocumentRevision.model_validate(
                revision(sections=[{"sectionId": "body", "start": 0, "end": 0}])
            ),
            QualityReport.model_validate(quality()),
        )


def test_whitespace_cannot_enter_accepted_f1_release() -> None:
    checks = [
        {"checkId": check, "outcome": "fail" if check == "non_whitespace" else "pass"}
        for check in REQUIRED
    ]
    diagnostic = QualityReport.model_validate(quality(checks=checks, disposition="needs_review"))
    value = DocumentRevision.model_validate(revision())
    with pytest.raises(ContractError):
        RevisionReview.model_validate(review()).validate_quality(value, diagnostic)
    for decision in ("needs_review", "rejected"):
        RevisionReview.model_validate(review(decision=decision)).validate_quality(value, diagnostic)
    with pytest.raises(ValidationError):
        QualityReport.model_validate(quality(checks=checks, disposition="valid"))


def test_extraction_and_mapping_literals_and_equal_digests() -> None:
    extraction = {
        "schemaVersion": "kf.extraction-spec.v1",
        "processorId": "text.utf8.v1",
        "processorVersion": "synthetic.v1",
        "codeVersion": "synthetic.v1",
        "imageDigest": "a" * 64,
        "limitsRef": ref(),
        "normalization": "none",
        "newlinePolicy": "preserve",
        "bomPolicy": "reject",
    }
    assert ExtractionSpec.model_validate(extraction).processor_id == "text.utf8.v1"
    for key, wrong in (
        ("processorId", "pdf"),
        ("normalization", "NFC"),
        ("newlinePolicy", "LF"),
        ("bomPolicy", "strip"),
    ):
        with pytest.raises(ValidationError):
            ExtractionSpec.model_validate(extraction | {key: wrong})
    mapping = {
        "schemaVersion": "kf.origin-map.v1",
        "kind": "identity_utf8",
        "originalDigest": "a" * 64,
        "textDigest": "a" * 64,
        "offsetUnit": "unicode_scalar",
    }
    assert OriginMap.model_validate(mapping).text_digest == "a" * 64
    for changed in ({"kind": "pdf"}, {"textDigest": "b" * 64}, {"offsetUnit": "utf16"}):
        with pytest.raises(ValidationError):
            OriginMap.model_validate(mapping | changed)


def test_scalar_strings_and_model_roundtrip() -> None:
    with pytest.raises(ContractError):
        Section.from_wire(b'{"sectionId":"\\ud800","start":0,"end":1}', limits())
    paired = Section.from_wire(b'{"sectionId":"\\ud83d\\ude00","start":0,"end":1}', limits())
    assert paired.section_id == "😀"
    for model, payload in (
        (DocumentRevision, revision()),
        (DocumentSpan, span()),
        (QualityReport, quality()),
        (RevisionReview, review()),
    ):
        value = model.model_validate(payload)
        assert model.from_wire(value.model_dump_json(by_alias=True).encode(), limits()) == value


def test_generic_sections_tree_and_explicit_f1_context() -> None:
    sections = [
        {"sectionId": "root", "start": 0, "end": 7},
        {"sectionId": "child", "parentSectionId": "root", "start": 1, "end": 3},
    ]
    generic = DocumentRevision.model_validate(revision(sections=sections))
    validate_span_shape(
        DocumentSpan.model_validate(span(sectionId="child", start=1, end=3)), generic, 7
    )
    with pytest.raises(ContractError):
        generic.validate_f1(7)
    for invalid in (
        [{"sectionId": "root", "parentSectionId": "missing", "start": 0, "end": 7}],
        [
            {"sectionId": "root", "parentSectionId": "child", "start": 0, "end": 7},
            {"sectionId": "child", "parentSectionId": "root", "start": 0, "end": 7},
        ],
        [
            {"sectionId": "root", "start": 1, "end": 7},
            {"sectionId": "child", "parentSectionId": "root", "start": 0, "end": 3},
        ],
    ):
        with pytest.raises(ValidationError):
            DocumentRevision.model_validate(revision(sections=invalid))
    for length in (6, 8, -1, True, 7.0):
        with pytest.raises(ContractError):
            DocumentRevision.model_validate(revision()).validate_f1(length)


def test_quality_disposition_requires_evidence_and_quarantines_failure() -> None:
    for outcome in ("fail", "not_run"):
        checks = [
            {"checkId": check, "outcome": outcome if check == "hash" else "pass"}
            for check in REQUIRED
        ]
        with pytest.raises(ValidationError):
            QualityReport.model_validate(quality(checks=checks))
        report = QualityReport.model_validate(quality(checks=checks, disposition="quarantined"))
        with pytest.raises(ContractError):
            RevisionReview.model_validate(review()).validate_quality(
                DocumentRevision.model_validate(revision()), report
            )
        if outcome == "fail":
            with pytest.raises(ValidationError):
                QualityReport.model_validate(quality(checks=checks, disposition="needs_review"))
        else:
            QualityReport.model_validate(quality(checks=checks, disposition="needs_review"))
