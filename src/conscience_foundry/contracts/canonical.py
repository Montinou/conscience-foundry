"""Immutable canonical-coordinate contracts and explicit contextual evidence checks."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, Field, model_validator
from pydantic.json_schema import SkipJsonSchema

from conscience_foundry.contracts.common import (
    MAX_SAFE_INTEGER,
    ContractError,
    Digest,
    Id,
    Instant,
    Reason,
    Ref,
    SafeInteger,
    ScalarString,
    Version,
    WireModel,
)

NonemptyString = Annotated[ScalarString, Field(min_length=1)]
REQUIRED_F1_CHECK_IDS = frozenset(
    {
        "hash",
        "encoding",
        "nonempty",
        "no_NUL",
        "no_BOM",
        "bounds",
        "identity_mapping",
        "non_whitespace",
    }
)
INTEGRITY_CHECK_IDS = REQUIRED_F1_CHECK_IDS - {"non_whitespace"}


def _json_array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _scalar_length(value: int) -> None:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise ContractError("invalid_span")


class ExtractionSpec(WireModel):
    schema_version: Literal["kf.extraction-spec.v1"]
    processor_id: Literal["text.utf8.v1"]
    processor_version: Version
    code_version: Version
    image_digest: Digest
    limits_ref: Ref
    normalization: Literal["none"]
    newline_policy: Literal["preserve"]
    bom_policy: Literal["reject"]


class Section(WireModel):
    section_id: NonemptyString
    parent_section_id: NonemptyString | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    start: SafeInteger
    end: SafeInteger
    heading: ScalarString | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def ordered_bounds(self) -> Self:
        if self.start > self.end:
            raise ValueError("section bounds reversed")
        return self


class DocumentRevision(WireModel):
    schema_version: Literal["kf.document-revision.v1"]
    project_id: Id
    source_id: Id
    asset_id: Id
    revision_id: Digest
    original_ref: Ref
    text_ref: Ref
    extraction_spec_ref: Ref
    text_encoding: Literal["utf-8"]
    offset_unit: Literal["unicode_scalar"]
    sections: Annotated[tuple[Section, ...], BeforeValidator(_json_array)]
    origin_map_ref: Ref
    quality_report_ref: Ref

    @model_validator(mode="after")
    def project_and_section_tree(self) -> Self:
        references = (
            self.original_ref,
            self.text_ref,
            self.extraction_spec_ref,
            self.origin_map_ref,
            self.quality_report_ref,
        )
        if any(reference.project_id != self.project_id for reference in references):
            raise ValueError("cross-project reference")
        by_id = {section.section_id: section for section in self.sections}
        if len(by_id) != len(self.sections):
            raise ValueError("duplicate section identity")
        for section in self.sections:
            if section.parent_section_id is not None:
                parent = by_id.get(section.parent_section_id)
                if parent is None or not parent.start <= section.start <= section.end <= parent.end:
                    raise ValueError("invalid parent containment")
            visited: set[str] = set()
            current: Section | None = section
            while current is not None:
                if current.section_id in visited:
                    raise ValueError("cyclic section ancestry")
                visited.add(current.section_id)
                current = (
                    by_id.get(current.parent_section_id) if current.parent_section_id else None
                )
        return self

    def validate_f1(self, scalar_length: int) -> None:
        """Check text.utf8.v1 structure with a length from separately verified bytes.

        Shape checks do not verify reference bytes or the revision hash. Generic
        revisions can represent later processor structures without this F1 check.
        Empty diagnostic text is representable but cannot pass accepted review.
        """
        _scalar_length(scalar_length)
        if len(self.sections) != 1:
            raise ContractError("invalid_span")
        body = self.sections[0]
        if (
            body.section_id != "body"
            or body.parent_section_id is not None
            or body.heading is not None
            or body.start != 0
            or body.end != scalar_length
        ):
            raise ContractError("invalid_span")


class DocumentSpan(WireModel):
    schema_version: Literal["kf.document-span.v1"]
    project_id: Id
    source_id: Id
    revision_id: Digest
    section_id: NonemptyString
    start: SafeInteger
    end: SafeInteger
    offset_unit: Literal["unicode_scalar"]

    @model_validator(mode="after")
    def nonempty_bounds(self) -> Self:
        if self.start >= self.end:
            raise ValueError("span must be nonempty")
        return self


def validate_span_shape(span: DocumentSpan, revision: DocumentRevision, scalar_length: int) -> None:
    """Check absolute scalar containment; this does not resolve or certify a quote."""
    _scalar_length(scalar_length)
    if (span.project_id, span.source_id, span.revision_id) != (
        revision.project_id,
        revision.source_id,
        revision.revision_id,
    ):
        raise ContractError("revision_mismatch")
    if any(section.end > scalar_length for section in revision.sections):
        raise ContractError("invalid_span")
    section = next((item for item in revision.sections if item.section_id == span.section_id), None)
    if section is None or not section.start <= span.start < span.end <= section.end:
        raise ContractError("invalid_span")


class OriginMap(WireModel):
    schema_version: Literal["kf.origin-map.v1"]
    kind: Literal["identity_utf8"]
    original_digest: Digest
    text_digest: Digest
    offset_unit: Literal["unicode_scalar"]

    @model_validator(mode="after")
    def identity_digests(self) -> Self:
        if self.original_digest != self.text_digest:
            raise ValueError("identity mapping has unequal digests")
        return self


class QualityCheck(WireModel):
    check_id: NonemptyString
    outcome: Literal["pass", "fail", "not_run"]
    reason: Reason | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )


class QualityReport(WireModel):
    schema_version: Literal["kf.quality-report.v1"]
    source_id: Id
    checks: Annotated[tuple[QualityCheck, ...], BeforeValidator(_json_array)]
    disposition: Literal["valid", "needs_review", "quarantined"]

    @model_validator(mode="after")
    def mandatory_evidence_and_disposition(self) -> Self:
        checks = {check.check_id: check.outcome for check in self.checks}
        if len(checks) != len(self.checks) or not REQUIRED_F1_CHECK_IDS <= checks.keys():
            raise ValueError("duplicate or missing required quality check")
        if self.disposition == "valid" and any(
            checks[name] != "pass" for name in REQUIRED_F1_CHECK_IDS
        ):
            raise ValueError("valid requires all mandatory evidence")
        integrity_failed = any(checks[name] == "fail" for name in INTEGRITY_CHECK_IDS)
        if integrity_failed and self.disposition != "quarantined":
            raise ValueError("integrity failure requires quarantine")
        if (
            not integrity_failed
            and checks["non_whitespace"] == "fail"
            and self.disposition != "needs_review"
        ):
            raise ValueError("whitespace-only candidate requires review")
        return self


class RevisionReview(WireModel):
    schema_version: Literal["kf.revision-review.v1"]
    project_id: Id
    revision_id: Digest
    decision: Literal["accepted", "needs_review", "rejected"]
    actor_id: Id
    policy_version: Version
    reviewed_at: Instant
    reason: Reason

    def validate_quality(self, revision: DocumentRevision, report: QualityReport) -> None:
        """Check correlated quality evidence; custody must verify referenced bytes.

        A parsed record neither authenticates the reviewer nor proves that the
        supplied report matches qualityReportRef. Trusted control-plane callers
        must establish those independent boundaries before accepting a revision.
        """
        if (self.project_id, self.revision_id) != (revision.project_id, revision.revision_id):
            raise ContractError("revision_mismatch")
        if report.source_id != revision.source_id:
            raise ContractError("revision_mismatch")
        if self.decision == "accepted":
            checks = {check.check_id: check.outcome for check in report.checks}
            if (
                report.disposition != "valid"
                or any(checks.get(name) != "pass" for name in REQUIRED_F1_CHECK_IDS)
                or not any(section.end > section.start for section in revision.sections)
            ):
                raise ContractError("invalid_schema")
