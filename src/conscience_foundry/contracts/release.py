"""Release/report wire shapes; authoritative history and grants live in the ledger."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, Field, model_validator
from pydantic.json_schema import SkipJsonSchema

from conscience_foundry.contracts.codec import hash_jcs
from conscience_foundry.contracts.common import (
    ContractError,
    Digest,
    Id,
    Instant,
    PositiveInteger,
    Reason,
    Ref,
    SafeInteger,
    ScalarString,
    Version,
    WireModel,
)

NonemptyString = Annotated[ScalarString, Field(min_length=1)]


def _array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _ref_key(ref: Ref) -> tuple[str, str, str, int]:
    return ref.project_id, ref.artifact_schema, ref.digest, ref.size_bytes


def _unique_refs(refs: tuple[Ref, ...]) -> None:
    if len({_ref_key(ref) for ref in refs}) != len(refs):
        raise ValueError("duplicate artifact identity")


def _project(refs: tuple[Ref, ...], project: str) -> None:
    if any(ref.project_id != project for ref in refs):
        raise ValueError("cross-project reference")


def _schema(ref: Ref, schema_id: str) -> None:
    if ref.artifact_schema != schema_id:
        raise ValueError("unexpected reference schema")


class ReleaseSource(WireModel):
    source_id: Id
    revision_ref: Ref
    review_ref: Ref

    @model_validator(mode="after")
    def reference_roles(self) -> Self:
        _schema(self.revision_ref, "kf.document-revision.v1")
        _schema(self.review_ref, "kf.revision-review.v1")
        if self.revision_ref.project_id != self.review_ref.project_id:
            raise ValueError("cross-project source references")
        return self


class ReleaseComponent(WireModel):
    role: Literal["annotations", "navigation", "embeddings", "index", "domain_export"]
    artifact_ref: Ref
    interface_version: Version


class LibraryRelease(WireModel):
    schema_version: Literal["kf.library-release.v1"]
    project_id: Id
    release_id: Id
    profile_id: NonemptyString
    profile_version: Version
    capabilities: Annotated[tuple[NonemptyString, ...], BeforeValidator(_array)]
    source_entries: Annotated[tuple[ReleaseSource, ...], BeforeValidator(_array)]
    component_refs: Annotated[tuple[ReleaseComponent, ...], BeforeValidator(_array)]
    coverage_report_ref: Ref
    provenance_report_ref: Ref
    created_at: Instant

    @model_validator(mode="after")
    def selection_and_references(self) -> Self:
        ids = tuple(entry.source_id for entry in self.source_entries)
        if len(set(ids)) != len(ids) or ids != tuple(sorted(ids)):
            raise ValueError("source entries must be unique and sorted")
        if len(set(self.capabilities)) != len(self.capabilities):
            raise ValueError("duplicate capability")
        if len({component.role for component in self.component_refs}) != len(self.component_refs):
            raise ValueError("duplicate component role")
        _project(
            (
                *(
                    ref
                    for source in self.source_entries
                    for ref in (source.revision_ref, source.review_ref)
                ),
                *(component.artifact_ref for component in self.component_refs),
                self.coverage_report_ref,
                self.provenance_report_ref,
            ),
            self.project_id,
        )
        _schema(self.coverage_report_ref, "kf.coverage-report.v1")
        _schema(self.provenance_report_ref, "kf.provenance-report.v1")
        return self

    def validate_f1(self) -> None:
        """Check declared F1 capability only; this does not prove release eligibility."""
        if self.capabilities != ("canonical_text",) or self.component_refs:
            raise ContractError("unsupported_capability")

    def selection_digest(self) -> str:
        return hash_jcs(
            "kf.release-selection.v1",
            [entry.model_dump(mode="json", by_alias=True) for entry in self.source_entries],
        )


class CoverageEntry(WireModel):
    batch_id: Id
    asset_id: Id
    source_id: Id
    status: Literal[
        "blocked", "pending", "running", "needs_review", "accepted", "failed", "withdrawn"
    ]
    selected: bool
    revision_ref: Ref | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    outcome_evidence_refs: Annotated[tuple[Ref, ...], BeforeValidator(_array), Field(min_length=1)]
    reasons: Annotated[tuple[Reason, ...], BeforeValidator(_array)]

    @model_validator(mode="after")
    def selection_evidence_shape(self) -> Self:
        if self.selected and (self.status != "accepted" or self.revision_ref is None):
            raise ValueError("selected coverage requires accepted revision")
        if self.status == "accepted" and self.revision_ref is None:
            raise ValueError("accepted coverage requires revision")
        if (self.status != "accepted" or not self.selected) and not self.reasons:
            raise ValueError("nonaccepted or excluded coverage requires reason")
        if self.revision_ref is not None:
            _schema(self.revision_ref, "kf.document-revision.v1")
        _unique_refs(self.outcome_evidence_refs)
        return self


class CoverageReport(WireModel):
    schema_version: Literal["kf.coverage-report.v1"]
    project_id: Id
    selection_digest: Digest
    admission_report_refs: Annotated[tuple[Ref, ...], BeforeValidator(_array), Field(min_length=1)]
    entries: Annotated[tuple[CoverageEntry, ...], BeforeValidator(_array)]
    report_at: Instant

    @model_validator(mode="after")
    def complete_row_shape(self) -> Self:
        keys = tuple((entry.batch_id, entry.asset_id) for entry in self.entries)
        if len(set(keys)) != len(keys) or keys != tuple(sorted(keys)):
            raise ValueError("coverage rows must be unique and sorted")
        _unique_refs(self.admission_report_refs)
        for ref in self.admission_report_refs:
            _schema(ref, "kf.admission-report.v1")
        _project(
            (
                *self.admission_report_refs,
                *(ref for entry in self.entries for ref in entry.outcome_evidence_refs),
                *(entry.revision_ref for entry in self.entries if entry.revision_ref is not None),
            ),
            self.project_id,
        )
        return self

    def validate_selection(self, release: LibraryRelease) -> None:
        """Bind exact selected references; admission universe/status proof is T14.

        A hash/schema check never proves a producer's administrative claims.
        Custody verifies raw report refs; ledger/audit access establishes history.
        """
        if (
            self.project_id != release.project_id
            or self.selection_digest != release.selection_digest()
        ):
            raise ContractError("hash_mismatch")
        selected = tuple(entry for entry in self.entries if entry.selected)
        if len(selected) != len(release.source_entries):
            raise ContractError("invalid_schema")
        by_source = {entry.source_id: entry for entry in selected}
        if len(by_source) != len(selected):
            raise ContractError("invalid_schema")
        for source in release.source_entries:
            entry = by_source.get(source.source_id)
            if entry is None or entry.revision_ref != source.revision_ref:
                raise ContractError("revision_mismatch")


class ProvenanceEntry(WireModel):
    source_id: Id
    revision_ref: Ref
    review_ref: Ref
    operation_result_ref: Ref
    attempt_refs: Annotated[tuple[Ref, ...], BeforeValidator(_array), Field(min_length=1)]
    run_report_refs: Annotated[tuple[Ref, ...], BeforeValidator(_array), Field(min_length=1)]

    @model_validator(mode="after")
    def reference_roles(self) -> Self:
        _schema(self.revision_ref, "kf.document-revision.v1")
        _schema(self.review_ref, "kf.revision-review.v1")
        _schema(self.operation_result_ref, "kf.operation-result-record.v1")
        for ref in self.attempt_refs:
            _schema(ref, "kf.stage-attempt.v1")
        for ref in self.run_report_refs:
            _schema(ref, "kf.run-report.v1")
        _unique_refs(self.attempt_refs)
        _unique_refs(self.run_report_refs)
        return self


class ProvenanceReport(WireModel):
    schema_version: Literal["kf.provenance-report.v1"]
    project_id: Id
    selection_digest: Digest
    entries: Annotated[tuple[ProvenanceEntry, ...], BeforeValidator(_array)]
    report_at: Instant

    @model_validator(mode="after")
    def selected_source_shape(self) -> Self:
        ids = tuple(entry.source_id for entry in self.entries)
        if len(set(ids)) != len(ids) or ids != tuple(sorted(ids)):
            raise ValueError("provenance entries must be unique and sorted")
        _project(
            tuple(
                ref
                for entry in self.entries
                for ref in (
                    entry.revision_ref,
                    entry.review_ref,
                    entry.operation_result_ref,
                    *entry.attempt_refs,
                    *entry.run_report_refs,
                )
            ),
            self.project_id,
        )
        return self

    def validate_selection(self, release: LibraryRelease) -> None:
        """Check exact selected refs, not the truth/completeness of historical audit."""
        if (
            self.project_id != release.project_id
            or self.selection_digest != release.selection_digest()
        ):
            raise ContractError("hash_mismatch")
        if len(self.entries) != len(release.source_entries):
            raise ContractError("invalid_schema")
        for entry, source in zip(self.entries, release.source_entries, strict=True):
            if (entry.source_id, entry.revision_ref, entry.review_ref) != (
                source.source_id,
                source.revision_ref,
                source.review_ref,
            ):
                raise ContractError("revision_mismatch")


class ImportReceipt(WireModel):
    schema_version: Literal["kf.import-receipt.v1"]
    project_id: Id
    import_id: Id
    release_ref: Ref
    verified_artifacts: Annotated[tuple[Ref, ...], BeforeValidator(_array)]
    status: Literal["local_verified", "failed"]
    checked_at: Instant
    reasons: Annotated[tuple[Reason, ...], BeforeValidator(_array)]

    @model_validator(mode="after")
    def verification_shape(self) -> Self:
        _schema(self.release_ref, "kf.library-release.v1")
        _project((self.release_ref, *self.verified_artifacts), self.project_id)
        _unique_refs(self.verified_artifacts)
        if self.status == "local_verified" and (not self.verified_artifacts or self.reasons):
            raise ValueError("verified import requires artifacts and no errors")
        if self.status == "failed" and not self.reasons:
            raise ValueError("failed import requires errors")
        return self


class RetentionPolicy(WireModel):
    schema_version: Literal["kf.retention.v1"]
    policy_version: Version
    min_staging_age_seconds: SafeInteger
    funded_staging_horizon_seconds: PositiveInteger
    escalation_lead_seconds: PositiveInteger
    backup_required: bool
    audit_retention_seconds: PositiveInteger

    @model_validator(mode="after")
    def funded_horizon(self) -> Self:
        if self.funded_staging_horizon_seconds < self.min_staging_age_seconds:
            raise ValueError("funding horizon shorter than minimum retention")
        if self.escalation_lead_seconds >= self.funded_staging_horizon_seconds:
            raise ValueError("escalation lead must be shorter than horizon")
        return self


PublicationStage = Literal[
    "candidate", "validated", "transferred", "local_verified", "published", "retired"
]


class PublicationRecord(WireModel):
    schema_version: Literal["kf.publication-record.v1"]
    project_id: Id
    release_digest: Digest
    event_id: Id
    previous_event_id: Id | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    stage: PublicationStage
    actor_id: Id
    policy_ref: Ref
    evidence_refs: Annotated[tuple[Ref, ...], BeforeValidator(_array), Field(min_length=1)]
    publication_authorization_ref: Ref | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    recorded_at: Instant

    @model_validator(mode="after")
    def transition_shape(self) -> Self:
        if (self.stage == "candidate") != (self.previous_event_id is None):
            raise ValueError("candidate is the only initial publication record")
        if self.previous_event_id == self.event_id:
            raise ValueError("publication event cannot follow itself")
        if (self.stage == "published") != (self.publication_authorization_ref is not None):
            raise ValueError("publication grant only belongs to published event")
        _schema(self.policy_ref, "kf.policy.v1")
        if self.publication_authorization_ref is not None:
            _schema(self.publication_authorization_ref, "kf.publication-authorization.v1")
        _project(
            (
                self.policy_ref,
                *self.evidence_refs,
                *(
                    (self.publication_authorization_ref,)
                    if self.publication_authorization_ref is not None
                    else ()
                ),
            ),
            self.project_id,
        )
        _unique_refs(self.evidence_refs)
        return self


class PublicationAuthorization(WireModel):
    schema_version: Literal["kf.publication-authorization.v1"]
    project_id: Id
    release_digest: Digest
    actor_id: Id
    policy_ref: Ref
    authorized_at: Instant
    expires_at: Instant

    @model_validator(mode="after")
    def bounded_grant_shape(self) -> Self:
        _schema(self.policy_ref, "kf.policy.v1")
        _project((self.policy_ref,), self.project_id)
        if self.expires_at <= self.authorized_at:
            raise ValueError("publication grant expiry must follow authorization")
        return self


class ActivationRecord(WireModel):
    schema_version: Literal["kf.activation.v1"]
    project_id: Id
    expected_previous_release_digest: Digest | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    next_release_digest: Digest
    actor_id: Id
    activated_at: Instant
