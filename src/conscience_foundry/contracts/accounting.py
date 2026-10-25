"""Immutable accounting evidence shapes; settlement arithmetic belongs to the ledger."""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, Field, StringConstraints, model_validator
from pydantic.json_schema import SkipJsonSchema

from conscience_foundry.contracts.admission import AdmissionReport, IntakeManifest
from conscience_foundry.contracts.common import (
    ContractError,
    Digest,
    Id,
    Instant,
    Money,
    Reason,
    Ref,
    SafeInteger,
    ScalarString,
    WireModel,
)
from conscience_foundry.contracts.project import PolicyArtifact


def _json_array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


Quantity = Annotated[ScalarString, StringConstraints(pattern=r"^[0-9]+(?:\.[0-9]+)?$")]
CostStatus = Literal["actual", "estimated", "unknown"]


class ResourceUsage(WireModel):
    cpu_seconds: Quantity | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    memory_gib_seconds: Quantity | SkipJsonSchema[None] = Field(
        default=None, alias="memoryGiBSeconds", exclude_if=lambda value: value is None
    )
    wall_seconds: Quantity | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    storage_byte_seconds: Quantity | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    transfer_bytes: SafeInteger | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    provider_request_ids: Annotated[tuple[ScalarString, ...], BeforeValidator(_json_array)]
    cost_status: CostStatus
    cost_usd: Money | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    tariff_ref: Ref

    @model_validator(mode="after")
    def known_cost_and_unique_requests(self) -> Self:
        if (self.cost_status == "unknown") != (self.cost_usd is None):
            raise ValueError("cost value contradicts cost status")
        if len(set(self.provider_request_ids)) != len(self.provider_request_ids):
            raise ValueError("duplicate provider request identity")
        return self


class BudgetEvent(WireModel):
    schema_version: Literal["kf.budget-event.v1"]
    project_id: Id
    run_id: Id
    reservation_id: Id
    scope: Literal["attempt", "run_storage"]
    attempt_id: Id | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    event_id: Id
    event_type: Literal["reserve", "record_usage", "settle", "release_unspent"]
    amount_usd: Money | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    cost_status: CostStatus
    evidence_ref: Ref
    created_at: Instant

    @model_validator(mode="after")
    def scoped_cost_shape(self) -> Self:
        if (self.scope == "attempt") != (self.attempt_id is not None):
            raise ValueError("attempt identity contradicts reservation scope")
        unknown_observation = self.event_type == "record_usage" and self.cost_status == "unknown"
        if unknown_observation != (self.amount_usd is None):
            raise ValueError("cost amount contradicts event status")
        if self.event_type == "reserve" and (
            self.cost_status != "estimated"
            or self.amount_usd is None
            or Decimal(self.amount_usd) <= 0
        ):
            raise ValueError("reservation requires positive estimate")
        if self.event_type in {"settle", "release_unspent"} and self.cost_status != "actual":
            raise ValueError("final accounting requires actual evidence")
        if self.evidence_ref.project_id != self.project_id:
            raise ValueError("cross-project accounting evidence")
        return self


class BillingAdjustment(WireModel):
    schema_version: Literal["kf.billing-adjustment.v1"]
    project_id: Id
    run_id: Id
    reservation_id: Id
    adjustment_id: Id
    settlement_event_id: Id
    expected_prior_actual_usd: Money
    revised_actual_usd: Money
    evidence_ref: Ref
    created_at: Instant

    @model_validator(mode="after")
    def evidence_project(self) -> Self:
        if self.evidence_ref.project_id != self.project_id:
            raise ValueError("cross-project billing evidence")
        return self


class OperationResultRecord(WireModel):
    schema_version: Literal["kf.operation-result-record.v1"]
    project_id: Id
    operation_key: Digest
    event_id: Id
    previous_event_id: Id | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    attempt_id: Id
    result_ref: Ref
    comparison_digest: Digest
    outcome: Literal["selected", "equivalent", "conflict"]
    selected_result_ref: Ref
    evidence_ref: Ref
    recorded_at: Instant

    @model_validator(mode="after")
    def initial_and_following_selection(self) -> Self:
        if any(
            reference.project_id != self.project_id
            for reference in (self.result_ref, self.selected_result_ref, self.evidence_ref)
        ):
            raise ValueError("cross-project operation evidence")
        if (self.previous_event_id is None) != (self.outcome == "selected"):
            raise ValueError("only initial operation record selects result")
        if self.outcome == "selected" and self.selected_result_ref != self.result_ref:
            raise ValueError("initial selection differs from recorded result")
        if self.previous_event_id == self.event_id:
            raise ValueError("operation event cannot follow itself")
        if any(
            reference.artifact_schema != "kf.result.v1"
            for reference in (self.result_ref, self.selected_result_ref)
        ):
            raise ValueError("operation selection requires result manifests")
        return self


class ItemOutcome(WireModel):
    asset_id: Id
    status: Literal[
        "blocked", "pending", "running", "needs_review", "accepted", "failed", "withdrawn"
    ]
    revision_ref: Ref | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    reasons: Annotated[tuple[Reason, ...], BeforeValidator(_json_array)]

    @model_validator(mode="after")
    def accepted_revision(self) -> Self:
        if self.status == "accepted" and self.revision_ref is None:
            raise ValueError("accepted outcome requires revision")
        if self.revision_ref is not None and (
            self.revision_ref.artifact_schema != "kf.document-revision.v1"
        ):
            raise ValueError("invalid revision reference schema")
        return self


class CostSummary(WireModel):
    settled_actual_usd: Money
    reserved_outstanding_usd: Money
    estimated_usd: Money
    has_unknown_cost: bool


class RunReport(WireModel):
    schema_version: Literal["kf.run-report.v1"]
    project_id: Id
    run_id: Id
    batch_id: Id
    admission_report_ref: Ref
    attempts: Annotated[tuple[Ref, ...], BeforeValidator(_json_array)]
    item_outcomes: Annotated[tuple[ItemOutcome, ...], BeforeValidator(_json_array)]
    cost_summary: CostSummary
    report_at: Instant

    @model_validator(mode="after")
    def unique_outcomes_and_project(self) -> Self:
        if len({item.asset_id for item in self.item_outcomes}) != len(self.item_outcomes):
            raise ValueError("duplicate item outcome")
        references = (
            self.admission_report_ref,
            *self.attempts,
            *(item.revision_ref for item in self.item_outcomes if item.revision_ref is not None),
        )
        if any(reference.project_id != self.project_id for reference in references):
            raise ValueError("cross-project run evidence")
        return self

    def validate_manifest(
        self, manifest: IntakeManifest, admission: AdmissionReport, pinned_policy: PolicyArtifact
    ) -> None:
        """Check complete denominators using pinned historical admission context.

        Custody must independently verify raw manifest/report/reference bytes;
        the ledger must attest outcome, attempt and cost evidence. This method
        does not make self-reported outcomes authoritative or grant access.
        """
        admission.validate_manifest(manifest, pinned_policy)
        if (self.project_id, self.batch_id) != (manifest.project_id, manifest.batch_id):
            raise ContractError("invalid_schema")
        if {item.asset_id for item in self.item_outcomes} != {
            item.asset_id for item in manifest.items
        }:
            raise ContractError("invalid_schema")
