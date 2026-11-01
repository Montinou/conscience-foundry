"""Withdrawal list and intake diff report: bounded records of how a batch relates to its history.

Neither record carries a reference to another artifact. The diff names sources by `sourceKey` only;
the withdrawal list is addressed by the digest of the batch that produced it, never the other way
round, so the diff holds no digest of the list.
"""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, Field, model_validator
from pydantic.json_schema import SkipJsonSchema

from conscience_foundry.contracts.common import Digest, Id, Reason, ScalarString, WireModel

Cause = Literal["changed", "missing"]
_REASON_CODE = {"changed": "source_changed", "missing": "source_missing"}
SourceKey = Annotated[ScalarString, Field(min_length=1)]


def _array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class WithdrawalEntry(WireModel):
    batch_id: Id
    asset_id: Id
    source_id: Id
    cause: Cause
    decision_id: Id
    reason: Reason

    @model_validator(mode="after")
    def reason_matches_cause(self) -> Self:
        if self.reason.code != _REASON_CODE[self.cause]:
            raise ValueError("reason code does not match cause")
        return self


class WithdrawalList(WireModel):
    schema_version: Literal["cf.withdrawal-list.v1"]
    project_id: Id
    by_batch_digest: Digest
    diff_report_digest: Digest
    entries: Annotated[tuple[WithdrawalEntry, ...], BeforeValidator(_array), Field(min_length=1)]

    @model_validator(mode="after")
    def unique_decisions(self) -> Self:
        decisions = [entry.decision_id for entry in self.entries]
        if len(decisions) != len(set(decisions)):
            raise ValueError("duplicate decision identity")
        return self


SourceKeys = Annotated[tuple[SourceKey, ...], BeforeValidator(_array)]


class DiffClasses(WireModel):
    new: SourceKeys
    unchanged: SourceKeys
    changed: SourceKeys
    moved: SourceKeys
    returned: SourceKeys
    missing: SourceKeys


class IntakeDiff(WireModel):
    schema_version: Literal["cf.intake-diff.v1"]
    project_id: Id
    batch_key: SourceKey
    batch_digest: Digest
    previous_batch_digests: Annotated[tuple[Digest, ...], BeforeValidator(_array)]
    status: Literal["ready", "policy_revision_needed"]
    classes: DiffClasses
    assumed_admitted_batch_ids: Annotated[tuple[Id, ...], BeforeValidator(_array)]
    intake_digest: Digest | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    new_sources_digest: Digest
