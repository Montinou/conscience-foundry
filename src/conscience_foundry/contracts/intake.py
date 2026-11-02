"""Curated batch, new-sources, withdrawal list and intake diff: bounded records of a batch.

The curated batch is the neutral manifest a producer hands over for one batch key; it names files
by relative path under a custody root the operator configures, never by absolute location. None of
these records carries a reference to another artifact. The diff names sources by `sourceKey` only;
the withdrawal list is addressed by the digest of the batch that produced it, never the other way
round, so the diff holds no digest of the list.
"""

from __future__ import annotations

import unicodedata
from typing import Annotated, ClassVar, Literal, Self

from pydantic import (
    AfterValidator,
    BeforeValidator,
    Field,
    StringConstraints,
    ValidationInfo,
    model_validator,
)
from pydantic.json_schema import SkipJsonSchema

from conscience_foundry.contracts.admission import Metadata
from conscience_foundry.contracts.codec import digest_canonical_json
from conscience_foundry.contracts.common import (
    ContractLimits,
    Digest,
    Id,
    Instant,
    PositiveInteger,
    Reason,
    ScalarString,
    WireModel,
    scalar_string,
)

Cause = Literal["changed", "missing"]
_REASON_CODE = {"changed": "source_changed", "missing": "source_missing"}
SourceKey = Annotated[ScalarString, Field(min_length=1)]


def _array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def safe_relative_path(value: str) -> str:
    """A relative POSIX path in NFC: no empty, `.` or `..` segment, no leading `/`, no backslash."""
    if (
        "\\" in value
        or "\x00" in value
        or not unicodedata.is_normalized("NFC", value)
        or any(segment in {"", ".", ".."} for segment in value.split("/"))
    ):
        raise ValueError("unsafe relative path")
    return value


BatchKey = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"),
    AfterValidator(scalar_string),
]
Label = Annotated[ScalarString, Field(min_length=1, max_length=128)]
CuratedSourceKey = Annotated[ScalarString, Field(min_length=1, max_length=256)]
RelativePath = Annotated[ScalarString, AfterValidator(safe_relative_path)]


class Producer(WireModel):
    name: Label
    version: Label


class Approval(WireModel):
    actor: Label
    method: Label
    evidence_digest: Digest


class CuratedItem(WireModel):
    # A profile may bound a metadata field below zero, so a metadata value may be negative; every
    # typed integer here stays non-negative.
    signed_integers: ClassVar[bool] = True

    relative_path: RelativePath
    sha256: Digest
    size_bytes: PositiveInteger
    media_type: Literal["text/plain"]
    source_key: CuratedSourceKey
    metadata: Metadata

    @model_validator(mode="after")
    def source_limit(self, info: ValidationInfo) -> Self:
        if info.context and isinstance(info.context.get("limits"), ContractLimits):
            if self.size_bytes > info.context["limits"].max_source_bytes:
                raise ValueError("source exceeds configured bound")
        return self


class CuratedBatch(WireModel):
    # The batch is the wire root of its items' metadata; see `CuratedItem.signed_integers`.
    signed_integers: ClassVar[bool] = True

    schema_version: Literal["cf.curated-batch.v1"]
    project_id: Id
    batch_key: BatchKey
    producer: Producer
    created_at: Instant
    custody_root_label: Label
    identity_fields: Annotated[
        tuple[Label, ...], BeforeValidator(_array), Field(min_length=1, max_length=64)
    ]
    approval: Approval
    items: Annotated[tuple[CuratedItem, ...], BeforeValidator(_array), Field(min_length=1)]

    @model_validator(mode="after")
    def batch_invariants(self, info: ValidationInfo) -> Self:
        paths = [item.relative_path for item in self.items]
        keys = [item.source_key for item in self.items]
        if len(paths) != len(set(paths)):
            raise ValueError("duplicate relative path")
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate source key")
        if any(name not in item.metadata for item in self.items for name in self.identity_fields):
            raise ValueError("identity field missing from an item")
        if info.context and isinstance(info.context.get("limits"), ContractLimits):
            if len(self.items) > info.context["limits"].max_manifest_items:
                raise ValueError("batch exceeds configured bound")
        return self


def batch_digest(batch_bytes: bytes) -> Digest:
    """The batch digest: SHA-256 of the batch's RFC 8785 bytes; spacing and key order never count.

    The bytes are decoded strictly (signed integers, as a batch's metadata may hold them) but not
    validated as a `CuratedBatch`; parse them with `CuratedBatch.from_wire` first.
    """
    return digest_canonical_json(batch_bytes, signed=True)


class NewSource(WireModel):
    source_id: Id
    source_key: CuratedSourceKey


class NewSources(WireModel):
    schema_version: Literal["cf.new-sources.v1"]
    project_id: Id
    batch_digest: Digest
    sources: Annotated[tuple[NewSource, ...], BeforeValidator(_array)]

    @model_validator(mode="after")
    def unique_sources(self) -> Self:
        ids = [source.source_id for source in self.sources]
        keys = [source.source_key for source in self.sources]
        if len(ids) != len(set(ids)) or len(keys) != len(set(keys)):
            raise ValueError("duplicate source")
        return self


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
