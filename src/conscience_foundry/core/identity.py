"""Pure F1 logical identity projections; verified artifact origin is caller-owned."""

from __future__ import annotations

import json
from dataclasses import dataclass

from pydantic import TypeAdapter, ValidationError

from conscience_foundry.contracts.canonical import Section
from conscience_foundry.contracts.codec import hash_jcs
from conscience_foundry.contracts.common import (
    MAX_SAFE_INTEGER,
    ContractError,
    ContractLimits,
    Digest,
    Id,
    ScalarString,
    Version,
)

_ID = TypeAdapter(Id)
_DIGEST = TypeAdapter(Digest)
_VERSION = TypeAdapter(Version)
_SCALAR = TypeAdapter(ScalarString)


@dataclass(frozen=True, slots=True)
class F1Operation:
    project_id: Id
    asset_id: Id
    source_id: Id
    input_digests: tuple[Digest, ...]
    extraction_spec_digest: Digest
    profile_id: str
    profile_version: Version
    policy_digest: Digest
    contract_set_digest: Digest
    limits_digests: tuple[Digest, ...]


@dataclass(frozen=True, slots=True)
class RevisionInputs:
    project_id: Id
    source_id: Id
    original_digest: Digest
    text_digest: Digest
    extraction_spec_digest: Digest
    structure_digest: Digest
    origin_map_digest: Digest


def _limits(limits: ContractLimits) -> None:
    if not isinstance(limits, ContractLimits):
        raise ContractError("limits_missing")


def _string(value: str, adapter: TypeAdapter[str], limits: ContractLimits) -> str:
    if type(value) is not str:
        raise ContractError("invalid_schema")
    if len(value) > limits.max_string_scalars:
        raise ContractError("limit_exceeded")
    try:
        return adapter.validate_python(value)
    except ValidationError:
        raise ContractError("invalid_schema") from None


def _digest_array(values: tuple[Digest, ...], limits: ContractLimits) -> list[str]:
    if type(values) is not tuple:
        raise ContractError("invalid_schema")
    if len(values) > limits.max_array_items:
        raise ContractError("limit_exceeded")
    if not values:
        raise ContractError("invalid_schema")
    return [_string(value, _DIGEST, limits) for value in values]


def _bounded_hash(domain: str, value: object, limits: ContractLimits) -> Digest:
    """Bound this internal finite JSON projection before canonicalization/hashing."""
    _limits(limits)
    pending = [(value, 0)]
    while pending:
        item, parent_depth = pending.pop()
        if type(item) is dict:
            depth = parent_depth + 1
            if depth > limits.max_depth:
                raise ContractError("limit_exceeded")
            for key, child in item.items():
                pending.append((key, depth))
                pending.append((child, depth))
        elif type(item) is list:
            depth = parent_depth + 1
            if depth > limits.max_depth or len(item) > limits.max_array_items:
                raise ContractError("limit_exceeded")
            pending.extend((child, depth) for child in item)
        elif type(item) is str:
            _string(item, _SCALAR, limits)
        elif type(item) is int:
            if not 0 <= item <= MAX_SAFE_INTEGER:
                raise ContractError("invalid_schema")
        else:
            raise ContractError("invalid_schema")
    size = 0
    try:
        for piece in json.JSONEncoder(
            ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).iterencode(value):
            size += len(piece.encode("utf-8"))
            if size > min(limits.max_json_bytes, limits.max_output_bytes):
                raise ContractError("limit_exceeded")
    except (UnicodeError, TypeError, ValueError) as error:
        if isinstance(error, ContractError):
            raise error from None
        raise ContractError("invalid_schema") from None
    return hash_jcs(domain, value)


def operation_key(projection: F1Operation, *, limits: ContractLimits) -> Digest:
    """Hash only F1 extraction pins; no attempt, time, location or budget identity."""
    _limits(limits)
    if type(projection) is not F1Operation:
        raise ContractError("invalid_schema")
    inputs = _digest_array(projection.input_digests, limits)
    if len(inputs) != 1:
        raise ContractError("invalid_schema")
    pinned_limits = sorted(set(_digest_array(projection.limits_digests, limits)))
    return _bounded_hash("kf.operation.v1", {
        "projectId": _string(projection.project_id, _ID, limits),
        "assetId": _string(projection.asset_id, _ID, limits),
        "sourceId": _string(projection.source_id, _ID, limits),
        "inputDigests": inputs,
        "extractionSpecDigest": _string(projection.extraction_spec_digest, _DIGEST, limits),
        "profileId": _string(projection.profile_id, _VERSION, limits),
        "profileVersion": _string(projection.profile_version, _VERSION, limits),
        "policyDigest": _string(projection.policy_digest, _DIGEST, limits),
        "contractSetDigest": _string(projection.contract_set_digest, _DIGEST, limits),
        "limitsDigests": pinned_limits,
    }, limits)


def revision_id(projected_inputs: RevisionInputs, *, limits: ContractLimits) -> Digest:
    """Hash the exact C04 content/source recipe, not a serialized revision wrapper."""
    _limits(limits)
    if type(projected_inputs) is not RevisionInputs:
        raise ContractError("invalid_schema")
    return _bounded_hash("kf.revision.v1", {
        "projectId": _string(projected_inputs.project_id, _ID, limits),
        "sourceId": _string(projected_inputs.source_id, _ID, limits),
        "originalDigest": _string(projected_inputs.original_digest, _DIGEST, limits),
        "textDigest": _string(projected_inputs.text_digest, _DIGEST, limits),
        "extractionSpecDigest": _string(projected_inputs.extraction_spec_digest, _DIGEST, limits),
        "structureDigest": _string(projected_inputs.structure_digest, _DIGEST, limits),
        "originMapDigest": _string(projected_inputs.origin_map_digest, _DIGEST, limits),
    }, limits)


def structure_digest(sections: tuple[Section, ...], *, limits: ContractLimits) -> Digest:
    """Preserve ordered sections; canonical revision context validates tree/text bounds."""
    _limits(limits)
    if type(sections) is not tuple:
        raise ContractError("invalid_schema")
    if len(sections) > limits.max_array_items:
        raise ContractError("limit_exceeded")
    projection: list[dict[str, object]] = []
    for section in sections:
        if type(section) is not Section:
            raise ContractError("invalid_schema")
        value: dict[str, object] = {
            "sectionId": _string(section.section_id, _VERSION, limits),
            "start": section.start, "end": section.end,
        }
        if section.parent_section_id is not None:
            value["parentSectionId"] = _string(section.parent_section_id, _VERSION, limits)
        if section.heading is not None:
            value["heading"] = _string(section.heading, _SCALAR, limits)
        try:
            Section.model_validate(value)
        except ValidationError:
            raise ContractError("invalid_schema") from None
        projection.append(value)
    return _bounded_hash("kf.structure.v1", projection, limits)
