"""Deterministic intake identities: UUIDv5 over RFC 8785 bytes, one domain prefix per identity.

Every id is `uuid5(INTAKE_NAMESPACE, domain + "\\n" + jcs(payload))`, so the same inputs always give
the same id and equal payloads under different domains never collide. `identity` is the item's
metadata already restricted to the batch's `identityFields`; the function hashes exactly what it
is given, so two calls differ only when the identity values differ.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal
from uuid import NAMESPACE_OID, uuid5

import rfc8785
from pydantic import TypeAdapter, ValidationError

from conscience_foundry.contracts.common import (
    ContractError,
    Digest,
    Id,
    ScalarString,
    validate_wire_value,
)

INTAKE_NAMESPACE = uuid5(NAMESPACE_OID, "cf.intake-identity.v1")

_SOURCE = "cf.intake-source.v1"
_ASSET = "cf.intake-asset.v1"
_BATCH = "cf.intake-batch.v1"
_WITHDRAWAL = "cf.intake-withdrawal.v1"

_ID = TypeAdapter(Id)
_DIGEST = TypeAdapter(Digest)
_TEXT = TypeAdapter(ScalarString)


def _plain(value: object) -> object:
    """Frozen admitted metadata (mappings and tuples) as the plain JSON it stands for."""
    if isinstance(value, Mapping):
        return {key: _plain(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(child) for child in value]
    return value


def _uuid(domain: str, payload: dict[str, object]) -> Id:
    try:
        plain = _plain(payload)
        validate_wire_value(plain, allow_negative=True)
        canonical = rfc8785.dumps(plain)  # type: ignore[arg-type]
        return str(uuid5(INTAKE_NAMESPACE, domain + "\n" + canonical.decode("utf-8")))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ContractError("invalid_schema") from None


def _checked(adapter: TypeAdapter[str], *values: object) -> None:
    try:
        for value in values:
            adapter.validate_python(value)
    except ValidationError:
        raise ContractError("invalid_schema") from None


def source_id(project_id: Id, source_key: str) -> Id:
    _checked(_ID, project_id)
    _checked(_TEXT, source_key)
    return _uuid(_SOURCE, {"projectId": project_id, "sourceKey": source_key})


def asset_id(project_id: Id, source_key: str, sha256: Digest, identity: Mapping[str, object]) -> Id:
    _checked(_ID, project_id)
    _checked(_TEXT, source_key)
    _checked(_DIGEST, sha256)
    if not isinstance(identity, Mapping):
        raise ContractError("invalid_schema")
    return _uuid(
        _ASSET,
        {"projectId": project_id, "sourceKey": source_key, "sha256": sha256, "identity": identity},
    )


def batch_id(project_id: Id, batch_key: str, batch_digest: Digest) -> Id:
    _checked(_ID, project_id)
    _checked(_TEXT, batch_key)
    _checked(_DIGEST, batch_digest)
    return _uuid(
        _BATCH, {"projectId": project_id, "batchKey": batch_key, "batchDigest": batch_digest}
    )


def decision_id(
    project_id: Id,
    batch_id: Id,
    asset_id: Id,
    cause: Literal["changed", "missing"],
    by_batch_digest: Digest,
) -> Id:
    _checked(_ID, project_id, batch_id, asset_id)
    _checked(_DIGEST, by_batch_digest)
    if cause not in ("changed", "missing"):
        raise ContractError("invalid_schema")
    return _uuid(
        _WITHDRAWAL,
        {
            "projectId": project_id,
            "batchId": batch_id,
            "assetId": asset_id,
            "cause": cause,
            "byBatchDigest": by_batch_digest,
        },
    )
