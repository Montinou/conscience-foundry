"""Bring a worker's staged result into the local store, so acceptance only ever reads local bytes.

The import walks the same edges as `verify_result` in `ledger/acceptance.py`: the result manifest,
each nominated output, and every content edge below those. Every object is hash-verified on the
way in, children are stored before their parents and the manifest is stored last, so a manifest
present in the local store always has its whole closure beside it. Nothing here trusts a
reference's ``locations``, writes to the staging side, or decides acceptance.
"""

from __future__ import annotations

import hashlib
import io
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

from conscience_foundry.contracts.common import ContractError, ContractLimits, Ref
from conscience_foundry.contracts.execution import ResultManifest
from conscience_foundry.contracts.registry import validate_artifact
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.release.edges import edge_roles
from conscience_foundry.storage.local import ObjectStore

ImportOutcome = Literal["imported", "already_present"]
"""``already_present`` means every object was already local, so nothing was fetched or written."""

_MANIFEST_SCHEMA = "cf.result.v1"


def _limits(limits_by_schema: Mapping[str, ContractLimits], schema: str) -> ContractLimits:
    value = limits_by_schema.get(schema)
    if type(value) is not ContractLimits:
        raise ContractError("limits_missing")
    return value


def _ceiling(limits_by_schema: Mapping[str, ContractLimits], ref: Ref) -> int:
    bound = _limits(limits_by_schema, ref.artifact_schema)
    if ref.artifact_schema == "cf.raw-original.v1":
        return bound.max_source_bytes
    return min(bound.max_output_bytes, bound.max_json_bytes)


@dataclass
class _Import:
    reader: ObjectStore = field(repr=False)
    local: ObjectStore = field(repr=False)
    context: AccessContext
    limits_by_schema: Mapping[str, ContractLimits] = field(repr=False)
    budget: int
    items: int
    seen: set[tuple[object, ...]] = field(default_factory=set)
    active: set[tuple[object, ...]] = field(default_factory=set)
    fetched: int = 0
    wrote: bool = False

    def fetch(self, ref: Ref) -> tuple[bytes, bool]:
        """Bytes of one object, verified: the local copy when there is one, else the reader's."""
        if type(ref) is not Ref or ref.project_id != self.context.project_id:
            raise ContractError("forbidden")
        ceiling = _ceiling(self.limits_by_schema, ref)
        present = True
        try:
            value = self.local.read_verified(ref, self.context, ceiling)
        except ContractError as error:
            if error.code != "artifact_missing":
                raise
            present = False
            self.fetched += ref.size_bytes
            if self.fetched > self.budget:
                raise ContractError("limit_exceeded") from None
            value = self.reader.read_verified(ref, self.context, ceiling)
        data = value.data
        if (
            type(data) is not bytes
            or len(data) != ref.size_bytes
            or hashlib.sha256(data).hexdigest() != ref.digest
            or value.digest != ref.digest
        ):
            raise ContractError("hash_mismatch")
        return data, present

    def store(self, ref: Ref, data: bytes, present: bool) -> None:
        if not present:
            self.local.put_verified(io.BytesIO(data), ref, self.context)
            self.wrote = True

    def visit(self, ref: Ref) -> None:
        key = (ref.project_id, ref.artifact_schema, ref.digest, ref.size_bytes, ref.media_type)
        if key in self.active:
            raise ContractError("result_incomplete")
        if key in self.seen:
            return
        if len(self.seen) >= self.items:
            raise ContractError("limit_exceeded")
        data, present = self.fetch(ref)
        value = validate_artifact(ref, data, limits_by_schema=self.limits_by_schema)
        self.active.add(key)
        for edge in edge_roles(ref.artifact_schema, value):
            if edge.role == "content":
                self.visit(edge.ref)
        self.active.remove(key)
        self.seen.add(key)
        self.store(ref, data, present)  # after every child, so a parent never outruns them


def import_staged_result(
    reader: ObjectStore,
    local: ObjectStore,
    manifest: Ref,
    context: AccessContext,
    *,
    limits_by_schema: Mapping[str, ContractLimits],
) -> ImportOutcome:
    """Copy the result manifest and everything it reaches from ``reader`` into ``local``.

    ``reader`` is the attempt-scoped read-only view of the staging destination; it alone decides
    what may be read, and a refusal there surfaces unchanged as its ``ContractError`` code. Any
    object that cannot be proven by hash, bound or schema stops the import with an error; objects
    already copied stay (they are content-addressed and harmless) but the manifest does not.
    """
    if type(manifest) is not Ref or manifest.artifact_schema != _MANIFEST_SCHEMA:
        raise ContractError("unsupported_schema")
    bound = _limits(limits_by_schema, _MANIFEST_SCHEMA)
    walk = _Import(
        reader,
        local,
        context,
        limits_by_schema,
        budget=bound.max_output_bytes,
        items=bound.max_array_items,
    )
    data, present = walk.fetch(manifest)
    result = validate_artifact(manifest, data, limits_by_schema=limits_by_schema)
    if type(result) is not ResultManifest:
        raise ContractError("unsupported_schema")
    if len(result.outputs) > bound.max_array_items:
        raise ContractError("limit_exceeded")
    for output in result.outputs:
        walk.visit(output)
    walk.store(manifest, data, present)
    return "imported" if walk.wrote else "already_present"
