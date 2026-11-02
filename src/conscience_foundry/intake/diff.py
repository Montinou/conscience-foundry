"""Effective state of a source set and the classification of a curated batch against it.

The state is rebuilt by replaying earlier batches in order with the same classification used for
the batch being built: per `sourceKey` the current asset (its identity, the batch key it now
sits under and `admitted_batch_id`, the id of the batch whose intake carried it) and the set of
withdrawn assets with the `admitted_batch_id` they were withdrawn under. Pure functions over
frozen records: no I/O, no clock, no ledger.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType

from conscience_foundry.contracts.common import ContractError, Digest, Id
from conscience_foundry.contracts.intake import CuratedBatch, CuratedItem
from conscience_foundry.intake.identity import asset_id, batch_id, source_id


@dataclass(frozen=True)
class CurrentAsset:
    asset_id: Id
    source_id: Id
    batch_key: str
    admitted_batch_id: Id


def _frozen(mapping: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType(dict(mapping))


@dataclass(frozen=True)
class EffectiveState:
    """`current` by source key; `withdrawn` maps an asset id to its `admitted_batch_id`."""

    current: Mapping[str, CurrentAsset]
    withdrawn: Mapping[Id, Id]

    def __post_init__(self) -> None:
        object.__setattr__(self, "current", _frozen(self.current))
        object.__setattr__(self, "withdrawn", _frozen(self.withdrawn))


@dataclass(frozen=True)
class Classification:
    """Source keys per class, each in sorted order; `missing_assets` follows `missing`.

    `displaced` maps a `returned` key to the different asset that was current for it: the asset
    returning is not re-admitted, and the one standing in its place is withdrawn.
    """

    new: tuple[str, ...]
    unchanged: tuple[str, ...]
    changed: tuple[str, ...]
    moved: tuple[str, ...]
    returned: tuple[str, ...]
    missing: tuple[str, ...]
    predecessors: Mapping[str, CurrentAsset] = field(default_factory=dict)
    missing_assets: tuple[CurrentAsset, ...] = ()
    displaced: Mapping[str, CurrentAsset] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "predecessors", _frozen(self.predecessors))
        object.__setattr__(self, "displaced", _frozen(self.displaced))


def asset_of(batch: CuratedBatch, item: CuratedItem) -> Id:
    """The asset identity of `item` under `batch`: its source, bytes and `identityFields` values."""
    identity = {name: item.metadata[name] for name in batch.identity_fields}
    return asset_id(batch.project_id, item.source_key, item.sha256, identity)


def classify(state: EffectiveState, batch: CuratedBatch, batch_id: Id) -> Classification:
    """Classify each item of `batch`, and each source it leaves behind, against `state`.

    `batch_id` is accepted for symmetry with `apply`; classification itself never depends on it.
    """
    del batch_id
    new: list[str] = []
    unchanged: list[str] = []
    changed: list[str] = []
    moved: list[str] = []
    returned: list[str] = []
    predecessors: dict[str, CurrentAsset] = {}
    displaced: dict[str, CurrentAsset] = {}
    for item in batch.items:
        key = item.source_key
        asset = asset_of(batch, item)
        current = state.current.get(key)
        if current is not None and current.asset_id == asset:
            (unchanged if current.batch_key == batch.batch_key else moved).append(key)
        elif asset in state.withdrawn:
            returned.append(key)
            if current is not None:
                # Final-review ruling: a withdrawn asset coming back over a different current
                # one (x, x', x) is not re-admitted, and the unapproved x' is withdrawn.
                displaced[key] = current
        elif current is not None:
            changed.append(key)
            predecessors[key] = current
        else:
            # Ruling (task 7, fix 1): no current asset and an asset id never withdrawn is `new`,
            # even for a key seen before (e.g. withdrawn as missing, back with other bytes).
            # U5 defines `returned` only for the exact withdrawn asset id and the state keeps
            # no seen-keys record; a different asset id is a distinct asset, so admitting it
            # is ledger-safe and refusing it would block the key for good.
            new.append(key)
    present = {item.source_key for item in batch.items}
    missing = sorted(
        key
        for key, current in state.current.items()
        if current.batch_key == batch.batch_key and key not in present
    )
    return Classification(
        new=tuple(sorted(new)),
        unchanged=tuple(sorted(unchanged)),
        changed=tuple(sorted(changed)),
        moved=tuple(sorted(moved)),
        returned=tuple(sorted(returned)),
        missing=tuple(missing),
        predecessors={key: predecessors[key] for key in sorted(predecessors)},
        missing_assets=tuple(state.current[key] for key in missing),
        displaced={key: displaced[key] for key in sorted(displaced)},
    )


def apply(
    state: EffectiveState, batch: CuratedBatch, batch_id: Id, classification: Classification
) -> EffectiveState:
    """The state after `batch` is applied: `new`/`changed` become current under `batch_id`.

    A `displaced` asset is withdrawn and stops being current; `missing` ones likewise.
    """
    current = dict(state.current)
    withdrawn = dict(state.withdrawn)
    items = {item.source_key: item for item in batch.items}
    for key in (*classification.new, *classification.changed):
        if key in classification.predecessors:
            before = classification.predecessors[key]
            withdrawn[before.asset_id] = before.admitted_batch_id
        current[key] = CurrentAsset(
            asset_id=asset_of(batch, items[key]),
            source_id=source_id(batch.project_id, key),
            batch_key=batch.batch_key,
            admitted_batch_id=batch_id,
        )
    for key in classification.moved:
        before = current[key]
        current[key] = CurrentAsset(
            asset_id=before.asset_id,
            source_id=before.source_id,
            batch_key=batch.batch_key,
            admitted_batch_id=before.admitted_batch_id,
        )
    for key, asset in classification.displaced.items():
        withdrawn[asset.asset_id] = asset.admitted_batch_id
        del current[key]
    for asset in classification.missing_assets:
        withdrawn[asset.asset_id] = asset.admitted_batch_id
    for key in classification.missing:
        del current[key]
    return EffectiveState(current=current, withdrawn=withdrawn)


def replay(project_id: Id, previous: Sequence[tuple[CuratedBatch, Digest]]) -> EffectiveState:
    """Replay earlier batches from an empty state, ordered by `createdAt` then batch digest.

    Input order never matters. The same digest twice is a `determinism_conflict`; a batch of
    another project is `invalid_schema`.
    """
    digests = [digest for _, digest in previous]
    if len(digests) != len(set(digests)):
        raise ContractError("determinism_conflict")
    if any(batch.project_id != project_id for batch, _ in previous):
        raise ContractError("invalid_schema")
    state = EffectiveState(current={}, withdrawn={})
    for batch, digest in sorted(previous, key=lambda pair: (pair[0].created_at, pair[1])):
        ident = batch_id(project_id, batch.batch_key, digest)
        state = apply(state, batch, ident, classify(state, batch, ident))
    return state
