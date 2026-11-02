"""Effective-state replay and classification of a curated batch against earlier batches."""

from __future__ import annotations

import random
from collections.abc import Mapping
from dataclasses import FrozenInstanceError

import pytest

from conscience_foundry.contracts.common import ContractError
from conscience_foundry.contracts.intake import CuratedBatch
from conscience_foundry.intake.diff import (
    Classification,
    CurrentAsset,
    EffectiveState,
    apply,
    classify,
    replay,
)
from conscience_foundry.intake.identity import asset_id, batch_id, source_id

PROJECT = "00000000-0000-4000-8000-000000000001"
EMPTY = EffectiveState(current={}, withdrawn={})


def entry(sha: str, lang: str = "en", note: str = "n") -> tuple[str, str, str]:
    return (sha * 64, lang, note)


def make(
    batch_key: str, items: Mapping[str, tuple[str, str, str]], created: int = 1
) -> CuratedBatch:
    """A synthetic batch: identity fields are `lang`; `note` is provenance only."""
    return CuratedBatch.model_validate(
        {
            "schemaVersion": "cf.curated-batch.v1",
            "projectId": PROJECT,
            "batchKey": batch_key,
            "producer": {"name": "synthetic-producer", "version": "1.0.0"},
            "createdAt": f"2026-01-02T03:04:{created:02d}.000Z",
            "custodyRootLabel": "library-root",
            "identityFields": ["lang"],
            "approval": {
                "actor": "auditor:synthetic",
                "method": "audit",
                "evidenceDigest": "c" * 64,
            },
            "items": [
                {
                    "relativePath": f"shelf/{key}.txt",
                    "sha256": sha,
                    "sizeBytes": 10,
                    "mediaType": "text/plain",
                    "sourceKey": key,
                    "metadata": {"lang": lang, "note": note, "rank": -1},
                }
                for key, (sha, lang, note) in items.items()
            ],
        },
        by_alias=True,
    )


def digest(label: str) -> str:
    return (label * 64)[:64]


def bid(batch: CuratedBatch, dig: str) -> str:
    return batch_id(PROJECT, batch.batch_key, dig)


def aid(key: str, sha: str, lang: str = "en") -> str:
    return asset_id(PROJECT, key, sha * 64, {"lang": lang})


def step(
    state: EffectiveState, batch: CuratedBatch, dig: str
) -> tuple[EffectiveState, Classification]:
    batch_ident = bid(batch, dig)
    classification = classify(state, batch, batch_ident)
    return apply(state, batch, batch_ident, classification), classification


def test_new_unchanged_changed_classes() -> None:
    first = make("k1", {"a": entry("1"), "b": entry("2"), "c": entry("3"), "d": entry("4")})
    state, one = step(EMPTY, first, digest("a"))
    assert one.new == ("a", "b", "c", "d")
    assert one.unchanged == one.changed == one.moved == one.returned == one.missing == ()

    second = make(
        "k1",
        {
            "a": entry("1"),  # unchanged
            "b": entry("9"),  # bytes changed
            "c": entry("3", lang="fr"),  # identity field changed
            "d": entry("4"),
            "e": entry("5"),  # new
        },
        created=2,
    )
    state, two = step(state, second, digest("b"))
    assert two.new == ("e",)
    assert two.unchanged == ("a", "d")
    assert two.changed == ("b", "c")
    assert two.missing == ()
    assert two.predecessors["b"].asset_id == aid("b", "2")
    assert two.predecessors["c"].asset_id == aid("c", "3")
    assert two.predecessors["b"].admitted_batch_id == bid(first, digest("a"))
    assert state.current["b"].asset_id == aid("b", "9")
    assert state.current["b"].admitted_batch_id == bid(second, digest("b"))
    assert state.current["a"].admitted_batch_id == bid(first, digest("a"))
    assert state.withdrawn == {
        aid("b", "2"): bid(first, digest("a")),
        aid("c", "3"): bid(first, digest("a")),
    }


def test_provenance_only_change_is_unchanged() -> None:
    state, _ = step(EMPTY, make("k1", {"a": entry("1", note="x")}), digest("a"))
    _, result = step(state, make("k1", {"a": entry("1", note="y")}, created=2), digest("b"))
    assert result.unchanged == ("a",)
    assert result.changed == ()


def test_other_batch_key_does_not_make_files_missing() -> None:
    state, _ = step(EMPTY, make("k1", {"a": entry("1"), "b": entry("2")}), digest("a"))
    _, result = step(state, make("k2", {"c": entry("3")}, created=2), digest("b"))
    assert result.missing == ()
    assert result.new == ("c",)
    assert result.missing_assets == ()


def test_missing_only_for_the_same_batch_key() -> None:
    state, _ = step(EMPTY, make("k1", {"a": entry("1"), "b": entry("2")}), digest("a"))
    _, result = step(state, make("k1", {"a": entry("1")}, created=2), digest("b"))
    assert result.missing == ("b",)
    assert [asset.asset_id for asset in result.missing_assets] == [aid("b", "2")]
    assert result.missing_assets[0].source_id == source_id(PROJECT, "b")


def test_moved_same_asset_keeps_admitted_batch() -> None:
    first = make("k1", {"a": entry("1")})
    state, _ = step(EMPTY, first, digest("a"))
    state, result = step(state, make("k2", {"a": entry("1")}, created=2), digest("b"))
    assert result.moved == ("a",)
    assert result.new == result.changed == result.unchanged == ()
    assert state.current["a"].batch_key == "k2"
    assert state.current["a"].admitted_batch_id == bid(first, digest("a"))
    assert state.withdrawn == {}


def test_moved_and_changed_is_changed() -> None:
    first = make("k1", {"a": entry("1")})
    state, _ = step(EMPTY, first, digest("a"))
    second = make("k2", {"a": entry("9")}, created=2)
    state, result = step(state, second, digest("b"))
    assert result.changed == ("a",)
    assert result.moved == ()
    assert result.predecessors["a"].batch_key == "k1"
    assert state.current["a"].batch_key == "k2"
    assert state.current["a"].admitted_batch_id == bid(second, digest("b"))
    assert state.withdrawn == {aid("a", "1"): bid(first, digest("a"))}


def test_unchanged_then_missing_withdrawn_under_original_batch() -> None:
    first = make("k1", {"a": entry("1"), "b": entry("2")})
    state, _ = step(EMPTY, first, digest("a"))
    state, _ = step(state, make("k1", {"a": entry("1"), "b": entry("2")}, 2), digest("b"))
    state, result = step(state, make("k1", {"a": entry("1")}, created=3), digest("c"))
    assert result.missing == ("b",)
    assert result.missing_assets[0].admitted_batch_id == bid(first, digest("a"))
    assert "b" not in state.current
    assert state.withdrawn == {aid("b", "2"): bid(first, digest("a"))}


def test_moved_then_missing_withdrawn_under_original_batch() -> None:
    first = make("k1", {"a": entry("1")})
    state, _ = step(EMPTY, first, digest("a"))
    state, _ = step(state, make("k2", {"a": entry("1")}, created=2), digest("b"))
    state, result = step(state, make("k2", {"z": entry("7")}, created=3), digest("c"))
    assert result.missing == ("a",)
    assert result.missing_assets[0].admitted_batch_id == bid(first, digest("a"))
    assert state.withdrawn == {aid("a", "1"): bid(first, digest("a"))}


def test_returned_after_missing_is_reported_not_admitted() -> None:
    first = make("k1", {"a": entry("1"), "b": entry("2")})
    state, _ = step(EMPTY, first, digest("a"))
    state, _ = step(state, make("k1", {"a": entry("1")}, created=2), digest("b"))
    before = state
    state, result = step(
        state, make("k1", {"a": entry("1"), "b": entry("2")}, created=3), digest("c")
    )
    assert result.returned == ("b",)
    assert result.new == ()
    assert "b" not in state.current
    assert state.withdrawn == before.withdrawn
    assert state.current == before.current


def test_returned_after_change_back_x_xprime_x() -> None:
    first = make("k1", {"a": entry("1")})
    state, _ = step(EMPTY, first, digest("a"))
    second = make("k1", {"a": entry("9")}, created=2)
    state, _ = step(state, second, digest("b"))
    state, result = step(state, make("k1", {"a": entry("1")}, created=3), digest("c"))
    assert result.returned == ("a",)
    assert result.changed == ()
    assert state.current["a"].asset_id == aid("a", "9")
    assert state.current["a"].admitted_batch_id == bid(second, digest("b"))
    assert state.withdrawn == {aid("a", "1"): bid(first, digest("a"))}


def test_missing_then_returned_with_changed_bytes_is_new() -> None:
    """Pins the controller ruling: a key seen before, back as a different asset, is `new`."""
    first = make("k1", {"a": entry("1"), "b": entry("2")})
    state, _ = step(EMPTY, first, digest("a"))
    state, one = step(state, make("k1", {"b": entry("2")}, created=2), digest("b"))
    assert one.missing == ("a",)
    assert "a" not in state.current
    assert state.withdrawn == {aid("a", "1"): bid(first, digest("a"))}

    third = make("k1", {"a": entry("9"), "b": entry("2")}, created=3)
    state, result = step(state, third, digest("c"))
    assert result.new == ("a",)
    assert "a" not in result.returned
    assert result.changed == ()
    assert result.unchanged == ("b",)
    assert state.current["a"].asset_id == aid("a", "9")
    assert state.current["a"].admitted_batch_id == bid(third, digest("c"))
    assert state.withdrawn == {aid("a", "1"): bid(first, digest("a"))}


def test_missing_across_two_reexports_withdrawn_once() -> None:
    first = make("k1", {"a": entry("1"), "b": entry("2")})
    state, _ = step(EMPTY, first, digest("a"))
    state, one = step(state, make("k1", {"a": entry("1")}, created=2), digest("b"))
    state, two = step(state, make("k1", {"a": entry("1")}, created=3), digest("c"))
    assert one.missing == ("b",)
    assert two.missing == ()
    assert two.missing_assets == ()
    assert state.withdrawn == {aid("b", "2"): bid(first, digest("a"))}


def test_apply_with_nothing_admitted_contributes_no_admitted_batch() -> None:
    first = make("k1", {"a": entry("1")})
    state, _ = step(EMPTY, first, digest("a"))
    state, _ = step(state, make("k1", {"a": entry("1")}, created=2), digest("b"))
    assert {asset.admitted_batch_id for asset in state.current.values()} == {
        bid(first, digest("a"))
    }


def test_replay_matches_stepwise_application() -> None:
    batches = [
        (make("k1", {"a": entry("1"), "b": entry("2")}, 1), digest("a")),
        (make("k1", {"a": entry("9")}, 2), digest("b")),
        (make("k2", {"c": entry("3")}, 3), digest("c")),
    ]
    state = EMPTY
    for batch, dig in batches:
        state, _ = step(state, batch, dig)
    assert replay(PROJECT, batches) == state


def test_replay_order_is_deterministic() -> None:
    batches = [
        (make("k1", {"a": entry("1"), "b": entry("2")}, 1), digest("a")),
        (make("k1", {"a": entry("9"), "b": entry("2")}, 2), digest("b")),
        (make("k2", {"b": entry("2"), "c": entry("3")}, 2), digest("c")),
        (make("k1", {"a": entry("9")}, 4), digest("d")),
    ]
    expected = replay(PROJECT, batches)
    rng = random.Random(7)
    for _ in range(6):
        shuffled = batches[:]
        rng.shuffle(shuffled)
        assert replay(PROJECT, shuffled) == expected


def test_replay_ties_on_created_at_break_by_digest() -> None:
    low = (make("k1", {"a": entry("1")}, 5), digest("1"))
    high = (make("k1", {"a": entry("9")}, 5), digest("2"))
    state = replay(PROJECT, [high, low])
    assert state.current["a"].asset_id == aid("a", "9")
    assert state.withdrawn == {aid("a", "1"): bid(low[0], low[1])}


def test_replay_refuses_duplicate_batch_digest() -> None:
    batch = make("k1", {"a": entry("1")})
    with pytest.raises(ContractError) as caught:
        replay(PROJECT, [(batch, digest("a")), (batch, digest("a"))])
    assert caught.value.code == "determinism_conflict"


def test_replay_refuses_a_batch_of_another_project() -> None:
    with pytest.raises(ContractError) as caught:
        replay(
            "00000000-0000-4000-8000-000000000002", [(make("k1", {"a": entry("1")}), digest("a"))]
        )
    assert caught.value.code == "invalid_schema"


def test_state_records_are_frozen() -> None:
    asset = CurrentAsset(
        asset_id=aid("a", "1"),
        source_id=source_id(PROJECT, "a"),
        batch_key="k1",
        admitted_batch_id=digest("a"),
    )
    with pytest.raises(FrozenInstanceError):
        asset.batch_key = "k2"  # type: ignore[misc]
    state = EffectiveState(current={"a": asset}, withdrawn={aid("a", "1"): digest("a")})
    with pytest.raises(FrozenInstanceError):
        state.current = {}  # type: ignore[misc]
    with pytest.raises(TypeError):
        state.current["b"] = asset  # type: ignore[index]
    with pytest.raises(TypeError):
        state.withdrawn["x"] = "y"  # type: ignore[index]
    _, result = step(state, make("k1", {"a": entry("9")}), digest("b"))
    with pytest.raises(FrozenInstanceError):
        result.new = ()  # type: ignore[misc]
    with pytest.raises(TypeError):
        result.predecessors["z"] = asset  # type: ignore[index]
