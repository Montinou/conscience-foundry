"""Intake identities: UUIDv5 over RFC 8785 bytes, one prefixed domain per identity."""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Literal, cast
from uuid import NAMESPACE_OID, UUID, uuid5

import pytest
import rfc8785

from conscience_foundry.contracts.common import ContractError
from conscience_foundry.intake.identity import (
    INTAKE_NAMESPACE,
    asset_id,
    batch_id,
    decision_id,
    source_id,
)

PROJECT = "00000000-0000-4000-8000-000000000001"
OTHER_PROJECT = "00000000-0000-4000-8000-000000000002"
SHA = "1" * 64
OTHER_SHA = "2" * 64
BATCH_DIGEST = "3" * 64
OTHER_DIGEST = "4" * 64
KEY = "work/a.txt"
IDENTITY: dict[str, object] = {"title": "A title", "year": 1999, "flag": True}


def derived(domain: str, payload: dict[str, object]) -> str:
    """Independent re-derivation of the specified formula; shares no code with the module."""
    name = domain + "\n" + rfc8785.dumps(cast(Any, payload)).decode("utf-8")
    return str(uuid5(UUID(str(uuid5(NAMESPACE_OID, "cf.intake-identity.v1"))), name))


def all_four(
    project: str = PROJECT, cause: Literal["changed", "missing"] = "changed"
) -> tuple[str, str, str, str]:
    source = source_id(project, KEY)
    asset = asset_id(project, KEY, SHA, IDENTITY)
    batch = batch_id(project, KEY, BATCH_DIGEST)
    decision = decision_id(project, batch, asset, cause, BATCH_DIGEST)
    return source, asset, batch, decision


def test_namespace_is_pinned() -> None:
    assert uuid5(NAMESPACE_OID, "cf.intake-identity.v1") == INTAKE_NAMESPACE


def test_ids_match_the_specified_formulas() -> None:
    batch = batch_id(PROJECT, "batch-1", BATCH_DIGEST)
    asset = asset_id(PROJECT, KEY, SHA, IDENTITY)
    assert source_id(PROJECT, KEY) == derived(
        "cf.intake-source.v1", {"projectId": PROJECT, "sourceKey": KEY}
    )
    assert asset == derived(
        "cf.intake-asset.v1",
        {"projectId": PROJECT, "sourceKey": KEY, "sha256": SHA, "identity": IDENTITY},
    )
    assert batch == derived(
        "cf.intake-batch.v1",
        {"projectId": PROJECT, "batchKey": "batch-1", "batchDigest": BATCH_DIGEST},
    )
    assert decision_id(PROJECT, batch, asset, "missing", OTHER_DIGEST) == derived(
        "cf.intake-withdrawal.v1",
        {
            "projectId": PROJECT,
            "batchId": batch,
            "assetId": asset,
            "cause": "missing",
            "byBatchDigest": OTHER_DIGEST,
        },
    )


def test_ids_are_deterministic_and_domain_separated() -> None:
    first = all_four()
    assert first == all_four()
    assert len(set(first)) == 4
    for value in first:
        assert str(UUID(value)) == value
        assert UUID(value).version == 5
    # equal payload text under different domains never collides
    same_text = "same"
    assert source_id(PROJECT, same_text) != batch_id(PROJECT, same_text, BATCH_DIGEST)
    # identity field order never changes the id
    reordered = dict(reversed(list(IDENTITY.items())))
    assert asset_id(PROJECT, KEY, SHA, reordered) == asset_id(PROJECT, KEY, SHA, IDENTITY)
    # every input is part of the identity
    assert all_four(OTHER_PROJECT) != first
    assert all_four(cause="missing")[3] != first[3]
    assert source_id(PROJECT, "work/b.txt") != first[0]
    assert asset_id(PROJECT, KEY, OTHER_SHA, IDENTITY) != first[1]
    assert batch_id(PROJECT, KEY, OTHER_DIGEST) != first[2]
    batch, asset = first[2], first[1]
    assert decision_id(PROJECT, batch, asset, "changed", OTHER_DIGEST) != first[3]
    assert decision_id(PROJECT, asset, batch, "changed", BATCH_DIGEST) != first[3]


def test_identity_ignores_non_identity_fields() -> None:
    # Callers pass only the batch's identityFields; the function hashes exactly what it is given,
    # so two calls differ only when the identity values differ.
    base = asset_id(PROJECT, KEY, SHA, {"title": "A"})
    assert asset_id(PROJECT, KEY, SHA, {"title": "A"}) == base
    assert asset_id(PROJECT, KEY, SHA, {"title": "B"}) != base
    assert asset_id(PROJECT, KEY, SHA, {}) != base
    nested = asset_id(PROJECT, KEY, SHA, {"origin": {"b": 2, "a": 1}})
    assert nested == asset_id(PROJECT, KEY, SHA, {"origin": {"a": 1, "b": 2}})


def test_frozen_admitted_metadata_gives_the_same_id() -> None:
    plain = {"origin": {"place": "p", "tags": ["a", "b"]}, "year": 1999}
    frozen = MappingProxyType(
        {"origin": MappingProxyType({"place": "p", "tags": ("a", "b")}), "year": 1999}
    )
    assert asset_id(PROJECT, KEY, SHA, frozen) == asset_id(PROJECT, KEY, SHA, plain)
    assert asset_id(PROJECT, KEY, SHA, {"n": -5}) == derived(
        "cf.intake-asset.v1",
        {"projectId": PROJECT, "sourceKey": KEY, "sha256": SHA, "identity": {"n": -5}},
    )


def test_unicode_keys_are_exact() -> None:
    assert source_id(PROJECT, "café") != source_id(PROJECT, "café")
    assert source_id(PROJECT, "café") == derived(
        "cf.intake-source.v1", {"projectId": PROJECT, "sourceKey": "café"}
    )


@pytest.mark.parametrize(
    "call",
    [
        lambda: source_id("not-an-id", KEY),
        lambda: source_id(PROJECT, "\ud800"),
        lambda: asset_id(PROJECT, KEY, "abc", IDENTITY),
        lambda: asset_id(PROJECT, KEY, SHA, {"x": 1.5}),
        lambda: asset_id(PROJECT, KEY, SHA, {"x": object()}),
        lambda: asset_id(PROJECT, KEY, SHA, {"x": float("nan")}),
        lambda: batch_id(PROJECT, KEY, "G" * 64),
        lambda: decision_id(PROJECT, "bad", "bad", "changed", BATCH_DIGEST),
        lambda: decision_id(PROJECT, PROJECT, PROJECT, "gone", BATCH_DIGEST),  # type: ignore[arg-type]
    ],
)
def test_malformed_inputs_are_invalid_schema(call: object) -> None:
    assert callable(call)
    with pytest.raises(ContractError) as error:
        call()
    assert error.value.code == "invalid_schema"
