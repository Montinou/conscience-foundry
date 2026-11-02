"""Curated-batch and new-sources contracts: shape, rules, digest and registration."""

from __future__ import annotations

import copy
import hashlib
import json
import unicodedata
from pathlib import Path

import pytest
import rfc8785

from conscience_foundry.contracts.common import ContractError, ContractLimits
from conscience_foundry.contracts.intake import CuratedBatch, NewSources, batch_digest
from conscience_foundry.contracts.registry import (
    SCHEMA_MODELS,
    _rules_bytes,
    _schema_bytes,
    registered_schema_ids,
)
from conscience_foundry.release.edges import edge_roles

SCHEMAS = Path(__file__).resolve().parents[2] / "schemas"
PROJECT = "00000000-0000-4000-8000-000000000001"
SOURCE_A = "00000000-0000-4000-8000-0000000000b1"
SOURCE_B = "00000000-0000-4000-8000-0000000000b2"


def limits(**overrides: int) -> ContractLimits:
    values: dict[str, object] = {
        "schemaVersion": "cf.contract-limits.v1",
        "version": "synthetic.limits.v1",
        "maxJsonBytes": 65536,
        "maxStringScalars": 256,
        "maxArrayItems": 32,
        "maxDepth": 16,
        "maxManifestItems": 4,
        "maxSourceBytes": 1024,
        "maxOutputBytes": 4096,
        "maxErrorMessageScalars": 40,
    }
    return ContractLimits.model_validate(values | overrides)


def item(
    path: str = "shelf/one.txt", key: str = "key-1", size: int = 10, **extra: object
) -> dict[str, object]:
    return {
        "relativePath": path,
        "sha256": "a" * 64,
        "sizeBytes": size,
        "mediaType": "text/plain",
        "sourceKey": key,
        "metadata": {"shelf": "s1", "lang": "en", "rank": -3},
    } | extra


def batch() -> dict[str, object]:
    return {
        "schemaVersion": "cf.curated-batch.v1",
        "projectId": PROJECT,
        "batchKey": "era-1",
        "producer": {"name": "synthetic-producer", "version": "1.0.0"},
        "createdAt": "2026-01-02T03:04:05.000Z",
        "custodyRootLabel": "library-root",
        "identityFields": ["shelf", "lang"],
        "approval": {"actor": "auditor:synthetic", "method": "audit", "evidenceDigest": "c" * 64},
        "items": [item(), item("shelf/two.txt", "key-2")],
    }


def new_sources() -> dict[str, object]:
    return {
        "schemaVersion": "cf.new-sources.v1",
        "projectId": PROJECT,
        "batchDigest": "d" * 64,
        "sources": [
            {"sourceId": SOURCE_A, "sourceKey": "key-1"},
            {"sourceId": SOURCE_B, "sourceKey": "key-2"},
        ],
    }


def wire(value: object) -> bytes:
    return json.dumps(value).encode("utf-8")


def refused(
    model: type[CuratedBatch] | type[NewSources],
    value: object,
    bounds: ContractLimits | None = None,
    code: str = "invalid_schema",
) -> None:
    with pytest.raises(ContractError) as error:
        model.from_wire(wire(value), bounds or limits())
    assert error.value.code == code


def with_items(*items: dict[str, object]) -> dict[str, object]:
    return batch() | {"items": list(items)}


def test_valid_batch_parses() -> None:
    parsed = CuratedBatch.from_wire(wire(batch()), limits())
    assert parsed.batch_key == "era-1"
    assert parsed.producer.name == "synthetic-producer"
    assert parsed.identity_fields == ("shelf", "lang")
    assert parsed.approval.evidence_digest == "c" * 64
    assert [entry.source_key for entry in parsed.items] == ["key-1", "key-2"]
    assert parsed.items[0].metadata["rank"] == -3
    assert json.loads(parsed.model_dump_json(by_alias=True)) == batch()


@pytest.mark.parametrize(
    "path",
    [
        "../escape.txt",
        "a/../b.txt",
        "a/./b.txt",
        "./a.txt",
        "/absolute.txt",
        "a\\b.txt",
        "a//b.txt",
        "a/b.txt/",
        "",
        "a/\x00b.txt",
        unicodedata.normalize("NFD", "café.txt"),
    ],
)
def test_unsafe_relative_paths_rejected(path: str) -> None:
    refused(CuratedBatch, with_items(item(path)))


def test_nfc_path_is_accepted_and_nfd_is_not() -> None:
    nfc = unicodedata.normalize("NFC", "café.txt")
    CuratedBatch.from_wire(wire(with_items(item(nfc))), limits())
    refused(CuratedBatch, with_items(item(unicodedata.normalize("NFD", nfc))))


def test_duplicate_path_and_source_key_rejected() -> None:
    refused(CuratedBatch, with_items(item("same.txt", "key-1"), item("same.txt", "key-2")))
    refused(CuratedBatch, with_items(item("one.txt", "same"), item("two.txt", "same")))


def test_missing_identity_field_rejected() -> None:
    lacking = item("two.txt", "key-2")
    lacking["metadata"] = {"shelf": "s1"}
    refused(CuratedBatch, with_items(item(), lacking))
    refused(CuratedBatch, batch() | {"identityFields": ["shelf", "absent"]})
    refused(CuratedBatch, batch() | {"identityFields": []})


def test_wrong_media_type_and_oversize_rejected() -> None:
    refused(CuratedBatch, with_items(item(mediaType="application/pdf")))
    refused(CuratedBatch, with_items(item(size=1025)))
    CuratedBatch.from_wire(wire(with_items(item(size=1024))), limits())
    refused(CuratedBatch, with_items(item(size=0)))
    refused(CuratedBatch, with_items(item(size=-1)))
    many = [item(f"p{number}.txt", f"k{number}") for number in range(5)]
    refused(CuratedBatch, batch() | {"items": many})
    CuratedBatch.from_wire(wire(batch() | {"items": many[:4]}), limits())
    refused(CuratedBatch, batch() | {"items": []})


def test_header_bounds_and_shape_are_closed() -> None:
    for key in (
        "schemaVersion",
        "projectId",
        "batchKey",
        "producer",
        "createdAt",
        "custodyRootLabel",
        "identityFields",
        "approval",
        "items",
    ):
        broken = batch()
        del broken[key]
        refused(CuratedBatch, broken)
    refused(CuratedBatch, batch() | {"extra": 1})
    refused(CuratedBatch, batch() | {"schemaVersion": "cf.curated-batch.v2"})
    refused(CuratedBatch, batch() | {"batchKey": ""})
    refused(CuratedBatch, batch() | {"batchKey": "x" * 129})
    refused(CuratedBatch, batch() | {"batchKey": "has space"})
    CuratedBatch.from_wire(wire(batch() | {"batchKey": "A.b_c:d-9"}), limits())
    refused(CuratedBatch, batch() | {"custodyRootLabel": ""})
    refused(CuratedBatch, batch() | {"custodyRootLabel": "x" * 129})
    refused(CuratedBatch, batch() | {"createdAt": "2026-01-02"})
    producer = {"name": "synthetic-producer", "version": "1.0.0"}
    refused(CuratedBatch, batch() | {"producer": producer | {"extra": 1}})
    refused(CuratedBatch, batch() | {"producer": {"name": "synthetic-producer"}})
    approval = {"actor": "auditor:synthetic", "method": "audit", "evidenceDigest": "c" * 64}
    refused(CuratedBatch, batch() | {"approval": approval | {"evidenceDigest": "short"}})
    refused(CuratedBatch, batch() | {"approval": {"actor": "auditor:synthetic"}})


def test_item_bounds_and_shape_are_closed() -> None:
    for key in ("relativePath", "sha256", "sizeBytes", "mediaType", "sourceKey", "metadata"):
        broken = item()
        del broken[key]
        refused(CuratedBatch, with_items(broken))
    refused(CuratedBatch, with_items(item(extra=1)))
    refused(CuratedBatch, with_items(item(sha256="A" * 64)))
    refused(CuratedBatch, with_items(item(key="")))
    refused(CuratedBatch, with_items(item(key="k" * 257)), limits(maxStringScalars=512))
    CuratedBatch.from_wire(wire(with_items(item(key="k" * 256))), limits(maxStringScalars=512))
    refused(CuratedBatch, with_items(item(metadata=[])))
    refused(CuratedBatch, with_items(item(sizeBytes="10")))


def test_metadata_is_closed_over_wire_values() -> None:
    nested = item(metadata={"shelf": "s1", "lang": "en", "origin": {"depth": -1, "tags": ["a"]}})
    parsed = CuratedBatch.from_wire(wire(with_items(nested)), limits())
    assert parsed.items[0].metadata["origin"]["depth"] == -1  # type: ignore[index]
    refused(CuratedBatch, with_items(item(metadata={"shelf": "s1", "lang": "en", "n": None})))
    refused(CuratedBatch, with_items(item(metadata={"shelf": "s1", "lang": "en", "n": 1.5})))
    refused(
        CuratedBatch,
        with_items(item(metadata={"shelf": "s1", "lang": "en", "n": -(2**53)})),
    )


def test_batch_digest_is_canonical() -> None:
    compact = json.dumps(batch(), separators=(",", ":")).encode("utf-8")
    spaced = json.dumps(batch(), indent=4).encode("utf-8")
    reordered = json.dumps(dict(reversed(list(batch().items())))).encode("utf-8")
    canonical = rfc8785.dumps(batch())  # type: ignore[arg-type]
    expected = hashlib.sha256(canonical).hexdigest()
    assert batch_digest(compact) == expected
    assert batch_digest(spaced) == expected
    assert batch_digest(reordered) == expected
    assert batch_digest(wire(batch() | {"batchKey": "era-2"})) != expected
    reordered_items = batch()
    reordered_items["items"] = list(reversed(copy.deepcopy(batch()["items"])))  # type: ignore[call-overload]
    assert batch_digest(wire(reordered_items)) != expected


def test_batch_digest_keeps_signed_metadata_and_refuses_malformed_bytes() -> None:
    assert len(batch_digest(wire(batch()))) == 64
    for data in (
        b"not json",
        b"[]",
        b'{"a":1,"a":2}',
        b'{"a":1.5}',
        b'{"a":NaN}',
        b'{"a":-9007199254740992}',
        b'{"a":9007199254740992}',
        b'{"a":"\\ud800"}',
        "{}".encode("utf-16"),
        b"",
    ):
        with pytest.raises(ContractError) as error:
            batch_digest(data)
        assert error.value.code == "invalid_schema"
    with pytest.raises(ContractError):
        batch_digest("{}")  # type: ignore[arg-type]


def test_new_sources_parse_and_rules() -> None:
    parsed = NewSources.from_wire(wire(new_sources()), limits())
    assert parsed.sources[1].source_key == "key-2"
    assert json.loads(parsed.model_dump_json(by_alias=True)) == new_sources()
    NewSources.from_wire(wire(new_sources() | {"sources": []}), limits())

    duplicate_id = new_sources() | {
        "sources": [
            {"sourceId": SOURCE_A, "sourceKey": "key-1"},
            {"sourceId": SOURCE_A, "sourceKey": "key-2"},
        ]
    }
    refused(NewSources, duplicate_id)
    duplicate_key = new_sources() | {
        "sources": [
            {"sourceId": SOURCE_A, "sourceKey": "key-1"},
            {"sourceId": SOURCE_B, "sourceKey": "key-1"},
        ]
    }
    refused(NewSources, duplicate_key)


def test_new_sources_shape_is_closed() -> None:
    for key in ("schemaVersion", "projectId", "batchDigest", "sources"):
        broken = new_sources()
        del broken[key]
        refused(NewSources, broken)
    refused(NewSources, new_sources() | {"extra": 1})
    refused(NewSources, new_sources() | {"batchDigest": "D" * 64})
    refused(NewSources, new_sources() | {"schemaVersion": "cf.new-sources.v2"})
    refused(NewSources, new_sources() | {"sources": [{"sourceId": SOURCE_A}]})
    refused(NewSources, new_sources() | {"sources": [{"sourceId": "nope", "sourceKey": "k"}]})
    refused(NewSources, new_sources() | {"sources": [{"sourceId": SOURCE_A, "sourceKey": ""}]})
    refused(
        NewSources,
        new_sources() | {"sources": [{"sourceId": SOURCE_A, "sourceKey": "k", "extra": 1}]},
    )


@pytest.mark.parametrize("schema_id", ["cf.curated-batch.v1", "cf.new-sources.v1"])
def test_registered_exported_and_reference_free(schema_id: str) -> None:
    assert schema_id in registered_schema_ids()
    assert (SCHEMAS / f"{schema_id}.schema.json").read_bytes() == _schema_bytes(schema_id)
    assert (SCHEMAS / f"{schema_id}.rules.json").read_bytes() == _rules_bytes(schema_id)
    assert SCHEMA_MODELS[schema_id].__module__ == "conscience_foundry.contracts.intake"
    raw = batch() if schema_id == "cf.curated-batch.v1" else new_sources()
    model = SCHEMA_MODELS[schema_id].from_wire(wire(raw), limits())
    assert edge_roles(schema_id, model) == ()
