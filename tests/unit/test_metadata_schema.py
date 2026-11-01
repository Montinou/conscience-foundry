"""Metadata-schema subset: parse operator documents, validate metadata, registered contract."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from conscience_foundry.contracts.common import ContractError, ContractLimits
from conscience_foundry.contracts.registry import (
    _rules_bytes,
    _schema_bytes,
    registered_schema_ids,
)
from conscience_foundry.intake.metadata_schema import MetadataSchema

SCHEMA_ID = "cf.metadata-schema.v1"
SCHEMAS = Path(__file__).resolve().parents[2] / "schemas"


def limits() -> ContractLimits:
    return ContractLimits.model_validate(
        {
            "schemaVersion": "cf.contract-limits.v1",
            "version": "synthetic.limits.v1",
            "maxJsonBytes": 1048576,
            "maxStringScalars": 4096,
            "maxArrayItems": 256,
            "maxDepth": 32,
            "maxManifestItems": 16,
            "maxSourceBytes": 8192,
            "maxOutputBytes": 16384,
            "maxErrorMessageScalars": 128,
        }
    )


def document(properties: dict[str, object], required: list[str] | None = None) -> dict[str, object]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required if required is not None else [],
        "properties": properties,
    }


def encode(value: object) -> bytes:
    return json.dumps(value).encode("utf-8")


def subset() -> dict[str, object]:
    return document(
        {
            "title": {"type": "string", "maxLength": 20, "pattern": "^[a-z ]+$"},
            "kind": {"type": "string", "maxLength": 8, "enum": ["alpha", "beta"]},
            "count": {"type": "integer", "minimum": 1, "maximum": 9},
            "flag": {"type": "boolean"},
            "origin": document(
                {"place": {"type": "string", "maxLength": 10}, "year": {"type": "integer"}},
                ["place"],
            ),
        },
        ["title", "count"],
    )


def parse(value: object) -> MetadataSchema:
    return MetadataSchema.parse(encode(value), limits())


def test_subset_document_parses() -> None:
    schema = parse(subset())
    assert isinstance(schema, MetadataSchema)
    with pytest.raises(FrozenInstanceError):
        schema.document = schema.document  # type: ignore[misc]


def bad_documents() -> dict[str, dict[str, object]]:
    def with_property(prop: dict[str, object]) -> dict[str, object]:
        return document({"field": prop})

    many: dict[str, object] = {f"p{i}": {"type": "boolean"} for i in range(65)}
    deep = document(
        {"a": document({"b": document({"c": {"type": "boolean"}})})},
    )
    no_additional = subset()
    del no_additional["additionalProperties"]
    open_additional = subset() | {"additionalProperties": True}
    return {
        "ref": with_property({"$ref": "#/$defs/x"}),
        "root_ref": subset() | {"$ref": "#/$defs/x"},
        "id": subset() | {"$id": "urn:x"},
        "format": with_property({"type": "string", "maxLength": 5, "format": "date"}),
        "missing_max_length": with_property({"type": "string"}),
        "max_length_too_large": with_property({"type": "string", "maxLength": 1025}),
        "additional_absent": no_additional,
        "additional_true": open_additional,
        "nested_additional_true": document(
            {"o": document({"x": {"type": "boolean"}}) | {"additionalProperties": True}}
        ),
        "depth_three": deep,
        "properties_65": document(many),
        "unsupported_type": with_property({"type": "number"}),
        "array_type": with_property({"type": "array"}),
        "bad_pattern": with_property({"type": "string", "maxLength": 5, "pattern": "("}),
        "required_unknown": document({"a": {"type": "boolean"}}, ["b"]),
        "root_not_object": {"type": "string", "maxLength": 5},
    }


@pytest.mark.parametrize("name", sorted(bad_documents()))
def test_outside_subset_is_invalid_schema(name: str) -> None:
    with pytest.raises(ContractError) as error:
        parse(bad_documents()[name])
    assert error.value.code == "invalid_schema"


def test_non_json_bytes_are_invalid_schema() -> None:
    for data in (b"not json", b"[]", b"\xff"):
        with pytest.raises(ContractError) as error:
            MetadataSchema.parse(data, limits())
        assert error.value.code == "invalid_schema"


def valid_metadata() -> dict[str, object]:
    return {
        "title": "a title",
        "kind": "alpha",
        "count": 3,
        "flag": True,
        "origin": {"place": "somewhere", "year": 1999},
    }


def test_validate_accepts_and_refuses() -> None:
    schema = parse(subset())
    schema.validate(valid_metadata())
    schema.validate({"title": "x", "count": 9})

    def refused(**changes: object) -> None:
        metadata = valid_metadata() | changes
        with pytest.raises(ContractError) as error:
            schema.validate({k: v for k, v in metadata.items() if v is not ...})
        assert error.value.code == "invalid_schema"

    refused(unknown="x")
    refused(title=...)
    refused(count=...)
    refused(title="a" * 21)
    refused(kind="gamma")
    refused(title="UPPER")
    refused(count=0)
    refused(count=10)
    refused(count="3")
    refused(count=True)
    refused(title=3)
    refused(flag="yes")
    refused(flag=1)
    refused(origin={"year": 2})
    refused(origin={"place": "p", "extra": 1})
    refused(origin={"place": "p" * 11})
    refused(origin="flat")
    refused(origin=None)
    refused(title=None)


def test_validate_refuses_non_mapping_metadata() -> None:
    schema = parse(subset())
    with pytest.raises(ContractError) as error:
        schema.validate(["title"])  # type: ignore[arg-type]
    assert error.value.code == "invalid_schema"


def test_registered_and_exported() -> None:
    assert SCHEMA_ID in registered_schema_ids()
    assert (SCHEMAS / f"{SCHEMA_ID}.schema.json").read_bytes() == _schema_bytes(SCHEMA_ID)
    assert (SCHEMAS / f"{SCHEMA_ID}.rules.json").read_bytes() == _rules_bytes(SCHEMA_ID)


def string_schema(pattern: str) -> dict[str, object]:
    return document({"field": {"type": "string", "maxLength": 20, "pattern": pattern}})


@pytest.mark.parametrize(
    "pattern",
    [
        "a{4294967296}",
        "a{1,4294967296}",
        "a{3,2}",
        "(?P<n>a)",
        "(?=a)",
        "(?i)a",
        "a*+",
        "a++",
        "a{",
        "a}",
        "]",
        "[]a]",
        "[[a]",
        r"\1",
        r"\s",
        r"\S",
        r"\u0041",
        r"\x41",
        r"\A",
        r"\Z",
        r"\-",
        "^*",
        "$+",
        r"\b+",
        "*a",
        "a|*",
        "(",
        "a)",
    ],
)
def test_pattern_outside_shared_dialect_is_invalid_schema(pattern: str) -> None:
    with pytest.raises(ContractError) as error:
        parse(string_schema(pattern))
    assert error.value.code == "invalid_schema"


def test_pattern_dollar_does_not_match_before_trailing_newline() -> None:
    schema = parse(string_schema("^[a-z]+$"))
    schema.validate({"field": "abc"})
    for value in ("abc\n", "abc\r", "abc\n\n"):
        with pytest.raises(ContractError) as error:
            schema.validate({"field": value})
        assert error.value.code == "invalid_schema"


def test_pattern_matches_with_ecmascript_character_semantics() -> None:
    digits = parse(string_schema(r"^\d+$"))
    digits.validate({"field": "123"})
    with pytest.raises(ContractError):
        digits.validate({"field": "\u0663"})
    word = parse(string_schema(r"^\w+$"))
    word.validate({"field": "a_1"})
    with pytest.raises(ContractError):
        word.validate({"field": "\u00e9"})
    dot = parse(string_schema("^.$"))
    dot.validate({"field": "x"})
    for value in ("\n", "\r", "\u2028", "\u2029"):
        with pytest.raises(ContractError):
            dot.validate({"field": value})
    unanchored = parse(string_schema("b+"))
    unanchored.validate({"field": "abbc"})
    group = parse(string_schema("^(?:ab|c){1,2}[x\\-]?$"))
    group.validate({"field": "abc-"})


@pytest.mark.parametrize(
    "pattern",
    [
        "^(a+)+$",
        "(a*)*",
        "^(?:a+)+$",
        "^(?:a+)*b",
        "^(a?)+$",
        "(?:x{2,3}y)+",
        "^((a+)b)+$",
        "(?:(?:a+)b){2}",
        "^(a|aa)+$",
        "^(?:a|ab)*c",
        "(?:ab|abc){2}",
    ],
)
def test_pattern_that_backtracks_exponentially_is_invalid_schema(pattern: str) -> None:
    with pytest.raises(ContractError) as error:
        parse(string_schema(pattern))
    assert error.value.code == "invalid_schema"


@pytest.mark.parametrize(
    ("pattern", "accepted"),
    [
        ("^(a+)b$", "aab"),
        ("^(?:a+)$", "aa"),
        ("^(?:ab)+$", "abab"),
        ("^(?:ab|c){1,2}[x\\-]?$", "abc-"),
        ("^(a|b)+$", "abba"),
        ("^(?:a+b)(?:c+d)$", "aabccd"),
    ],
)
def test_bounded_group_patterns_stay_admitted(pattern: str, accepted: str) -> None:
    parse(string_schema(pattern)).validate({"field": accepted})


def integer_schema(**bounds: int) -> dict[str, object]:
    return document({"n": {"type": "integer"} | bounds})


def test_negative_integer_bounds_are_admitted() -> None:
    schema = parse(integer_schema(minimum=-5, maximum=5))
    for value in (-5, 0, 5):
        schema.validate({"n": value})
    for value in (-6, 6):
        with pytest.raises(ContractError) as error:
            schema.validate({"n": value})
        assert error.value.code == "invalid_schema"
    parse(integer_schema(minimum=-9007199254740991, maximum=-1)).validate({"n": -9007199254740991})
    parse(integer_schema(minimum=-3)).validate({"n": 100})
    parse(integer_schema(maximum=-3)).validate({"n": -100})


@pytest.mark.parametrize(
    "bounds",
    [
        {"minimum": -9007199254740992},
        {"maximum": -9007199254740992},
        {"minimum": 9007199254740992},
        {"minimum": -1, "maximum": -2},
        {"minimum": 2, "maximum": -2},
    ],
)
def test_integer_bounds_outside_range_or_order_are_invalid_schema(bounds: dict[str, int]) -> None:
    with pytest.raises(ContractError) as error:
        parse(integer_schema(**bounds))
    assert error.value.code == "invalid_schema"


def test_negative_numbers_elsewhere_stay_refused() -> None:
    for prop in (
        {"type": "string", "maxLength": -1},
        {"type": "integer", "minimum": -1.5},
    ):
        with pytest.raises(ContractError) as error:
            parse(document({"field": prop}))
        assert error.value.code == "invalid_schema"
