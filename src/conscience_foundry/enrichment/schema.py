"""Strict bounded dialect for operator-installed task schemas."""

from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError
from referencing import Registry
from referencing.exceptions import NoSuchResource

from conscience_foundry.contracts.codec import load_json
from conscience_foundry.contracts.common import ContractError, ContractLimits

_URI = "https://json-schema.org/draft/2020-12/schema"
_ALLOWED = frozenset(
    {
        "$schema",
        "$id",
        "title",
        "description",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "enum",
        "const",
    }
)


def _refuse(uri: str) -> Any:
    raise NoSuchResource(ref=uri)  # type: ignore[call-arg]  # attrs-generated initializer


def validate_schema(schema_bytes: bytes, *, limits: ContractLimits) -> dict[str, object]:
    """Reject unbounded or executable dialect features before any validator runs."""
    schema = load_json(schema_bytes, limits, signed=True)
    pending: list[dict[str, object]] = [schema]
    if schema.get("type") != "object":
        raise ContractError("invalid_schema")
    while pending:
        node = pending.pop()
        if set(node) - _ALLOWED:
            raise ContractError("unsupported_schema")
        if "$schema" in node and node["$schema"] != _URI:
            raise ContractError("unsupported_schema")
        if "$id" in node and (type(node["$id"]) is not str or not node["$id"]):
            raise ContractError("invalid_schema")
        kind = node.get("type")
        if kind not in ("object", "array", "string", "integer", "number", "boolean", "null"):
            raise ContractError("invalid_schema")
        typed = {
            "object": {"properties", "required", "additionalProperties"},
            "array": {"items", "minItems", "maxItems"},
            "string": {"minLength", "maxLength"},
            "number": {"minimum", "maximum"},
        }
        for expected, keys in typed.items():
            if keys & node.keys() and not (
                kind == expected or expected == "number" and kind == "integer"
            ):
                raise ContractError("invalid_schema")
        if kind == "object":
            props = node.get("properties", {})
            if (
                type(props) is not dict
                or len(props) > limits.max_manifest_items
                or node.get("additionalProperties") is not False
            ):
                raise ContractError("invalid_schema")
            if not all(type(key) is str and type(value) is dict for key, value in props.items()):
                raise ContractError("invalid_schema")
            pending.extend(props.values())
        if kind == "array":
            maximum = node.get("maxItems")
            item = node.get("items")
            if (
                type(maximum) is not int
                or maximum < 0
                or maximum > limits.max_array_items
                or type(item) is not dict
            ):
                raise ContractError("invalid_schema")
            pending.append(item)
        if kind == "string":
            maximum = node.get("maxLength")
            if type(maximum) is not int or maximum < 0 or maximum > limits.max_string_scalars:
                raise ContractError("invalid_schema")
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError:
        raise ContractError("invalid_schema") from None
    return schema


def validate_payload(
    schema_bytes: bytes, payload_bytes: bytes, *, limits: ContractLimits
) -> dict[str, object]:
    if type(limits) is not ContractLimits:
        raise ContractError("limits_missing")
    if type(payload_bytes) is bytes and len(payload_bytes) > limits.max_output_bytes:
        raise ContractError("limit_exceeded")
    schema = validate_schema(schema_bytes, limits=limits)
    payload = load_json(payload_bytes, limits, signed=True)
    try:
        registry = Registry(retrieve=_refuse)  # type: ignore[call-arg]  # attrs initializer
        Draft202012Validator(schema, registry=registry).validate(payload)
    except ValidationError:
        raise ContractError("invalid_schema") from None
    return payload
