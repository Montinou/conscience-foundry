"""Bound wire JSON before construction and hash RFC 8785 canonical bytes."""

from __future__ import annotations

import hashlib
import json
from typing import Any, NoReturn, cast

import rfc8785

from conscience_foundry.contracts.common import (
    MAX_SAFE_INTEGER,
    ContractError,
    ContractLimits,
    Digest,
    scalar_string,
    validate_wire_value,
)


def _reject_number(value: str) -> NoReturn:
    raise ContractError("invalid_schema")


def _integer(value: str) -> int:
    if value.startswith("-") or len(value) > 16:
        raise ContractError("invalid_schema")
    result = int(value)
    if result > MAX_SAFE_INTEGER:
        raise ContractError("invalid_schema")
    return result


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("invalid_schema")
        result[key] = value
    return result


def _check_depth(data: bytes, maximum: int) -> None:
    """Scan containers before json.loads can allocate a nested object tree."""
    depth = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                in_string = False
        elif byte == 34:
            in_string = True
        elif byte in (123, 91):
            depth += 1
            if depth > maximum:
                raise ContractError("invalid_schema")
        elif byte in (125, 93):
            depth -= 1


def load_json(data: bytes, limits: ContractLimits) -> dict[str, object]:
    """Decode one object with byte/depth admission before object construction."""
    if not isinstance(limits, ContractLimits):
        raise ContractError("limits_missing")
    if not isinstance(data, bytes):
        raise ContractError("invalid_schema")
    if len(data) > limits.max_json_bytes:
        raise ContractError("limit_exceeded")
    _check_depth(data, limits.max_depth)
    try:
        text = data.decode("utf-8")
        value = json.loads(
            text,
            parse_int=_integer,
            parse_float=_reject_number,
            parse_constant=_reject_number,
            object_pairs_hook=_object,
        )
        if not isinstance(value, dict):
            raise ContractError("invalid_schema")
        validate_wire_value(value, allow_null=True)
        pending: list[object] = [value]
        while pending:
            item = pending.pop()
            if isinstance(item, str) and len(item) > limits.max_string_scalars:
                raise ContractError("limit_exceeded")
            if isinstance(item, list):
                if len(item) > limits.max_array_items:
                    raise ContractError("limit_exceeded")
                pending.extend(item)
            elif isinstance(item, dict):
                pending.extend(item.keys())
                pending.extend(item.values())
        return cast(dict[str, object], value)
    except (UnicodeError, ValueError, RecursionError) as error:
        if isinstance(error, ContractError):
            raise error from None
        raise ContractError("invalid_schema") from None


def hash_jcs(domain: str, value: object) -> Digest:
    """Hash domain + newline + JCS, retaining exact Unicode and decimal strings."""
    try:
        if not isinstance(domain, str) or not domain or "\n" in domain or "\r" in domain:
            raise ValueError("invalid domain")
        scalar_string(domain)
        validate_wire_value(value, allow_null=True)
        canonical = rfc8785.dumps(cast(Any, value))
        return hashlib.sha256(domain.encode("utf-8") + b"\n" + canonical).hexdigest()
    except (ValueError, UnicodeError, RecursionError):
        raise ContractError("invalid_schema") from None
