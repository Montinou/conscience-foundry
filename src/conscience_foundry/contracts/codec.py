"""Bound wire JSON before construction and hash RFC 8785 canonical bytes."""

from __future__ import annotations

import hashlib
import json
from functools import partial
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


def _integer(value: str, *, signed: bool = False) -> int:
    digits = value[1:] if signed and value.startswith("-") else value
    if digits.startswith("-") or len(digits) > 16:
        raise ContractError("invalid_schema")
    result = int(value)
    if abs(result) > MAX_SAFE_INTEGER:
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


def load_json(data: bytes, limits: ContractLimits, *, signed: bool = False) -> dict[str, object]:
    """Decode one object with byte/depth admission before object construction.

    Integers are non-negative unless `signed`, which only a contract that needs them requests.
    """
    if not isinstance(limits, ContractLimits):
        raise ContractError("limits_missing")
    if type(data) is not bytes:
        raise ContractError("invalid_schema")
    if len(data) > limits.max_json_bytes:
        raise ContractError("limit_exceeded")
    _check_depth(data, limits.max_depth)
    try:
        text = data.decode("utf-8")
        value = json.loads(
            text,
            parse_int=partial(_integer, signed=signed),
            parse_float=_reject_number,
            parse_constant=_reject_number,
            object_pairs_hook=_object,
        )
        if not isinstance(value, dict):
            raise ContractError("invalid_schema")
        validate_wire_value(value, allow_null=True, allow_negative=signed)
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


def digest_canonical_json(data: bytes, *, signed: bool = False) -> Digest:
    """SHA-256 of the RFC 8785 bytes of one JSON object, whatever its spacing or key order.

    Strict decoding only (no duplicate keys, floats or constants; integers within +/-(2^53-1),
    non-negative unless `signed`); byte, depth and string bounds are the caller's, applied when
    the same bytes are admitted as a contract.
    """
    try:
        if type(data) is not bytes:
            raise ValueError("expected bytes")
        value = json.loads(
            data.decode("utf-8"),
            parse_int=partial(_integer, signed=signed),
            parse_float=_reject_number,
            parse_constant=_reject_number,
            object_pairs_hook=_object,
        )
        if not isinstance(value, dict):
            raise ValueError("expected one object")
        validate_wire_value(value, allow_null=True, allow_negative=signed)
        return hashlib.sha256(rfc8785.dumps(cast(Any, value))).hexdigest()
    except (ValueError, UnicodeError, RecursionError):
        raise ContractError("invalid_schema") from None
