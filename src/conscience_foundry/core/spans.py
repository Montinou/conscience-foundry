"""Bounded exact coordinate conversion; occurrence never certifies meaning or rights."""

from __future__ import annotations

import hashlib
from typing import Literal

from conscience_foundry.contracts.canonical import (
    DocumentRevision,
    DocumentSpan,
    validate_span_shape,
)
from conscience_foundry.contracts.common import MAX_SAFE_INTEGER, ContractError, ContractLimits
from conscience_foundry.storage.local import VerifiedBytes

Coordinate = Literal["scalar", "byte", "utf16"]


def _decode_bounded_text(text: bytes, limits: ContractLimits) -> str:
    if not isinstance(limits, ContractLimits):
        raise ContractError("limits_missing")
    if type(text) is not bytes:
        raise ContractError("invalid_encoding")
    if len(text) > limits.max_output_bytes:
        raise ContractError("limit_exceeded")
    try:
        decoded = text.decode("utf-8", errors="strict")
    except UnicodeError:
        raise ContractError("invalid_encoding") from None
    if len(decoded) > limits.max_string_scalars:
        raise ContractError("limit_exceeded")
    return decoded


def _convert(
    text: bytes, start: int, end: int, source: Coordinate, target: Coordinate,
    limits: ContractLimits,
) -> tuple[int, int]:
    if (
        type(start) is not int or type(end) is not int
        or not 0 <= start <= end <= MAX_SAFE_INTEGER
    ):
        raise ContractError("invalid_span")
    decoded = _decode_bounded_text(text, limits)
    positions = {"scalar": 0, "byte": 0, "utf16": 0}
    first: int | None = None
    last: int | None = None
    for character in decoded:
        if positions[source] == start:
            first = positions[target]
        if positions[source] == end:
            last = positions[target]
        positions["scalar"] += 1
        positions["byte"] += len(character.encode("utf-8"))
        positions["utf16"] += 2 if ord(character) > 0xFFFF else 1
    if positions[source] == start:
        first = positions[target]
    if positions[source] == end:
        last = positions[target]
    if first is None or last is None:
        raise ContractError("invalid_span")
    return first, last


def scalar_to_bytes(
    text: bytes, start: int, end: int, *, limits: ContractLimits,
) -> tuple[int, int]:
    """Map a bounded scalar range, including empty coordinate ranges, to UTF-8."""
    return _convert(text, start, end, "scalar", "byte", limits)


def scalar_to_utf16(
    text: bytes, start: int, end: int, *, limits: ContractLimits,
) -> tuple[int, int]:
    return _convert(text, start, end, "scalar", "utf16", limits)


def bytes_to_scalar(
    text: bytes, start: int, end: int, *, limits: ContractLimits,
) -> tuple[int, int]:
    """Reject byte offsets inside an encoded scalar rather than round or clamp."""
    return _convert(text, start, end, "byte", "scalar", limits)


def utf16_to_scalar(
    text: bytes, start: int, end: int, *, limits: ContractLimits,
) -> tuple[int, int]:
    """Reject UTF-16 offsets inside a surrogate pair."""
    return _convert(text, start, end, "utf16", "scalar", limits)


def check_exact_quote(
    text: VerifiedBytes, span: DocumentSpan, quote: str, *,
    revision: DocumentRevision, limits: ContractLimits,
) -> None:
    """Verify exact occurrence against an independently trusted revision context.

    Callers establish revision authenticity, its hash projection, current rights
    and release membership separately. This helper cannot grant access or prove
    semantic support, speaker attribution, or truth.
    """
    if not isinstance(limits, ContractLimits):
        raise ContractError("limits_missing")
    if not isinstance(text, VerifiedBytes) or not isinstance(text.data, bytes):
        raise ContractError("hash_mismatch")
    if len(text.data) > limits.max_output_bytes:
        raise ContractError("limit_exceeded")
    actual = hashlib.sha256(text.data).hexdigest()
    if (
        actual != text.digest or actual != revision.text_ref.digest
        or len(text.data) != revision.text_ref.size_bytes
    ):
        raise ContractError("hash_mismatch")
    if (
        revision.text_ref.artifact_schema != "kf.canonical-text.v1"
        or revision.text_ref.media_type != "text/plain"
    ):
        raise ContractError("unsupported_format")
    decoded = _decode_bounded_text(text.data, limits)
    validate_span_shape(span, revision, len(decoded))
    if not isinstance(quote, str):
        raise ContractError("invalid_encoding")
    if len(quote) > limits.max_string_scalars:
        raise ContractError("limit_exceeded")
    if any(0xD800 <= ord(c) <= 0xDFFF for c in quote):
        raise ContractError("invalid_encoding")
    if decoded[span.start:span.end] != quote:
        raise ContractError("invalid_span")
