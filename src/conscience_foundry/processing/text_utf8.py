"""The text.utf8.v1 identity processor: bounded exact bytes and explicit quality."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from conscience_foundry.contracts.admission import SourceAsset
from conscience_foundry.contracts.canonical import (
    REQUIRED_F1_CHECK_IDS,
    ExtractionSpec,
    OriginMap,
    QualityCheck,
    QualityReport,
    Section,
)
from conscience_foundry.contracts.common import ContractError, ContractLimits, Reason, WireModel
from conscience_foundry.core.spans import _decode_bounded_text
from conscience_foundry.storage.local import VerifiedBytes

F1_WHITESPACE_SCALARS = frozenset(
    (*range(0x0009, 0x000E), 0x0020, 0x0085, 0x00A0, 0x1680,
     *range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000)
)


@dataclass(frozen=True)
class CanonicalOutput:
    text: bytes
    sections: tuple[Section, ...]
    origin_map: OriginMap
    quality: QualityReport


def _bounded_output(record: WireModel, limits: ContractLimits) -> None:
    raw = record.model_dump_json(by_alias=True).encode("utf-8")
    if len(raw) > limits.max_output_bytes:
        raise ContractError("limit_exceeded")
    type(record).from_wire(raw, limits)


def process_text(
    asset: SourceAsset, data: VerifiedBytes, spec: ExtractionSpec, *,
    limits: ContractLimits, limits_bytes: bytes,
) -> CanonicalOutput:
    """Process already authorized custody bytes; do not dispatch or accept a release.

    The caller supplies the trusted admitted SourceAsset and pinned extraction
    recipe. Limits are bound here to their exact immutable bytes. No model,
    policy lookup, normalization, or source-path reread occurs.
    """
    if not isinstance(limits, ContractLimits):
        raise ContractError("limits_missing")
    reference = spec.limits_ref
    if reference.project_id != asset.project_id:
        raise ContractError("forbidden")
    if (
        reference.artifact_schema != "kf.contract-limits.v1"
        or reference.media_type != "application/json"
    ):
        raise ContractError("unsupported_schema")
    parsed = ContractLimits.from_wire(limits_bytes, limits)
    if parsed != limits:
        raise ContractError("invalid_schema")
    if (
        hashlib.sha256(limits_bytes).hexdigest() != reference.digest
        or len(limits_bytes) != reference.size_bytes
    ):
        raise ContractError("hash_mismatch")
    original = asset.original_ref
    if original.project_id != asset.project_id:
        raise ContractError("forbidden")
    if original.artifact_schema != "kf.raw-original.v1" or original.media_type != "text/plain":
        raise ContractError("unsupported_format")
    if not isinstance(data, VerifiedBytes) or not isinstance(data.data, bytes):
        raise ContractError("hash_mismatch")
    if len(data.data) > limits.max_source_bytes or len(data.data) > limits.max_output_bytes:
        raise ContractError("limit_exceeded")
    actual = hashlib.sha256(data.data).hexdigest()
    if actual != data.digest or actual != original.digest or len(data.data) != original.size_bytes:
        raise ContractError("hash_mismatch")
    if not data.data:
        raise ContractError("empty_text")
    if data.data.startswith(b"\xef\xbb\xbf"):
        raise ContractError("bom_rejected")
    decoded = _decode_bounded_text(data.data, limits)
    if "\x00" in decoded:
        raise ContractError("nul_rejected")
    whitespace_only = all(ord(character) in F1_WHITESPACE_SCALARS for character in decoded)
    checks = tuple(
        QualityCheck(
            check_id=name,
            outcome="fail" if name == "non_whitespace" and whitespace_only else "pass",
            **({"reason": Reason(code="whitespace_only", message="whitespace_only")}
               if name == "non_whitespace" and whitespace_only else {}),
        )
        for name in sorted(REQUIRED_F1_CHECK_IDS)
    )
    output = CanonicalOutput(
        text=data.data,
        sections=(Section(section_id="body", start=0, end=len(decoded)),),
        origin_map=OriginMap(
            schema_version="kf.origin-map.v1", kind="identity_utf8",
            original_digest=actual, text_digest=actual, offset_unit="unicode_scalar",
        ),
        quality=QualityReport(
            schema_version="kf.quality-report.v1", source_id=asset.source_id, checks=checks,
            disposition="needs_review" if whitespace_only else "valid",
        ),
    )
    for record in (*output.sections, output.origin_map, output.quality):
        _bounded_output(record, limits)
    return output
