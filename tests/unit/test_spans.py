"""Generic exact scalar coordinates use synthetic canonical text only."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator

import pytest

from conscience_foundry.contracts.canonical import DocumentRevision, DocumentSpan
from conscience_foundry.contracts.common import ContractError, ContractLimits
from conscience_foundry.core.spans import (
    bytes_to_scalar,
    check_exact_quote,
    scalar_to_bytes,
    scalar_to_utf16,
    utf16_to_scalar,
)
from conscience_foundry.storage.local import VerifiedBytes

PROJECT = "00000000-0000-0000-0000-000000000001"
SOURCE = "00000000-0000-0000-0000-000000000002"
ASSET = "00000000-0000-0000-0000-000000000003"
OTHER = "00000000-0000-0000-0000-000000000004"
REVISION = "b" * 64
SAMPLE = "A😀e\u0301\r\nB".encode()


def limits(**changes: object) -> ContractLimits:
    return ContractLimits.model_validate({
        "schemaVersion": "kf.contract-limits.v1", "version": "synthetic.spans.v1",
        "maxJsonBytes": 65536, "maxStringScalars": 1024, "maxArrayItems": 128,
        "maxDepth": 16, "maxManifestItems": 4, "maxSourceBytes": 65536,
        "maxOutputBytes": 65536, "maxErrorMessageScalars": 80,
    } | changes)


def reference(data: bytes, schema: str = "synthetic.v1") -> dict[str, object]:
    return {
        "schemaVersion": "kf.artifact-ref.v1", "projectId": PROJECT,
        "digest": hashlib.sha256(data).hexdigest(), "sizeBytes": len(data),
        "mediaType": "text/plain" if schema == "kf.canonical-text.v1" else "application/json",
        "artifactSchema": schema, "locations": [],
    }


def revision(data: bytes, **changes: object) -> DocumentRevision:
    return DocumentRevision.model_validate({
        "schemaVersion": "kf.document-revision.v1", "projectId": PROJECT,
        "sourceId": SOURCE, "assetId": ASSET, "revisionId": REVISION,
        "originalRef": reference(data), "textRef": reference(data, "kf.canonical-text.v1"),
        "extractionSpecRef": reference(b"synthetic extraction"),
        "textEncoding": "utf-8", "offsetUnit": "unicode_scalar",
        "sections": [{"sectionId": "body", "start": 0, "end": len(data.decode())}],
        "originMapRef": reference(b"synthetic map"),
        "qualityReportRef": reference(b"synthetic quality"),
    } | changes)


def span(first: int, last: int, **changes: object) -> DocumentSpan:
    return DocumentSpan.model_validate({
        "schemaVersion": "kf.document-span.v1", "projectId": PROJECT,
        "sourceId": SOURCE, "revisionId": REVISION, "sectionId": "body",
        "start": first, "end": last, "offsetUnit": "unicode_scalar",
    } | changes)


def test_unicode_crlf_exact_fixture_and_reverse_roundtrips() -> None:
    bound = limits()
    byte_prefixes = [0, 1, 5, 6, 8, 9, 10, 11]
    utf16_prefixes = [0, 1, 3, 4, 5, 6, 7, 8]
    for start in range(8):
        for end in range(start, 8):
            byte_bounds = scalar_to_bytes(SAMPLE, start, end, limits=bound)
            utf16_bounds = scalar_to_utf16(SAMPLE, start, end, limits=bound)
            assert byte_bounds == (byte_prefixes[start], byte_prefixes[end])
            assert utf16_bounds == (utf16_prefixes[start], utf16_prefixes[end])
            assert bytes_to_scalar(SAMPLE, *byte_bounds, limits=bound) == (start, end)
            assert utf16_to_scalar(SAMPLE, *utf16_bounds, limits=bound) == (start, end)
    with pytest.raises(ContractError, match="invalid_span"):
        bytes_to_scalar(SAMPLE, 2, 5, limits=bound)
    with pytest.raises(ContractError, match="invalid_span"):
        utf16_to_scalar(SAMPLE, 2, 3, limits=bound)


@pytest.mark.parametrize("start,end", [(-1, 1), (2, 1), (0, 8), (True, 2), (0, 1.0)])
def test_coordinates_reject_invalid_bounds_without_coercion(start: int, end: int) -> None:
    for converter in (scalar_to_bytes, scalar_to_utf16):
        with pytest.raises(ContractError, match="invalid_span"):
            converter(SAMPLE, start, end, limits=limits())


def test_converters_reject_malformed_or_oversized_text() -> None:
    for converter in (scalar_to_bytes, scalar_to_utf16, bytes_to_scalar, utf16_to_scalar):
        with pytest.raises(ContractError, match="invalid_encoding"):
            converter(b"\xff", 0, 1, limits=limits())
        with pytest.raises(ContractError, match="limit_exceeded"):
            converter(SAMPLE, 0, 1, limits=limits(maxOutputBytes=10))
        with pytest.raises(ContractError, match="limit_exceeded"):
            converter(SAMPLE, 0, 1, limits=limits(maxStringScalars=6))


def test_exact_quote_checks_requested_occurrence_and_normalization() -> None:
    data = b"abc abc"
    verified = VerifiedBytes(data, hashlib.sha256(data).hexdigest())
    rev = revision(data)
    check_exact_quote(verified, span(4, 7), "abc", revision=rev, limits=limits())
    with pytest.raises(ContractError, match="invalid_span"):
        check_exact_quote(verified, span(3, 6), "abc", revision=rev, limits=limits())
    decomposed = "e\u0301".encode()
    exact = VerifiedBytes(decomposed, hashlib.sha256(decomposed).hexdigest())
    check_exact_quote(exact, span(1, 2), "\u0301", revision=revision(decomposed), limits=limits())
    with pytest.raises(ContractError, match="invalid_span"):
        check_exact_quote(exact, span(0, 2), "é", revision=revision(decomposed), limits=limits())
    with pytest.raises(ContractError, match="invalid_encoding"):
        check_exact_quote(verified, span(4, 7), "\ud800", revision=rev, limits=limits())


def test_exact_quote_rejects_overridden_byte_decoding() -> None:
    class FabricatedDecode(bytes):
        def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
            return "y"

    actual = b"x"
    verified = VerifiedBytes(FabricatedDecode(actual), hashlib.sha256(actual).hexdigest())
    with pytest.raises(ContractError, match="invalid_encoding"):
        check_exact_quote(verified, span(0, 1), "y", revision=revision(actual), limits=limits())


def test_exact_quote_binds_revision_section_and_actual_text() -> None:
    verified = VerifiedBytes(SAMPLE, hashlib.sha256(SAMPLE).hexdigest())
    rev = revision(SAMPLE)
    for changes in ({"projectId": OTHER}, {"sourceId": OTHER}, {"revisionId": "c" * 64}):
        with pytest.raises(ContractError, match="revision_mismatch"):
            check_exact_quote(verified, span(1, 2, **changes), "😀", revision=rev, limits=limits())
    for changes in ({"sectionId": "missing"}, {"start": 7, "end": 8}):
        with pytest.raises(ContractError, match="invalid_span"):
            check_exact_quote(verified, span(1, 2, **changes), "😀", revision=rev, limits=limits())
    wrong_bytes = VerifiedBytes(b"wrong", hashlib.sha256(b"wrong").hexdigest())
    with pytest.raises(ContractError, match="hash_mismatch"):
        check_exact_quote(wrong_bytes, span(1, 2), "😀", revision=rev, limits=limits())
    nested = revision(SAMPLE, sections=[
        {"sectionId": "parent", "start": 0, "end": 7},
        {"sectionId": "child", "parentSectionId": "parent", "start": 1, "end": 4},
    ])
    check_exact_quote(
        verified, span(1, 2, sectionId="child"), "😀", revision=nested, limits=limits(),
    )


def test_quote_length_ceiling_precedes_scalar_scan() -> None:
    class GuardedQuote(str):
        def __iter__(self) -> Iterator[str]:
            raise AssertionError("oversized quote scanned before configured length bound")

    verified = VerifiedBytes(SAMPLE, hashlib.sha256(SAMPLE).hexdigest())
    with pytest.raises(ContractError, match="limit_exceeded"):
        check_exact_quote(
            verified, span(1, 2), GuardedQuote("x" * 1025),
            revision=revision(SAMPLE), limits=limits(),
        )


def test_empty_coordinate_mapping_is_not_empty_evidence() -> None:
    for converter in (scalar_to_bytes, scalar_to_utf16, bytes_to_scalar, utf16_to_scalar):
        assert converter(b"", 0, 0, limits=limits()) == (0, 0)
        with pytest.raises(ContractError, match="invalid_span"):
            converter(b"", 0, 1, limits=limits())


def test_quote_requires_canonical_artifact_role_and_bounded_section() -> None:
    verified = VerifiedBytes(SAMPLE, hashlib.sha256(SAMPLE).hexdigest())
    for change in ({"artifactSchema": "kf.raw-original.v1"}, {"mediaType": "application/json"}):
        rev = revision(SAMPLE, textRef=reference(SAMPLE, "kf.canonical-text.v1") | change)
        with pytest.raises(ContractError, match="unsupported_format"):
            check_exact_quote(verified, span(1, 2), "😀", revision=rev, limits=limits())
    wrong_size = revision(SAMPLE, textRef=reference(SAMPLE, "kf.canonical-text.v1") | {
        "sizeBytes": len(SAMPLE) + 1,
    })
    with pytest.raises(ContractError, match="hash_mismatch"):
        check_exact_quote(verified, span(1, 2), "😀", revision=wrong_size, limits=limits())
    out_of_text = revision(SAMPLE, sections=[{"sectionId": "body", "start": 0, "end": 8}])
    with pytest.raises(ContractError, match="invalid_span"):
        check_exact_quote(verified, span(1, 2), "😀", revision=out_of_text, limits=limits())


def test_zero_width_joiner_and_crlf_keep_individual_scalar_boundaries() -> None:
    text = "👩\u200d🚀\r\n".encode()
    assert scalar_to_bytes(text, 1, 2, limits=limits()) == (4, 7)
    assert scalar_to_utf16(text, 1, 2, limits=limits()) == (2, 3)
    assert bytes_to_scalar(text, 7, 11, limits=limits()) == (2, 3)
    assert utf16_to_scalar(text, 5, 6, limits=limits()) == (3, 4)
    assert scalar_to_bytes(text, 3, 4, limits=limits()) == (11, 12)
