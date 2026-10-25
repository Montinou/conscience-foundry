"""Synthetic text.utf8.v1 cases exercise production bytes and quality outputs."""

from __future__ import annotations

import hashlib

import pytest

from conscience_foundry.contracts.admission import SourceAsset
from conscience_foundry.contracts.canonical import ExtractionSpec
from conscience_foundry.contracts.common import ArtifactRef, ContractError, ContractLimits
from conscience_foundry.processing.text_utf8 import CanonicalOutput, process_text
from conscience_foundry.storage.local import VerifiedBytes

PROJECT = "00000000-0000-0000-0000-000000000001"
SOURCE = "00000000-0000-0000-0000-000000000002"
ASSET = "00000000-0000-0000-0000-000000000003"
OTHER = "00000000-0000-0000-0000-000000000004"
SAMPLE = "A😀e\u0301\r\nB".encode()


def limits(**changes: object) -> ContractLimits:
    return ContractLimits.model_validate(
        {
            "schemaVersion": "kf.contract-limits.v1",
            "version": "synthetic.text-limits.v1",
            "maxJsonBytes": 65536,
            "maxStringScalars": 1024,
            "maxArrayItems": 128,
            "maxDepth": 16,
            "maxManifestItems": 4,
            "maxSourceBytes": 65536,
            "maxOutputBytes": 65536,
            "maxErrorMessageScalars": 80,
        }
        | changes
    )


def ref(data: bytes, schema: str, media: str = "application/json") -> ArtifactRef:
    return ArtifactRef(
        schema_version="kf.artifact-ref.v1",
        project_id=PROJECT,
        digest=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        media_type=media,
        artifact_schema=schema,
        locations=(),
    )


def asset(data: bytes, *, source: str = SOURCE, asset_id: str = ASSET) -> SourceAsset:
    return SourceAsset(
        schema_version="kf.source-asset.v1",
        project_id=PROJECT,
        asset_id=asset_id,
        source_id=source,
        original_ref=ref(data, "kf.raw-original.v1", "text/plain"),
        admission_report_ref=ref(b"synthetic admission evidence", "kf.admission-report.v1"),
        metadata={},
    )


def spec(bound: ContractLimits, **changes: object) -> tuple[ExtractionSpec, bytes]:
    raw = bound.model_dump_json(by_alias=True).encode()
    value: dict[str, object] = {
        "schema_version": "kf.extraction-spec.v1",
        "processor_id": "text.utf8.v1",
        "processor_version": "synthetic.processor.v1",
        "code_version": "synthetic.code.v1",
        "image_digest": "a" * 64,
        "limits_ref": ref(raw, "kf.contract-limits.v1"),
        "normalization": "none",
        "newline_policy": "preserve",
        "bom_policy": "reject",
    }
    return ExtractionSpec.model_validate(value | changes), raw


def run(data: bytes, *, bound: ContractLimits | None = None) -> CanonicalOutput:
    bound = bound if bound is not None else limits()
    recipe, raw = spec(bound)
    return process_text(
        asset(data), VerifiedBytes(data, hashlib.sha256(data).hexdigest()), recipe,
        limits=bound, limits_bytes=raw,
    )


def test_unicode_crlf_exact_fixture_and_quality() -> None:
    output = run(SAMPLE)
    assert output.text == SAMPLE
    assert len(output.sections) == 1
    body = output.sections[0]
    assert (body.section_id, body.start, body.end) == ("body", 0, 7)
    assert body.parent_section_id is None and body.heading is None
    assert output.origin_map.kind == "identity_utf8"
    assert output.origin_map.original_digest == hashlib.sha256(SAMPLE).hexdigest()
    assert output.origin_map.text_digest == output.origin_map.original_digest
    assert output.quality.source_id == SOURCE
    assert output.quality.disposition == "valid"
    assert {check.check_id: check.outcome for check in output.quality.checks} == {
        name: "pass" for name in (
            "hash", "encoding", "nonempty", "no_NUL", "no_BOM", "bounds",
            "identity_mapping", "non_whitespace",
        )
    }


@pytest.mark.parametrize(
    ("data", "code"),
    [(b"\xef\xbb\xbftext", "bom_rejected"), (b"a\x00b", "nul_rejected"),
     (b"", "empty_text"), (b"\xff", "invalid_encoding"),
     (b"\xed\xa0\x80", "invalid_encoding")],
)
def test_processor_rejects_invalid_input(data: bytes, code: str) -> None:
    with pytest.raises(ContractError) as caught:
        run(data)
    assert caught.value.code == code
    assert str(caught.value) == code


def test_processor_rejects_overridden_byte_decoding() -> None:
    class FabricatedDecode(bytes):
        def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
            return "y"

    with pytest.raises(ContractError, match="invalid_encoding"):
        run(FabricatedDecode(b"\xff"))


def test_fixed_whitespace_and_interior_feff_policy() -> None:
    whitespace = "\t\n\v\f\r \u0085\u00a0\u1680" + "".join(
        chr(value) for value in range(0x2000, 0x200B)
    ) + "\u2028\u2029\u202f\u205f\u3000"
    output = run(whitespace.encode())
    assert output.text == whitespace.encode()
    assert output.quality.disposition == "needs_review"
    checks = {check.check_id: check for check in output.quality.checks}
    assert checks["non_whitespace"].outcome == "fail"
    assert checks["non_whitespace"].reason is not None
    assert checks["non_whitespace"].reason.code == "whitespace_only"
    # U+001C is a Python isspace() character outside the pinned processor set.
    assert run(b"\x1c").quality.disposition == "valid"
    interior = b"a\xef\xbb\xbfb"
    assert run(interior).text == interior


def test_same_bytes_keep_source_identity_and_actual_hash() -> None:
    bound = limits()
    recipe, raw = spec(bound)
    verified = VerifiedBytes(SAMPLE, hashlib.sha256(SAMPLE).hexdigest())
    a = process_text(asset(SAMPLE), verified, recipe, limits=bound, limits_bytes=raw)
    b = process_text(
        asset(SAMPLE, source=OTHER, asset_id=OTHER), verified, recipe,
        limits=bound, limits_bytes=raw,
    )
    assert a.origin_map.text_digest == b.origin_map.text_digest
    assert (a.quality.source_id, b.quality.source_id) == (SOURCE, OTHER)
    with pytest.raises(ContractError, match="hash_mismatch"):
        VerifiedBytes(b"changed", verified.digest)
    forged = object.__new__(VerifiedBytes)
    object.__setattr__(forged, "data", b"changed")
    object.__setattr__(forged, "digest", verified.digest)
    with pytest.raises(ContractError, match="hash_mismatch"):
        process_text(asset(SAMPLE), forged, recipe, limits=bound, limits_bytes=raw)
    with pytest.raises(ContractError, match="hash_mismatch"):
        process_text(asset(b"different"), verified, recipe, limits=bound, limits_bytes=raw)


@pytest.mark.parametrize(
    ("data", "bound"),
    [(SAMPLE, limits(maxSourceBytes=10)), (SAMPLE, limits(maxOutputBytes=10)),
     (b"x" * 65, limits(maxStringScalars=64))],
)
def test_processor_enforces_explicit_byte_and_scalar_limits(
    data: bytes, bound: ContractLimits,
) -> None:
    with pytest.raises(ContractError, match="limit_exceeded"):
        run(data, bound=bound)


def test_limits_pin_and_original_role_are_verified() -> None:
    bound = limits()
    recipe, raw = spec(bound)
    verified = VerifiedBytes(SAMPLE, hashlib.sha256(SAMPLE).hexdigest())
    with pytest.raises(ContractError, match="hash_mismatch"):
        process_text(asset(SAMPLE), verified, recipe, limits=bound, limits_bytes=raw + b" ")
    changed_bound = limits(maxSourceBytes=100)
    with pytest.raises(ContractError):
        process_text(asset(SAMPLE), verified, recipe, limits=changed_bound, limits_bytes=raw)
    wrong_role = asset(SAMPLE).model_copy(update={
        "original_ref": ref(SAMPLE, "kf.canonical-text.v1", "text/plain")
    })
    with pytest.raises(ContractError, match="unsupported_format"):
        process_text(wrong_role, verified, recipe, limits=bound, limits_bytes=raw)
    wrong_project = recipe.model_copy(update={
        "limits_ref": recipe.limits_ref.model_copy(update={"project_id": OTHER})
    })
    with pytest.raises(ContractError, match="forbidden"):
        process_text(asset(SAMPLE), verified, wrong_project, limits=bound, limits_bytes=raw)


@pytest.mark.parametrize("bound", [limits(maxArrayItems=7), limits(maxOutputBytes=400)])
def test_generated_quality_respects_configured_structured_limits(bound: ContractLimits) -> None:
    with pytest.raises(ContractError, match="limit_exceeded"):
        run(b"text", bound=bound)
