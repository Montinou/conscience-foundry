"""Public synthetic contract tests; no corpus or provider connection."""

import hashlib
import socket
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from conftest import deny_network
from pydantic import TypeAdapter, ValidationError

from conscience_foundry.contracts.codec import hash_jcs, load_json
from conscience_foundry.contracts.common import (
    ArtifactLocation,
    ArtifactRef,
    ContractError,
    ContractLimits,
    Digest,
    Id,
    Instant,
    Money,
    Reason,
    Version,
)

ORIGINAL_CREATE_CONNECTION = socket.create_connection


def limits(**overrides: int) -> ContractLimits:
    fields = {
        "schemaVersion": "kf.contract-limits.v1",
        "version": "synthetic.limits.v1",
        "maxJsonBytes": 4096,
        "maxStringScalars": 256,
        "maxArrayItems": 8,
        "maxDepth": 4,
        "maxManifestItems": 8,
        "maxSourceBytes": 4096,
        "maxOutputBytes": 4096,
        "maxErrorMessageScalars": 80,
    }
    fields.update(overrides)
    return ContractLimits.model_validate(fields)


def test_duplicate_depth_and_numeric_rejection() -> None:
    invalid = [b'{"a":1,"a":2}', b'{"a":[[[[0]]]]}', b'{"n":1.0}', b'{"n":9007199254740992}']
    codes = []
    for data in invalid:
        with pytest.raises(ContractError) as exc:
            load_json(data, limits())
        codes.append(exc.value.code)
    assert codes == ["invalid_schema"] * 4


def test_unicode_and_decimal_wire_rules() -> None:
    assert load_json(b'{"s":"\\ud83d\\ude00"}', limits()) == {"s": "😀"}
    for data in (
        b'{"s":"\\ud800"}',
        b'{"s":"\\udfff"}',
        b'{"n":-1}',
        b'{"n":NaN}',
        b'{"n":Infinity}',
        b'{"n":1e0}',
        b'{"n":-0}',
    ):
        with pytest.raises(ContractError):
            load_json(data, limits())
    for value in ("-1", "1.1234567890", "1e2", 1, 1.0, True, " 1"):
        with pytest.raises(ValidationError):
            TypeAdapter(Money).validate_python(value)
    for value in ("0", "1.00", "0.123456789", "01.2"):
        assert TypeAdapter(Money).validate_python(value) == value
    with pytest.raises(ValidationError):
        Reason.model_validate({"code": "invalid_schema", "message": None})


def test_parser_bounds_and_safe_errors() -> None:
    for data, kwargs in [
        (b'{"a":1}', {"maxJsonBytes": 2}),
        (b'{"a":[0,1]}', {"maxArrayItems": 1}),
        (b'{"a":"abcdef"}', {"maxStringScalars": 5}),
    ]:
        with pytest.raises(ContractError):
            load_json(data, limits(**kwargs))
    for data in (
        b"[]",
        b"null",
        b"1",
        b'{"private":"secret",}',
        b"\xff",
        b"\xef\xbb\xbf{}",
        b"{} {}",
    ):
        with pytest.raises(ContractError) as exc:
            load_json(data, limits())
        assert "secret" not in str(exc.value)
    assert load_json(b'{"s":"{[\\"} ]","n":9007199254740991}', limits()) == {
        "s": '{["} ]',
        "n": 9007199254740991,
    }
    assert load_json(b'{"a":{"b":0}}', limits(maxDepth=2)) == {"a": {"b": 0}}


def test_common_scalar_contracts() -> None:
    assert TypeAdapter(Id).validate_python("00000000-0000-0000-0000-000000000001")
    assert TypeAdapter(Digest).validate_python("a" * 64)
    for annotation, value in [
        (Id, "00000000-0000-0000-0000-00000000000A"),
        (Digest, "A" * 64),
        (Version, ""),
        (Version, "\ud800"),
        (Instant, "2026-02-30T00:00:00.000Z"),
        (Instant, "2026-10-25T00:00:00Z"),
        (Instant, "2026-10-25T00:00:00.000+00:00"),
    ]:
        with pytest.raises(ValidationError):
            TypeAdapter(annotation).validate_python(value)
    assert TypeAdapter(Instant).validate_python("2026-10-25T00:00:00.123Z")
    with pytest.raises(ValidationError):
        ContractLimits.model_validate({})
    for bad in (0, -1, True, 1.0, "4", 9007199254740992):
        with pytest.raises(ValidationError):
            limits(maxDepth=bad)


def test_artifact_locations_and_strict_common_models() -> None:
    location = {"storeId": "synthetic", "objectKey": "sha256/abc"}
    ref = {
        "schemaVersion": "kf.artifact-ref.v1",
        "projectId": "00000000-0000-0000-0000-000000000001",
        "digest": "a" * 64,
        "sizeBytes": 0,
        "mediaType": "text/plain",
        "artifactSchema": "raw.utf8.v1",
        "locations": [location],
    }
    assert ArtifactRef.model_validate(ref).size_bytes == 0
    for update in (
        {"extra": 1},
        {"sizeBytes": True},
        {"sizeBytes": None},
        {"mediaType": "\ud800"},
        {"schemaVersion": "kf.artifact-ref.v2"},
    ):
        with pytest.raises(ValidationError):
            ArtifactRef.model_validate(ref | update)
    for key in (
        "../x",
        "/x",
        "x//y",
        "x/./y",
        "x\\y",
        "C:/x",
        "x\x00y",
        "https://example.invalid/x",
    ):
        with pytest.raises(ValidationError):
            ArtifactLocation.model_validate(location | {"objectKey": key})
    with pytest.raises(ValidationError):
        Reason.model_validate({"code": "invented_unregistered", "message": "Synthetic"})
    with pytest.raises(ContractError):
        Reason.from_wire(
            b'{"code":"invalid_schema","message":"too long"}', limits(maxErrorMessageScalars=3)
        )
    with pytest.raises(ContractError):
        ArtifactRef.model_validate_json(b"{}")


def test_jcs_canonical_bytes_domain_and_unicode() -> None:
    value = {"\ue000": "1.00", "\U00010000": [True, 0, "😀"], "a": "e\u0301"}
    canonical = '{"a":"é","𐀀":[true,0,"😀"],"":"1.00"}'.encode()
    assert (
        hash_jcs("synthetic.v1", value) == hashlib.sha256(b"synthetic.v1\n" + canonical).hexdigest()
    )
    assert hash_jcs("other.v1", value) != hash_jcs("synthetic.v1", value)
    assert hash_jcs("synthetic.v1", {"a": "é"}) != hash_jcs("synthetic.v1", {"a": "é"})
    for invalid in ({"n": 1.0}, {"n": -1}, {"n": 9007199254740992}, {"s": "\ud800"}):
        with pytest.raises(ContractError):
            hash_jcs("synthetic.v1", invalid)
    for domain in ("", "synthetic.v1\n", "\ud800"):
        with pytest.raises(ContractError):
            hash_jcs(domain, {})


def test_external_network_is_denied_by_default() -> None:
    with pytest.raises(RuntimeError, match="Network access is disabled"):
        socket.create_connection(("example.invalid", 443))


def test_cyclic_python_values_and_wire_aliases_are_rejected() -> None:
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    with pytest.raises(ContractError):
        hash_jcs("synthetic.v1", cyclic)
    with pytest.raises(ContractError):
        ContractLimits.from_wire(b'{"schema_version":"kf.contract-limits.v1"}', limits())
    with pytest.raises(RuntimeError, match="Network access is disabled"):
        socket.getaddrinfo("example.invalid", 443)


def test_timestamp_schema_and_trusted_nested_construction() -> None:
    assert "pattern" in TypeAdapter(Instant).json_schema()
    location = ArtifactLocation(store_id="synthetic", object_key="sha256/abc")
    ref = ArtifactRef(
        schema_version="kf.artifact-ref.v1",
        project_id="00000000-0000-0000-0000-000000000001",
        digest="a" * 64,
        size_bytes=1,
        media_type="text/plain",
        artifact_schema="raw.utf8.v1",
        locations=[location],
    )
    assert ref.locations == (location,)


def test_accepted_artifact_locations_cannot_be_mutated() -> None:
    location = ArtifactLocation(store_id="synthetic", object_key="sha256/abc")
    ref = ArtifactRef(
        schema_version="kf.artifact-ref.v1",
        project_id="00000000-0000-0000-0000-000000000001",
        digest="a" * 64,
        size_bytes=1,
        media_type="text/plain",
        artifact_schema="raw.utf8.v1",
        locations=[location],
    )
    assert isinstance(ref.locations, tuple)
    with pytest.raises(AttributeError):
        ref.locations.append({"unvalidated": True})
    with pytest.raises(TypeError):
        ref.locations[0] = {"unvalidated": True}
    assert ref.model_dump(mode="json", by_alias=True)["locations"] == [
        {"storeId": "synthetic", "objectKey": "sha256/abc"}
    ]
    assert ArtifactRef.from_wire(ref.model_dump_json(by_alias=True).encode(), limits()) == ref


def test_all_dns_entry_points_are_denied_without_resolver_io() -> None:
    for resolve in (socket.gethostbyname, socket.gethostbyname_ex, socket.gethostbyaddr):
        # A numeric local address makes this a safe regression even before the fix.
        with pytest.raises(RuntimeError, match="Network access is disabled"):
            resolve("127.0.0.1")
    with pytest.raises(RuntimeError, match="Network access is disabled"):
        socket.getnameinfo(("127.0.0.1", 443), socket.NI_NUMERICHOST | socket.NI_NUMERICSERV)


def test_database_guard_permits_only_approved_private_socket(tmp_path: Path) -> None:
    connections: list[object] = []

    def connect(sock: socket.socket, address: object) -> None:
        connections.append(address)

    request = cast(
        pytest.FixtureRequest,
        SimpleNamespace(node=SimpleNamespace(get_closest_marker=lambda name: object())),
    )
    tmp_path.chmod(0o700)
    dsn = f"dbname=cf_test_guard user=synthetic host={tmp_path}"
    address = str(tmp_path / ".s.PGSQL.5432")
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("CF_TEST_POSTGRES_DSN", dsn)
        patch.setenv("CF_TEST_POSTGRES_APPROVED_DSN", dsn)
        patch.setattr(socket.socket, "connect", connect)
        guard = deny_network.__wrapped__(request, patch)
        next(guard)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.connect(address)
                assert sock.connect_ex(address) == 0
                with pytest.raises(RuntimeError, match="Network access is disabled"):
                    sock.connect(str(tmp_path / ".s.PGSQL.5433"))
            with socket.socket() as sock:
                with pytest.raises(RuntimeError, match="Network access is disabled"):
                    sock.connect(("127.0.0.1", 5432))
            with pytest.raises(RuntimeError, match="Network access is disabled"):
                socket.create_connection(("db.example.invalid", 5432))
            with pytest.raises(RuntimeError, match="Network access is disabled"):
                socket.getaddrinfo("db.example.invalid", 5432)
            assert connections == [address, address]
        finally:
            guard.close()
