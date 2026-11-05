import json

import pytest

from conscience_foundry.contracts.common import ContractError, ContractLimits
from conscience_foundry.enrichment.schema import validate_payload


@pytest.fixture
def limits():
    return ContractLimits(
        schemaVersion="cf.contract-limits.v1",
        version="1",
        maxJsonBytes=4096,
        maxStringScalars=128,
        maxArrayItems=16,
        maxDepth=12,
        maxManifestItems=16,
        maxSourceBytes=4096,
        maxOutputBytes=4096,
        maxErrorMessageScalars=128,
    )


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def test_valid_bounded_object_and_invalid_payload(limits):
    schema = {
        "type": "object",
        "properties": {"name": {"type": "string", "maxLength": 8}},
        "required": ["name"],
        "additionalProperties": False,
    }
    assert validate_payload(encoded(schema), encoded({"name": "hello"}), limits=limits) == {
        "name": "hello"
    }
    with pytest.raises(ContractError):
        validate_payload(encoded(schema), encoded({"name": "too long!"}), limits=limits)


@pytest.mark.parametrize(
    "schema",
    [
        {"$ref": "file:///etc/passwd", "type": "object", "additionalProperties": False},
        {
            "type": "object",
            "properties": {"x": {"type": "string", "pattern": "a+", "maxLength": 8}},
            "additionalProperties": False,
        },
        {"type": "object", "properties": {"x": {"type": "string"}}, "additionalProperties": False},
        {"type": "array", "items": {"type": "string", "maxLength": 3}, "maxItems": 2},
        {
            "type": "object",
            "properties": {"x": {"type": "array", "items": {"type": "string", "maxLength": 3}}},
            "additionalProperties": False,
        },
        {"type": "object", "additionalProperties": True},
    ],
)
def test_disallowed_or_unbounded_schema_refused(limits, schema):
    with pytest.raises(ContractError):
        validate_payload(encoded(schema), b"{}", limits=limits)


def test_private_schema_requires_exact_trusted_registry(limits):
    import hashlib

    from conscience_foundry.contracts.common import ArtifactLocation, Ref
    from conscience_foundry.contracts.registry import validate_artifact
    from conscience_foundry.contracts.task_schema_registry import TaskSchemaRegistry

    schema = encoded(
        {
            "type": "object",
            "properties": {"name": {"type": "string", "maxLength": 8}},
            "additionalProperties": False,
        }
    )
    project = "00000000-0000-0000-0000-000000000001"
    ref = Ref(
        schema_version="cf.artifact-ref.v1",
        project_id=project,
        digest=hashlib.sha256(schema).hexdigest(),
        size_bytes=len(schema),
        media_type="application/json",
        artifact_schema="json-schema.2020-12",
        locations=(ArtifactLocation(store_id="test", object_key="schema"),),
    )
    schema_limits = {"json-schema.2020-12": limits}
    with pytest.raises(ContractError):
        validate_artifact(ref, schema, limits_by_schema=schema_limits)
    registry = TaskSchemaRegistry(
        project_id=project,
        spec_ref=ref.model_copy(update={"artifact_schema": "cf.enrichment-spec.v1"}),
        installation_ref=ref.model_copy(
            update={"artifact_schema": "cf.enrichment-schema-installation.v1"}
        ),
        schemas=((ref, schema),),
    )
    assert (
        validate_artifact(ref, schema, limits_by_schema=schema_limits, task_schemas=registry)[
            "type"
        ]
        == "object"
    )
    with pytest.raises(ContractError):
        validate_artifact(
            ref.model_copy(update={"project_id": "00000000-0000-0000-0000-000000000002"}),
            schema,
            limits_by_schema=schema_limits,
            task_schemas=registry,
        )


def test_no_external_resolution_even_for_nested_ref(limits, monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("network should not be used")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    schema = {
        "type": "object",
        "properties": {"x": {"$ref": "https://invalid.example/schema"}},
        "additionalProperties": False,
    }
    with pytest.raises(ContractError):
        validate_payload(encoded(schema), b"{}", limits=limits)


def test_reject_deep_schema_and_oversized_payload(limits):
    schema = {"type": "object", "additionalProperties": False}
    for _ in range(12):
        schema = {"type": "object", "properties": {"child": schema}, "additionalProperties": False}
    with pytest.raises(ContractError):
        validate_payload(encoded(schema), b"{}", limits=limits)
    schema = {"type": "object", "additionalProperties": False}
    with pytest.raises(ContractError):
        validate_payload(encoded(schema), b"{" + b" " * 4096 + b"}", limits=limits)


def test_opaque_tariff_requires_bounded_verified_bytes(limits):
    import hashlib
    from types import SimpleNamespace

    from conscience_foundry.contracts.common import Ref
    from conscience_foundry.enrichment.registration import _read_opaque_tariff
    from conscience_foundry.policy.access import AccessContext

    project = "00000000-0000-0000-0000-000000000001"
    actor = "00000000-0000-0000-0000-000000000002"
    data = b"synthetic tariff bytes"
    ref = Ref(
        schema_version="cf.artifact-ref.v1",
        project_id=project,
        digest=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        media_type="application/octet-stream",
        artifact_schema="operator.tariff.v1",
        locations=(),
    )

    class Store:
        raw = data

        def read_verified(self, ref, access, ceiling):
            return SimpleNamespace(data=self.raw, digest=hashlib.sha256(self.raw).hexdigest())

    store = Store()
    context = SimpleNamespace(
        access=AccessContext(project, actor, frozenset()),
        store=store,
        limits_by_schema={"operator.tariff.v1": limits},
    )
    assert _read_opaque_tariff(ref, context) == data
    store.raw = b"tampered"
    with pytest.raises(ContractError, match="hash_mismatch"):
        _read_opaque_tariff(ref, context)
    store.raw = data
    with pytest.raises(ContractError, match="forbidden"):
        _read_opaque_tariff(ref.model_copy(update={"project_id": actor}), context)
    with pytest.raises(ContractError, match="limit_exceeded"):
        _read_opaque_tariff(ref.model_copy(update={"size_bytes": 99999}), context)
    context.limits_by_schema.clear()
    with pytest.raises(ContractError, match="limits_missing"):
        _read_opaque_tariff(ref, context)
    malformed = b"{}"
    store.raw = malformed
    context.limits_by_schema["cf.contract-limits.v1"] = limits
    known = ref.model_copy(
        update={
            "artifact_schema": "cf.contract-limits.v1",
            "media_type": "application/json",
            "digest": hashlib.sha256(malformed).hexdigest(),
            "size_bytes": len(malformed),
        }
    )
    with pytest.raises(ContractError):
        _read_opaque_tariff(known, context)


def test_private_metadata_slot_verifies_bytes_and_known_core_semantics(limits):
    import hashlib
    from types import SimpleNamespace

    from conscience_foundry.contracts.common import Ref
    from conscience_foundry.enrichment.registration import _read_spec_metadata
    from conscience_foundry.policy.access import AccessContext

    project = "00000000-0000-0000-0000-000000000001"
    actor = "00000000-0000-0000-0000-000000000002"
    raw = b"opaque private runtime specification"
    ref = Ref(
        schema_version="cf.artifact-ref.v1",
        project_id=project,
        digest=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        media_type="application/octet-stream",
        artifact_schema="private.runtime.v1",
        locations=(),
    )

    class Store:
        value = raw

        def read_verified(self, ref, access, ceiling):
            return SimpleNamespace(data=self.value, digest=hashlib.sha256(self.value).hexdigest())

    store = Store()
    context = SimpleNamespace(
        access=AccessContext(project, actor, frozenset()),
        store=store,
        limits_by_schema={"private.runtime.v1": limits, "cf.contract-limits.v1": limits},
        clock=lambda: "2026-10-25T00:00:00.000Z",
        output_store_id="test",
        current_policy=lambda: None,
    )
    assert _read_spec_metadata(ref, context) == raw
    store.value = b"forged"
    with pytest.raises(ContractError, match="hash_mismatch"):
        _read_spec_metadata(ref, context)
    store.value = raw
    with pytest.raises(ContractError, match="forbidden"):
        _read_spec_metadata(ref.model_copy(update={"project_id": actor}), context)
    del context.limits_by_schema["private.runtime.v1"]
    with pytest.raises(ContractError, match="limits_missing"):
        _read_spec_metadata(ref, context)
    bad = b"{}"
    store.value = bad
    known = ref.model_copy(
        update={
            "artifact_schema": "cf.contract-limits.v1",
            "media_type": "application/json",
            "digest": hashlib.sha256(bad).hexdigest(),
            "size_bytes": len(bad),
        }
    )
    with pytest.raises(ContractError):
        _read_spec_metadata(known, context)


def test_metadata_and_tariff_refuse_known_content_before_read(limits):
    import hashlib
    from types import SimpleNamespace

    from conscience_foundry.contracts.common import Ref
    from conscience_foundry.enrichment.registration import _read_opaque_tariff, _read_spec_metadata
    from conscience_foundry.policy.access import AccessContext

    project = "00000000-0000-0000-0000-000000000001"
    actor = "00000000-0000-0000-0000-000000000002"
    ref = Ref(
        schema_version="cf.artifact-ref.v1",
        project_id=project,
        digest=hashlib.sha256(b"data").hexdigest(),
        size_bytes=4,
        media_type="text/plain",
        artifact_schema="cf.canonical-text.v1",
        locations=(),
    )

    class Store:
        def read_verified(self, ref, access, ceiling):
            raise AssertionError("content read before source authorization")

    context = SimpleNamespace(
        access=AccessContext(project, actor, frozenset()),
        store=Store(),
        limits_by_schema={"cf.canonical-text.v1": limits},
        clock=lambda: "2026-10-25T00:00:00.000Z",
        output_store_id="test",
        current_policy=lambda: None,
    )
    for read in (_read_opaque_tariff, _read_spec_metadata):
        with pytest.raises(ContractError, match="forbidden"):
            read(ref, context)


def test_output_byte_ceiling_is_enforced_independently(limits):
    bounded = limits.model_copy(update={"max_output_bytes": 100})
    schema = encoded(
        {
            "type": "object",
            "properties": {"x": {"type": "string", "maxLength": 128}},
            "additionalProperties": False,
        }
    )
    payload = encoded({"x": "a" * 110})
    with pytest.raises(ContractError, match="limit_exceeded"):
        validate_payload(schema, payload, limits=bounded)


def test_ref_hidden_in_inapplicable_schema_keyword_is_rejected(limits):
    schema = {
        "type": "object",
        "additionalProperties": False,
        "items": {"$ref": "https://invalid.example/schema"},
    }
    with pytest.raises(ContractError):
        validate_payload(encoded(schema), b"{}", limits=limits)
