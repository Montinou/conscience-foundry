"""A second synthetic profile admits metadata against its own pinned schema file."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from conftest import approved_database_dsn
from test_cli import (
    ADMIT_ASSET_B,
    SOURCE_A,
    Env,
    admit_environment,
    count,
    intake,
    write_private,
)
from test_ledger_db import (
    ASSET,
    BATCH,
    PROJECT,
    TIME,
    admission,
    encoded,
    limits,
    reference,
)

from conscience_foundry.cli.config import TrustedServices
from conscience_foundry.contracts.common import ArtifactRef
from conscience_foundry.contracts.project import ProfileDescriptor, ProjectConfig
from conscience_foundry.contracts.registry import (
    export_schemas,
    registered_schema_ids,
)
from conscience_foundry.ledger.db import Ledger

PROFILE_ID = "shelf_catalog"
SCHEMA_ID = "cf.metadata-schema.v1"
SHELF_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["shelfKey", "lang", "provenance"],
    "properties": {
        "shelfKey": {"type": "string", "maxLength": 32, "pattern": "^[a-z0-9-]+$"},
        "lang": {"type": "string", "maxLength": 2, "enum": ["en", "es"]},
        "provenance": {
            "type": "object",
            "additionalProperties": False,
            "required": ["origin"],
            "properties": {
                "origin": {"type": "string", "maxLength": 16},
                "year": {"type": "integer", "minimum": 0, "maximum": 3000},
            },
        },
    },
}
SHELF_BYTES = json.dumps(SHELF_SCHEMA, separators=(",", ":")).encode()
VALID_METADATA: dict[str, Any] = {
    "shelfKey": "shelf-1",
    "lang": "en",
    "provenance": {"origin": "synthetic", "year": 1999},
}
SERVICES = TrustedServices(clock=lambda: TIME)


def profile_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ledger: Ledger,
    *,
    schema_file: bytes | None = SHELF_BYTES,
    profile_ref: ArtifactRef | None = None,
) -> tuple[Env, Path]:
    """A project on the second profile; `schema_file=None` configures no schema path."""
    bound = limits()
    schemas = dict.fromkeys(registered_schema_ids(), bound)
    policy = admission().evidence.pinned_policy
    policy_bytes = policy.model_dump_json(by_alias=True).encode()
    bundle = export_schemas(
        tmp_path / "schemas",
        project_id=PROJECT,
        store_id="synthetic",
        version="synthetic.contract-set.v1",
        limits_by_schema=schemas,
    )
    pinned = profile_ref if profile_ref is not None else reference(SHELF_BYTES, SCHEMA_ID)
    profile = ProfileDescriptor(
        schema_version="cf.profile.v1",
        profile_id=PROFILE_ID,
        version="synthetic.profile.v1",
        metadata_schema_ref=pinned,
        allowed_processor_ids=("text.utf8.v1",),
        extension_schema_refs=(),
        export_adapters=(),
    )
    project = ProjectConfig(
        schema_version="cf.project.v1",
        project_id=PROJECT,
        profile_id=PROFILE_ID,
        profile_version="synthetic.profile.v1",
        policy_ref=reference(policy_bytes, "cf.policy.v1"),
        limits_refs=(reference(b"{}", "cf.contract-limits.v1"),),
        contract_set_ref=reference(encoded(bundle), "cf.contract-set.v1"),
        storage_config_ref=reference(b"{}", "cf.storage-config.v1"),
        execution_config_ref=reference(b"{}", "cf.execution-config.v1"),
    )
    env = Env(
        tmp_path,
        monkeypatch,
        schemas=schemas,
        bound=bound,
        dsn=approved_database_dsn(),
        schema_name=ledger.schema,
        scopes=frozenset({"read", "extract", "auditMetadataRead"}),
    )
    root = tmp_path / "custody"
    root.mkdir()
    for name, value in (
        ("project.json", project.model_dump_json(by_alias=True)),
        ("profile.json", profile.model_dump_json(by_alias=True)),
        ("contract-set.json", bundle.model_dump_json(by_alias=True)),
    ):
        write_private(env.private / name, value)
    admission_settings: dict[str, Any] = {
        "projectConfigPath": str(env.private / "project.json"),
        "profilePath": str(env.private / "profile.json"),
        "contractSetPath": str(env.private / "contract-set.json"),
        "inputRoots": [{"rootId": "synthetic-input", "path": str(root)}],
    }
    if schema_file is not None:
        schema_path = write_private(env.private / "metadata-schema.json", schema_file)
        admission_settings["profileMetadataSchemaPath"] = str(schema_path)
    env.extra["admission"] = admission_settings
    env.write_config()
    return env, root


def shelf_manifest(metadata: dict[str, Any]) -> str:
    policy_bytes = admission().evidence.pinned_policy.model_dump_json(by_alias=True).encode()
    policy_ref = reference(policy_bytes, "cf.policy.v1")
    name = "a.txt"
    return json.dumps(
        {
            "schemaVersion": "cf.intake.v1",
            "projectId": PROJECT,
            "batchId": BATCH,
            "profileId": PROFILE_ID,
            "profileVersion": "synthetic.profile.v1",
            "policyRef": json.loads(policy_ref.model_dump_json(by_alias=True)),
            "createdAt": TIME,
            "items": [
                {
                    "assetId": ASSET,
                    "sourceId": SOURCE_A,
                    "originalDigest": hashlib.sha256(name.encode()).hexdigest(),
                    "sizeBytes": len(name),
                    "mediaType": "text/plain",
                    "custodyRef": {"rootId": "synthetic-input", "relativePath": name},
                    "metadata": metadata,
                }
            ],
        }
    )


def admit(env: Env, root: Path, metadata: dict[str, Any]) -> Any:
    (root / "a.txt").write_bytes(b"a.txt")
    manifest = env.input("manifest.json", shelf_manifest(metadata))
    return env.invoke("admit", "--manifest", manifest, "--execute", services=SERVICES)


def nothing_admitted(ledger: Ledger) -> bool:
    return all(
        count(ledger, table) == 0
        for table in ("admission_reports", "admission_entries", "assets", "batches")
    )


@pytest.mark.database
def test_second_profile_admits_valid_metadata(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env, root = profile_environment(tmp_path, monkeypatch, ledger)
    result = admit(env, root, VALID_METADATA)
    assert result.exit == 0, result.raw
    assert [row["status"] for row in result.payload["entries"]] == ["admitted"]
    assert count(ledger, "admission_entries") == 1 and count(ledger, "assets") == 1


@pytest.mark.database
@pytest.mark.parametrize(
    "metadata",
    [
        VALID_METADATA | {"extra": "unknown field"},
        VALID_METADATA | {"shelfKey": "x" * 33},
        VALID_METADATA | {"lang": "fr"},
        VALID_METADATA | {"provenance": {"origin": "synthetic", "year": 3001}},
        {"shelfKey": "shelf-1", "lang": "en"},
    ],
    ids=["unknown_field", "overlong", "enum_miss", "nested_range", "missing_required"],
)
def test_invalid_metadata_refuses_manifest(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, metadata: dict[str, Any]
) -> None:
    env, root = profile_environment(tmp_path, monkeypatch, ledger)
    result = admit(env, root, metadata)
    assert result.exit != 0 and result.code == "invalid_schema", result.raw
    assert nothing_admitted(ledger)


SIGNED_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["delta"],
    "properties": {"delta": {"type": "integer", "minimum": -5, "maximum": 5}},
}
SIGNED_BYTES = json.dumps(SIGNED_SCHEMA, separators=(",", ":")).encode()
SAFE_BOUND = 9007199254740991


def signed_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ledger: Ledger
) -> tuple[Env, Path]:
    return profile_environment(
        tmp_path,
        monkeypatch,
        ledger,
        schema_file=SIGNED_BYTES,
        profile_ref=reference(SIGNED_BYTES, SCHEMA_ID),
    )


@pytest.mark.database
@pytest.mark.parametrize("delta", [-5, -1, 0, 5], ids=["lower_bound", "negative", "zero", "upper"])
def test_negative_metadata_within_signed_bounds_is_admitted(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, delta: int
) -> None:
    env, root = signed_profile(tmp_path, monkeypatch, ledger)
    result = admit(env, root, {"delta": delta})
    assert result.exit == 0, result.raw
    assert [row["status"] for row in result.payload["entries"]] == ["admitted"]
    assert count(ledger, "admission_entries") == 1 and count(ledger, "assets") == 1


@pytest.mark.database
@pytest.mark.parametrize(
    "delta",
    [-6, 6, -SAFE_BOUND, SAFE_BOUND, -SAFE_BOUND - 1, SAFE_BOUND + 1],
    ids=["below", "above", "min_safe", "max_safe", "beyond_min_safe", "beyond_max_safe"],
)
def test_metadata_outside_bounds_or_wire_range_is_refused(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, delta: int
) -> None:
    env, root = signed_profile(tmp_path, monkeypatch, ledger)
    result = admit(env, root, {"delta": delta})
    assert result.exit != 0 and result.code == "invalid_schema", result.raw
    assert nothing_admitted(ledger)


@pytest.mark.database
def test_negative_non_metadata_integer_is_still_refused(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env, root = signed_profile(tmp_path, monkeypatch, ledger)
    (root / "a.txt").write_bytes(b"a.txt")
    document = json.loads(shelf_manifest({"delta": -1}))
    document["items"][0]["sizeBytes"] = -1
    manifest = env.input("manifest.json", json.dumps(document))
    result = env.invoke("admit", "--manifest", manifest, "--execute", services=SERVICES)
    assert result.exit != 0 and result.code == "invalid_schema", result.raw
    assert nothing_admitted(ledger)


@pytest.mark.database
def test_schema_file_digest_mismatch_refused(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env, root = profile_environment(tmp_path, monkeypatch, ledger, schema_file=SHELF_BYTES + b" ")
    result = admit(env, root, VALID_METADATA)
    assert result.exit != 0 and result.code == "hash_mismatch", result.raw
    assert nothing_admitted(ledger)


@pytest.mark.database
def test_pinned_ref_of_another_schema_kind_refused(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wrong_kind = reference(SHELF_BYTES, "cf.technical-metadata.v1")
    env, root = profile_environment(tmp_path, monkeypatch, ledger, profile_ref=wrong_kind)
    result = admit(env, root, VALID_METADATA)
    assert result.exit != 0 and result.code == "unsupported_schema", result.raw
    assert nothing_admitted(ledger)


@pytest.mark.database
@pytest.mark.parametrize("configured", [True, False], ids=["with_path", "without_path"])
def test_profile_ref_matches_nothing_refused(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, configured: bool
) -> None:
    stray = reference(b'{"unrelated":true}', SCHEMA_ID)
    env, root = profile_environment(
        tmp_path,
        monkeypatch,
        ledger,
        schema_file=SHELF_BYTES if configured else None,
        profile_ref=stray,
    )
    result = admit(env, root, VALID_METADATA)
    # With a file configured it is the only candidate for a non-technical pin, so a ref it does not
    # match is indistinguishable from an edited file: hash_mismatch (design U3, brief `_admit`).
    expected = "hash_mismatch" if configured else "unsupported_schema"
    assert result.exit != 0 and result.code == expected, result.raw
    assert nothing_admitted(ledger)


@pytest.mark.database
def test_technical_profile_unchanged_without_path(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env, root = admit_environment(tmp_path, monkeypatch, ledger)
    assert "profileMetadataSchemaPath" not in env.extra["admission"]
    (root / "a.txt").write_bytes(b"a.txt")
    (root / "b.txt").write_bytes(b"b.txt")
    policy_bytes = admission().evidence.pinned_policy.model_dump_json(by_alias=True).encode()
    manifest = env.input(
        "manifest.json",
        intake(
            reference(policy_bytes, "cf.policy.v1"),
            [
                (ASSET, SOURCE_A, "a.txt"),
                (ADMIT_ASSET_B, "00000000-0000-0000-0000-000000000008", "b.txt"),
            ],
        ),
    )
    result = env.invoke("admit", "--manifest", manifest, "--execute", services=SERVICES)
    assert result.exit == 0, result.raw
    assert [row["status"] for row in result.payload["entries"]] == ["admitted", "admitted"]


@pytest.mark.database
def test_technical_ref_is_accepted_even_with_a_configured_path(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The technical pin wins over a configured file: the file is never consulted for it."""
    env, root = admit_environment(tmp_path, monkeypatch, ledger)
    schema_path = write_private(env.private / "metadata-schema.json", SHELF_BYTES + b" ")
    env.extra["admission"]["profileMetadataSchemaPath"] = str(schema_path)
    env.write_config()
    (root / "a.txt").write_bytes(b"a.txt")
    policy_bytes = admission().evidence.pinned_policy.model_dump_json(by_alias=True).encode()
    manifest = env.input(
        "manifest.json",
        intake(reference(policy_bytes, "cf.policy.v1"), [(ASSET, SOURCE_A, "a.txt")]),
    )
    result = env.invoke("admit", "--manifest", manifest, "--execute", services=SERVICES)
    assert result.exit == 0, result.raw
    assert [row["status"] for row in result.payload["entries"]] == ["admitted"]


@pytest.mark.parametrize("delta", [-5, 5], ids=["negative", "positive"])
def test_run_preparation_opens_a_source_asset_for_signed_metadata(delta: int) -> None:
    """prepare-run's source_asset copies the admitted item's metadata verbatim."""
    from test_budget import case

    from conscience_foundry.contracts.admission import IntakeManifest
    from conscience_foundry.execution.evidence import source_asset

    c = case()
    document = json.loads(c.data.evidence.manifest_bytes)
    document["items"][0]["metadata"] = {"delta": delta}
    manifest = IntakeManifest.from_wire(json.dumps(document).encode(), limits())
    asset = source_asset(c.plan, manifest, c.data.report, c.context)
    assert asset.metadata == {"delta": delta}
    assert asset.model_dump(by_alias=True)["metadata"] == {"delta": delta}


@pytest.mark.parametrize(
    ("schema_bytes", "metadata"),
    [(SHELF_BYTES, VALID_METADATA), (SIGNED_BYTES, {"delta": -5}), (SIGNED_BYTES, {"delta": 5})],
    ids=["shelf", "negative", "positive"],
)
def test_source_asset_carries_metadata(
    tmp_path: Path, schema_bytes: bytes, metadata: dict[str, Any]
) -> None:
    from conscience_foundry.contracts.admission import IntakeManifest
    from conscience_foundry.contracts.common import ContractLimits
    from conscience_foundry.contracts.project import PolicyArtifact, ProfileMetadataBinding
    from conscience_foundry.contracts.project import ProfileDescriptor as Profile
    from conscience_foundry.intake.metadata_schema import MetadataSchema
    from conscience_foundry.policy.access import AccessContext
    from conscience_foundry.storage.custody import inspect_intake, source_asset
    from conscience_foundry.storage.local import LocalObjectStore
    from conscience_foundry.storage.locator import LocationRegistry

    bound: ContractLimits = limits()
    schemas = dict.fromkeys(registered_schema_ids(), bound)
    policy: PolicyArtifact = admission().evidence.pinned_policy
    policy_bytes = encoded(policy)
    pinned = reference(schema_bytes, SCHEMA_ID)
    profile = Profile(
        schema_version="cf.profile.v1",
        profile_id=PROFILE_ID,
        version="synthetic.profile.v1",
        metadata_schema_ref=pinned,
        allowed_processor_ids=("text.utf8.v1",),
        extension_schema_refs=(),
        export_adapters=(),
    )
    project = ProjectConfig(
        schema_version="cf.project.v1",
        project_id=PROJECT,
        profile_id=PROFILE_ID,
        profile_version="synthetic.profile.v1",
        policy_ref=reference(policy_bytes, "cf.policy.v1"),
        limits_refs=(reference(b"{}", "cf.contract-limits.v1"),),
        contract_set_ref=reference(b"{}", "cf.contract-set.v1"),
        storage_config_ref=reference(b"{}", "cf.storage-config.v1"),
        execution_config_ref=reference(b"{}", "cf.execution-config.v1"),
    )
    manifest_bytes = shelf_manifest(metadata).encode()
    manifest = IntakeManifest.from_wire(manifest_bytes, bound)
    source_root, target_root = tmp_path / "source", tmp_path / "target"
    source_root.mkdir()
    target_root.mkdir()
    (source_root / "a.txt").write_bytes(b"a.txt")
    context = AccessContext(
        PROJECT,
        "00000000-0000-0000-0000-000000000002",
        frozenset({"read", "extract", "auditMetadataRead"}),
    )
    binding = ProfileMetadataBinding(pinned, MetadataSchema.parse(schema_bytes, bound))

    def authorize(ref: ArtifactRef, actor: AccessContext, effect: str) -> None:
        return None

    with LocationRegistry({"synthetic-target": target_root}, bound, authorize) as locator:
        store = LocalObjectStore("synthetic-target", locator)
        report = inspect_intake(
            manifest,
            project,
            policy,
            context,
            store,
            manifest_bytes=manifest_bytes,
            policy_bytes=policy_bytes,
            profile=profile,
            metadata_binding=binding,
            input_roots={"synthetic-input": source_root},
            limits_by_schema=schemas,
            checked_at=TIME,
        )
        assert [entry.status for entry in report.entries] == ["admitted"]
        report_bytes = encoded(report)
        asset = source_asset(
            manifest,
            report,
            reference(report_bytes, "cf.admission-report.v1"),
            ASSET,
            manifest_bytes=manifest_bytes,
            report_bytes=report_bytes,
            pinned_policy=policy,
            policy_bytes=policy_bytes,
            limits_by_schema=schemas,
            context=context,
            current_policy=policy,
        )
    assert asset.model_dump(by_alias=True)["metadata"] == metadata
    assert asset.metadata == manifest.items[0].metadata
