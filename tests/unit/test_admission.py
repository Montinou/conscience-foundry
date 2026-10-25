"""Synthetic custody tests exercise real source paths and immutable local storage."""

from __future__ import annotations

import hashlib
import io
import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from conscience_foundry.contracts.admission import AdmissionReport, IntakeManifest
from conscience_foundry.contracts.common import ArtifactRef, ContractError, ContractLimits
from conscience_foundry.contracts.project import (
    PolicyArtifact,
    ProfileDescriptor,
    ProjectConfig,
    TechnicalMetadataBinding,
)
from conscience_foundry.contracts.registry import (
    export_schemas,
    registered_schema_ids,
    technical_metadata_binding,
)
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.custody import inspect_intake, source_asset
from conscience_foundry.storage.local import LocalObjectStore
from conscience_foundry.storage.locator import LocationRegistry

PROJECT = "00000000-0000-0000-0000-000000000001"
ACTOR = "00000000-0000-0000-0000-000000000002"
ASSET_A = "00000000-0000-0000-0000-000000000003"
ASSET_B = "00000000-0000-0000-0000-000000000004"
SOURCE_A = "00000000-0000-0000-0000-000000000005"
SOURCE_B = "00000000-0000-0000-0000-000000000006"
BATCH = "00000000-0000-0000-0000-000000000007"
TIME = "2026-10-25T00:00:00.000Z"
CONTEXT = AccessContext(PROJECT, ACTOR, frozenset({"read", "extract", "auditMetadataRead"}))


def encoded(value: object) -> bytes:
    if hasattr(value, "model_dump_json"):
        return value.model_dump_json(by_alias=True).encode()  # type: ignore[union-attr]
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def reference(data: bytes, schema: str, media: str = "application/json") -> ArtifactRef:
    return ArtifactRef(
        schema_version="kf.artifact-ref.v1",
        project_id=PROJECT,
        digest=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        media_type=media,
        artifact_schema=schema,
        locations=(),
    )


def source_policy(source: str, *, read: str = "allow", extract: str = "allow") -> dict[str, str]:
    return {
        "sourceId": source,
        "read": read,
        "extract": extract,
        "remoteTransfer": "deny",
        "enrich": "deny",
        "embed": "deny",
        "train": "deny",
        "publish": "deny",
        "auditMetadataRead": "allow",
    }


@dataclass
class Environment:
    source_root: Path
    target_root: Path
    limits: dict[str, ContractLimits]
    profile: ProfileDescriptor
    binding: TechnicalMetadataBinding
    policy: PolicyArtifact
    policy_bytes: bytes
    project: ProjectConfig
    store: LocalObjectStore
    locator: LocationRegistry

    def manifest(self, files: list[tuple[str, str, str, bytes]]) -> tuple[IntakeManifest, bytes]:
        items = [
            {
                "assetId": asset,
                "sourceId": source,
                "originalDigest": hashlib.sha256(data).hexdigest(),
                "sizeBytes": len(data),
                "mediaType": "text/plain",
                "custodyRef": {"rootId": "synthetic-input", "relativePath": name},
                "metadata": {"title": "Synthetic manual"},
            }
            for asset, source, name, data in files
        ]
        raw = encoded(
            {
                "schemaVersion": "kf.intake.v1",
                "projectId": PROJECT,
                "batchId": BATCH,
                "profileId": "technical_minimal",
                "profileVersion": "synthetic.profile.v1",
                "policyRef": self.project.policy_ref.model_dump(by_alias=True),
                "createdAt": TIME,
                "items": items,
            }
        )
        return IntakeManifest.from_wire(raw, self.limits["kf.intake.v1"]), raw

    def inspect(self, manifest: IntakeManifest, raw: bytes, **overrides: object) -> AdmissionReport:
        arguments: dict[str, object] = {
            "manifest_bytes": raw,
            "policy_bytes": self.policy_bytes,
            "profile": self.profile,
            "metadata_binding": self.binding,
            "input_roots": {"synthetic-input": self.source_root},
            "limits_by_schema": self.limits,
            "checked_at": TIME,
        }
        arguments.update(overrides)
        return inspect_intake(manifest, self.project, self.policy, CONTEXT, self.store, **arguments)  # type: ignore[arg-type]

    def asset(
        self,
        manifest: IntakeManifest,
        manifest_bytes: bytes,
        report: AdmissionReport,
        asset_id: str,
        *,
        report_bytes: bytes | None = None,
        report_ref: ArtifactRef | None = None,
    ) -> object:
        raw = encoded(report) if report_bytes is None else report_bytes
        report_ref = reference(raw, "kf.admission-report.v1") if report_ref is None else report_ref
        return source_asset(
            manifest,
            report,
            report_ref,
            asset_id,
            manifest_bytes=manifest_bytes,
            report_bytes=raw,
            pinned_policy=self.policy,
            policy_bytes=self.policy_bytes,
            limits_by_schema=self.limits,
            context=CONTEXT,
            current_policy=self.policy,
        )


def test_intake_rejects_pinned_denial_bytes_with_fabricated_decoding(
    environment: Environment,
) -> None:
    env = environment
    allowed = env.policy_bytes.decode()
    policy_value = json.loads(env.policy_bytes)
    policy_value["sources"][0]["read"] = "deny"
    denied = encoded(policy_value)
    env.project = ProjectConfig.model_validate(
        env.project.model_dump() | {"policy_ref": reference(denied, "kf.policy.v1")}
    )
    actual = b"synthetic source"
    (env.source_root / "manual.txt").write_bytes(actual)
    manifest, raw = env.manifest([(ASSET_A, SOURCE_A, "manual.txt", actual)])

    class FabricatedPolicy(bytes):
        def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
            return allowed

    with pytest.raises(ContractError, match="invalid_schema"):
        env.inspect(manifest, raw, policy_bytes=FabricatedPolicy(denied))
    assert not [path for path in env.target_root.rglob("*") if path.is_file()]


@pytest.fixture
def environment(tmp_path: Path) -> Iterator[Environment]:
    source_root, target_root = tmp_path / "source", tmp_path / "target"
    source_root.mkdir()
    target_root.mkdir()
    bounds = ContractLimits(
        schema_version="kf.contract-limits.v1",
        version="synthetic.custody-limits.v1",
        max_json_bytes=500_000,
        max_string_scalars=1024,
        max_array_items=256,
        max_depth=32,
        max_manifest_items=8,
        max_source_bytes=1024,
        max_output_bytes=500_000,
        max_error_message_scalars=80,
    )
    limits = dict.fromkeys(registered_schema_ids(), bounds)
    bundle = export_schemas(
        tmp_path / "schemas",
        project_id=PROJECT,
        store_id="synthetic-schema-store",
        version="synthetic.contract-set.v1",
        limits_by_schema=limits,
    )
    binding = technical_metadata_binding(bundle, project_id=PROJECT, limits_by_schema=limits)
    profile = ProfileDescriptor(
        schema_version="kf.profile.v1",
        profile_id="technical_minimal",
        version="synthetic.profile.v1",
        metadata_schema_ref=binding.expected_schema_ref,
        allowed_processor_ids=("text.utf8.v1",),
        extension_schema_refs=(),
        export_adapters=(),
    )
    policy_bytes = encoded(
        {
            "schemaVersion": "kf.policy.v1",
            "projectId": PROJECT,
            "policyVersion": "synthetic.policy.v1",
            "sources": [source_policy(SOURCE_A), source_policy(SOURCE_B)],
            "allowedRemoteDestinations": [],
            "effectiveAt": TIME,
        }
    )
    policy = PolicyArtifact.from_wire(policy_bytes, bounds)
    project = ProjectConfig(
        schema_version="kf.project.v1",
        project_id=PROJECT,
        profile_id=profile.profile_id,
        profile_version=profile.version,
        policy_ref=reference(policy_bytes, "kf.policy.v1"),
        limits_refs=(reference(encoded(bounds), "kf.contract-limits.v1"),),
        contract_set_ref=reference(encoded(bundle), "kf.contract-set.v1"),
        storage_config_ref=reference(b"{}", "kf.storage-config.v1"),
        execution_config_ref=reference(b"{}", "kf.execution-config.v1"),
    )

    def authorize(ref: ArtifactRef, context: AccessContext, effect: str) -> None:
        if ref.project_id != context.project_id or effect not in {
            "read",
            "write",
            "register_location",
        }:
            raise ContractError("forbidden")

    locator = LocationRegistry({"synthetic-target": target_root}, bounds, authorize)
    yield Environment(
        source_root,
        target_root,
        limits,
        profile,
        binding,
        policy,
        policy_bytes,
        project,
        LocalObjectStore("synthetic-target", locator),
        locator,
    )
    locator.close()


def test_success_snapshots_original_and_preserves_source(environment: Environment) -> None:
    data = b"Synthetic immutable manual\r\n"
    source = environment.source_root / "a.txt"
    source.write_bytes(data)
    manifest, raw = environment.manifest([(ASSET_A, SOURCE_A, "a.txt", data)])
    report = environment.inspect(manifest, raw)
    assert report.manifest_digest == hashlib.sha256(raw).hexdigest()
    assert report.policy_version == environment.policy.policy_version
    assert [row.status for row in report.entries] == ["admitted"]
    snapshot = report.entries[0].snapshot_ref
    assert snapshot is not None and snapshot.artifact_schema == "kf.raw-original.v1"
    assert snapshot.digest == hashlib.sha256(data).hexdigest()
    assert environment.store.read_verified(snapshot, CONTEXT, 1024).data == data
    assert source.read_bytes() == data
    source.rename(environment.source_root / "moved.txt")
    assert environment.store.read_verified(snapshot, CONTEXT, 1024).data == data
    assert "a.txt" not in encoded(report).decode()
    assert "synthetic-input" not in encoded(report).decode()


def test_same_bytes_distinct_sources_remain_distinct(environment: Environment) -> None:
    data = b"Same synthetic bytes"
    for name in ("a.txt", "b.txt"):
        (environment.source_root / name).write_bytes(data)
    manifest, raw = environment.manifest(
        [
            (ASSET_A, SOURCE_A, "a.txt", data),
            (ASSET_B, SOURCE_B, "b.txt", data),
        ]
    )
    report = environment.inspect(manifest, raw)
    first = environment.asset(manifest, raw, report, ASSET_A)
    second = environment.asset(manifest, raw, report, ASSET_B)
    assert first.source_id == SOURCE_A and second.source_id == SOURCE_B  # type: ignore[attr-defined]
    assert first.original_ref.digest == second.original_ref.digest  # type: ignore[attr-defined]
    assert first.asset_id != second.asset_id  # type: ignore[attr-defined]
    assert first.metadata == manifest.items[0].metadata  # type: ignore[attr-defined]


def test_missing_symlink_and_changed_source_keep_every_row(environment: Environment) -> None:
    data = b"Expected synthetic bytes"
    outside = environment.source_root.parent / "outside.txt"
    outside.write_bytes(data)
    (environment.source_root / "a.txt").symlink_to(outside)
    manifest, raw = environment.manifest(
        [
            (ASSET_A, SOURCE_A, "a.txt", data),
            (ASSET_B, SOURCE_B, "missing.txt", data),
        ]
    )
    report = environment.inspect(manifest, raw)
    assert {row.asset_id for row in report.entries} == {ASSET_A, ASSET_B}
    assert all(
        row.status == "blocked" and row.reasons and row.snapshot_ref is None
        for row in report.entries
    )
    assert outside.read_bytes() == data
    assert str(outside) not in encoded(report).decode()
    (environment.source_root / "a.txt").unlink()
    (environment.source_root / "a.txt").write_bytes(b"Changed synthetic bytes")
    report = environment.inspect(manifest, raw)
    assert report.entries[0].status == "blocked"
    assert not [path for path in environment.target_root.rglob("*") if path.is_file()]


def test_exact_custody_path_checked_despite_existing_identical_snapshot(
    environment: Environment,
) -> None:
    data = b"Existing synthetic snapshot"
    known = reference(data, "kf.raw-original.v1", "text/plain")
    environment.store.put_verified(io.BytesIO(data), known, CONTEXT)
    manifest, raw = environment.manifest([(ASSET_A, SOURCE_A, "missing.txt", data)])
    report = environment.inspect(manifest, raw)
    assert report.entries[0].status == "blocked"
    assert report.entries[0].snapshot_ref is None


def test_deny_and_unknown_block_before_source_read(
    environment: Environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"Permission protected synthetic bytes"
    for name in ("a.txt", "b.txt"):
        (environment.source_root / name).write_bytes(data)
    policy_bytes = encoded(
        {
            "schemaVersion": "kf.policy.v1",
            "projectId": PROJECT,
            "policyVersion": "synthetic.policy.v2",
            "effectiveAt": TIME,
            "sources": [
                source_policy(SOURCE_A, read="deny"),
                source_policy(SOURCE_B, extract="unknown"),
            ],
            "allowedRemoteDestinations": [],
        }
    )
    environment.policy_bytes = policy_bytes
    environment.policy = PolicyArtifact.from_wire(policy_bytes, environment.limits["kf.policy.v1"])
    environment.project = environment.project.model_copy(
        update={"policy_ref": reference(policy_bytes, "kf.policy.v1")}
    )
    manifest, raw = environment.manifest(
        [
            (ASSET_A, SOURCE_A, "a.txt", data),
            (ASSET_B, SOURCE_B, "b.txt", data),
        ]
    )
    calls: list[str] = []
    original_open = os.open

    def tracked_open(path: object, *args: object, **kwargs: object) -> int:
        calls.append(str(path))
        return original_open(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", tracked_open)
    report = environment.inspect(manifest, raw)
    assert [row.status for row in report.entries] == ["blocked", "blocked"]
    assert [row.reasons[0].code for row in report.entries] == ["forbidden", "permission_unknown"]
    assert "a.txt" not in calls and "b.txt" not in calls
    assert not [path for path in environment.target_root.rglob("*") if path.is_file()]


def test_raw_context_mismatch_fails_before_source_io(
    environment: Environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"Bound synthetic bytes"
    (environment.source_root / "a.txt").write_bytes(data)
    manifest, raw = environment.manifest([(ASSET_A, SOURCE_A, "a.txt", data)])
    original_open = os.open
    calls: list[str] = []

    def tracked_open(path: object, *args: object, **kwargs: object) -> int:
        calls.append(str(path))
        return original_open(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", tracked_open)
    wrong = raw.replace(ASSET_A.encode(), ASSET_B.encode())
    for overrides in (
        {"manifest_bytes": wrong},
        {"policy_bytes": environment.policy_bytes + b" "},
        {"manifest_bytes": raw[:-1] + b',"batchId":"duplicate"}'},
        {"limits_by_schema": {}},
    ):
        with pytest.raises(ContractError):
            environment.inspect(manifest, raw, **overrides)
    assert calls == []


def test_source_mutation_during_verified_copy_fails(
    environment: Environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"Expected stable content"
    path = environment.source_root / "a.txt"
    path.write_bytes(data)
    manifest, raw = environment.manifest([(ASSET_A, SOURCE_A, "a.txt", data)])
    original_open = os.open

    def mutate_after_open(name: object, *args: object, **kwargs: object) -> int:
        fd = original_open(name, *args, **kwargs)  # type: ignore[arg-type]
        if name == "a.txt":
            path.write_bytes(b"Changed content bytes")
        return fd

    monkeypatch.setattr(os, "open", mutate_after_open)
    report = environment.inspect(manifest, raw)
    assert report.entries[0].status == "blocked"
    assert report.entries[0].reasons[0].code in {"hash_mismatch", "limit_exceeded"}
    assert report.entries[0].snapshot_ref is None


def test_source_swap_and_symlink_race_fail(
    environment: Environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"Synthetic race content"
    directory = environment.source_root / "nested"
    directory.mkdir()
    (directory / "a.txt").write_bytes(data)
    outside = environment.source_root.parent / "outside"
    outside.mkdir()
    (outside / "a.txt").write_bytes(data)
    manifest, raw = environment.manifest([(ASSET_A, SOURCE_A, "nested/a.txt", data)])
    original_open = os.open
    swapped = False

    def swap_parent(name: object, *args: object, **kwargs: object) -> int:
        nonlocal swapped
        if name == "nested" and not swapped:
            swapped = True
            directory.rename(environment.source_root / "retained")
            directory.symlink_to(outside, target_is_directory=True)
        return original_open(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", swap_parent)
    report = environment.inspect(manifest, raw)
    assert swapped and report.entries[0].status == "blocked"
    assert report.entries[0].snapshot_ref is None
    assert (outside / "a.txt").read_bytes() == data


def test_source_asset_verifies_exact_report_and_manifest_bytes(environment: Environment) -> None:
    data = b"Synthetic asset content"
    (environment.source_root / "a.txt").write_bytes(data)
    manifest, raw = environment.manifest([(ASSET_A, SOURCE_A, "a.txt", data)])
    report = environment.inspect(manifest, raw)
    report_bytes = encoded(report)
    report_ref = reference(report_bytes, "kf.admission-report.v1")
    assert environment.asset(manifest, raw, report, ASSET_A).source_id == SOURCE_A  # type: ignore[attr-defined]
    for changed_bytes in (
        report_bytes + b" ",
        report_bytes.replace(SOURCE_A.encode(), SOURCE_B.encode()),
    ):
        with pytest.raises(ContractError):
            environment.asset(
                manifest, raw, report, ASSET_A, report_bytes=changed_bytes, report_ref=report_ref
            )
    with pytest.raises(ContractError):
        environment.asset(manifest, raw + b" ", report, ASSET_A)
    wrong_ref = report_ref.model_copy(update={"artifact_schema": "kf.policy.v1"})
    with pytest.raises(ContractError):
        environment.asset(manifest, raw, report, ASSET_A, report_ref=wrong_ref)


def test_blocked_entry_cannot_become_source_asset(environment: Environment) -> None:
    data = b"Missing synthetic bytes"
    manifest, raw = environment.manifest([(ASSET_A, SOURCE_A, "a.txt", data)])
    report = environment.inspect(manifest, raw)
    with pytest.raises(ContractError):
        environment.asset(manifest, raw, report, ASSET_A)


@pytest.mark.parametrize("audit_permission", ["deny", "unknown"])
def test_report_audit_denial_withholds_before_any_source_content(
    environment: Environment,
    monkeypatch: pytest.MonkeyPatch,
    audit_permission: str,
) -> None:
    data = b"Synthetic partial admission"
    for name in ("a.txt", "b.txt"):
        (environment.source_root / name).write_bytes(data)
    blocked = source_policy(SOURCE_B, read="deny") | {"auditMetadataRead": audit_permission}
    raw_policy = encoded(
        {
            "schemaVersion": "kf.policy.v1",
            "projectId": PROJECT,
            "policyVersion": "synthetic.policy.v3",
            "effectiveAt": TIME,
            "sources": [source_policy(SOURCE_A), blocked],
            "allowedRemoteDestinations": [],
        }
    )
    environment.policy_bytes = raw_policy
    environment.policy = PolicyArtifact.from_wire(raw_policy, environment.limits["kf.policy.v1"])
    environment.project = environment.project.model_copy(
        update={"policy_ref": reference(raw_policy, "kf.policy.v1")}
    )
    manifest, raw = environment.manifest(
        [
            (ASSET_A, SOURCE_A, "a.txt", data),
            (ASSET_B, SOURCE_B, "b.txt", data),
        ]
    )
    calls: list[str] = []
    original_open = os.open

    def track_open(path: object, *args: object, **kwargs: object) -> int:
        calls.append(str(path))
        return original_open(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", track_open)
    with pytest.raises(ContractError) as exc:
        environment.inspect(manifest, raw)
    assert exc.value.code == ("forbidden" if audit_permission == "deny" else "permission_unknown")
    assert "a.txt" not in calls and "b.txt" not in calls
    assert not [path for path in environment.target_root.rglob("*") if path.is_file()]


def test_source_asset_requires_project_audit_scope(environment: Environment) -> None:
    data = b"Synthetic asset audit context"
    (environment.source_root / "a.txt").write_bytes(data)
    manifest, raw = environment.manifest([(ASSET_A, SOURCE_A, "a.txt", data)])
    report = environment.inspect(manifest, raw)
    report_bytes = encoded(report)
    context = AccessContext(PROJECT, ACTOR, frozenset({"read", "extract"}))
    with pytest.raises(ContractError):
        source_asset(
            manifest,
            report,
            reference(report_bytes, "kf.admission-report.v1"),
            ASSET_A,
            manifest_bytes=raw,
            report_bytes=report_bytes,
            pinned_policy=environment.policy,
            policy_bytes=environment.policy_bytes,
            limits_by_schema=environment.limits,
            context=context,
            current_policy=environment.policy,
        )


@pytest.mark.parametrize(
    "source,effect,permission",
    [
        (SOURCE_A, "read", "deny"),
        (SOURCE_A, "extract", "unknown"),
        (SOURCE_B, "auditMetadataRead", "deny"),
        (SOURCE_B, "auditMetadataRead", "unknown"),
    ],
)
def test_current_revocation_cannot_reuse_historical_admission_allow(
    environment: Environment,
    source: str,
    effect: str,
    permission: str,
) -> None:
    data = b"Synthetic historical admission"
    for name in ("a.txt", "b.txt"):
        (environment.source_root / name).write_bytes(data)
    manifest, raw = environment.manifest(
        [
            (ASSET_A, SOURCE_A, "a.txt", data),
            (ASSET_B, SOURCE_B, "b.txt", data),
        ]
    )
    report = environment.inspect(manifest, raw)
    report_bytes = encoded(report)
    policies = [source_policy(SOURCE_A), source_policy(SOURCE_B)]
    for row in policies:
        if row["sourceId"] == source:
            row[effect] = permission
    current = PolicyArtifact.from_wire(
        encoded(
            {
                "schemaVersion": "kf.policy.v1",
                "projectId": PROJECT,
                "policyVersion": "synthetic.current-policy.v4",
                "effectiveAt": TIME,
                "sources": policies,
                "allowedRemoteDestinations": [],
            }
        ),
        environment.limits["kf.policy.v1"],
    )
    with pytest.raises(ContractError):
        source_asset(
            manifest,
            report,
            reference(report_bytes, "kf.admission-report.v1"),
            ASSET_A,
            manifest_bytes=raw,
            report_bytes=report_bytes,
            pinned_policy=environment.policy,
            policy_bytes=environment.policy_bytes,
            limits_by_schema=environment.limits,
            context=CONTEXT,
            current_policy=current,
        )


@pytest.mark.parametrize("schema", ["kf.intake.v1", "kf.policy.v1"])
def test_structured_input_role_output_ceiling_precedes_source_io(
    environment: Environment,
    monkeypatch: pytest.MonkeyPatch,
    schema: str,
) -> None:
    data = b"Synthetic ceiling source"
    (environment.source_root / "a.txt").write_bytes(data)
    manifest, raw = environment.manifest([(ASSET_A, SOURCE_A, "a.txt", data)])
    body = raw if schema == "kf.intake.v1" else environment.policy_bytes
    configured = environment.limits | {
        schema: environment.limits[schema].model_copy(update={"max_output_bytes": len(body) - 1})
    }
    calls: list[str] = []
    original_open = os.open

    def tracked_open(path: object, *args: object, **kwargs: object) -> int:
        calls.append(str(path))
        return original_open(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", tracked_open)
    with pytest.raises(ContractError) as exc:
        environment.inspect(manifest, raw, limits_by_schema=configured)
    assert exc.value.code == "limit_exceeded"
    assert "a.txt" not in calls


def test_report_role_ceiling_and_snapshot_role_are_verified(environment: Environment) -> None:
    data = b"Synthetic report limits"
    (environment.source_root / "a.txt").write_bytes(data)
    manifest, raw = environment.manifest([(ASSET_A, SOURCE_A, "a.txt", data)])
    report = environment.inspect(manifest, raw)
    report_bytes = encoded(report)
    limited = environment.limits | {
        "kf.admission-report.v1": environment.limits["kf.admission-report.v1"].model_copy(
            update={"max_output_bytes": len(report_bytes) - 1}
        )
    }
    with pytest.raises(ContractError) as exc:
        environment.inspect(manifest, raw, limits_by_schema=limited)
    assert exc.value.code == "limit_exceeded"


def test_snapshot_role_cannot_be_reinterpreted(environment: Environment) -> None:
    data = b"Synthetic original role"
    (environment.source_root / "a.txt").write_bytes(data)
    manifest, raw = environment.manifest([(ASSET_A, SOURCE_A, "a.txt", data)])
    report = environment.inspect(manifest, raw)
    snapshot = report.entries[0].snapshot_ref
    assert snapshot is not None
    wrong_snapshot = snapshot.model_copy(update={"artifact_schema": "kf.canonical-text.v1"})
    wrong_row = report.entries[0].model_copy(update={"snapshot_ref": wrong_snapshot})
    wrong_report = report.model_copy(update={"entries": (wrong_row,)})
    with pytest.raises(ContractError):
        environment.asset(manifest, raw, wrong_report, ASSET_A)


def test_malformed_root_configuration_aborts_before_any_source_read(
    environment: Environment,
) -> None:
    data = b"Synthetic explicit roots"
    (environment.source_root / "a.txt").write_bytes(data)
    manifest, raw = environment.manifest([(ASSET_A, SOURCE_A, "a.txt", data)])
    with pytest.raises(ContractError):
        environment.inspect(manifest, raw, input_roots={})


@pytest.mark.parametrize("missing", [False, True])
def test_source_asset_requires_its_own_finite_family_limits(
    environment: Environment,
    missing: bool,
) -> None:
    data = b"Synthetic provisional asset bound"
    (environment.source_root / "a.txt").write_bytes(data)
    manifest, raw = environment.manifest([(ASSET_A, SOURCE_A, "a.txt", data)])
    report = environment.inspect(manifest, raw)
    asset = environment.asset(manifest, raw, report, ASSET_A)
    configured = dict(environment.limits)
    if missing:
        configured.pop("kf.source-asset.v1")
    else:
        configured["kf.source-asset.v1"] = configured["kf.source-asset.v1"].model_copy(
            update={"max_output_bytes": len(encoded(asset)) - 1}
        )
    environment.limits = configured
    with pytest.raises(ContractError) as exc:
        environment.asset(manifest, raw, report, ASSET_A)
    assert exc.value.code == ("limits_missing" if missing else "limit_exceeded")


def test_partial_report_retains_denied_source_without_content_read(
    environment: Environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"Synthetic partial source content"
    for name in ("a.txt", "b.txt"):
        (environment.source_root / name).write_bytes(data)
    policy_bytes = encoded(
        {
            "schemaVersion": "kf.policy.v1",
            "projectId": PROJECT,
            "policyVersion": "synthetic.partial-policy.v1",
            "effectiveAt": TIME,
            "sources": [source_policy(SOURCE_A), source_policy(SOURCE_B, read="deny")],
            "allowedRemoteDestinations": [],
        }
    )
    environment.policy_bytes = policy_bytes
    environment.policy = PolicyArtifact.from_wire(policy_bytes, environment.limits["kf.policy.v1"])
    environment.project = environment.project.model_copy(
        update={"policy_ref": reference(policy_bytes, "kf.policy.v1")}
    )
    manifest, raw = environment.manifest(
        [
            (ASSET_A, SOURCE_A, "a.txt", data),
            (ASSET_B, SOURCE_B, "b.txt", data),
        ]
    )
    calls: list[str] = []
    original_open = os.open

    def track_open(path: object, *args: object, **kwargs: object) -> int:
        calls.append(str(path))
        return original_open(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", track_open)
    report = environment.inspect(manifest, raw)
    assert [row.status for row in report.entries] == ["admitted", "blocked"]
    assert [row.asset_id for row in report.entries] == [ASSET_A, ASSET_B]
    assert "a.txt" in calls and "b.txt" not in calls
    assert environment.asset(manifest, raw, report, ASSET_A).source_id == SOURCE_A  # type: ignore[attr-defined]


def test_unavailable_current_policy_never_falls_back(environment: Environment) -> None:
    data = b"Synthetic policy availability"
    (environment.source_root / "a.txt").write_bytes(data)
    manifest, raw = environment.manifest([(ASSET_A, SOURCE_A, "a.txt", data)])
    report = environment.inspect(manifest, raw)
    report_bytes = encoded(report)
    with pytest.raises(ContractError) as exc:
        source_asset(
            manifest,
            report,
            reference(report_bytes, "kf.admission-report.v1"),
            ASSET_A,
            manifest_bytes=raw,
            report_bytes=report_bytes,
            pinned_policy=environment.policy,
            policy_bytes=environment.policy_bytes,
            limits_by_schema=environment.limits,
            context=CONTEXT,
            current_policy=None,  # type: ignore[arg-type]
        )
    assert exc.value.code == "unavailable"
