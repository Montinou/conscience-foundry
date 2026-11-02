"""`cfoundry build-intake`: curated batches in, intake, withdrawals, new sources and a diff out.

Synthetic data only: a generic second profile (`shelf_catalog`) and invented producers, sources and
bytes. Most tests drive the real command line over files in a temporary directory; the pure
classification cases call `build_intake` with in-memory bytes. The end-to-end test admits the built
intake and applies the built withdrawal list on the temporary PostgreSQL.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from conftest import approved_database_dsn
from test_cli import Env, Result, count, write_private
from test_ledger_db import PROJECT, TIME, encoded, limits, reference

from conscience_foundry.cli import live
from conscience_foundry.cli.commands import admission_metadata_binding
from conscience_foundry.cli.config import AdmissionSettings, Runtime, TrustedServices, load_config
from conscience_foundry.contracts.common import ContractError, ContractLimits, Ref
from conscience_foundry.contracts.intake import (
    IntakeDiff,
    NewSources,
    WithdrawalList,
    batch_digest,
)
from conscience_foundry.contracts.project import (
    PolicyArtifact,
    ProfileDescriptor,
    ProfileMetadataBinding,
    ProjectConfig,
)
from conscience_foundry.contracts.registry import export_schemas, registered_schema_ids
from conscience_foundry.intake.build import IntakeOutputs, build_intake
from conscience_foundry.intake.identity import batch_id, decision_id, source_id
from conscience_foundry.intake.metadata_schema import MetadataSchema
from conscience_foundry.ledger.db import Ledger

LABEL = "synthetic-input"
PRODUCER = "synthetic-producer"
PROFILE_ID = "shelf_catalog"
T1, T2, T3 = (f"2026-10-0{n}T00:00:00.000Z" for n in (1, 2, 3))
SHELF_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["shelfKey", "lang", "decidedAt"],
    "properties": {
        "shelfKey": {"type": "string", "maxLength": 32, "pattern": "^[a-z0-9-]+$"},
        "lang": {"type": "string", "maxLength": 2, "enum": ["en", "es"]},
        "decidedAt": {"type": "string", "maxLength": 32},
    },
}
SIGNED_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["delta"],
    "properties": {"delta": {"type": "integer", "minimum": -5, "maximum": 5}},
}


def schema_bytes(document: dict[str, Any]) -> bytes:
    return json.dumps(document, separators=(",", ":")).encode()


SHELF_BYTES = schema_bytes(SHELF_SCHEMA)
SIGNED_BYTES = schema_bytes(SIGNED_SCHEMA)
IDENTITY = ("shelfKey", "lang")


@dataclass
class Row:
    """One approved file: `meta` overrides the default metadata for the whole item."""

    key: str
    content: bytes = b"synthetic text"
    meta: dict[str, Any] | None = None
    path: str | None = None
    decided: str = T1

    @property
    def relative_path(self) -> str:
        return self.path if self.path is not None else f"files/{self.key}.txt"

    def metadata(self) -> dict[str, Any]:
        if self.meta is not None:
            return self.meta
        return {"shelfKey": self.key, "lang": "en", "decidedAt": self.decided}


def batch_document(
    key: str,
    rows: Sequence[Row],
    created: str,
    *,
    producer: str = PRODUCER,
    label: str = LABEL,
    project: str = PROJECT,
    identity: Sequence[str] = IDENTITY,
) -> dict[str, Any]:
    return {
        "schemaVersion": "cf.curated-batch.v1",
        "projectId": project,
        "batchKey": key,
        "producer": {"name": producer, "version": "1"},
        "createdAt": created,
        "custodyRootLabel": label,
        "identityFields": list(identity),
        "approval": {"actor": "synthetic-auditor", "method": "review", "evidenceDigest": "e" * 64},
        "items": [
            {
                "relativePath": row.relative_path,
                "sha256": hashlib.sha256(row.content).hexdigest(),
                "sizeBytes": len(row.content),
                "mediaType": "text/plain",
                "sourceKey": row.key,
                "metadata": row.metadata(),
            }
            for row in rows
        ],
    }


def batch_bytes(document: dict[str, Any], *, indent: int | None = None) -> bytes:
    return json.dumps(document, indent=indent).encode()


def digest_of(document: dict[str, Any]) -> str:
    return batch_digest(batch_bytes(document))


class Memory:
    """An in-memory custody root for the pure cases; it records every read."""

    def __init__(self, rows: Sequence[Row] = ()) -> None:
        self.files: dict[tuple[str, str], bytes] = {}
        self.reads: list[tuple[str, str]] = []
        self.add(rows)

    def add(self, rows: Sequence[Row]) -> None:
        for row in rows:
            self.files[(LABEL, row.relative_path)] = row.content

    def __call__(self, label: str, relative_path: str) -> bytes:
        self.reads.append((label, relative_path))
        try:
            return self.files[(label, relative_path)]
        except KeyError:
            raise ContractError("artifact_missing") from None


def policy_artifact(sources: Sequence[str], version: str) -> PolicyArtifact:
    return PolicyArtifact.model_validate(
        {
            "schemaVersion": "cf.policy.v1",
            "projectId": PROJECT,
            "allowedRemoteDestinations": [],
            "effectiveAt": TIME,
            "policyVersion": version,
            "sources": [
                {
                    "sourceId": source_id(PROJECT, key),
                    **{
                        effect: "allow"
                        for effect in (
                            "read",
                            "extract",
                            "auditMetadataRead",
                            "remoteTransfer",
                            "enrich",
                            "embed",
                            "train",
                            "publish",
                        )
                    },
                }
                for key in sources
            ],
        }
    )


class World:
    """A private operator configuration for the synthetic profile, plus its trusted objects."""

    def __init__(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        sources: Sequence[str] = (),
        schema_file: bytes | None = SHELF_BYTES,
        grants: dict[str, list[str]] | None = None,
        ledger: Ledger | None = None,
        tightened: Mapping[str, ContractLimits] | None = None,
    ) -> None:
        self.tmp = tmp_path
        self.sources = list(sources)
        self.revision = 1
        self.schema_bytes = schema_file if schema_file is not None else SHELF_BYTES
        bound = limits()
        self.schemas = dict.fromkeys(registered_schema_ids(), bound)
        self.schemas.update(tightened or {})
        self.env = Env(
            tmp_path,
            monkeypatch,
            schemas=self.schemas,
            bound=bound,
            policy=self.policy,
            grants=grants,
            dsn=approved_database_dsn() if ledger is not None else None,
            schema_name=ledger.schema if ledger is not None else "cf_cli_test",
        )
        self.root = tmp_path / "custody"
        self.root.mkdir()
        self.bundle = export_schemas(
            tmp_path / "schemas",
            project_id=PROJECT,
            store_id="synthetic",
            version="synthetic.contract-set.v1",
            limits_by_schema=self.schemas,
        )
        write_private(self.env.private / "contract-set.json", encoded(self.bundle))
        self.profile = ProfileDescriptor(
            schema_version="cf.profile.v1",
            profile_id=PROFILE_ID,
            version="synthetic.profile.v1",
            metadata_schema_ref=reference(self.schema_bytes, "cf.metadata-schema.v1"),
            allowed_processor_ids=("text.utf8.v1",),
            extension_schema_refs=(),
            export_adapters=(),
        )
        write_private(self.env.private / "profile.json", encoded(self.profile))
        admission: dict[str, Any] = {
            "projectConfigPath": str(self.env.private / "project.json"),
            "profilePath": str(self.env.private / "profile.json"),
            "contractSetPath": str(self.env.private / "contract-set.json"),
            "inputRoots": [{"rootId": LABEL, "path": str(self.root)}],
        }
        if schema_file is not None:
            path = write_private(self.env.private / "metadata-schema.json", schema_file)
            admission["profileMetadataSchemaPath"] = str(path)
        self.env.extra["admission"] = admission
        self.write_project()
        self.env.write_config()

    def policy(self) -> PolicyArtifact:
        return policy_artifact(self.sources, f"synthetic.v{self.revision}")

    def policy_bytes(self) -> bytes:
        return encoded(self.policy())

    def write_project(self) -> None:
        project = ProjectConfig(
            schema_version="cf.project.v1",
            project_id=PROJECT,
            profile_id=PROFILE_ID,
            profile_version="synthetic.profile.v1",
            policy_ref=reference(self.policy_bytes(), "cf.policy.v1"),
            limits_refs=(reference(b"{}", "cf.contract-limits.v1"),),
            contract_set_ref=reference(encoded(self.bundle), "cf.contract-set.v1"),
            storage_config_ref=reference(b"{}", "cf.storage-config.v1"),
            execution_config_ref=reference(b"{}", "cf.execution-config.v1"),
        )
        write_private(self.env.private / "project.json", encoded(project))

    def revise_policy(self, sources: Sequence[str]) -> None:
        """The operator's policy step: a new policy revision and the project's pointer to it."""
        self.sources = list(sources)
        self.revision += 1
        self.write_project()
        self.env.write_config()

    def put(self, rows: Sequence[Row]) -> None:
        for row in rows:
            target = self.root / row.relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(row.content)

    def batch_file(self, name: str, document: dict[str, Any], *, indent: int | None = None) -> str:
        return self.env.input(name, batch_bytes(document, indent=indent))

    def build(
        self, batch: str, *previous: str, out: Path | None = None, services: Any = None
    ) -> tuple[Result, Path]:
        target = out if out is not None else self.tmp / f"out-{len(list(self.tmp.glob('out-*')))}"
        arguments = ["build-intake", "--batch", batch, "--output-dir", str(target)]
        for item in previous:
            arguments += ["--previous", item]
        return self.env.invoke(*arguments, services=services), target

    # --- the same inputs, handed to the library function directly ---------------------------

    def settings(self) -> AdmissionSettings:
        settings = load_config(self.env.config_path).admission
        assert settings is not None
        return settings

    def project(self) -> ProjectConfig:
        return ProjectConfig.from_wire(
            (self.env.private / "project.json").read_bytes(), self.schemas["cf.project.v1"]
        )

    def binding(self) -> ProfileMetadataBinding:
        return ProfileMetadataBinding(
            self.profile.metadata_schema_ref,
            MetadataSchema.parse(self.schema_bytes, self.schemas["cf.metadata-schema.v1"]),
        )

    def direct(
        self,
        document: dict[str, Any],
        previous: Sequence[dict[str, Any]] = (),
        *,
        memory: Memory,
    ) -> IntakeOutputs:
        return build_intake(
            batch_bytes(document),
            [batch_bytes(item) for item in previous],
            settings=self.settings(),
            project=self.project(),
            policy=self.policy(),
            binding=self.binding(),
            read_root=memory,
            limits_by_schema=self.schemas,
        )


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    return World(tmp_path, monkeypatch, sources=["k-a", "k-b", "k-c", "k-d", "k-e"])


def key_of(name: str) -> str:
    return f"k-{name}"


def rows_of(*names: str, content: bytes = b"synthetic text") -> list[Row]:
    return [Row(key_of(name), content=content + name.encode()) for name in names]


def outputs_of(directory: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in sorted(directory.iterdir())}


def loaded(files: Mapping[str, bytes], name: str) -> dict[str, Any]:
    value = json.loads(files[name])
    assert isinstance(value, dict)
    return value


def asset_of_row(document: dict[str, Any], key: str) -> str:
    item = next(item for item in document["items"] if item["sourceKey"] == key)
    from conscience_foundry.intake.identity import asset_id

    identity = {name: item["metadata"][name] for name in document["identityFields"]}
    return asset_id(PROJECT, key, item["sha256"], identity)


# --- determinism and refusal ---------------------------------------------------------------


def test_outputs_are_byte_identical_across_runs(world: World) -> None:
    rows = rows_of("a", "b")
    world.put(rows)
    document = batch_document("era-1", rows, T1)
    first, out_one = world.build(world.batch_file("one.json", document))
    # Same batch, different spacing and a different file name: the outputs cannot differ.
    second, out_two = world.build(world.batch_file("two.json", document, indent=2))
    assert first.exit == 0 and second.exit == 0, (first.raw, second.raw)
    files = outputs_of(out_one)
    assert files == outputs_of(out_two)
    assert sorted(files) == ["diff-report.json", "intake.json", "new-sources.json"]
    for name, data in files.items():
        assert rfc8785.dumps(json.loads(data)) == data, name  # canonical, byte for byte
    assert first.payload["status"] == "ready"


def test_tampered_file_refuses_whole_build(world: World) -> None:
    rows = rows_of("a", "b")
    world.put(rows)
    batch = world.batch_file("batch.json", batch_document("era-1", rows, T1))
    (world.root / rows[1].relative_path).write_bytes(b"altered after export")
    result, out = world.build(batch)
    assert result.exit == 1 and result.code == "source_changed", result.raw
    assert not out.exists()
    assert not [path for path in world.tmp.iterdir() if path.name.startswith(".")]


def test_missing_file_refuses_whole_build(world: World) -> None:
    rows = rows_of("a", "b")
    world.put(rows[:1])
    batch = world.batch_file("batch.json", batch_document("era-1", rows, T1))
    result, out = world.build(batch)
    assert result.exit == 1 and result.code == "source_missing", result.raw
    assert not out.exists()


def test_symlinked_file_is_not_followed(world: World) -> None:
    rows = rows_of("a")
    world.put(rows)
    target = world.root / rows[0].relative_path
    elsewhere = world.tmp / "elsewhere.txt"
    elsewhere.write_bytes(rows[0].content)
    target.unlink()
    target.symlink_to(elsewhere)
    result, out = world.build(world.batch_file("b.json", batch_document("era-1", rows, T1)))
    assert result.code == "unsafe_path", result.raw
    assert not out.exists()


def test_unsafe_path_reads_nothing(world: World) -> None:
    rows = [*rows_of("a"), Row(key_of("b"), path="files/b:colon.txt")]
    memory = Memory(rows)
    with pytest.raises(ContractError) as refused:
        world.direct(batch_document("era-1", rows, T1), memory=memory)
    assert refused.value.code == "unsafe_path"
    assert memory.reads == []  # not even the safe first row was read


def test_invalid_metadata_refused_before_output(world: World) -> None:
    rows = [
        *rows_of("a"),
        Row(key_of("b"), meta={"shelfKey": "k-b", "lang": "fr", "decidedAt": T1}),
    ]
    world.put(rows)
    result, out = world.build(world.batch_file("batch.json", batch_document("era-1", rows, T1)))
    assert result.exit == 1 and result.code == "invalid_schema", result.raw
    assert not out.exists()


def test_unknown_root_label_is_config_invalid(world: World) -> None:
    rows = rows_of("a")
    world.put(rows)
    document = batch_document("era-1", rows, T1, label="elsewhere")
    result, out = world.build(world.batch_file("batch.json", document))
    assert result.exit == 3 and result.code == "config_invalid", result.raw
    assert not out.exists()


def test_batch_of_another_project_refused(world: World) -> None:
    rows = rows_of("a")
    world.put(rows)
    other = "00000000-0000-0000-0000-0000000000ff"
    result, out = world.build(
        world.batch_file("batch.json", batch_document("era-1", rows, T1, project=other))
    )
    assert result.exit == 1 and result.code == "invalid_schema", result.raw
    assert not out.exists()


def test_needs_no_grant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ungranted = World(tmp_path, monkeypatch, sources=["k-a"], grants={})
    rows = rows_of("a")
    ungranted.put(rows)
    result, out = ungranted.build(
        ungranted.batch_file("batch.json", batch_document("era-1", rows, T1))
    )
    assert result.exit == 0, result.raw
    assert (out / "intake.json").is_file()
    assert ungranted.env.connects == []  # no ledger access


def test_execute_flag_does_not_exist(world: World) -> None:
    rows = rows_of("a")
    world.put(rows)
    batch = world.batch_file("batch.json", batch_document("era-1", rows, T1))
    result = world.env.invoke(
        "build-intake", "--batch", batch, "--output-dir", str(world.tmp / "o"), "--execute"
    )
    assert result.exit == 2 and result.code == "usage"


# --- shared inputs of the build ------------------------------------------------------------


def test_previous_batches_must_share_project_producer_and_root(world: World) -> None:
    older = batch_document("era-0", rows_of("c"), T1)
    current = batch_document("era-1", rows_of("a"), T2)
    memory = Memory([*rows_of("a"), *rows_of("c")])
    for changes in (
        {"producer": "another-producer"},
        {"project": "00000000-0000-0000-0000-0000000000ff"},
    ):
        bad = batch_document("era-0", rows_of("c"), T1, **changes)
        with pytest.raises(ContractError) as refused:
            world.direct(current, [bad], memory=memory)
        assert refused.value.code == "invalid_schema", changes
    other_label = batch_document("era-0", rows_of("c"), T1, label="elsewhere")
    with pytest.raises(ContractError) as refused:
        world.direct(current, [other_label], memory=memory)
    assert refused.value.code == "invalid_schema"
    assert world.direct(current, [older], memory=memory).status == "ready"


def test_batch_cannot_be_its_own_previous_and_duplicates_are_refused(world: World) -> None:
    memory = Memory(rows_of("a", "c"))
    current = batch_document("era-1", rows_of("a"), T2)
    older = batch_document("era-0", rows_of("c"), T1)
    for previous in ([current], [older, older], [older, json.loads(json.dumps(older))]):
        with pytest.raises(ContractError) as refused:
            world.direct(current, previous, memory=memory)
        assert refused.value.code == "determinism_conflict"


def test_input_order_of_previous_batches_never_matters(world: World) -> None:
    one = batch_document("era-1", rows_of("a", "b"), T1)
    two = batch_document("era-1", rows_of("a", "c"), T2)  # b missing, c new
    current = batch_document("era-1", rows_of("a", "d"), T3)  # c missing, d new
    memory = Memory(rows_of("a", "b", "c", "d"))
    forward = world.direct(current, [one, two], memory=memory)
    backward = world.direct(current, [two, one], memory=memory)
    assert dict(forward.files) == dict(backward.files)


def test_project_config_policy_pointer_must_match_the_policy(world: World) -> None:
    rows = rows_of("a")
    world.put(rows)
    world.sources.append("k-z")  # the policy changed on disk, the project still points at the old
    world.env.write_config()
    result, out = world.build(world.batch_file("batch.json", batch_document("era-1", rows, T1)))
    assert result.exit == 1 and result.code == "hash_mismatch", result.raw
    assert not out.exists()


def test_profile_pin_that_matches_nothing_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bare = World(tmp_path, monkeypatch, sources=["k-a"], schema_file=None)
    rows = rows_of("a")
    bare.put(rows)
    result, out = bare.build(bare.batch_file("batch.json", batch_document("era-1", rows, T1)))
    assert result.exit == 3 and result.code == "unsupported_schema", result.raw
    assert not out.exists()


def test_admission_metadata_binding_is_one_shared_helper(world: World) -> None:
    runtime = Runtime(load_config(world.env.config_path), TrustedServices(), "build-intake")
    try:
        binding = admission_metadata_binding(
            world.settings(),
            world.profile,
            world.bundle,
            project_id=PROJECT,
            limits_by_schema=runtime.limits,
        )
    finally:
        runtime.close()
    assert isinstance(binding, ProfileMetadataBinding)
    assert binding.expected_schema_ref == world.profile.metadata_schema_ref


# --- the output directory ------------------------------------------------------------------


def test_existing_nonempty_output_directory_is_refused(world: World) -> None:
    rows = rows_of("a")
    world.put(rows)
    batch = world.batch_file("batch.json", batch_document("era-1", rows, T1))
    occupied = world.tmp / "occupied"
    occupied.mkdir()
    (occupied / "keep.txt").write_text("operator file")
    result, _ = world.build(batch, out=occupied)
    assert result.exit == 3 and result.code == "config_invalid", result.raw
    assert outputs_of(occupied) == {"keep.txt": b"operator file"}
    plain_file = world.tmp / "plain-file"
    plain_file.write_text("x")
    again, _ = world.build(batch, out=plain_file)
    assert again.code == "config_invalid"
    assert plain_file.read_text() == "x"


def test_existing_empty_output_directory_is_filled(world: World) -> None:
    rows = rows_of("a")
    world.put(rows)
    batch = world.batch_file("batch.json", batch_document("era-1", rows, T1))
    empty = world.tmp / "empty"
    empty.mkdir()
    result, out = world.build(batch, out=empty)
    assert result.exit == 0, result.raw
    assert sorted(outputs_of(out)) == ["diff-report.json", "intake.json", "new-sources.json"]
    assert not [path for path in world.tmp.iterdir() if path.name.startswith(".")]


def test_missing_parent_directory_is_refused(world: World) -> None:
    rows = rows_of("a")
    world.put(rows)
    batch = world.batch_file("batch.json", batch_document("era-1", rows, T1))
    result, _ = world.build(batch, out=world.tmp / "no" / "such" / "parent")
    assert result.exit == 3 and result.code == "config_invalid", result.raw


# --- the policy-first flow -----------------------------------------------------------------


def test_new_sources_need_policy_revision(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fresh = World(tmp_path, monkeypatch, sources=[])
    rows = rows_of("a", "b")
    fresh.put(rows)
    batch = fresh.batch_file("batch.json", batch_document("era-1", rows, T1))
    first, out_one = fresh.build(batch)
    assert first.exit == 0, first.raw
    assert first.payload["status"] == "policy_revision_needed"
    files = outputs_of(out_one)
    assert sorted(files) == ["diff-report.json", "new-sources.json"]  # no intake, no withdrawals
    listed = NewSources.from_wire(files["new-sources.json"], fresh.schemas["cf.new-sources.v1"])
    assert [(entry.source_key, entry.source_id) for entry in listed.sources] == [
        (key_of("a"), source_id(PROJECT, key_of("a"))),
        (key_of("b"), source_id(PROJECT, key_of("b"))),
    ]
    report = IntakeDiff.from_wire(files["diff-report.json"], fresh.schemas["cf.intake-diff.v1"])
    assert report.status == "policy_revision_needed" and report.intake_digest is None
    assert report.new_sources_digest == hashlib.sha256(files["new-sources.json"]).hexdigest()
    # The operator adds the sources to the policy and points the project at the revision.
    fresh.revise_policy([key_of("a"), key_of("b")])
    second, out_two = fresh.build(batch)
    assert second.exit == 0 and second.payload["status"] == "ready", second.raw
    ready = outputs_of(out_two)
    assert sorted(ready) == ["diff-report.json", "intake.json", "new-sources.json"]
    assert ready["new-sources.json"] == files["new-sources.json"]
    intake = loaded(ready, "intake.json")
    assert intake["policyRef"]["digest"] == hashlib.sha256(fresh.policy_bytes()).hexdigest()
    ready_report = loaded(ready, "diff-report.json")
    assert ready_report["intakeDigest"] == hashlib.sha256(ready["intake.json"]).hexdigest()
    assert ready_report["status"] == "ready"


def test_a_source_already_in_the_policy_needs_no_revision(world: World) -> None:
    """A key withdrawn as missing that returns with other bytes is `new`; its source is known."""
    first = batch_document("era-1", rows_of("a", "b"), T1)
    second = batch_document("era-1", rows_of("a"), T2)  # b missing
    third = batch_document("era-1", [*rows_of("a"), Row(key_of("b"), content=b"other bytes")], T3)
    memory = Memory([*rows_of("a", "b"), Row(key_of("b"), content=b"other bytes")])
    outputs = world.direct(third, [first, second], memory=memory)
    assert outputs.status == "ready"
    report = loaded(outputs.files, "diff-report.json")
    assert report["classes"]["new"] == [key_of("b")] and report["classes"]["unchanged"] == [
        key_of("a")
    ]
    assert "withdrawals.json" not in outputs.files  # b was already withdrawn by the second batch
    listed = loaded(outputs.files, "new-sources.json")
    assert [entry["sourceKey"] for entry in listed["sources"]] == [key_of("b")]


# --- classification into files -------------------------------------------------------------


def test_changed_missing_and_provenance_only_change(world: World) -> None:
    first = batch_document("era-1", rows_of("a", "b", "c", "d"), T1)
    changed = Row(key_of("a"), content=b"new bytes for a")
    reasserted = Row(key_of("c"), content=rows_of("c")[0].content, decided=T2)  # provenance only
    second = batch_document(
        "era-1", [changed, reasserted, *rows_of("d"), *rows_of("e")], T2
    )  # b is missing
    memory = Memory([*rows_of("a", "b", "c", "d", "e"), changed])
    outputs = world.direct(second, [first], memory=memory)
    assert outputs.status == "ready"
    files = outputs.files
    diff = loaded(files, "diff-report.json")
    assert diff["classes"] == {
        "new": [key_of("e")],
        "unchanged": [key_of("c"), key_of("d")],
        "changed": [key_of("a")],
        "moved": [],
        "returned": [],
        "missing": [key_of("b")],
    }
    first_id = batch_id(PROJECT, "era-1", digest_of(first))
    assert diff["assumedAdmittedBatchIds"] == [first_id]
    assert diff["previousBatchDigests"] == [digest_of(first)]
    assert diff["batchDigest"] == digest_of(second)
    intake = loaded(files, "intake.json")
    assert intake["batchId"] == batch_id(PROJECT, "era-1", digest_of(second))
    assert [item["sourceId"] for item in intake["items"]] == [
        source_id(PROJECT, key_of("a")),
        source_id(PROJECT, key_of("e")),
    ]
    assert intake["items"][0]["assetId"] == asset_of_row(second, key_of("a"))
    assert intake["items"][0]["custodyRef"] == {
        "rootId": LABEL,
        "relativePath": changed.relative_path,
    }
    assert intake["profileId"] == PROFILE_ID and intake["createdAt"] == T2
    withdrawals = WithdrawalList.from_wire(
        files["withdrawals.json"], world.schemas["cf.withdrawal-list.v1"]
    )
    assert withdrawals.by_batch_digest == digest_of(second)
    assert withdrawals.diff_report_digest == hashlib.sha256(files["diff-report.json"]).hexdigest()
    assert [(entry.cause, entry.reason.code) for entry in withdrawals.entries] == [
        ("changed", "source_changed"),
        ("missing", "source_missing"),
    ]
    assert [entry.asset_id for entry in withdrawals.entries] == [
        asset_of_row(first, key_of("a")),
        asset_of_row(first, key_of("b")),
    ]
    for entry in withdrawals.entries:
        assert entry.batch_id == first_id
        assert entry.decision_id == decision_id(
            PROJECT, first_id, entry.asset_id, entry.cause, digest_of(second)
        )
    assert "diffReportDigest" not in diff and "withdrawalsDigest" not in diff  # no digest cycle


def test_second_batch_key_does_not_make_the_first_missing_and_moves_are_reported(
    world: World,
) -> None:
    first = batch_document("era-1", rows_of("a", "b"), T1)
    second = batch_document("era-2", [*rows_of("b"), *rows_of("c")], T2)
    memory = Memory(rows_of("a", "b", "c"))
    outputs = world.direct(second, [first], memory=memory)
    diff = loaded(outputs.files, "diff-report.json")
    assert diff["classes"]["missing"] == [] and diff["classes"]["moved"] == [key_of("b")]
    assert diff["classes"]["new"] == [key_of("c")]
    assert "withdrawals.json" not in outputs.files
    intake = loaded(outputs.files, "intake.json")
    assert [item["sourceId"] for item in intake["items"]] == [source_id(PROJECT, key_of("c"))]


def test_returned_asset_is_reported_and_left_out(world: World) -> None:
    first = batch_document("era-1", rows_of("a", "b"), T1)
    second = batch_document("era-1", rows_of("a"), T2)  # b withdrawn as missing
    third = batch_document("era-1", rows_of("a", "b"), T3)  # the very same b is back
    memory = Memory(rows_of("a", "b"))
    outputs = world.direct(third, [first, second], memory=memory)
    diff = loaded(outputs.files, "diff-report.json")
    assert diff["classes"]["returned"] == [key_of("b")] and diff["classes"]["new"] == []
    assert "intake.json" not in outputs.files and "withdrawals.json" not in outputs.files
    assert outputs.status == "ready"


def test_a_key_absent_from_two_later_exports_is_withdrawn_once(world: World) -> None:
    first = batch_document("era-1", rows_of("a", "b"), T1)
    second = batch_document("era-1", rows_of("a"), T2)
    third = batch_document("era-1", rows_of("a", "c"), T3)
    memory = Memory(rows_of("a", "b", "c"))
    second_run = world.direct(second, [first], memory=memory)
    assert "withdrawals.json" in second_run.files
    third_run = world.direct(third, [first, second], memory=memory)
    assert "withdrawals.json" not in third_run.files  # b was withdrawn by the second batch


def test_unchanged_item_that_later_goes_missing_keeps_its_original_batch(world: World) -> None:
    first = batch_document("era-1", rows_of("a", "b"), T1)
    second = batch_document("era-1", rows_of("a", "b", "c"), T2)  # a, b unchanged, c new
    third = batch_document("era-1", rows_of("b", "c"), T3)  # a missing
    memory = Memory(rows_of("a", "b", "c"))
    outputs = world.direct(third, [first, second], memory=memory)
    withdrawals = WithdrawalList.from_wire(
        outputs.files["withdrawals.json"], world.schemas["cf.withdrawal-list.v1"]
    )
    assert [entry.batch_id for entry in withdrawals.entries] == [
        batch_id(PROJECT, "era-1", digest_of(first))  # not the second, which only re-listed it
    ]
    assert loaded(outputs.files, "diff-report.json")["assumedAdmittedBatchIds"] == sorted(
        {
            batch_id(PROJECT, "era-1", digest_of(first)),
            batch_id(PROJECT, "era-1", digest_of(second)),
        }
    )


def test_signed_metadata_flows_through_identity_digest_and_intake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signed = World(tmp_path, monkeypatch, sources=["k-a"], schema_file=SIGNED_BYTES)
    rows = [Row(key_of("a"), meta={"delta": -3})]
    document = batch_document("era-1", rows, T1, identity=["delta"])
    memory = Memory(rows)
    first = signed.direct(document, memory=memory)
    again = signed.direct(document, memory=memory)
    assert dict(first.files) == dict(again.files)
    intake = loaded(first.files, "intake.json")
    assert intake["items"][0]["metadata"] == {"delta": -3}
    assert intake["items"][0]["assetId"] == asset_of_row(document, key_of("a"))
    changed = batch_document(
        "era-1", [Row(key_of("a"), meta={"delta": -4})], T2, identity=["delta"]
    )
    later = signed.direct(changed, [document], memory=Memory(rows))
    assert loaded(later.files, "diff-report.json")["classes"]["changed"] == [key_of("a")]


def test_outputs_are_held_to_the_limits_a_consumer_applies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two new sources against a new-sources array bound of one: refused, never truncated."""
    tight = limits().model_copy(update={"max_array_items": 1})
    bound = World(
        tmp_path,
        monkeypatch,
        sources=[],
        tightened={"cf.new-sources.v1": tight},
    )
    rows = rows_of("a", "b")
    bound.put(rows)
    result, out = bound.build(bound.batch_file("batch.json", batch_document("era-1", rows, T1)))
    assert result.exit == 3 and result.code == "limit_exceeded", result.raw
    assert not out.exists()


# --- end to end on the temporary PostgreSQL ------------------------------------------------


def withdrawal_rows(ledger: Ledger) -> dict[str, tuple[str, str]]:
    from psycopg import sql

    with ledger.transaction() as tx:
        rows = tx.connection.execute(
            sql.SQL("SELECT asset_id,batch_id,reason FROM {}").format(
                tx.table("admission_withdrawals")
            )
        ).fetchall()
    return {str(row[0]): (str(row[1]), row[2]["code"]) for row in rows}


def coverage_status(world: World, refs: Sequence[Ref]) -> dict[str, str]:
    from conscience_foundry.release.coverage import build_coverage, capture

    runtime = Runtime(load_config(world.env.config_path), TrustedServices(), "build-release")
    try:
        with runtime.ledger.transaction() as tx:
            snapshot = capture(tuple(refs), tx, runtime.release)
        report = build_coverage(snapshot, (), "f" * 64, {})
    finally:
        runtime.close()
    return {entry.asset_id: entry.status for entry in report.entries}


@pytest.mark.database
def test_end_to_end_admit_then_withdraw(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    e2e = World(tmp_path, monkeypatch, sources=[key_of(n) for n in "abc"], ledger=ledger)
    e2e.env.extra["releaseAuthority"] = {"kind": "local"}
    e2e.env.write_config()

    def current_services() -> TrustedServices:
        """Built from the policy in force now: the local authority pins it when it is built."""
        built = live.build_services(load_config(e2e.env.config_path))
        return replace(built, clock=lambda: TIME)

    services = current_services()

    first_rows = rows_of("a", "b", "c")
    e2e.put(first_rows)
    first = batch_document("era-1", first_rows, T1)
    first_file = e2e.batch_file("one.json", first)
    built, out_one = e2e.build(first_file)
    assert built.exit == 0 and built.payload["status"] == "ready", built.raw
    admitted = e2e.env.invoke(
        "admit", "--manifest", str(out_one / "intake.json"), "--execute", services=services
    )
    assert admitted.exit == 0, admitted.raw
    assert [row["status"] for row in admitted.payload["entries"]] == ["admitted"] * 3
    first_report = Ref.model_validate(admitted.payload["reportRef"])
    assert count(ledger, "assets") == 3

    # The re-export: a changed, b missing, c unchanged, d new (and not yet in the policy).
    replacement = Row(key_of("a"), content=b"a, revised")
    second_rows = [replacement, *rows_of("c", "d")]
    e2e.put(second_rows)
    second = batch_document("era-1", second_rows, T2)
    second_file = e2e.batch_file("two.json", second)
    held, held_out = e2e.build(second_file, first_file)
    assert held.payload["status"] == "policy_revision_needed", held.raw
    assert sorted(outputs_of(held_out)) == ["diff-report.json", "new-sources.json"]
    e2e.revise_policy([key_of(n) for n in "abcd"])
    services = current_services()
    ready, out_two = e2e.build(second_file, first_file)
    assert ready.payload["status"] == "ready", ready.raw
    admitted_two = e2e.env.invoke(
        "admit", "--manifest", str(out_two / "intake.json"), "--execute", services=services
    )
    assert admitted_two.exit == 0, admitted_two.raw
    assert [row["status"] for row in admitted_two.payload["entries"]] == ["admitted"] * 2
    second_report = Ref.model_validate(admitted_two.payload["reportRef"])

    arguments = (
        "withdraw",
        "--list",
        str(out_two / "withdrawals.json"),
        "--evidence",
        str(out_two / "diff-report.json"),
    )
    dry = e2e.env.invoke(*arguments, services=services)
    assert dry.payload["outcome"] == "dry_run" and dry.payload["wouldApply"] == 2, dry.raw
    assert withdrawal_rows(ledger) == {}
    done = e2e.env.invoke(*arguments, "--execute", services=services)
    assert done.exit == 0 and (done.payload["applied"], done.payload["alreadyRecorded"]) == (
        2,
        0,
    ), done.raw
    first_batch = batch_id(PROJECT, "era-1", digest_of(first))
    old_a, old_b = asset_of_row(first, key_of("a")), asset_of_row(first, key_of("b"))
    assert withdrawal_rows(ledger) == {
        old_a: (first_batch, "source_changed"),
        old_b: (first_batch, "source_missing"),
    }
    again = e2e.env.invoke(*arguments, "--execute", services=services)
    assert (again.payload["applied"], again.payload["alreadyRecorded"]) == (0, 2), again.raw

    new_a, new_d = asset_of_row(second, key_of("a")), asset_of_row(second, key_of("d"))
    status = coverage_status(e2e, [first_report, second_report])
    assert status[old_a] == "withdrawn" and status[old_b] == "withdrawn"
    assert status[new_a] != "withdrawn" and status[new_d] != "withdrawn"
    assert status[asset_of_row(first, key_of("c"))] != "withdrawn"
    assert count(ledger, "assets") == 5
