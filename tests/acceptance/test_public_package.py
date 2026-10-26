"""Public-package boundary and independent cross-language parity (offline, synthetic)."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import rfc8785

from conscience_foundry.contracts.common import ContractLimits
from conscience_foundry.contracts.registry import registered_schema_ids
from conscience_foundry.core.comparison import F1Comparison, comparison_digest
from conscience_foundry.core.identity import (
    F1Operation,
    RevisionInputs,
    operation_key,
    revision_id,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "public" / "schema_parity.json"
BUNDLE = ROOT / "schemas"


def load_script(name: str) -> ModuleType:
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"cf_script_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def git_lines(*arguments: str) -> list[str]:
    result = subprocess.run(
        ["git", *arguments, "-z"], cwd=ROOT, check=True, capture_output=True, text=True
    )
    return [item for item in result.stdout.split("\0") if item]


def prospective_index_paths() -> list[str]:
    """Tracked files plus untracked files that a plain `git add` could stage."""
    tracked = git_lines("ls-files")
    untracked = git_lines("ls-files", "--others", "--exclude-standard")
    return sorted(
        {path for path in (*tracked, *untracked) if (ROOT / path).exists() or path in tracked}
    )


def build_distributions(
    index_paths: Sequence[str], destination: Path
) -> tuple[list[str], list[str]]:
    tree = destination / "tree"
    for relative in index_paths:
        source = ROOT / relative
        if source.is_file():
            target = tree / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    out = destination / "out"
    subprocess.run(
        ["uv", "build", "--offline", "--out-dir", str(out)],
        cwd=tree,
        check=True,
        capture_output=True,
        timeout=600,
    )
    (wheel,) = out.glob("*.whl")
    (sdist,) = out.glob("*.tar.gz")
    with zipfile.ZipFile(wheel) as archive:
        wheel_members = archive.namelist()
    with tarfile.open(sdist) as tar:
        sdist_members = [m.name + "/" if m.isdir() else m.name for m in tar.getmembers()]
    return wheel_members, sdist_members


def test_distribution_excludes_private_material(tmp_path: Path) -> None:
    boundary = load_script("check_public_boundary")
    index_paths = prospective_index_paths()
    # No staged or stageable path may be private, so a bulk `git add` stays safe.
    assert boundary.check_public_boundary(index_paths, ()) == ()

    wheel_members, sdist_members = build_distributions(index_paths, tmp_path)
    assert "conscience_foundry/__init__.py" in wheel_members
    assert "conscience_foundry/ledger/migrations/001_initial.sql" in wheel_members
    assert any(name.endswith("/pyproject.toml") for name in sdist_members)
    # The allowlist, not a denylist, decides what a wheel and an sdist may contain.
    assert boundary.check_public_boundary((), wheel_members) == ()
    assert boundary.check_public_boundary((), sdist_members) == ()
    for member in (*wheel_members, *sdist_members):
        # Neither archive may carry a test, schema bundle, doc or script tree, at the root or
        # under an sdist's versioned top directory.
        parts = member.split("/")
        assert not {"tests", "schemas", "docs", "scripts", "node_modules"} & set(parts), member
        assert "HANDOFF" not in member and "CLAUDE" not in member and ".env" not in member
    assert not any(name.endswith(".json") for name in wheel_members)
    assert {name.split("/")[0] for name in wheel_members} == {
        "conscience_foundry",
        next(name.split("/")[0] for name in wheel_members if ".dist-info/" in name),
    }


PRIVATE = [
    "HANDOFF.md",
    "CLAUDE.md",
    ".DS_Store",
    "docs/specs/imported.md",
    "docs/requirements/imported.md",
    "docs/references/imported.md",
    ".env",
    ".env.local",
    "src/conscience_foundry/.env",
    "corpus/raw/a.txt",
    "data/raw_corpus.jsonl",
    "models/weights.safetensors",
    "src/conscience_foundry/models/x.bin",
    "src/conscience_foundry/imported_history/x.py",
    ".methodology/sdd/plan/report.md",
    ".triqual/store.db",
    "store/objects/aa",
    "/etc/passwd",
    "../outside.txt",
    "src/conscience_foundry/../../escape.py",
    "C:\\Users\\someone\\x.txt",
]


@pytest.mark.parametrize("private", PRIVATE)
def test_boundary_rejects_private_paths_and_unlisted_members(private: str) -> None:
    boundary = load_script("check_public_boundary")
    assert boundary.check_public_boundary([private], ()) != ()
    assert boundary.check_public_boundary((), [private]) != ()
    mixed = boundary.check_public_boundary(["README.md", private], ["conscience_foundry/x.py"])
    assert mixed != () and all(isinstance(item, str) for item in mixed)


UNLISTED_UNDER_ALLOWED_PREFIXES = [
    "tests/fixtures/raw_corpus.jsonl",
    "tests/notes/old-HANDOFF.md",
    "scripts/models.bin",
    "tests/js/.npmrc",
    "tests/x/.pgpass",
    "tests/x/.netrc",
    "tests/x/.envrc",
    "tests/x/terraform.tfstate",
    "tests/x/a.p8",
    "src/conscience_foundry/notes.txt",
    "src/conscience_foundry/storage/blob.bin",
    "schemas/notes.md",
    "schemas/kf.extra.v1.dump.json",
    "scripts/run.sh",
    "scripts/data.json",
    "tests/fixtures/export.csv",
    "tests/fixtures/public/export.csv",
    "tests/fixtures/other/data.json",
    "tests/data.sqlite-journal",
    "tests/js/package-lock.json.bak",
    "tests/__pycache__/x.cpython-314.pyc",
]


@pytest.mark.parametrize("path", UNLISTED_UNDER_ALLOWED_PREFIXES)
def test_prefix_alone_never_allowlists_an_index_path(path: str) -> None:
    boundary = load_script("check_public_boundary")
    violations = boundary.check_public_boundary([path], ())
    assert len(violations) == 1 and violations[0].endswith(f":{path}"), violations


def test_every_shipped_extension_family_stays_allowed() -> None:
    boundary = load_script("check_public_boundary")
    shipped = [
        "src/conscience_foundry/__init__.py",
        "src/conscience_foundry/py.typed",
        "src/conscience_foundry/ledger/migrations/001_initial.sql",
        "schemas/kf.document-span.v1.schema.json",
        "schemas/kf.document-span.v1.rules.json",
        "schemas/json-schema.2020-12.schema.json",
        "scripts/check_public_boundary.py",
        "tests/conftest.py",
        "tests/acceptance/test_public_package.py",
        "tests/fixtures/public/schema_parity.json",
        "tests/js/package.json",
        "tests/js/package-lock.json",
        "tests/js/schema_parity.mjs",
    ]
    assert boundary.check_public_boundary(shipped, ()) == ()


def test_boundary_allows_only_the_owned_guide_and_package_layout() -> None:
    boundary = load_script("check_public_boundary")
    assert boundary.check_public_boundary(["docs/guide/f1.md", "README.md"], ()) == ()
    assert boundary.check_public_boundary((), ["docs/guide/f1.md"]) != ()
    assert boundary.check_public_boundary(["docs/guide/other.md"], ()) != ()
    assert boundary.check_public_boundary(["tests/js/node_modules/ajv/package.json"], ()) != ()
    assert boundary.check_public_boundary((), ["conscience_foundry/storage/new_blob.bin"]) != ()
    assert boundary.check_public_boundary((), ["conscience_foundry-0.1.0/HANDOFF.md"]) != ()
    assert boundary.check_public_boundary((), ["conscience_foundry-0.1.0.dist-info/METADATA"]) == ()
    reasons = boundary.check_public_boundary(["HANDOFF.md"], ["x/.env"])
    assert len(reasons) == 2 and reasons == tuple(sorted(reasons))


@pytest.mark.parametrize(
    "path",
    [
        "docs/specs/KNOWLEDGE_FOUNDRY_F0_SPEC_v0_1.md",
        "docs/references/document-checksums.json",
        "docs/requirements/imported.md",
        "HANDOFF.md",
        "CLAUDE.md",
        ".DS_Store",
        "tests/js/node_modules/ajv/package.json",
    ],
)
def test_historical_material_is_ignored_by_exact_patterns(path: str) -> None:
    ignored = subprocess.run(["git", "check-ignore", "-q", "--no-index", path], cwd=ROOT)
    assert ignored.returncode == 0


@pytest.mark.parametrize(
    "path",
    [
        "docs/guide/f1.md",
        "tests/js/package.json",
        "tests/js/package-lock.json",
        "tests/js/schema_parity.mjs",
        "scripts/check_public_boundary.py",
        "README.md",
    ],
)
def test_owned_paths_stay_includable(path: str) -> None:
    ignored = subprocess.run(["git", "check-ignore", "-q", "--no-index", path], cwd=ROOT)
    assert ignored.returncode == 1


def test_js_tooling_is_locked_without_absolute_paths_or_credentials() -> None:
    package = json.loads((ROOT / "tests/js/package.json").read_text(encoding="utf-8"))
    lock = json.loads((ROOT / "tests/js/package-lock.json").read_text(encoding="utf-8"))
    assert package["private"] is True
    assert set(package["devDependencies"]) == {"ajv", "canonicalize"}
    assert all(version[0].isdigit() for version in package["devDependencies"].values())
    assert package["devDependencies"]["ajv"] == "8.20.0"
    for name, version in package["devDependencies"].items():
        assert lock["packages"][f"node_modules/{name}"]["version"] == version
    for entry in lock["packages"].values():
        if entry.get("resolved"):
            assert entry["resolved"].startswith("https://registry.npmjs.org/")
            assert entry["integrity"].startswith("sha512-")
    for path in (ROOT / "tests" / "js").iterdir():
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            assert "/Users/" not in text and "/home/" not in text and "/private/" not in text
            assert "_authToken" not in text and "password" not in text.lower()


def limits() -> ContractLimits:
    return ContractLimits(
        schema_version="kf.contract-limits.v1",
        version="synthetic.v1",
        max_json_bytes=1_000_000,
        max_string_scalars=10_000,
        max_array_items=1_000,
        max_depth=16,
        max_manifest_items=100,
        max_source_bytes=1_000_000,
        max_output_bytes=1_000_000,
        max_error_message_scalars=200,
    )


def fixture_data() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(FIXTURES.read_text(encoding="utf-8"))
    return loaded


def test_cross_language_schema_and_unicode_fixtures() -> None:
    parity = load_script("check_schema_parity")
    assert parity.check_schema_parity(BUNDLE, FIXTURES) is None

    fixtures = fixture_data()
    python = parity.python_report(fixtures)
    node = parity.node_report(BUNDLE, FIXTURES)
    kinds = {case["kind"] for case in fixtures["shapeCases"]}
    assert kinds == {"valid", "shape_invalid", "semantic_invalid"}
    # The independent validator compiled every exported schema in the bundle.
    assert node["compiledSchemas"] == sorted(registered_schema_ids())
    # The two raw byte roles compile as {"not": {}} but are outside JSON-instance parity.
    assert node["outsideInstanceParity"] == ["kf.canonical-text.v1", "kf.raw-original.v1"]
    assert set(node["outsideInstanceParity"]) <= set(node["compiledSchemas"])
    for case in fixtures["shapeCases"]:
        cid = case["caseId"]
        py, js = python["shape"][cid], node["shape"][cid]
        if case["kind"] == "valid":
            assert (py, js) == (True, True), cid
        elif case["kind"] == "shape_invalid":
            assert (py, js) == (False, False), cid
        else:  # semantic checks stay separate from JSON Schema shape
            assert (py, js) == (False, True), cid
    for case in fixtures["unicodeCases"]:
        cid = case["caseId"]
        assert python["unicode"][cid] == node["unicode"][cid], cid
        assert node["unicode"][cid]["wellFormed"] is case["wellFormed"]
        assert node["unicode"][cid]["scalarLength"] == case["scalarLength"]
        assert node["unicode"][cid]["utf16Length"] == case["utf16Length"]
        assert node["unicode"][cid]["utf8Hex"] == case["utf8Hex"]
    astral = node["unicode"]["astral-scalar"]
    assert astral["scalarLength"] == 3 and astral["utf16Length"] == 4
    assert node["unicode"]["composed"]["utf8Hex"] != node["unicode"]["decomposed"]["utf8Hex"]


def test_parity_checker_rejects_divergence_and_blocks_on_missing_node_dependency(
    tmp_path: Path,
) -> None:
    parity = load_script("check_schema_parity")
    fixtures = fixture_data()
    wrong_kind = json.loads(json.dumps(fixtures))
    wrong_kind["shapeCases"][0]["kind"] = "shape_invalid"
    bad = tmp_path / "wrong_kind.json"
    bad.write_text(json.dumps(wrong_kind), encoding="utf-8")
    with pytest.raises(parity.SchemaParityError):
        parity.check_schema_parity(BUNDLE, bad)

    wrong_digest = json.loads(json.dumps(fixtures))
    vector = next(item for item in wrong_digest["jcsVectors"] if "digest" in item)
    vector["digest"] = "0" * 64
    bad_digest = tmp_path / "wrong_digest.json"
    bad_digest.write_text(json.dumps(wrong_digest), encoding="utf-8")
    with pytest.raises(parity.SchemaParityError):
        parity.check_schema_parity(BUNDLE, bad_digest)

    # A missing locked dependency is blocked, never skipped and never replaced.
    isolated = tmp_path / "js"
    isolated.mkdir()
    shutil.copy2(ROOT / "tests/js/schema_parity.mjs", isolated / "schema_parity.mjs")
    shutil.copy2(ROOT / "tests/js/package.json", isolated / "package.json")
    with pytest.raises(parity.NodeToolchainBlocked):
        parity.node_report(BUNDLE, FIXTURES, node_script=isolated / "schema_parity.mjs")


def vector_by_id(fixtures: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["caseId"]: item for item in fixtures["jcsVectors"]}


def test_independent_jcs_bytes_and_digests() -> None:
    import hashlib

    parity = load_script("check_schema_parity")
    fixtures = fixture_data()
    node = parity.node_report(BUNDLE, FIXTURES)
    vectors = vector_by_id(fixtures)
    assert len(vectors) >= 10
    for cid, vector in vectors.items():
        expected = bytes.fromhex(vector["canonicalUtf8Hex"])
        assert expected.decode("utf-8") == vector["canonical"]
        python_bytes = rfc8785.dumps(vector["value"])
        assert python_bytes == expected, cid
        assert bytes.fromhex(node["jcs"][cid]["canonicalHex"]) == expected, cid
        if "digest" in vector:
            prefix = vector["domain"].encode("utf-8") + b"\n"
            assert hashlib.sha256(prefix + python_bytes).hexdigest() == vector["digest"], cid
            assert node["jcs"][cid]["digest"] == vector["digest"], cid

    ordering = bytes.fromhex(vectors["key-order-utf16"]["canonicalUtf8Hex"])
    # JCS sorts keys by UTF-16 code units: U+10000 (D800 DC00) precedes U+E000.
    assert ordering.index("\U00010000".encode()) < ordering.index("\ue000".encode())
    codepoint_order = sorted(vectors["key-order-utf16"]["value"])
    assert codepoint_order.index("\ue000") < codepoint_order.index("\U00010000")
    assert (
        vectors["composed-string"]["canonicalUtf8Hex"]
        != vectors["decomposed-string"]["canonicalUtf8Hex"]
    )
    assert b'"1.00"' in bytes.fromhex(vectors["decimal-strings"]["canonicalUtf8Hex"])
    assert b"9007199254740991" in bytes.fromhex(vectors["safe-integer-limits"]["canonicalUtf8Hex"])
    assert vectors["domain-key-order-digest"]["digest"] != hashlib.sha256(
        b"kf.revision.v1\n" + '{"\ue000":"x","\U00010000":"y"}'.encode()
    ).hexdigest()


def test_production_identity_digests_match_independent_vectors() -> None:
    vectors = vector_by_id(fixture_data())
    configured = limits()
    revision = vectors["revision-projection"]
    assert (
        revision_id(RevisionInputs(
            project_id=revision["value"]["projectId"],
            source_id=revision["value"]["sourceId"],
            original_digest=revision["value"]["originalDigest"],
            text_digest=revision["value"]["textDigest"],
            extraction_spec_digest=revision["value"]["extractionSpecDigest"],
            structure_digest=revision["value"]["structureDigest"],
            origin_map_digest=revision["value"]["originMapDigest"],
        ), limits=configured)
        == revision["digest"]
    )
    op = vectors["operation-projection"]["value"]
    assert (
        operation_key(F1Operation(
            project_id=op["projectId"],
            asset_id=op["assetId"],
            source_id=op["sourceId"],
            input_digests=tuple(op["inputDigests"]),
            extraction_spec_digest=op["extractionSpecDigest"],
            profile_id=op["profileId"],
            profile_version=op["profileVersion"],
            policy_digest=op["policyDigest"],
            contract_set_digest=op["contractSetDigest"],
            limits_digests=tuple(op["limitsDigests"]),
        ), limits=configured)
        == vectors["operation-projection"]["digest"]
    )
    cmp_ = vectors["comparison-projection"]["value"]
    assert (
        comparison_digest(F1Comparison(
            project_id=cmp_["projectId"],
            asset_id=cmp_["assetId"],
            source_id=cmp_["sourceId"],
            operation_key=cmp_["operationKey"],
            revision_id=cmp_["revisionId"],
            original_digest=cmp_["originalDigest"],
            text_digest=cmp_["textDigest"],
            extraction_spec_digest=cmp_["extractionSpecDigest"],
            structure_digest=cmp_["structureDigest"],
            origin_map_digest=cmp_["originMapDigest"],
            quality_projection_digest=cmp_["qualityProjectionDigest"],
        ), limits=configured)
        == vectors["comparison-projection"]["digest"]
    )


def test_public_guide_and_readme_are_agnostic() -> None:
    guide = (ROOT / "docs" / "guide" / "f1.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for required in (
        "node tests/js/schema_parity.mjs",
        "uv run python scripts/check_schema_parity.py",
        "uv run python scripts/check_public_boundary.py",
        "uv run pytest tests/acceptance/test_public_package.py -q",
        "CF_TEST_POSTGRES_DSN",
        "CF_TEST_POSTGRES_APPROVED_DSN",
        "not_run",
        "ajv@8.20.0",
        "canonicalize@5.1.0",
        "unsigned",
        "staging",
        "scoped executor",
        "restart",
        "single-use",
    ):
        assert required in guide, required
    for label in ("synthetic_offline", "local_isolated_postgres", "not_run", "blocked"):
        assert label in guide, label
    for text in (guide, readme):
        for private in (
            "/Users/",
            "/home/",
            "HANDOFF",
            "Knowledge Foundry",
            "KF-",
            "Agora",
            "Laya",
            "@gmail.com",
            "postgres://",
            "postgresql://",
            "AKIA",
            "sk-",
        ):
            assert private not in text, private
    assert "docs/guide/f1.md" in readme
    assert "No product implementation" not in readme


def array_nodes(schema_id: str) -> list[tuple[str, dict[str, Any]]]:
    """Every array-typed node of one exported schema, with its JSON pointer."""
    schema = json.loads((BUNDLE / f"{schema_id}.schema.json").read_text(encoding="utf-8"))
    found: list[tuple[str, dict[str, Any]]] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            if node.get("type") == "array":
                found.append((path, node))
            for key, value in node.items():
                walk(value, f"{path}/{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}/{index}")

    walk(schema, "")
    return found


def test_exported_schemas_express_array_bounds_as_items_keywords() -> None:
    """The Pydantic source is the contract: its array bounds reach every non-Python consumer."""
    for schema_id in registered_schema_ids():
        for path, node in array_nodes(schema_id):
            assert not node.keys() & {"minLength", "maxLength"}, f"{schema_id}{path}"
    plan = dict(array_nodes("kf.run-authorization.v1"))["/properties/allowedPlanDigests"]
    assert plan["minItems"] == 1
    result = dict(array_nodes("kf.result.v1"))["/properties/inputDigests"]
    assert (result["minItems"], result["maxItems"]) == (1, 1)
    # The array-bound cases are plain shape failures now: the independent validator rejects them.
    parity = load_script("check_schema_parity")
    fixtures = fixture_data()
    node_report = parity.node_report(BUNDLE, FIXTURES)
    cases = {
        "run-authorization-empty-plan-digests",
        "result-empty-input-digests",
        "result-two-input-digests",
    }
    by_id = {case["caseId"]: case for case in fixtures["shapeCases"]}
    for cid in cases:
        assert by_id[cid]["kind"] == "shape_invalid", cid
        assert node_report["shape"][cid] is False, cid


def test_generator_emits_items_bounds_for_before_validated_arrays() -> None:
    from conscience_foundry.contracts.registry import _array_bounds

    schema: dict[str, Any] = {
        "properties": {"a": {"type": "array", "minLength": 1, "maxLength": 2, "items": {}}},
        "$defs": {"B": {"properties": {"s": {"type": "string", "minLength": 3}}}},
    }
    _array_bounds(schema)
    assert schema["properties"]["a"] == {"type": "array", "minItems": 1, "maxItems": 2, "items": {}}
    assert schema["$defs"]["B"]["properties"]["s"]["minLength"] == 3  # strings keep theirs


def test_parity_checker_flags_a_retired_or_unknown_kind(tmp_path: Path) -> None:
    parity = load_script("check_schema_parity")
    fixtures = fixture_data()
    # The retired python_only kind is no longer a known verdict pair, whatever the instance does.
    stale = json.loads(json.dumps(fixtures))
    control = next(c for c in stale["shapeCases"] if c["caseId"] == "run-authorization-valid")
    control["kind"] = "python_only"
    stale_path = tmp_path / "stale.json"
    stale_path.write_text(json.dumps(stale), encoding="utf-8")
    with pytest.raises(parity.SchemaParityError):
        parity.check_schema_parity(BUNDLE, stale_path)
    unknown = json.loads(json.dumps(fixtures))
    # A case whose verdict pair happens to be (False, True) must still name a known kind.
    next(c for c in unknown["shapeCases"] if c["kind"] == "semantic_invalid")["kind"] = "mystery"
    unknown_path = tmp_path / "unknown.json"
    unknown_path.write_text(json.dumps(unknown), encoding="utf-8")
    with pytest.raises(parity.SchemaParityError):
        parity.check_schema_parity(BUNDLE, unknown_path)


def test_node_timeout_is_blocked_with_its_own_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parity = load_script("check_schema_parity")

    def hang(*arguments: Any, **keywords: Any) -> None:
        raise subprocess.TimeoutExpired(cmd="node", timeout=1)

    monkeypatch.setattr(parity.subprocess, "run", hang)
    with pytest.raises(parity.NodeToolchainBlocked) as blocked:
        parity.node_report(BUNDLE, FIXTURES)
    assert "timed out" in str(blocked.value)
    assert "unavailable" not in str(blocked.value)
