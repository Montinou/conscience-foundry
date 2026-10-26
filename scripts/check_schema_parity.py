"""Cross-language parity of exported schemas, Unicode handling and RFC 8785 bytes and digests.

    uv run python scripts/check_schema_parity.py [--bundle DIR] [--fixtures FILE]

The Python side validates fixture instances with the maintained Pydantic models and canonicalizes
with the Python RFC 8785 package. The Node side (`tests/js/schema_parity.mjs`) validates the same
instances against the exported JSON Schema 2020-12 files with Ajv and canonicalizes with an
independently locked RFC 8785 library; it imports no repository code. Fixture expectations are
authored literals. Shape verdicts must agree; `semantic_invalid` cases are shape-valid for
JSON Schema and rejected by the trusted semantic checks, and `python_only` cases pin the known
array-bound gap of the exported schemas (Python rejects, Ajv accepts). Both splits are asserted,
not hidden.

A missing Node toolchain or locked dependency raises `NodeToolchainBlocked`; it is never skipped
and never replaced by a Python-only check.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import rfc8785

from conscience_foundry.contracts.common import ContractError, ContractLimits
from conscience_foundry.contracts.registry import SCHEMA_MODELS, registered_schema_ids

ROOT = Path(__file__).resolve().parents[1]
NODE_SCRIPT = ROOT / "tests" / "js" / "schema_parity.mjs"
NODE_TIMEOUT_SECONDS = 120
BLOCKED_EXIT = 2

LIMITS = ContractLimits(
    schema_version="kf.contract-limits.v1",
    version="synthetic.parity.v1",
    max_json_bytes=1_000_000,
    max_string_scalars=10_000,
    max_array_items=1_000,
    max_depth=16,
    max_manifest_items=100,
    max_source_bytes=1_000_000,
    max_output_bytes=1_000_000,
    max_error_message_scalars=200,
)


# (python accepts, node accepts) per fixture kind. `semantic_invalid` is rejected by trusted
# semantic checks only. `python_only` pins a known export gap: Python enforces a bound that the
# exported JSON Schema does not express; once the export is fixed Ajv rejects it too, this check
# fails and the pin must be retired.
EXPECTED_VERDICTS: dict[str, tuple[bool, bool]] = {
    "valid": (True, True),
    "shape_invalid": (False, False),
    "semantic_invalid": (False, True),
    "python_only": (False, True),
}


class SchemaParityError(Exception):
    """Python and Node disagree, or a fixture expectation does not hold."""


class NodeToolchainBlocked(Exception):
    """The locked Node toolchain is unavailable; this is a blocker, never a skip."""


def python_report(fixtures: dict[str, Any]) -> dict[str, Any]:
    shape: dict[str, bool] = {}
    for case in fixtures["shapeCases"]:
        model = SCHEMA_MODELS[case["schemaId"]]
        data = json.dumps(case["instance"]).encode("utf-8")
        try:
            model.from_wire(data, LIMITS)
            shape[case["caseId"]] = True
        except ContractError:
            shape[case["caseId"]] = False
    unicode_report: dict[str, Any] = {}
    for case in fixtures["unicodeCases"]:
        text: str = case["text"]
        well_formed = not any(0xD800 <= ord(character) <= 0xDFFF for character in text)
        unicode_report[case["caseId"]] = {
            "wellFormed": well_formed,
            "scalarLength": len(text) if well_formed else None,
            "utf16Length": len(text.encode("utf-16-le", "surrogatepass")) // 2,
            "utf8Hex": text.encode("utf-8").hex() if well_formed else None,
        }
    jcs: dict[str, Any] = {}
    for vector in fixtures["jcsVectors"]:
        canonical = rfc8785.dumps(vector["value"])
        entry: dict[str, str] = {"canonicalHex": canonical.hex()}
        if "domain" in vector:
            entry["digest"] = hashlib.sha256(
                vector["domain"].encode("utf-8") + b"\n" + canonical
            ).hexdigest()
        jcs[vector["caseId"]] = entry
    return {"shape": shape, "unicode": unicode_report, "jcs": jcs}


def node_report(
    bundle: Path, fixtures: Path, *, node_script: Path | None = None
) -> dict[str, Any]:
    script = node_script if node_script is not None else NODE_SCRIPT
    try:
        completed = subprocess.run(
            ["node", str(script), "--bundle", str(bundle), "--fixtures", str(fixtures)],
            check=False,
            capture_output=True,
            text=True,
            timeout=NODE_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        raise NodeToolchainBlocked("node is unavailable") from None
    except subprocess.TimeoutExpired:
        raise NodeToolchainBlocked(
            f"node parity check timed out after {NODE_TIMEOUT_SECONDS} seconds"
        ) from None
    if completed.returncode == BLOCKED_EXIT:
        raise NodeToolchainBlocked(completed.stderr.strip())
    if completed.returncode != 0:
        raise SchemaParityError(completed.stderr.strip() or "node parity check failed")
    report: dict[str, Any] = json.loads(completed.stdout)
    return report


def check_schema_parity(bundle: Path, fixtures: Path) -> None:
    """Raise `SchemaParityError` or `NodeToolchainBlocked`; return None when parity holds."""
    data: dict[str, Any] = json.loads(fixtures.read_text(encoding="utf-8"))
    node = node_report(bundle, fixtures)
    python = python_report(data)
    problems: list[str] = []
    if node["compiledSchemas"] != sorted(registered_schema_ids()):
        problems.append("bundle schema set differs from the registered schemas")
    for case in data["shapeCases"]:
        cid, kind = case["caseId"], case["kind"]
        py, js = python["shape"][cid], node["shape"][cid]
        expected = EXPECTED_VERDICTS.get(kind)
        if expected is None:
            problems.append(f"shape {cid}: unknown kind {kind}")
        elif (py, js) != expected:
            problems.append(f"shape {cid}: python={py} node={js} kind={kind}")
    for cid, entry in python["unicode"].items():
        if entry != node["unicode"][cid]:
            problems.append(f"unicode {cid}")
    for vector in data["jcsVectors"]:
        cid = vector["caseId"]
        expected_hex = vector["canonicalUtf8Hex"]
        if (
            python["jcs"][cid]["canonicalHex"] != expected_hex
            or python["jcs"][cid] != node["jcs"][cid]
        ):
            problems.append(f"jcs bytes {cid}")
        if "digest" in vector and python["jcs"][cid]["digest"] != vector["digest"]:
            problems.append(f"jcs digest {cid}")
    if problems:
        raise SchemaParityError("; ".join(problems))


def main(arguments: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--bundle", type=Path, default=ROOT / "schemas")
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=ROOT / "tests" / "fixtures" / "public" / "schema_parity.json",
    )
    options = parser.parse_args(list(arguments))
    try:
        check_schema_parity(options.bundle, options.fixtures)
    except NodeToolchainBlocked as blocked:
        print(f"BLOCKED: {blocked}", file=sys.stderr)
        return BLOCKED_EXIT
    except SchemaParityError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print("schema parity ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
