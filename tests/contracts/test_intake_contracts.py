"""Withdrawal-list and intake-diff contracts: shape, rules and registration."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from conscience_foundry.contracts.common import ContractError, ContractLimits
from conscience_foundry.contracts.intake import IntakeDiff, WithdrawalList
from conscience_foundry.contracts.registry import (
    SCHEMA_MODELS,
    _rules_bytes,
    _schema_bytes,
    registered_schema_ids,
)
from conscience_foundry.release.build import EVIDENCE_SCHEMAS
from conscience_foundry.release.edges import edge_roles

SCHEMAS = Path(__file__).resolve().parents[2] / "schemas"
PROJECT = "00000000-0000-4000-8000-000000000001"
BATCH = "00000000-0000-4000-8000-000000000002"
ASSET_A = "00000000-0000-4000-8000-0000000000a1"
ASSET_B = "00000000-0000-4000-8000-0000000000a2"
SOURCE_A = "00000000-0000-4000-8000-0000000000b1"
SOURCE_B = "00000000-0000-4000-8000-0000000000b2"
DECISION_A = "00000000-0000-4000-8000-0000000000c1"
DECISION_B = "00000000-0000-4000-8000-0000000000c2"


def limits() -> ContractLimits:
    return ContractLimits.model_validate(
        {
            "schemaVersion": "cf.contract-limits.v1",
            "version": "synthetic.limits.v1",
            "maxJsonBytes": 65536,
            "maxStringScalars": 256,
            "maxArrayItems": 32,
            "maxDepth": 16,
            "maxManifestItems": 8,
            "maxSourceBytes": 1024,
            "maxOutputBytes": 4096,
            "maxErrorMessageScalars": 40,
        }
    )


def entry(
    asset: str = ASSET_A,
    source: str = SOURCE_A,
    decision: str = DECISION_A,
    cause: str = "changed",
    code: str = "source_changed",
) -> dict[str, object]:
    return {
        "batchId": BATCH,
        "assetId": asset,
        "sourceId": source,
        "cause": cause,
        "decisionId": decision,
        "reason": {"code": code, "message": "synthetic withdrawal"},
    }


def withdrawal_list() -> dict[str, object]:
    return {
        "schemaVersion": "cf.withdrawal-list.v1",
        "projectId": PROJECT,
        "byBatchDigest": "a" * 64,
        "diffReportDigest": "b" * 64,
        "entries": [
            entry(),
            entry(ASSET_B, SOURCE_B, DECISION_B, "missing", "source_missing"),
        ],
    }


def diff() -> dict[str, object]:
    return {
        "schemaVersion": "cf.intake-diff.v1",
        "projectId": PROJECT,
        "batchKey": "era-2",
        "batchDigest": "a" * 64,
        "previousBatchDigests": ["c" * 64],
        "status": "ready",
        "classes": {
            "new": ["n/1.txt"],
            "unchanged": ["u/1.txt", "u/2.txt"],
            "changed": ["c/1.txt"],
            "moved": [],
            "returned": [],
            "missing": ["m/1.txt"],
        },
        "assumedAdmittedBatchIds": [BATCH],
        "intakeDigest": "d" * 64,
        "newSourcesDigest": "e" * 64,
    }


def wire(value: object) -> bytes:
    return json.dumps(value).encode("utf-8")


def refused(model: type[WithdrawalList] | type[IntakeDiff], value: object) -> None:
    with pytest.raises(ContractError) as error:
        model.from_wire(wire(value), limits())
    assert error.value.code == "invalid_schema"


def test_withdrawal_list_parses_and_roundtrips() -> None:
    parsed = WithdrawalList.from_wire(wire(withdrawal_list()), limits())
    assert parsed.entries[1].reason.code == "source_missing"
    assert json.loads(parsed.model_dump_json(by_alias=True)) == withdrawal_list()


def test_withdrawal_list_rules() -> None:
    empty = withdrawal_list() | {"entries": []}
    refused(WithdrawalList, empty)

    duplicate = withdrawal_list()
    duplicate["entries"] = [entry(), entry(ASSET_B, SOURCE_B, DECISION_A)]
    refused(WithdrawalList, duplicate)

    mismatch = withdrawal_list()
    mismatch["entries"] = [entry(code="source_missing")]
    refused(WithdrawalList, mismatch)
    flipped = withdrawal_list()
    flipped["entries"] = [entry(cause="missing", code="source_changed")]
    refused(WithdrawalList, flipped)

    other_code = withdrawal_list()
    other_code["entries"] = [entry(code="forbidden")]
    refused(WithdrawalList, other_code)

    unknown_cause = withdrawal_list()
    unknown_cause["entries"] = [entry(cause="gone")]
    refused(WithdrawalList, unknown_cause)


def test_withdrawal_list_shape_is_closed() -> None:
    for key in ("projectId", "byBatchDigest", "diffReportDigest", "entries", "schemaVersion"):
        broken = withdrawal_list()
        del broken[key]
        refused(WithdrawalList, broken)
    refused(WithdrawalList, withdrawal_list() | {"extra": 1})
    refused(WithdrawalList, withdrawal_list() | {"byBatchDigest": "A" * 64})
    refused(WithdrawalList, withdrawal_list() | {"schemaVersion": "cf.withdrawal-list.v2"})
    extra_entry = withdrawal_list()
    extra_entry["entries"] = [entry() | {"extra": 1}]
    refused(WithdrawalList, extra_entry)
    for key in ("batchId", "assetId", "sourceId", "cause", "decisionId", "reason"):
        partial = withdrawal_list()
        broken_entry = entry()
        del broken_entry[key]
        partial["entries"] = [broken_entry]
        refused(WithdrawalList, partial)


def test_withdrawal_reason_message_is_bounded_by_limits() -> None:
    long_message = withdrawal_list()
    long_entry = entry()
    long_entry["reason"] = {"code": "source_changed", "message": "x" * 41}
    long_message["entries"] = [long_entry]
    refused(WithdrawalList, long_message)


def test_intake_diff_shape() -> None:
    parsed = IntakeDiff.from_wire(wire(diff()), limits())
    assert parsed.status == "ready"
    assert parsed.classes.missing == ("m/1.txt",)
    assert json.loads(parsed.model_dump_json(by_alias=True)) == diff()

    blocked = diff() | {"status": "policy_revision_needed"}
    del blocked["intakeDigest"]
    again = IntakeDiff.from_wire(wire(blocked), limits())
    assert again.intake_digest is None
    assert "intakeDigest" not in json.loads(again.model_dump_json(by_alias=True))

    empty_history = diff() | {"previousBatchDigests": [], "assumedAdmittedBatchIds": []}
    IntakeDiff.from_wire(wire(empty_history), limits())


def test_intake_diff_refuses_other_shapes() -> None:
    for key in (
        "projectId",
        "batchKey",
        "batchDigest",
        "previousBatchDigests",
        "status",
        "classes",
        "assumedAdmittedBatchIds",
        "newSourcesDigest",
        "schemaVersion",
    ):
        broken = diff()
        del broken[key]
        refused(IntakeDiff, broken)
    refused(IntakeDiff, diff() | {"status": "done"})
    refused(IntakeDiff, diff() | {"withdrawalListDigest": "f" * 64})
    refused(IntakeDiff, diff() | {"intakeDigest": None})
    refused(IntakeDiff, diff() | {"batchKey": ""})
    refused(IntakeDiff, diff() | {"newSourcesDigest": "short"})
    refused(IntakeDiff, diff() | {"previousBatchDigests": ["nope"]})
    refused(IntakeDiff, diff() | {"assumedAdmittedBatchIds": ["nope"]})
    for name in ("new", "unchanged", "changed", "moved", "returned", "missing"):
        classes = copy.deepcopy(diff()["classes"])
        assert isinstance(classes, dict)
        del classes[name]
        refused(IntakeDiff, diff() | {"classes": classes})
        refused(IntakeDiff, diff() | {"classes": classes | {name: [1]}})
        refused(IntakeDiff, diff() | {"classes": classes | {name: [""]}})
    classes = copy.deepcopy(diff()["classes"])
    assert isinstance(classes, dict)
    refused(IntakeDiff, diff() | {"classes": classes | {"extra": []}})


@pytest.mark.parametrize("schema_id", ["cf.withdrawal-list.v1", "cf.intake-diff.v1"])
def test_registered_exported_and_reference_free(schema_id: str) -> None:
    assert schema_id in registered_schema_ids()
    assert (SCHEMAS / f"{schema_id}.schema.json").read_bytes() == _schema_bytes(schema_id)
    assert (SCHEMAS / f"{schema_id}.rules.json").read_bytes() == _rules_bytes(schema_id)
    assert SCHEMA_MODELS[schema_id].__module__ == "conscience_foundry.contracts.intake"
    raw = withdrawal_list() if schema_id == "cf.withdrawal-list.v1" else diff()
    model = SCHEMA_MODELS[schema_id].from_wire(wire(raw), limits())
    assert edge_roles(schema_id, model) == ()


def test_diff_is_evidence_schema() -> None:
    assert "cf.intake-diff.v1" in EVIDENCE_SCHEMAS
    assert "cf.withdrawal-list.v1" not in EVIDENCE_SCHEMAS
