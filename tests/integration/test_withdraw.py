"""``cfoundry withdraw``: a derived withdrawal list applied once over the existing record.

Synthetic data only. Two assets of one batch are admitted (source A has a produced, reviewed
revision; source B was never extracted); the release authority is the opt-in local one, built from
the config exactly as the console script builds it. Nothing reaches a network or a provider.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest
from psycopg import sql
from test_cli import (  # noqa: F401  (the autouse fixture must be active in this module)
    ALL_GRANTS,
    Env,
    Result,
    clean_libpq_environment,
    database_env,
    file_names,
    ref_file,
)
from test_ledger_db import ACTOR, ASSET, BATCH, PROJECT, TIME
from test_release_build import B_ASSET, B_SOURCE, ReleaseCase, make_case, produced_revision

from conscience_foundry.cli import live
from conscience_foundry.cli.config import TrustedServices, load_config
from conscience_foundry.contracts.common import Reason, Ref
from conscience_foundry.contracts.intake import IntakeDiff, WithdrawalEntry, WithdrawalList
from conscience_foundry.contracts.release import CoverageReport, ReleaseSource
from conscience_foundry.intake.identity import decision_id, source_id
from conscience_foundry.ledger.db import Ledger

pytestmark = pytest.mark.database

BY_BATCH = "b" * 64
KEY_A = "synthetic/a.txt"
KEY_B = "synthetic/b.txt"
SOURCE_A = source_id(PROJECT, KEY_A)  # the sources the entries name derive from the report's keys
SOURCE_B = source_id(PROJECT, KEY_B)
OTHER_ACTOR = "00000000-0000-0000-0000-0000000000f2"
CONSUMER = "synthetic.consumer.v1"
GRANTED = {**ALL_GRANTS, "admission": ["admit", "withdraw"]}
SCOPES_WITHOUT_AUDIT = frozenset({"read", "extract", "remoteTransfer"})


def reason(cause: str) -> Reason:
    return Reason(code=f"source_{cause}", message=f"Synthetic {cause} source")  # type: ignore[arg-type]


def entry(asset: str, source: str, cause: str = "missing", **changes: Any) -> WithdrawalEntry:
    fields: dict[str, Any] = {
        "batch_id": BATCH,
        "asset_id": asset,
        "source_id": source,
        "cause": cause,
        "decision_id": decision_id(PROJECT, BATCH, asset, cause, BY_BATCH),  # type: ignore[arg-type]
        "reason": reason(cause),
    }
    return WithdrawalEntry(**{**fields, **changes})


def diff_bytes(
    new_sources_digest: str = "c" * 64,
    batch_digest: str = BY_BATCH,
    **classes: list[str],
) -> bytes:
    """A report in which A was replaced (`changed`) and B left its batch (`missing`)."""
    diff = IntakeDiff.model_validate(
        {
            "schemaVersion": "cf.intake-diff.v1",
            "projectId": PROJECT,
            "batchKey": "synthetic-batch",
            "batchDigest": batch_digest,
            "previousBatchDigests": ["a" * 64],
            "status": "ready",
            "classes": {
                "new": [],
                "unchanged": [],
                "changed": [KEY_A],
                "moved": [],
                "returned": [],
                "missing": [KEY_B],
                **classes,
            },
            "assumedAdmittedBatchIds": [BATCH],
            "newSourcesDigest": new_sources_digest,
        }
    )
    return diff.model_dump_json(by_alias=True, exclude_none=True).encode()


def list_bytes(evidence: bytes, entries: list[WithdrawalEntry], *, project: str = PROJECT) -> bytes:
    document = WithdrawalList(
        schema_version="cf.withdrawal-list.v1",
        project_id=project,
        by_batch_digest=BY_BATCH,
        diff_report_digest=hashlib.sha256(evidence).hexdigest(),
        entries=tuple(entries),
    )
    return document.model_dump_json(by_alias=True).encode()


@dataclass
class Setup:
    value: ReleaseCase
    env: Env
    services: TrustedServices
    source_a: str
    revision: Ref | None = None

    def selected_a(self) -> ReleaseSource:
        """Source A with its one produced revision and an accepted review (made once)."""
        if self.revision is None:
            self.revision = produced_revision(self.value)
        return ReleaseSource(
            source_id=self.source_a,
            revision_ref=self.revision,
            review_ref=self.value.review(self.revision),
        )

    @property
    def ledger(self) -> Ledger:
        return self.value.ledger

    def both(self, cause: str = "missing") -> list[WithdrawalEntry]:
        return [entry(B_ASSET, SOURCE_B, cause)]

    def invoke(
        self, evidence: bytes, list_document: bytes, *extra: str, services: Any = None
    ) -> Result:
        return self.env.invoke(
            "withdraw",
            "--list",
            self.env.input("list.json", list_document),
            "--evidence",
            self.env.input("evidence.json", evidence),
            *extra,
            services=services if services is not None else self.services,
        )

    def rows(self) -> list[tuple[str, str, str]]:
        with self.ledger.transaction() as tx:
            return [
                (str(row[0]), str(row[1]), str(row[2]))
                for row in tx.connection.execute(
                    sql.SQL(
                        "SELECT decision_id,asset_id,actor_id FROM {} ORDER BY decision_id"
                    ).format(tx.table("admission_withdrawals"))
                ).fetchall()
            ]

    def reconfigure(self, **changes: Any) -> None:
        for name, value in changes.items():
            setattr(self.env, name, value)
        self.env.write_config()


@pytest.fixture
def setup(ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Setup:
    value = make_case(ledger, tmp_path, monkeypatch, b"Synthetic text")
    env = database_env(tmp_path, monkeypatch, ledger, value.case, grants=GRANTED)
    env.extra["releaseAuthority"] = {"kind": "local"}
    env.write_config()
    services = replace(live.build_services(load_config(env.config_path)), clock=lambda: TIME)
    assert services.release_authority is not None
    return Setup(value, env, services, value.case.data.report.entries[0].source_id)


def test_withdraw_records_and_coverage_reports_withdrawn(setup: Setup) -> None:
    source = setup.selected_a()
    evidence = diff_bytes()
    done = setup.invoke(evidence, list_bytes(evidence, setup.both()), "--execute")
    assert done.exit == 0, done.raw
    assert done.payload["applied"] == 1 and done.payload["alreadyRecorded"] == 0
    assert "refusedAt" not in done.payload and done.payload["executed"] is True
    expected = entry(B_ASSET, SOURCE_B).decision_id
    assert setup.rows() == [(expected, B_ASSET, ACTOR)]
    with setup.ledger.transaction() as tx:
        stored = tx.connection.execute(
            sql.SQL("SELECT reason,evidence_ref FROM {}").format(tx.table("admission_withdrawals"))
        ).fetchone()
    assert stored is not None
    assert stored[0] == {"code": "source_missing", "message": "Synthetic missing source"}
    assert stored[1]["digest"] == hashlib.sha256(evidence).hexdigest()
    assert stored[1]["artifactSchema"] == "cf.intake-diff.v1"
    setup.env.assert_redacted(done)
    candidate = build(setup, source)
    assert candidate["status"] == {ASSET: "accepted", B_ASSET: "withdrawn"}


def build(setup: Setup, source: ReleaseSource) -> dict[str, Any]:
    """Build a release through the CLI and report its source entries and coverage statuses."""
    selection = {
        "schemaVersion": "cfoundry.release-selection.v1",
        "sources": [json.loads(source.model_dump_json(by_alias=True))],
        "admissionReportRefs": [
            json.loads(setup.value.case.data.report_ref.model_dump_json(by_alias=True))
        ],
    }
    path = setup.env.input("selection.json", json.dumps(selection))
    built = setup.env.invoke(
        "build-release", "--selection", path, "--execute", services=setup.services
    )
    assert built.exit == 0, built.raw
    release_ref = Ref.model_validate(built.payload["releaseRef"])
    read = setup.value.read
    release = json.loads(read(release_ref, setup.value.case.access, 1 << 20).data)
    coverage = CoverageReport.from_wire(
        read(
            Ref.model_validate(release["coverageReportRef"]), setup.value.case.access, 1 << 20
        ).data,
        setup.value.case.bound,
    )
    return {
        "ref": release_ref,
        "digest": built.payload["releaseDigest"],
        "sources": [item["sourceId"] for item in release["sourceEntries"]],
        "status": {item.asset_id: item.status for item in coverage.entries},
        "selected": {item.asset_id: item.selected for item in coverage.entries},
    }


def test_release_after_withdraw_omits_asset_earlier_release_verifies(setup: Setup) -> None:
    source = setup.selected_a()
    earlier = build(setup, source)
    assert earlier["status"][B_ASSET] != "withdrawn"
    evidence = diff_bytes()
    done = setup.invoke(evidence, list_bytes(evidence, setup.both()), "--execute")
    assert done.exit == 0, done.raw
    later = build(setup, source)
    assert later["digest"] != earlier["digest"]
    assert later["status"][B_ASSET] == "withdrawn" and later["selected"][B_ASSET] is False
    assert later["sources"] == [setup.source_a] and B_SOURCE not in later["sources"]
    # The earlier release does not name the withdrawn asset, so it still verifies on import.
    setup.reconfigure(
        pins=[
            {
                "releaseDigest": earlier["digest"],
                "storeId": "synthetic",
                "consumerContract": CONSUMER,
                "capabilities": ["canonical_text"],
            }
        ],
    )
    imported = setup.env.invoke(
        "import-release",
        "--release-ref",
        ref_file(setup.env, "earlier-ref.json", earlier["ref"]),
        "--execute",
        services=setup.services,
    )
    assert imported.exit == 0, imported.raw
    assert imported.payload["receipt"]["status"] == "local_verified"


def test_rerun_same_list_records_nothing_new(setup: Setup) -> None:
    evidence = diff_bytes()
    document = list_bytes(evidence, setup.both())
    first = setup.invoke(evidence, document, "--execute")
    assert first.exit == 0 and (first.payload["applied"], first.payload["alreadyRecorded"]) == (
        1,
        0,
    )
    before = setup.rows()
    again = setup.invoke(evidence, document, "--execute")
    assert again.exit == 0, again.raw
    assert (again.payload["applied"], again.payload["alreadyRecorded"]) == (0, 1)
    assert setup.rows() == before


def test_rerun_with_other_evidence_conflicts(setup: Setup) -> None:
    evidence = diff_bytes()
    document = list_bytes(evidence, setup.both())
    assert setup.invoke(evidence, document, "--execute").exit == 0
    before = setup.rows()
    other = diff_bytes("d" * 64)  # a different, valid report; its list has the same decisionIds
    assert hashlib.sha256(other).hexdigest() != hashlib.sha256(evidence).hexdigest()
    conflicting = setup.invoke(other, list_bytes(other, setup.both()), "--execute")
    assert conflicting.exit == 1 and conflicting.code == "determinism_conflict", conflicting.raw
    assert conflicting.payload["refusedAt"] == setup.both()[0].decision_id
    assert (conflicting.payload["applied"], conflicting.payload["alreadyRecorded"]) == (0, 0)
    assert setup.rows() == before
    # The same original list under another actor is a conflict too, never a second record.
    second = other_actor(setup)
    again = setup.invoke(evidence, document, "--execute", services=second)
    assert again.exit == 1 and again.code == "determinism_conflict", again.raw
    assert setup.rows() == before


def other_actor(setup: Setup) -> TrustedServices:
    """Switch the operator to another actor and return services for the new config."""
    config = setup.env.config()["operator"] | {"actorId": OTHER_ACTOR}
    setup.env.extra["operator"] = config
    setup.env.write_config()
    return replace(live.build_services(load_config(setup.env.config_path)), clock=lambda: TIME)


def test_evidence_digest_mismatch_refused(setup: Setup) -> None:
    evidence = diff_bytes()
    document = list_bytes(evidence, setup.both())
    swapped = diff_bytes("e" * 64)
    result = setup.invoke(swapped, document, "--execute")
    assert result.exit == 1 and result.code == "hash_mismatch", result.raw
    assert setup.rows() == []
    setup.env.assert_redacted(result)


def test_entry_decision_identity_must_be_derived(setup: Setup) -> None:
    evidence = diff_bytes()
    forged = entry(B_ASSET, SOURCE_B, decision_id="00000000-0000-0000-0000-0000000000d1")
    result = setup.invoke(evidence, list_bytes(evidence, [forged]), "--execute")
    assert result.exit == 1 and result.code == "determinism_conflict", result.raw
    assert setup.rows() == []


def test_evidence_must_be_the_diff_contract(setup: Setup) -> None:
    evidence = b'{"schemaVersion":"cf.intake-diff.v1"}'
    result = setup.invoke(evidence, list_bytes(evidence, setup.both()), "--execute")
    assert result.exit == 1 and result.code == "invalid_schema", result.raw
    assert setup.rows() == []


def test_list_for_another_project_refused(setup: Setup) -> None:
    evidence = diff_bytes()
    other = "00000000-0000-0000-0000-0000000000ff"
    forged = entry(
        B_ASSET, B_SOURCE, decision_id=decision_id(other, BATCH, B_ASSET, "missing", BY_BATCH)
    )
    result = setup.invoke(evidence, list_bytes(evidence, [forged], project=other), "--execute")
    assert result.exit == 3 and result.code == "forbidden", result.raw
    assert setup.rows() == []


def test_stops_at_the_first_refusal_and_reports_it(setup: Setup) -> None:
    evidence = diff_bytes()
    unknown = "00000000-0000-0000-0000-0000000000e9"
    entries = [
        entry(B_ASSET, SOURCE_B),
        entry(unknown, SOURCE_B),  # no admission row routes this asset
        entry(ASSET, SOURCE_A, "changed"),
    ]
    result = setup.invoke(evidence, list_bytes(evidence, entries), "--execute")
    assert result.exit == 1 and result.code == "unavailable", result.raw
    assert result.payload["refusedAt"] == entries[1].decision_id
    assert (result.payload["applied"], result.payload["alreadyRecorded"]) == (1, 0)
    assert [row[0] for row in setup.rows()] == [entries[0].decision_id]


def test_report_of_another_batch_refused_before_any_write(setup: Setup) -> None:
    """The list names the batch that emitted it; the report must be that batch's own."""
    evidence = diff_bytes(batch_digest="9" * 64)
    before = file_names(setup.env.tmp)
    result = setup.invoke(evidence, list_bytes(evidence, setup.both()), "--execute")
    assert result.exit == 1 and result.code == "determinism_conflict", result.raw
    assert "refusedAt" not in result.payload and setup.rows() == []
    assert [name for name in file_names(setup.env.tmp) if name not in before] == [
        "inputs/evidence.json",
        "inputs/list.json",
    ]  # the object store was not written


def test_dry_run_writes_nothing(setup: Setup) -> None:
    evidence = diff_bytes()
    document = list_bytes(evidence, setup.both())
    before = file_names(setup.env.tmp)
    dry = setup.invoke(evidence, document)
    assert dry.exit == 0 and dry.payload["outcome"] == "dry_run", dry.raw
    assert dry.payload["executed"] is False and dry.payload["blockers"] == []
    assert dry.payload["wouldApply"] == 1
    assert setup.rows() == []
    after = file_names(setup.env.tmp)
    assert [name for name in after if name not in before] == [
        "inputs/evidence.json",
        "inputs/list.json",
    ]  # only the operator's own inputs; the object store is untouched


def test_dry_run_counts_every_entry_it_would_submit(setup: Setup) -> None:
    evidence = diff_bytes()
    entries = [entry(B_ASSET, SOURCE_B), entry(ASSET, SOURCE_A, "changed")]
    dry = setup.invoke(evidence, list_bytes(evidence, entries))
    assert dry.exit == 0 and dry.payload["outcome"] == "dry_run", dry.raw
    assert dry.payload["wouldApply"] == 2


def dry_run_cases(setup: Setup) -> dict[str, tuple[bytes, bytes, str]]:
    evidence = diff_bytes()
    other = diff_bytes(batch_digest="9" * 64)
    forged = entry(B_ASSET, SOURCE_B, decision_id="00000000-0000-0000-0000-0000000000d1")
    return {
        "evidence_digest": (
            diff_bytes("e" * 64),
            list_bytes(evidence, setup.both()),
            "hash_mismatch",
        ),
        "not_a_diff_report": (
            b'{"schemaVersion":"cf.intake-diff.v1"}',
            list_bytes(b'{"schemaVersion":"cf.intake-diff.v1"}', setup.both()),
            "invalid_schema",
        ),
        "another_batch": (other, list_bytes(other, setup.both()), "determinism_conflict"),
        "forged_decision": (evidence, list_bytes(evidence, [forged]), "determinism_conflict"),
    }


@pytest.mark.parametrize(
    "case", ["evidence_digest", "not_a_diff_report", "another_batch", "forged_decision"]
)
def test_dry_run_catches_a_wrong_report_without_execute(setup: Setup, case: str) -> None:
    evidence, document, code = dry_run_cases(setup)[case]
    before = file_names(setup.env.tmp)
    result = setup.invoke(evidence, document)
    assert result.exit == 1 and result.code == code, result.raw
    assert result.payload["executed"] is False and "wouldApply" not in result.payload
    assert setup.rows() == []
    assert [name for name in file_names(setup.env.tmp) if name not in before] == [
        "inputs/evidence.json",
        "inputs/list.json",
    ]


def inconsistent_entries() -> dict[str, list[WithdrawalEntry]]:
    unrelated = source_id(PROJECT, "synthetic/never-listed.txt")
    return {
        "missing_entry_for_a_changed_source": [entry(B_ASSET, SOURCE_A, "missing")],
        "changed_entry_for_a_missing_source": [entry(ASSET, SOURCE_B, "changed")],
        "source_the_report_never_lists": [entry(B_ASSET, unrelated, "missing")],
        "one_bad_entry_among_good_ones": [
            entry(B_ASSET, SOURCE_B, "missing"),
            entry(ASSET, SOURCE_B, "changed"),
        ],
    }


@pytest.mark.parametrize("case", sorted(inconsistent_entries()))
def test_entry_must_match_the_reports_classes_before_any_write(setup: Setup, case: str) -> None:
    """Each entry's cause and source must be what the cited report says happened."""
    evidence = diff_bytes()
    document = list_bytes(evidence, inconsistent_entries()[case])
    before = file_names(setup.env.tmp)
    dry = setup.invoke(evidence, document)
    assert dry.exit == 1 and dry.code == "determinism_conflict", dry.raw
    assert dry.payload["executed"] is False and "wouldApply" not in dry.payload
    done = setup.invoke(evidence, document, "--execute")
    assert done.exit == 1 and done.code == "determinism_conflict", done.raw
    assert "refusedAt" not in done.payload and setup.rows() == []
    assert [name for name in file_names(setup.env.tmp) if name not in before] == [
        "inputs/evidence.json",
        "inputs/list.json",
    ]  # nothing reached the object store


def test_changed_entry_may_cite_a_returned_source(setup: Setup) -> None:
    """A withdrawn asset returning over a different current one is `returned`; the displaced
    asset's withdrawal (cause `changed`) is therefore consistent with that report."""
    evidence = diff_bytes(changed=[], returned=[KEY_A])
    entries = [entry(ASSET, SOURCE_A, "changed")]
    dry = setup.invoke(evidence, list_bytes(evidence, entries))
    assert dry.exit == 0 and dry.payload["wouldApply"] == 1, dry.raw
    still = diff_bytes(changed=[], returned=[])
    refused = setup.invoke(still, list_bytes(still, entries))
    assert refused.exit == 1 and refused.code == "determinism_conflict", refused.raw


def test_dry_run_still_needs_its_grant_and_authority(setup: Setup) -> None:
    evidence = diff_bytes()
    document = list_bytes(evidence, setup.both())
    bare = setup.invoke(evidence, document, services=TrustedServices(clock=lambda: TIME))
    assert bare.exit == 3 and bare.code == "adapter_unavailable", bare.raw
    assert "wouldApply" not in bare.payload


def test_without_release_authority_refused(setup: Setup) -> None:
    evidence = diff_bytes()
    bare = TrustedServices(clock=lambda: TIME)
    result = setup.invoke(evidence, list_bytes(evidence, setup.both()), "--execute", services=bare)
    assert result.exit == 3 and result.code == "adapter_unavailable", result.raw
    assert result.payload["blockers"] == ["release_authority"]
    assert setup.rows() == []


def test_without_grant_refused(setup: Setup) -> None:
    setup.reconfigure(
        grants={**ALL_GRANTS, "admission": ["admit"]}
    )  # everything else, including the audit scope, is valid
    evidence = diff_bytes()
    result = setup.invoke(evidence, list_bytes(evidence, setup.both()), "--execute")
    assert result.exit == 3 and result.code == "grant_missing", result.raw
    assert setup.rows() == []


def test_missing_audit_scope_refused(setup: Setup) -> None:
    setup.reconfigure(scopes=SCOPES_WITHOUT_AUDIT)
    evidence = diff_bytes()
    result = setup.invoke(evidence, list_bytes(evidence, setup.both()), "--execute")
    assert result.exit == 3 and result.code == "forbidden", result.raw
    assert result.payload["refusedAt"] == setup.both()[0].decision_id
    assert setup.rows() == []
