"""Independent backup, restore barrier and retention report on synthetic data only.

The fakes here exercise mechanics: a second local directory stands in for the independent store and
a second schema of the approved disposable database stands in for the recovered ledger. They prove
no independent media; that is a separate live gate.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from psycopg import sql
from test_cli import ALL_GRANTS, Env, database_env
from test_execution_control import Executor
from test_import_publication import Library, b_content_reads, build_library, span_of
from test_ledger_db import ACTOR, ASSET, BATCH, PROJECT, TIME
from test_release_build import B_SOURCE, approval_request, deny_b, make_case

from conscience_foundry.cli.config import TrustedServices
from conscience_foundry.contracts.common import ContractError, Reason, Ref
from conscience_foundry.contracts.execution import ResultManifest
from conscience_foundry.contracts.release import RetentionPolicy
from conscience_foundry.execution.evidence import limits_for
from conscience_foundry.ledger.allowance import install_allowance_schema
from conscience_foundry.ledger.attempts import json_ref
from conscience_foundry.ledger.db import Ledger
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.recovery.backup import (
    SNAPSHOT_TABLES,
    RecoveryManifest,
    backup,
    binding_digest,
    independent_media,
    manifest_wire,
)
from conscience_foundry.recovery.restore import BARRIER_REASON, RecoveryReport, restore
from conscience_foundry.recovery.retention import (
    ESCALATION_DUE,
    HORIZON_PASSED,
    NO_BACKUP,
    NO_BACKUP_STORE,
    NO_LOCAL,
    OUTPUT_NO_BACKUP,
    OUTPUT_NO_LOCAL,
    TOO_YOUNG,
    UNRECONCILED,
    retention_report,
)
from conscience_foundry.release.build import record_admission_withdrawal
from conscience_foundry.release.importer import import_release
from conscience_foundry.release.read import resolve_span
from conscience_foundry.storage.local import LocalObjectStore
from conscience_foundry.storage.locator import LocationRegistry

pytestmark = pytest.mark.database
REVOKED = "2026-10-26T00:00:00.000Z"
POLICY = RetentionPolicy(
    schema_version="kf.retention.v1",
    policy_version="synthetic.v1",
    min_staging_age_seconds=60,
    funded_staging_horizon_seconds=3600,
    escalation_lead_seconds=600,
    backup_required=True,
    audit_retention_seconds=86400,
)
LONG_AFTER = "2027-01-01T00:00:00.000Z"


def local_store(root: Path, store_id: str, library: Library) -> LocalObjectStore:
    root.mkdir(parents=True)
    access = library.value.case.access

    def authority(ref: Ref, context: AccessContext, effect: str) -> None:
        if ref.project_id != PROJECT or context != access:
            raise ContractError("forbidden")

    bound = library.value.case.bound
    return LocalObjectStore(store_id, LocationRegistry({store_id: root}, bound, authority))


@pytest.fixture
def library(ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Library:
    lib = build_library(
        make_case(ledger, tmp_path, monkeypatch, b"Synthetic text"), tmp_path / "objects"
    )
    # One trusted context that can also dispatch, so a pending attempt can be created later.
    case = lib.value.case
    case.access = AccessContext(PROJECT, ACTOR, case.access.scopes | {"remoteTransfer"})
    case.control = replace(case.control, access=case.access)
    lib.value.release = replace(lib.value.release, access=case.access)
    return lib


@pytest.fixture
def target_ledger(ledger: Ledger) -> Iterator[Ledger]:
    """A second, empty schema in the same approved disposable database."""
    other = Ledger(ledger.connection_factory, schema="cf_test_" + uuid4().hex)
    other.migrate()
    try:
        yield other
    finally:
        with other.connection_factory() as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(other.schema))
            )


@pytest.fixture
def backup_store(library: Library, tmp_path: Path) -> LocalObjectStore:
    return local_store(tmp_path / "backup", "backup", library)


@pytest.fixture
def restore_store(library: Library, tmp_path: Path) -> LocalObjectStore:
    return local_store(tmp_path / "restored", "restored", library)


def verified(library: Library) -> None:
    library.allow_import()
    library.import_()
    assert library.row()[0] is True


def take(library: Library, destination: LocalObjectStore, **overrides: Any) -> RecoveryManifest:
    arguments: dict[str, Any] = {"release": library.value.release, **overrides}
    store = library.value.release.store
    return backup(library.access, library.ledger, store, destination, **arguments)


def put_back(
    library: Library,
    manifest: RecoveryManifest,
    source: LocalObjectStore,
    target: LocalObjectStore,
    ledger: Ledger,
) -> RecoveryReport:
    return restore(manifest, library.access, ledger, source, target)


def pause_rows(ledger: Ledger) -> list[tuple[bool, int, str]]:
    with ledger.transaction() as tx:
        rows = tx.connection.execute(
            sql.SQL(
                "SELECT s.paused,s.version,h.reason FROM {} s JOIN {} h USING "
                "(project_id,scope,scope_id,version) WHERE s.scope='project'"
            ).format(tx.table("pause_state"), tx.table("pause_history"))
        ).fetchall()
    return [(row[0], row[1], row[2]) for row in rows]


def release_rows(ledger: Ledger) -> list[tuple[bool, Any]]:
    with ledger.transaction() as tx:
        return [
            (row[0], row[1])
            for row in tx.connection.execute(
                sql.SQL("SELECT local_verified,import_receipt_ref FROM {}").format(
                    tx.table("releases")
                )
            ).fetchall()
        ]


def revoke_a(library: Library) -> None:
    case = library.value.case
    sources = tuple(
        source.model_copy(update={"read": "deny", "extract": "deny"})
        if source.source_id != B_SOURCE
        else source
        for source in case.policy.sources
    )
    case.policy = case.policy.model_copy(update={"sources": sources})


def assert_unverified(ledger: Ledger) -> None:
    """Every restored release is unverified with no receipt (rows hold JSON, so no set())."""
    rows = release_rows(ledger)
    assert rows and all(row == (False, None) for row in rows), rows


def row_count(ledger: Ledger, table: str) -> int:
    with ledger.transaction() as tx:
        row = tx.connection.execute(
            sql.SQL("SELECT count(*) FROM {}").format(tx.table(table))
        ).fetchone()
    assert row is not None
    return int(row[0])


def lift(ledger: Ledger) -> None:
    """The ordinary resume step, reduced to its ledger effect."""
    with ledger.transaction() as tx:
        old = tx.get_pause("project", PROJECT, None)
        tx.record_pause(
            "project",
            PROJECT,
            None,
            False,
            expected_version=old.version,
            actor_id=ACTOR,
            reason="operator_resume",
            decided_at=TIME,
            decision_id=str(uuid4()),
        )


def pending_attempt(library: Library) -> str:
    """A second attempt whose submission outcome is unknown: remote work may still be running."""
    case = library.value.case
    case.estimate = case.proof()  # a fresh estimate for a fresh reservation
    case.authority.estimates[case.estimate.digest] = next(iter(case.authority.estimates.values()))
    attempt = case.dispatch(library.ledger, Executor(case, lost=True))
    assert attempt.state == "unknown_outcome"
    return str(attempt.attempt_id)


def test_restore_stale_ledger_blocks_spend_and_access(
    library: Library,
    target_ledger: Ledger,
    backup_store: LocalObjectStore,
    restore_store: LocalObjectStore,
) -> None:
    lib = library
    verified(lib)
    unresolved = pending_attempt(lib)
    manifest = take(lib, backup_store)
    assert manifest.pending_attempt_ids == (unresolved,)

    report = put_back(lib, manifest, backup_store, restore_store, target_ledger)

    # unresolved_remote_work_blocks_dispatch
    assert report.dispatch_blocked is True
    assert pause_rows(target_ledger) == [(True, 1, BARRIER_REASON)]
    assert any(reason.code == "dispatch_unknown" for reason in report.reasons)
    case = lib.value.case
    with pytest.raises(ContractError) as spend:
        case.dispatch(target_ledger, Executor(case))
    assert spend.value.code == "forbidden"  # the durable pause barrier
    attempts = row_count(target_ledger, "attempts")
    # Even after an operator lifts the barrier, the unresolved attempt still holds dispatch.
    lift(target_ledger)
    with pytest.raises(ContractError) as unresolved_hold:
        case.dispatch(target_ledger, Executor(case))
    assert unresolved_hold.value.code == "dispatch_unknown"
    assert row_count(target_ledger, "attempts") == attempts == 2  # nothing new was claimed
    # old_allow_does_not_reenable_read: the snapshot's local verification is gone and only a
    # fresh import under the policy as it is now can bring it back (and current policy refuses).
    assert report.access_blocked is True
    assert_unverified(target_ledger)
    restored = replace(lib.value.release, store=restore_store)
    revoke_a(lib)  # policy changed after the recovery point; the snapshot still says allow
    with pytest.raises(ContractError) as read:
        import_release(
            lib.ref, lib.access, target_ledger, restore_store, release=restored, pin=lib.pin
        )
    assert read.value.code == "forbidden"
    assert_unverified(target_ledger)


def object_files(root: Path) -> set[Path]:
    return {path for path in root.rglob("*") if path.is_file()}


def object_path(store_root: Path, ref: Ref) -> Path:
    return store_root / "sha256" / ref.digest[:2] / ref.digest


def ref_digests(refs: tuple[Ref, ...]) -> set[str]:
    return {ref.digest for ref in refs}


def test_backup_content_audit_edges(
    library: Library,
    target_ledger: Ledger,
    backup_store: LocalObjectStore,
    restore_store: LocalObjectStore,
    tmp_path: Path,
) -> None:
    lib = library
    deny_b(lib.value)  # source B: content denied, audit metadata still allowed
    verified(lib)
    staging_before = object_files(tmp_path / "objects")
    lib.value.reads.clear()
    manifest = take(lib, backup_store)
    excluded = lib.value.case.data.report.entries[1].snapshot_ref
    assert excluded is not None

    assert b_content_reads(lib) == 0
    assert excluded.digest not in ref_digests(manifest.content_refs + manifest.audit_refs)
    assert lib.digest in ref_digests(manifest.content_refs)
    assert lib.value.case.data.report_ref.digest in ref_digests(manifest.audit_refs)
    assert not set(manifest.content_refs) & set(manifest.audit_refs)
    assert not object_path(tmp_path / "backup", excluded).exists()

    report = put_back(lib, manifest, backup_store, restore_store, target_ledger)
    # restored_a_valid: the closure is complete and a fresh authorized import reads A again.
    assert report.missing_refs == ()
    assert set(report.verified_refs) == set(manifest.content_refs + manifest.audit_refs)
    assert not object_path(tmp_path / "restored", excluded).exists()
    restored = replace(lib.value.release, store=restore_store)
    lib.allow_import()
    receipt = import_release(
        lib.ref, lib.access, target_ledger, restore_store, release=restored, pin=lib.pin
    )
    assert receipt.status == "local_verified"
    span = span_of(lib, 0, 4)
    resolved = resolve_span(
        lib.access, lib.digest, span, target_ledger, restore_store, release=restored, pin=lib.pin
    )
    assert resolved.text == "Synt"
    # unique_staging_not_deleted: nothing in the original store was removed or replaced.
    assert staging_before <= object_files(tmp_path / "objects")
    assert b_content_reads(lib) == 0


def test_manifest_binding_and_snapshot_integrity_fail_closed(
    library: Library,
    target_ledger: Ledger,
    backup_store: LocalObjectStore,
    restore_store: LocalObjectStore,
    tmp_path: Path,
) -> None:
    lib = library
    verified(lib)
    manifest = take(lib, backup_store)
    assert manifest.snapshot_digest == binding_digest(
        manifest.project_id,
        manifest.ledger_snapshot_ref,
        manifest.recovery_point,
        manifest.content_refs,
        manifest.audit_refs,
        manifest.pending_attempt_ids,
    )
    shortened = manifest.model_copy(update={"content_refs": manifest.content_refs[1:]})
    with pytest.raises(ContractError) as binding:
        put_back(lib, shortened, backup_store, restore_store, target_ledger)
    assert binding.value.code == "hash_mismatch"
    other = AccessContext("00000000-0000-0000-0000-0000000000f1", ACTOR, lib.access.scopes)
    with pytest.raises(ContractError) as foreign:
        restore(manifest, other, target_ledger, backup_store, restore_store)
    assert foreign.value.code == "forbidden"
    # A snapshot whose pending set disagrees with the manifest rolls the whole restore back.
    lying = manifest.model_copy(update={"pending_attempt_ids": (str(uuid4()),)})
    lying = lying.model_copy(
        update={
            "snapshot_digest": binding_digest(
                lying.project_id,
                lying.ledger_snapshot_ref,
                lying.recovery_point,
                lying.content_refs,
                lying.audit_refs,
                lying.pending_attempt_ids,
            )
        }
    )
    with pytest.raises(ContractError) as disagree:
        put_back(lib, lying, backup_store, restore_store, target_ledger)
    assert disagree.value.code == "hash_mismatch"
    assert row_count(target_ledger, "projects") == 0
    # Altered snapshot bytes never reach the ledger.
    path = object_path(tmp_path / "backup", manifest.ledger_snapshot_ref)
    path.write_bytes(b"x" * manifest.ledger_snapshot_ref.size_bytes)
    with pytest.raises(ContractError) as altered:
        put_back(lib, manifest, backup_store, restore_store, target_ledger)
    assert altered.value.code == "hash_mismatch"
    assert row_count(target_ledger, "projects") == 0


def test_missing_backup_objects_are_reported_not_skipped(
    library: Library,
    target_ledger: Ledger,
    backup_store: LocalObjectStore,
    restore_store: LocalObjectStore,
    tmp_path: Path,
) -> None:
    lib = library
    verified(lib)
    manifest = take(lib, backup_store)
    lost = manifest.audit_refs[0]
    object_path(tmp_path / "backup", lost).unlink()

    report = put_back(lib, manifest, backup_store, restore_store, target_ledger)

    assert report.missing_refs == (lost,)
    assert lost not in report.verified_refs
    assert any(reason.code == "artifact_missing" for reason in report.reasons)
    assert report.dispatch_blocked is True  # an incomplete recovery is still fenced


def test_restore_is_idempotent_and_refuses_a_populated_target(
    library: Library,
    target_ledger: Ledger,
    backup_store: LocalObjectStore,
    restore_store: LocalObjectStore,
    ledger: Ledger,
) -> None:
    lib = library
    verified(lib)
    manifest = take(lib, backup_store)
    first = put_back(lib, manifest, backup_store, restore_store, target_ledger)
    again = put_back(lib, manifest, backup_store, restore_store, target_ledger)
    assert again.verified_refs == first.verified_refs and again.dispatch_blocked is True
    assert pause_rows(target_ledger) == [(True, 1, BARRIER_REASON)]
    assert row_count(target_ledger, "pause_history") == 1
    # The live source ledger is not a recovery target: its project already exists.
    with pytest.raises(ContractError) as populated:
        put_back(lib, manifest, backup_store, restore_store, ledger)
    assert populated.value.code == "determinism_conflict"
    assert pause_rows(ledger) == []


def test_backup_authority_is_checked_before_anything_is_written(
    library: Library, backup_store: LocalObjectStore, tmp_path: Path
) -> None:
    lib = library
    verified(lib)
    empty = object_files(tmp_path / "backup")
    store = lib.value.release.store
    # Scopes: both read and audit-metadata authority are required.
    narrow = AccessContext(PROJECT, ACTOR, frozenset({"read"}))
    with pytest.raises(ContractError) as scopes:
        backup(
            narrow,
            lib.ledger,
            store,
            backup_store,
            release=replace(lib.value.release, access=narrow),
        )
    assert scopes.value.code == "forbidden"
    # The destination must be a different store.
    with pytest.raises(ContractError) as same:
        backup(lib.access, lib.ledger, store, store, release=lib.value.release)
    assert same.value.code == "forbidden"
    assert object_files(tmp_path / "backup") == empty
    # Current policy overrides a historical import: a revoked source stops its release from being
    # copied, but never the ledger and audit recovery point (see the exclusion test below).
    revoke_a(lib)
    manifest = take(lib, backup_store)
    assert manifest.excluded_release_digests == (lib.digest,)
    assert lib.digest not in ref_digests(manifest.content_refs)
    assert manifest.content_refs == ()
    # Without audit metadata authority nothing is recorded at all: that stays fail closed.
    lib.value.case.policy = lib.value.case.policy.model_copy(
        update={
            "sources": tuple(
                source.model_copy(update={"audit_metadata_read": "deny"})
                for source in lib.value.case.policy.sources
            )
        }
    )
    with pytest.raises(ContractError) as unaudited:
        take(lib, backup_store)
    assert unaudited.value.code == "forbidden"


def withdraw_a(lib: Library, reason: Reason) -> None:
    """The operator's withdrawal of source A's admission, through the production release code."""
    value, decision = lib.value, str(uuid4())
    report_ref = value.case.data.report_ref
    value.authority.allowed.add(
        (
            "withdraw_admission",
            approval_request(
                {
                    "projectId": PROJECT,
                    "batchId": BATCH,
                    "assetId": ASSET,
                    "sourceId": value.case.data.report.entries[0].source_id,
                    "decisionId": decision,
                    "actorId": ACTOR,
                    "reason": reason.model_dump(mode="json", by_alias=True),
                    "decidedAt": TIME,
                    "evidenceRef": report_ref.model_dump(mode="json", by_alias=True),
                }
            ),
        )
    )
    record_admission_withdrawal(
        BATCH,
        ASSET,
        decision,
        lib.access,
        lib.ledger,
        value.release.store,
        release=value.release,
        reason=reason,
        evidence_ref=report_ref,
    )


def hold_operation(lib: Library) -> None:
    key = lib.value.case.plan.operation_key
    with lib.ledger.transaction() as tx:
        tx.lock(PROJECT)
        tx.connection.execute(
            sql.SQL("UPDATE {} SET held=true WHERE operation_key=%s").format(
                tx.table("operations")
            ),
            (key,),
        )
        tx.connection.execute(
            sql.SQL("INSERT INTO {} VALUES (%s,%s,%s,%s,%s)").format(tx.table("integrity_holds")),
            (
                PROJECT,
                str(uuid4()),
                key,
                json_ref(lib.value.case.data.report_ref),
                TIME,
            ),
        )


@pytest.mark.parametrize("change", ["withdrawal", "hold", "revocation"])
def test_backup_survives_a_verified_release_that_is_no_longer_eligible(
    library: Library,
    target_ledger: Ledger,
    backup_store: LocalObjectStore,
    restore_store: LocalObjectStore,
    change: str,
) -> None:
    """D09: backup follows the closure of retained eligible releases, not a permanent refusal."""
    lib = library
    verified(lib)
    if change == "withdrawal":
        withdraw_a(lib, Reason(code="forbidden", message="Synthetic withdrawal"))
    elif change == "hold":
        hold_operation(lib)
    else:
        revoke_a(lib)
    first = take(lib, backup_store)
    second = take(lib, backup_store)  # not a one-shot success: the next backup works too
    for manifest in (first, second):
        assert manifest.excluded_release_digests == (lib.digest,)
        assert manifest.content_refs == ()
        assert lib.value.case.data.report_ref.digest in ref_digests(manifest.audit_refs)
    report = put_back(lib, first, backup_store, restore_store, target_ledger)
    assert report.missing_refs == () and report.dispatch_blocked


@pytest.mark.parametrize("cap", [{"max_array_items": 14}, {"max_json_bytes": 8000}])
def test_backup_refuses_a_manifest_the_restore_limits_would_refuse(
    library: Library, backup_store: LocalObjectStore, tmp_path: Path, cap: dict[str, int]
) -> None:
    """The manifest is decoded at restore under kf.library-release.v1 limits; backup must agree."""
    lib = library
    verified(lib)
    release = lib.value.release
    # The caps stay above what loading the release itself needs, so only the manifest trips them.
    tight = dict(release.limits_by_schema)
    tight["kf.library-release.v1"] = tight["kf.library-release.v1"].model_copy(update=cap)
    with pytest.raises(ContractError) as error:
        take(lib, backup_store, release=replace(release, limits_by_schema=tight))
    assert error.value.code == "limit_exceeded"
    assert object_files(tmp_path / "backup") == set()  # nothing was copied before the refusal
    manifest = take(lib, backup_store)  # the same recovery point under the normal limits is fine
    normal = release.limits_by_schema["kf.library-release.v1"]
    assert RecoveryManifest.from_wire(manifest_wire(manifest), normal) == manifest


@pytest.mark.parametrize("audit", ["deny", "unknown"])
def test_backup_requires_audit_metadata_permission_for_every_named_source(
    library: Library, backup_store: LocalObjectStore, tmp_path: Path, audit: str
) -> None:
    deny_b(library.value, audit=audit)
    with pytest.raises(ContractError) as refused:
        take(library, backup_store)
    assert refused.value.code in {"forbidden", "permission_unknown"}
    assert object_files(tmp_path / "backup") == set()


def test_backup_fences_writers_so_a_snapshot_is_never_mixed(
    library: Library, backup_store: LocalObjectStore
) -> None:
    lib = library
    verified(lib)
    holding, release_writer = threading.Event(), threading.Event()
    outcome: dict[str, Any] = {}

    def writer() -> None:
        with lib.ledger.transaction() as tx:
            tx.lock(PROJECT)
            holding.set()
            release_writer.wait(15)
            old = tx.get_pause("project", PROJECT, None)
            tx.record_pause(
                "project",
                PROJECT,
                None,
                True,
                expected_version=old.version,
                actor_id=ACTOR,
                reason="operator_stop",
                decided_at=TIME,
                decision_id=str(uuid4()),
            )

    def taker() -> None:
        try:
            outcome["manifest"] = take(lib, backup_store)
        except Exception as error:  # surfaced below
            outcome["error"] = error

    first = threading.Thread(target=writer)
    first.start()
    assert holding.wait(10)
    second = threading.Thread(target=taker)
    second.start()
    time.sleep(0.5)
    # The backup waits behind the in-flight writer rather than reading a partial state.
    assert second.is_alive() and not outcome
    release_writer.set()
    first.join(15)
    second.join(30)
    assert "error" not in outcome, outcome.get("error")
    manifest: RecoveryManifest = outcome["manifest"]
    document = backup_store.read_verified(
        manifest.ledger_snapshot_ref, lib.access, manifest.ledger_snapshot_ref.size_bytes
    ).data
    tables = json.loads(document)["tables"]
    assert [row["paused"] for row in tables["pause_state"]] == [True]
    assert [row["reason"] for row in tables["pause_history"]] == ["operator_stop"]
    assert set(tables) == set(SNAPSHOT_TABLES)
    flags = {row["release_digest"]: row["local_verified"] for row in tables["releases"]}
    assert flags[lib.digest] is True


def test_allowance_counters_travel_with_the_snapshot_and_need_a_matching_target(
    library: Library,
    target_ledger: Ledger,
    backup_store: LocalObjectStore,
    restore_store: LocalObjectStore,
) -> None:
    lib = library
    verified(lib)
    install_allowance_schema(lib.ledger)
    manifest = take(lib, backup_store)
    document = backup_store.read_verified(
        manifest.ledger_snapshot_ref, lib.access, manifest.ledger_snapshot_ref.size_bytes
    ).data
    assert b"call_allowance_scopes" in document
    # A target without the additive tables cannot silently drop spend-control counters.
    with pytest.raises(ContractError) as missing:
        put_back(lib, manifest, backup_store, restore_store, target_ledger)
    assert missing.value.code == "schema_incompatible"
    assert row_count(target_ledger, "projects") == 0
    install_allowance_schema(target_ledger)
    assert put_back(lib, manifest, backup_store, restore_store, target_ledger).dispatch_blocked


def retention(
    lib: Library,
    now: str,
    backup_store: Any = None,
    policy: RetentionPolicy = POLICY,
) -> Any:
    return retention_report(
        lib.access,
        lib.ledger,
        lib.value.release.store,
        policy,
        now,
        limits=limits_for(lib.value.release, "kf.result.v1"),
        backup=backup_store,
    )


def result_outputs(lib: Library) -> tuple[Ref, ...]:
    """The outputs the staged result manifest lists, read the way the retention report reads it."""
    (entry,) = retention(lib, "2026-10-25T00:10:00.000Z").entries
    raw = lib.value.release.store.read_verified(entry.ref, lib.access, entry.ref.size_bytes).data
    manifest = ResultManifest.from_wire(raw, limits_for(lib.value.release, "kf.result.v1"))
    assert {ref.artifact_schema for ref in manifest.outputs} >= {
        "kf.document-revision.v1",
        "kf.quality-report.v1",
    }
    return manifest.outputs


def test_retention_report_is_eligibility_only_and_never_deletes(
    library: Library, backup_store: LocalObjectStore, tmp_path: Path
) -> None:
    lib = library
    verified(lib)
    objects = tmp_path / "objects"
    before = object_files(objects)
    soon, escalation, late = (
        "2026-10-25T00:00:30.000Z",
        "2026-10-25T00:55:00.000Z",
        "2026-10-25T05:00:00.000Z",
    )
    ready = "2026-10-25T00:10:00.000Z"

    # No independent backup yet: a unique copy is never eligible, whatever the age.
    unbacked = retention(lib, ready, backup_store)
    assert unbacked.entries and not any(entry.eligible for entry in unbacked.entries)
    assert all(NO_BACKUP in entry.reasons for entry in unbacked.entries)
    assert retention(lib, ready, None).entries[0].reasons == (NO_BACKUP_STORE,)
    escalated = retention(lib, escalation, backup_store).entries[0].reasons
    assert ESCALATION_DUE in escalated and HORIZON_PASSED not in escalated
    # Beyond the funded horizon the liability is reported; the object is still not eligible.
    expired = retention(lib, late, backup_store)
    assert all(HORIZON_PASSED in entry.reasons for entry in expired.entries)
    assert not any(entry.eligible for entry in expired.entries)
    assert retention(lib, soon, backup_store).entries[0].reasons[0] == TOO_YOUNG

    take(lib, backup_store)
    good = retention(lib, ready, backup_store)
    assert good.checked_at == ready
    assert good.entries and all(entry.eligible and not entry.reasons for entry in good.entries)
    relaxed = POLICY.model_copy(update={"backup_required": False})
    assert all(entry.eligible for entry in retention(lib, ready, None, relaxed).entries)
    # Age alone never qualifies: too young stays ineligible even with every copy verified.
    assert not retention(lib, soon, backup_store).entries[0].eligible
    # Reporting is read only.
    assert object_files(objects) == before
    for entry in good.entries:
        lib.value.release.store.read_verified(entry.ref, lib.access, entry.ref.size_bytes)


def test_retention_blocks_on_unreconciled_work_and_missing_local_copy(
    library: Library, backup_store: LocalObjectStore, tmp_path: Path
) -> None:
    lib = library
    verified(lib)
    take(lib, backup_store)
    ready = "2026-10-25T00:10:00.000Z"
    first = retention(lib, ready, backup_store).entries[0]
    object_path(tmp_path / "objects", first.ref).unlink()
    missing = {e.ref.digest: e for e in retention(lib, ready, backup_store).entries}
    assert missing[first.ref.digest].reasons == (NO_LOCAL,)
    assert not missing[first.ref.digest].eligible
    pending_attempt(lib)
    unresolved = retention(lib, ready, backup_store).entries
    assert all(UNRECONCILED in entry.reasons and not entry.eligible for entry in unresolved)


@pytest.mark.parametrize("position", range(4))
@pytest.mark.parametrize("where", ["local", "backup"])
def test_retention_requires_every_result_output_verified_in_both_stores(
    library: Library, backup_store: LocalObjectStore, tmp_path: Path, where: str, position: int
) -> None:
    lib = library
    verified(lib)
    take(lib, backup_store)
    ready = "2026-10-25T00:10:00.000Z"
    outputs = result_outputs(lib)
    assert len(outputs) == 4
    assert all(entry.eligible for entry in retention(lib, ready, backup_store).entries)
    root = tmp_path / ("objects" if where == "local" else "backup")
    object_path(root, outputs[position]).unlink()
    (entry,) = retention(lib, ready, backup_store).entries
    assert not entry.eligible
    assert entry.reasons == (OUTPUT_NO_LOCAL if where == "local" else OUTPUT_NO_BACKUP,)


def test_retention_keeps_a_result_ineligible_when_its_outputs_were_never_backed_up(
    library: Library, backup_store: LocalObjectStore
) -> None:
    """A backup of a library that was never verified holds the result manifest, not its outputs."""
    lib = library
    verified(lib)
    withdraw_a(lib, Reason(code="forbidden", message="Synthetic withdrawal"))
    take(lib, backup_store)  # the release is excluded, so no output is copied
    (entry,) = retention(lib, "2026-10-25T00:10:00.000Z", backup_store).entries
    assert not entry.eligible and entry.reasons == (OUTPUT_NO_BACKUP,)


def test_independent_media_rejects_a_second_directory_on_the_same_device(tmp_path: Path) -> None:
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    assert independent_media(first, second) is False  # same device
    assert independent_media(first, first / "inner") is False  # absent path
    assert independent_media(Path("/"), Path("/dev")) in {True, False}  # never raises


# --- operator CLI ------------------------------------------------------------------------------

RECOVERY_GRANTS = {**ALL_GRANTS, "recovery": ["backup", "restore", "retention-report"]}
READY = "2026-10-25T00:10:00.000Z"


def cli_env(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    lib: Library,
    schema_ledger: Ledger,
    backup_root: Path | None,
    **overrides: Any,
) -> Env:
    env = database_env(
        root, monkeypatch, schema_ledger, lib.value.case, grants=RECOVERY_GRANTS, **overrides
    )
    if backup_root is not None:
        backup_root.mkdir(exist_ok=True)
        env.extra["backupStore"] = {
            "storeId": "backup",
            "rootPath": str(backup_root),
            "limits": env.bound.model_dump(by_alias=True),
        }
        env.write_config()
    return env


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    return Env(tmp_path / "plain", monkeypatch)


def test_cli_recovery_commands_follow_the_same_gates_as_every_other_effect(
    env: Env, tmp_path: Path
) -> None:
    out = tmp_path / "manifest.json"
    arguments = {
        "backup": ["--manifest-output", str(out)],
        "restore": ["--manifest", "manifest.json"],
        "retention-report": ["--policy", "retention.json"],
    }
    for command, argv in arguments.items():  # no grant: refused before anything is touched
        result = env.invoke(command, *argv)
        assert result.code == "grant_missing" and result.exit == 3
    env.grants = RECOVERY_GRANTS
    env.write_config()
    # Granted but no backup store configured: a stated blocker, not a default location.
    for command in ("backup", "restore"):
        blocked = env.invoke(command, *arguments[command])
        assert blocked.code == "config_required" and "backup_store" in blocked.payload["blockers"]
    env.extra["backupStore"] = {
        "storeId": "backup",
        "rootPath": str(tmp_path / "somewhere"),
        "limits": env.bound.model_dump(by_alias=True),
    }
    env.write_config()
    dry = env.invoke("backup", *arguments["backup"])
    assert dry.payload["outcome"] == "dry_run" and dry.payload["executed"] is False
    assert not out.exists()


def test_cli_backup_restore_and_report_round_trip(
    library: Library,
    ledger: Ledger,
    target_ledger: Ledger,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lib = library
    verified(lib)
    backup_root = tmp_path / "cli-backup"
    source = cli_env(tmp_path, monkeypatch, lib, ledger, backup_root)
    services = TrustedServices(clock=lambda: READY)
    manifest_path = tmp_path / "recovery.json"

    dry = source.invoke("backup", "--manifest-output", str(manifest_path), services=services)
    assert dry.payload["outcome"] == "dry_run" and not manifest_path.exists()
    done = source.invoke(
        "backup", "--manifest-output", str(manifest_path), "--execute", services=services
    )
    assert done.exit == 0, done.raw
    assert done.payload["contentRefs"] > 0 and done.payload["pendingAttempts"] == 0
    # A second directory on the same device is mechanics only, never an independent copy.
    assert done.payload["independentMedia"] is False
    assert done.payload["independentlyVerified"] is False
    assert manifest_path.stat().st_mode & 0o777 == 0o600
    source.assert_redacted(done)
    original = manifest_path.read_bytes()
    again = source.invoke(
        "backup", "--manifest-output", str(manifest_path), "--execute", services=services
    )
    assert again.code == "unavailable" and manifest_path.read_bytes() == original

    policy = source.input("retention.json", POLICY.model_dump_json(by_alias=True))
    report = source.invoke("retention-report", "--policy", policy, services=services)
    assert report.exit == 0 and report.payload["deleted"] == 0
    assert report.payload["entries"] and all(e["eligible"] for e in report.payload["entries"])

    target = cli_env(tmp_path / "target", monkeypatch, lib, target_ledger, backup_root)
    dry_restore = target.invoke("restore", "--manifest", str(manifest_path), services=services)
    assert dry_restore.payload["outcome"] == "dry_run"
    assert row_count(target_ledger, "projects") == 0
    restored = target.invoke(
        "restore", "--manifest", str(manifest_path), "--execute", services=services
    )
    assert restored.exit == 0, restored.raw
    assert restored.payload["dispatchBlocked"] is True and restored.payload["accessBlocked"] is True
    assert restored.payload["missingRefs"] == []
    assert pause_rows(target_ledger) == [(True, 1, BARRIER_REASON)]
    target.assert_redacted(restored)
