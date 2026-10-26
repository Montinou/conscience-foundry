"""Durable import, local trusted reads and publication state on synthetic data only."""

from __future__ import annotations

import errno
import hashlib
import io
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, BinaryIO
from uuid import uuid4

import pytest
from psycopg import sql
from psycopg.types.json import Jsonb
from test_ledger_db import ACTOR, ASSET, BATCH, PROJECT, TIME, reference
from test_release_build import (
    B_SOURCE,
    Authority,
    ReleaseCase,
    approval_request,
    deny_b,
    make_case,
    selected_source,
)

from conscience_foundry.contracts.canonical import DocumentRevision, DocumentSpan
from conscience_foundry.contracts.common import ContractError, Ref
from conscience_foundry.contracts.release import (
    ActivationRecord,
    ImportReceipt,
    LibraryRelease,
    PublicationAuthorization,
    PublicationRecord,
    ReleaseSource,
)
from conscience_foundry.ledger.db import Ledger
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.release.context import ReleaseApproval, TrustedReleasePin
from conscience_foundry.release.importer import import_release
from conscience_foundry.release.publication import activate, append_publication
from conscience_foundry.release.read import ResolvedSlice, resolve_span, verify_resolved_slice
from conscience_foundry.storage.local import ObjectStore, VerifiedBytes

pytestmark = pytest.mark.database
OPERATOR_ACTIONS = {"import_release", "append_publication", "activate_release"}
STORE_ID = "synthetic"
CONSUMER = "synthetic.consumer.v1"


class Operator(Authority):
    """Exact-bytes approval of T15 actions; unregistered requests are never approved."""

    def __init__(self) -> None:
        super().__init__()
        self.operations: set[tuple[str, bytes]] = set()

    def approve(self, proof: Any) -> ReleaseApproval:
        if proof.action not in OPERATOR_ACTIONS:
            return super().approve(proof)
        if self.hook is not None:
            self.hook()
        if self.fail or (proof.action, proof.request_bytes) not in self.operations:
            raise ContractError("forbidden")
        return ReleaseApproval(
            project_id=PROJECT,
            actor_id=ACTOR,
            action=proof.action,
            request_digest="0" * 64
            if self.wrong_binding
            else hashlib.sha256(proof.request_bytes).hexdigest(),
            state_digest=proof.state_digest,
            evidence_digest=proof.evidence_ref.digest if proof.evidence_ref else None,
            revision_ref=proof.revision_ref,
        )


class FullDisk:
    """Test-only store wrapper: reads pass through, writes can fail with ENOSPC."""

    def __init__(self, inner: ObjectStore) -> None:
        self.inner = inner
        self.full = False
        self.writes = 0

    def put_verified(self, stream: BinaryIO, expected: Ref, context: AccessContext) -> Ref:
        if self.full:
            raise OSError(errno.ENOSPC, "No space left on device")
        self.writes += 1
        return self.inner.put_verified(stream, expected, context)

    def open_verified(self, ref: Ref, context: AccessContext) -> BinaryIO:
        return self.inner.open_verified(ref, context)

    def read_verified(self, ref: Ref, context: AccessContext, limit: int) -> VerifiedBytes:
        return self.inner.read_verified(ref, context, limit)


@dataclass
class Library:
    value: ReleaseCase
    root: Path
    ref: Ref
    model: LibraryRelease
    pin: TrustedReleasePin
    source: ReleaseSource
    disk: FullDisk
    old_digest: str

    @property
    def digest(self) -> str:
        return self.ref.digest

    @property
    def ledger(self) -> Ledger:
        return self.value.ledger

    @property
    def access(self) -> AccessContext:
        return self.value.release.access

    def allow_import(self) -> bytes:
        raw = approval_request(
            {"projectId": PROJECT, "releaseDigest": self.digest, "storeId": STORE_ID}
        )
        operator(self.value).operations.add(("import_release", raw))
        return raw

    def import_(self, **overrides: Any) -> ImportReceipt:
        arguments: dict[str, Any] = {"release": self.value.release, "pin": self.pin, **overrides}
        return import_release(
            self.ref, self.access, self.ledger, self.value.release.store, **arguments
        )

    def row(self, digest: str | None = None) -> tuple[bool, Any]:
        with self.ledger.transaction() as tx:
            found = tx.connection.execute(
                sql.SQL(
                    "SELECT local_verified,import_receipt_ref FROM {} WHERE release_digest=%s"
                ).format(tx.table("releases")),
                (digest or self.digest,),
            ).fetchone()
        assert found is not None
        return found


def release_digest(model: LibraryRelease) -> str:
    return hashlib.sha256(
        model.model_dump_json(by_alias=True, exclude_none=True).encode()
    ).hexdigest()


def operator(value: ReleaseCase) -> Operator:
    assert isinstance(value.authority, Operator)
    return value.authority


def build_library(value: ReleaseCase, root: Path) -> Library:
    value.authority = Operator()
    value.release = replace(value.release, authority=value.authority)
    source = selected_source(value)
    selected = (source,)
    value.allow_build(selected)
    # A first, never-imported build stands in for the previously active release.
    old_digest = release_digest(value.build(selected))
    candidate = value.build(selected)
    with value.ledger.transaction() as tx:
        stored = tx.connection.execute(
            sql.SQL("SELECT release_ref FROM {} WHERE release_digest=%s").format(
                tx.table("releases")
            ),
            (release_digest(candidate),),
        ).fetchone()
    assert stored is not None
    ref = Ref.model_validate(stored[0])
    disk = FullDisk(value.case.store)
    # The store's synthetic authorizer follows case.access; production code is unaffected.
    value.case.access = AccessContext(
        PROJECT, ACTOR, frozenset({"read", "extract", "auditMetadataRead", "publish"})
    )
    value.release = replace(value.release, access=value.case.access, store=disk)
    pin = TrustedReleasePin(PROJECT, ref.digest, STORE_ID, CONSUMER, ("canonical_text",))
    return Library(value, root, ref, candidate, pin, source, disk, old_digest)


@pytest.fixture
def library(ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Library:
    value = make_case(ledger, tmp_path, monkeypatch, b"Synthetic text")
    return build_library(value, tmp_path / "objects")


def code(error: pytest.ExceptionInfo[ContractError]) -> str:
    return error.value.code


def failed_import_not_verified(lib: Library, digest: str | None = None) -> None:
    verified, receipt = lib.row(digest)
    assert verified is False and receipt is None


def b_content_reads(lib: Library) -> int:
    excluded = lib.value.case.data.report.entries[1].snapshot_ref
    assert excluded is not None
    return lib.value.reads.count(excluded.digest)


def test_import_verifies_selected_closure_and_records_receipt(library: Library) -> None:
    lib = library
    failed_import_not_verified(lib)
    lib.allow_import()
    lib.value.reads.clear()
    receipt = lib.import_()
    assert receipt.status == "local_verified" and receipt.reasons == ()
    assert receipt.release_ref.digest == lib.digest
    assert lib.digest not in {ref.digest for ref in receipt.verified_artifacts}
    schemas = {ref.artifact_schema for ref in receipt.verified_artifacts}
    assert {
        "kf.document-revision.v1",
        "kf.revision-review.v1",
        "kf.canonical-text.v1",
        "kf.coverage-report.v1",
        "kf.provenance-report.v1",
        "kf.extraction-spec.v1",
        "kf.contract-limits.v1",
    } <= schemas
    verified, stored = lib.row()
    assert verified is True
    stored_ref = Ref.model_validate(stored)
    raw = lib.value.read(stored_ref, lib.value.case.access, 65536).data
    assert ImportReceipt.from_wire(raw, lib.value.case.bound) == receipt
    # Administrative audit edges and the excluded source are never traversed.
    assert b_content_reads(lib) == 0
    assert lib.value.case.data.report_ref.digest not in lib.value.reads
    again = lib.import_()
    assert again == receipt
    assert lib.row()[1] == stored


def test_import_requires_trusted_pin_and_exact_binding(library: Library) -> None:
    lib = library
    lib.allow_import()
    other = "f" * 64
    for pin, expected in (
        (replace(lib.pin, release_digest=other), "forbidden"),
        (replace(lib.pin, project_id=B_SOURCE), "forbidden"),
        (replace(lib.pin, store_id="elsewhere"), "forbidden"),
        (replace(lib.pin, capabilities=("embeddings",)), "unsupported_capability"),
        (replace(lib.pin, consumer_contract=""), "forbidden"),
        ({"release_digest": lib.digest}, "forbidden"),
    ):
        with pytest.raises(ContractError) as error:
            lib.import_(pin=pin)
        assert code(error) == expected
    # A self-supplied ref whose digest matches no trusted pin is rejected.
    wrong_ref = lib.ref.model_copy(update={"digest": other})
    with pytest.raises(ContractError) as error:
        import_release(
            wrong_ref,
            lib.access,
            lib.ledger,
            lib.value.release.store,
            release=lib.value.release,
            pin=lib.pin,
        )
    assert code(error) == "forbidden"
    failed_import_not_verified(lib)


def test_import_requires_exact_independent_approval(library: Library) -> None:
    lib = library
    with pytest.raises(ContractError) as error:
        lib.import_()
    assert code(error) == "forbidden"
    lib.allow_import()
    operator(lib.value).wrong_binding = True
    with pytest.raises(ContractError):
        lib.import_()
    operator(lib.value).wrong_binding = False
    operator(lib.value).fail = True
    with pytest.raises(ContractError):
        lib.import_()
    operator(lib.value).fail = False
    failed_import_not_verified(lib)
    with pytest.raises(ContractError):
        lib.import_(
            release=replace(lib.value.release, access=replace(lib.access, actor_id=B_SOURCE))
        )
    failed_import_not_verified(lib)
    assert lib.import_().status == "local_verified"


@pytest.mark.parametrize("audit", ["deny", "unknown"])
def test_import_withholds_release_when_report_metadata_is_not_authorized(
    library: Library, audit: str
) -> None:
    lib = library
    lib.allow_import()
    deny_b(lib.value, audit=audit)
    lib.value.reads.clear()
    with pytest.raises(ContractError) as error:
        lib.import_()
    assert code(error) == ("forbidden" if audit == "deny" else "permission_unknown")
    failed_import_not_verified(lib)
    assert b_content_reads(lib) == 0
    coverage = lib.model.coverage_report_ref.digest
    assert coverage not in lib.value.reads


def active_digest(lib: Library) -> str | None:
    with lib.ledger.transaction() as tx:
        found = tx.connection.execute(
            sql.SQL("SELECT release_digest FROM {} WHERE pointer_id='active'").format(
                tx.table("active_releases")
            )
        ).fetchone()
    return None if found is None else str(found[0])


def seed_active(lib: Library, digest: str) -> None:
    """Factory state: this task's import must never move an existing pointer."""
    with lib.ledger.transaction() as tx:
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,pointer_id,release_digest,version) "
                "VALUES (%s,'active',%s,1)"
            ).format(tx.table("active_releases")),
            (PROJECT, digest),
        )


def test_disk_full_and_wrong_hash_preserve_active_pointer(library: Library) -> None:
    lib = library
    seed_active(lib, lib.old_digest)
    lib.allow_import()
    lib.disk.full = True
    with pytest.raises(ContractError) as error:
        lib.import_()
    assert code(error) == "storage_full"
    failed_import_not_verified(lib)
    assert active_digest(lib) == lib.old_digest
    lib.disk.full = False
    revision = json.loads(lib.value.read(lib.source.revision_ref, lib.access, 65536).data)
    digest = revision["textRef"]["digest"]
    blob = lib.root / "sha256" / digest[:2] / digest
    good = blob.read_bytes()
    blob.write_bytes(b"Synthetic tex!")
    assert len(good) == 14
    with pytest.raises(ContractError) as error:
        lib.import_()
    assert code(error) == "hash_mismatch"
    failed_import_not_verified(lib)
    assert active_digest(lib) == lib.old_digest
    blob.write_bytes(good)
    assert lib.import_().status == "local_verified"
    assert active_digest(lib) == lib.old_digest
    assert lib.row()[0] is True and lib.row(lib.old_digest)[0] is False


def set_held(lib: Library, held: bool) -> None:
    with lib.ledger.transaction() as tx:
        tx.connection.execute(
            sql.SQL("UPDATE {} SET held=%s").format(tx.table("operations")), (held,)
        )


def withdraw_asset(lib: Library) -> None:
    """Factory row equivalent to a recorded operator withdrawal of the selected asset."""
    with lib.ledger.transaction() as tx:
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,batch_id,asset_id,source_id,decision_id,actor_id,"
                "reason,evidence_ref,request_digest,record_bytes,decided_at) VALUES "
                "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())"
            ).format(tx.table("admission_withdrawals")),
            (
                PROJECT,
                BATCH,
                ASSET,
                lib.source.source_id,
                "00000000-0000-0000-0000-0000000000aa",
                ACTOR,
                Jsonb({"code": "forbidden", "message": "Synthetic"}),
                Jsonb({}),
                "0" * 64,
                b"{}",
            ),
        )


def revoke_a(lib: Library, **permissions: str) -> None:
    sources = tuple(
        source.model_copy(update=permissions)
        if source.source_id == lib.source.source_id
        else source
        for source in lib.value.case.policy.sources
    )
    lib.value.case.policy = lib.value.case.policy.model_copy(update={"sources": sources})


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ("read", "forbidden"),
        ("extract", "forbidden"),
        ("unknown", "permission_unknown"),
        ("hold", "determinism_conflict"),
        ("withdrawn", "forbidden"),
    ],
)
def test_import_rechecks_current_authority(library: Library, change: str, expected: str) -> None:
    lib = library
    lib.allow_import()
    if change == "hold":
        set_held(lib, True)
    elif change == "withdrawn":
        withdraw_asset(lib)
    elif change == "unknown":
        revoke_a(lib, read="unknown")
    else:
        revoke_a(lib, **{change: "deny"})
    with pytest.raises(ContractError) as error:
        lib.import_()
    assert code(error) == expected
    failed_import_not_verified(lib)


def test_failed_reimport_never_reverts_local_verification(library: Library) -> None:
    lib = library
    imported(lib)
    verified, stored = lib.row()
    assert verified is True
    set_held(lib, True)
    with pytest.raises(ContractError) as error:
        lib.import_()
    assert code(error) == "determinism_conflict"
    # The recorded receipt stays; reads and activation are blocked by current authority.
    assert lib.row() == (True, stored)
    with pytest.raises(ContractError):
        resolve(lib, span_of(lib, 0, 9))
    set_held(lib, False)
    assert resolve(lib, span_of(lib, 0, 9)).text == "Synthetic"


def revision_of(lib: Library) -> DocumentRevision:
    raw = lib.value.read(lib.source.revision_ref, lib.access, 65536).data
    return DocumentRevision.from_wire(raw, lib.value.case.bound)


def span_of(lib: Library, start: int, end: int, **overrides: Any) -> DocumentSpan:
    fields: dict[str, Any] = {
        "schema_version": "kf.document-span.v1",
        "project_id": PROJECT,
        "source_id": lib.source.source_id,
        "revision_id": revision_of(lib).revision_id,
        "section_id": "body",
        "start": start,
        "end": end,
        "offset_unit": "unicode_scalar",
    }
    return DocumentSpan(**{**fields, **overrides})


def resolve(lib: Library, span: DocumentSpan, **overrides: Any) -> ResolvedSlice:
    arguments: dict[str, Any] = {"release": lib.value.release, "pin": lib.pin, **overrides}
    digest = arguments.pop("release_digest", lib.digest)
    return resolve_span(lib.access, digest, span, lib.ledger, lib.value.release.store, **arguments)


def imported(lib: Library) -> None:
    lib.allow_import()
    assert lib.import_().status == "local_verified"
    lib.value.reads.clear()


@pytest.fixture
def unicode_library(ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Library:
    value = make_case(ledger, tmp_path, monkeypatch, "Caf\u00e9 \U0001f642 text".encode())
    return build_library(value, tmp_path / "objects")


def test_resolve_span_returns_exact_scalar_slice_after_full_verification(
    unicode_library: Library,
) -> None:
    lib = unicode_library
    imported(lib)
    resolved = resolve(lib, span_of(lib, 5, 6))
    assert resolved.text == "\U0001f642"
    assert resolved.text_digest == hashlib.sha256(resolved.text.encode()).hexdigest()
    assert resolved.revision_id == revision_of(lib).revision_id
    assert resolved.span == span_of(lib, 5, 6)
    assert resolve(lib, span_of(lib, 0, 4)).text == "Caf\u00e9"
    # Only the manifest, the one selected revision and its full text are opened.
    reads = set(lib.value.reads)
    assert lib.model.coverage_report_ref.digest not in reads
    assert lib.model.provenance_report_ref.digest not in reads
    assert lib.value.case.data.report_ref.digest not in reads
    assert b_content_reads(lib) == 0
    revision = revision_of(lib)
    assert revision.text_ref.digest in reads and lib.source.revision_ref.digest in reads


def test_resolve_span_requires_pin_import_and_exact_binding(library: Library) -> None:
    lib = library
    span = span_of(lib, 0, 9)
    with pytest.raises(ContractError) as error:
        resolve(lib, span)
    assert code(error) == "unavailable"
    imported(lib)
    other = "f" * 64
    with pytest.raises(ContractError) as error:
        resolve(lib, span, release_digest=other)
    assert code(error) == "forbidden"
    with pytest.raises(ContractError) as error:
        resolve(lib, span, pin=replace(lib.pin, release_digest=other))
    assert code(error) == "forbidden"
    with pytest.raises(ContractError) as error:
        resolve(lib, span, pin=replace(lib.pin, capabilities=("embeddings",)))
    assert code(error) == "unsupported_capability"
    with pytest.raises(ContractError) as error:
        resolve(
            lib,
            span,
            release_digest=lib.old_digest,
            pin=replace(lib.pin, release_digest=lib.old_digest),
        )
    assert code(error) == "unavailable"
    assert resolve(lib, span).text == "Synthetic"


@pytest.mark.parametrize(
    ("overrides", "start", "end", "expected"),
    [
        ({"project_id": B_SOURCE}, 0, 9, "forbidden"),
        ({"source_id": B_SOURCE}, 0, 9, "revision_mismatch"),
        ({"revision_id": "e" * 64}, 0, 9, "revision_mismatch"),
        ({"section_id": "appendix"}, 0, 9, "invalid_span"),
        ({}, 0, 15, "invalid_span"),
    ],
)
def test_resolve_span_rejects_spans_outside_the_pinned_release(
    library: Library, overrides: dict[str, Any], start: int, end: int, expected: str
) -> None:
    lib = library
    imported(lib)
    with pytest.raises(ContractError) as error:
        resolve(lib, span_of(lib, start, end, **overrides))
    assert code(error) == expected


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ("read", "forbidden"),
        ("extract", "forbidden"),
        ("unknown", "permission_unknown"),
        ("hold", "determinism_conflict"),
        ("withdrawn", "forbidden"),
    ],
)
def test_resolve_span_rechecks_current_authority_every_call(
    library: Library, change: str, expected: str
) -> None:
    lib = library
    imported(lib)
    span = span_of(lib, 0, 9)
    assert resolve(lib, span).text == "Synthetic"
    lib.value.reads.clear()
    if change == "hold":
        set_held(lib, True)
    elif change == "withdrawn":
        withdraw_asset(lib)
    elif change == "unknown":
        revoke_a(lib, read="unknown")
    else:
        revoke_a(lib, **{change: "deny"})
    with pytest.raises(ContractError) as error:
        resolve(lib, span)
    assert code(error) == expected
    # No content bytes are opened once current authority is gone.
    assert revision_of_digest(lib) not in lib.value.reads
    assert b_content_reads(lib) == 0


def revision_of_digest(lib: Library) -> str:
    return json.loads(lib.value.read(lib.source.revision_ref, lib.access, 65536).data)["textRef"][
        "digest"
    ]


def test_resolve_span_detects_tampered_full_text(library: Library) -> None:
    lib = library
    imported(lib)
    digest = revision_of_digest(lib)
    blob = lib.root / "sha256" / digest[:2] / digest
    good = blob.read_bytes()
    blob.write_bytes(b"Synthetic tex!")
    with pytest.raises(ContractError) as error:
        resolve(lib, span_of(lib, 0, 9))
    assert code(error) == "hash_mismatch"
    blob.write_bytes(good)
    assert resolve(lib, span_of(lib, 0, 9)).text == "Synthetic"


def test_independent_verification_compares_full_bytes_and_exact_slice(library: Library) -> None:
    lib = library
    imported(lib)
    revision = revision_of(lib)
    resolved = resolve(lib, span_of(lib, 0, 9))
    full = lib.value.read(revision.text_ref, lib.access, 65536)
    verify_resolved_slice(resolved, full, revision, limits=lib.value.case.bound)
    forged = "Synthetiq"
    # The full-text digest still matches the pin; only the exact slice is wrong.
    for tampered in (
        replace(resolved, text=forged),
        replace(resolved, text=forged, text_digest=hashlib.sha256(forged.encode()).hexdigest()),
        replace(resolved, span=span_of(lib, 0, 8)),
        replace(resolved, revision_id="e" * 64),
    ):
        with pytest.raises(ContractError):
            verify_resolved_slice(tampered, full, revision, limits=lib.value.case.bound)
    with pytest.raises(ContractError):
        verify_resolved_slice(
            resolved,
            VerifiedBytes(b"Synthetic tex!", hashlib.sha256(b"Synthetic tex!").hexdigest()),
            revision,
            limits=lib.value.case.bound,
        )


LATER = "2026-10-26T00:00:00.000Z"
EARLIER = "2026-10-24T00:00:00.000Z"
EXPIRED = "2026-10-24T12:00:00.000Z"
STAGES = ("candidate", "validated", "transferred", "local_verified", "published", "retired")


def record_bytes(value: Any) -> bytes:
    return value.model_dump_json(by_alias=True, exclude_none=True).encode()


def store(lib: Library, value: Any, schema: str) -> Ref:
    raw = record_bytes(value)
    ref = reference(raw, schema)
    lib.value.case.store.put_verified(io.BytesIO(raw), ref, lib.value.case.access)
    return ref


def policy_ref(lib: Library, version: str | None = None) -> Ref:
    policy = lib.value.case.policy
    if version is not None:
        policy = policy.model_copy(update={"policy_version": version})
    return store(lib, policy, "kf.policy.v1")


def grant(lib: Library, **overrides: Any) -> Ref:
    fields: dict[str, Any] = {
        "schema_version": "kf.publication-authorization.v1",
        "project_id": PROJECT,
        "release_digest": lib.digest,
        "actor_id": ACTOR,
        "policy_ref": policy_ref(lib),
        "authorized_at": EARLIER,
        "expires_at": LATER,
    }
    return store(
        lib, PublicationAuthorization(**{**fields, **overrides}), "kf.publication-authorization.v1"
    )


def receipt_ref(lib: Library) -> Ref:
    stored = lib.row()[1]
    assert stored is not None
    return Ref.model_validate(stored)


def evidence_for(lib: Library, stage: str) -> tuple[Ref, ...]:
    if stage == "validated":
        return (lib.source.review_ref,)
    if stage in {"local_verified", "published", "retired"}:
        return (receipt_ref(lib),)
    return (lib.ref,)


def publication(
    lib: Library, stage: str, previous: str | None, **overrides: Any
) -> PublicationRecord:
    fields: dict[str, Any] = {
        "schema_version": "kf.publication-record.v1",
        "project_id": PROJECT,
        "release_digest": lib.digest,
        "event_id": str(uuid4()),
        "stage": stage,
        "actor_id": ACTOR,
        "policy_ref": policy_ref(lib),
        "recorded_at": TIME,
    }
    if "evidence_refs" not in overrides:
        fields["evidence_refs"] = evidence_for(lib, stage)
    if previous is not None:
        fields["previous_event_id"] = previous
    if stage == "published":
        fields["publication_authorization_ref"] = grant(lib)
    return PublicationRecord(**{**fields, **overrides})


def append(
    lib: Library,
    record: PublicationRecord,
    *,
    approved: bool = True,
    pin: TrustedReleasePin | None | str = "trusted",
) -> None:
    raw = record_bytes(record)
    if approved:
        operator(lib.value).operations.add(("append_publication", raw))
    trusted = lib.pin if pin == "trusted" else pin
    assert trusted is None or isinstance(trusted, TrustedReleasePin)
    append_publication(record, lib.access, lib.ledger, release=lib.value.release, pin=trusted)


def events(lib: Library, digest: str | None = None) -> list[tuple[str, str, str | None]]:
    with lib.ledger.transaction() as tx:
        rows = tx.connection.execute(
            sql.SQL(
                "SELECT event_id::text,stage,previous_event_id::text FROM {} WHERE "
                "release_digest=%s ORDER BY recorded_at,stage"
            ).format(tx.table("publications")),
            (digest or lib.digest,),
        ).fetchall()
    return sorted(rows, key=lambda row: STAGES.index(row[1]))


def advance(lib: Library, through: str) -> str:
    """Append a valid chain up to and including `through`; return the tail event id."""
    previous: str | None = None
    for stage in STAGES[: STAGES.index(through) + 1]:
        if stage == "validated":
            imported(lib)
        record = publication(lib, stage, previous)
        append(lib, record)
        previous = record.event_id
    assert previous is not None
    return previous


def test_publication_chain_is_append_only_ordered_without_skips(library: Library) -> None:
    lib = library
    first = publication(lib, "candidate", None)
    append(lib, first)
    # Validated rests on local import, so the import precedes the validated event.
    imported(lib)
    # Exact replay of an event is a no-op; changed reuse of its id fails.
    append(lib, first)
    assert len(events(lib)) == 1
    with pytest.raises(ContractError) as error:
        append(lib, publication(lib, "validated", str(uuid4()), event_id=first.event_id))
    assert code(error) == "determinism_conflict"
    # Stale or invented predecessors lose the compare-and-swap; skips are invalid.
    with pytest.raises(ContractError) as error:
        append(lib, publication(lib, "validated", str(uuid4())))
    assert code(error) == "activation_conflict"
    with pytest.raises(ContractError) as error:
        append(lib, publication(lib, "candidate", None))
    assert code(error) == "activation_conflict"
    with pytest.raises(ContractError) as error:
        append(lib, publication(lib, "transferred", first.event_id))
    assert code(error) == "invalid_schema"
    assert len(events(lib)) == 1
    tail = first.event_id
    for stage in ("validated", "transferred"):
        record = publication(lib, stage, tail)
        append(lib, record)
        tail = record.event_id
    with pytest.raises(ContractError):
        append(lib, publication(lib, "validated", tail))
    for stage in ("local_verified", "published", "retired"):
        record = publication(lib, stage, tail)
        append(lib, record)
        tail = record.event_id
    assert [event[1] for event in events(lib)] == list(STAGES)
    with pytest.raises(ContractError) as error:
        append(lib, publication(lib, "published", tail))
    assert code(error) == "invalid_schema"
    assert len(events(lib)) == 6


def test_publication_database_rejects_forked_or_duplicate_chain_rows(library: Library) -> None:
    import psycopg

    lib = library
    first = publication(lib, "candidate", None)
    append(lib, first)
    imported(lib)
    second = publication(lib, "validated", first.event_id)
    append(lib, second)
    ref = store(lib, second, "kf.publication-record.v1")

    def insert(event_id: str, stage: str, previous: str | None) -> None:
        with lib.ledger.transaction() as tx:
            tx.connection.execute(
                sql.SQL(
                    "INSERT INTO {} (project_id,event_id,release_digest,previous_event_id,"
                    "stage,publication_ref,actor_id,recorded_at) VALUES "
                    "(%s,%s,%s,%s,%s,%s,%s,now())"
                ).format(tx.table("publications")),
                (
                    PROJECT,
                    event_id,
                    lib.digest,
                    previous,
                    stage,
                    Jsonb(ref.model_dump(by_alias=True)),
                    ACTOR,
                ),
            )

    with pytest.raises(psycopg.errors.IntegrityError):
        insert(str(uuid4()), "transferred", first.event_id)
    with pytest.raises(psycopg.errors.IntegrityError):
        insert(str(uuid4()), "candidate", None)
    with pytest.raises(psycopg.errors.IntegrityError):
        insert(str(uuid4()), "validated", None)
    with pytest.raises(psycopg.errors.IntegrityError):
        insert(str(uuid4()), "transferred", str(uuid4()))
    assert len(events(lib)) == 2


def test_publication_requires_authenticated_actor_and_exact_approval(library: Library) -> None:
    lib = library
    with pytest.raises(ContractError) as error:
        append(lib, publication(lib, "candidate", None), approved=False)
    assert code(error) == "forbidden"
    operator(lib.value).wrong_binding = True
    with pytest.raises(ContractError):
        append(lib, publication(lib, "candidate", None))
    operator(lib.value).wrong_binding = False
    operator(lib.value).fail = True
    with pytest.raises(ContractError):
        append(lib, publication(lib, "candidate", None))
    operator(lib.value).fail = False
    # Direct trusted-API models can bypass field validation, so project/actor are rechecked.
    for update in ({"actor_id": B_SOURCE}, {"project_id": B_SOURCE}):
        with pytest.raises(ContractError) as error:
            append(lib, publication(lib, "candidate", None).model_copy(update=update))
        assert code(error) in {"forbidden", "invalid_schema"}
    with pytest.raises(ContractError):
        append(lib, publication(lib, "candidate", None, recorded_at=LATER))
    with pytest.raises(ContractError):
        append_publication(
            publication(lib, "candidate", None),
            lib.access,
            lib.ledger,
            release=replace(lib.value.release, access=replace(lib.access, actor_id=B_SOURCE)),
        )
    other = publication(lib, "candidate", None, release_digest="f" * 64)
    with pytest.raises(ContractError) as error:
        append(lib, other)
    assert code(error) == "unavailable"
    assert events(lib) == []
    append(lib, publication(lib, "candidate", None))
    assert len(events(lib)) == 1


def replace_evidence(record: PublicationRecord, refs: tuple[Ref, ...]) -> PublicationRecord:
    return record.model_copy(update={"evidence_refs": refs})


def release_ref_of(lib: Library, digest: str) -> Ref:
    with lib.ledger.transaction() as tx:
        row = tx.connection.execute(
            sql.SQL("SELECT release_ref FROM {} WHERE release_digest=%s").format(
                tx.table("releases")
            ),
            (digest,),
        ).fetchone()
    assert row is not None
    return Ref.model_validate(row[0])


def test_publication_evidence_is_closed_and_bound_to_the_release(library: Library) -> None:
    lib = library
    first = publication(lib, "candidate", None)
    for refs, expected in (
        ((lib.model.coverage_report_ref,), "unsupported_schema"),
        ((lib.value.case.data.report_ref,), "unsupported_schema"),
        ((lib.ref.model_copy(update={"project_id": B_SOURCE}),), "invalid_schema"),
        ((release_ref_of(lib, lib.old_digest),), "forbidden"),
    ):
        with pytest.raises(ContractError) as error:
            append(lib, replace_evidence(first, refs))
        assert code(error) == expected
    assert events(lib) == []
    append(lib, first)
    imported(lib)
    validated = publication(lib, "validated", first.event_id)
    # A validated release needs the accepted review of every selected revision.
    with pytest.raises(ContractError) as error:
        append(lib, replace_evidence(validated, (lib.ref,)))
    assert code(error) == "unsupported_schema"
    append(lib, validated)
    transferred = publication(lib, "transferred", validated.event_id)
    # Transport completion is not a local integrity claim.
    with pytest.raises(ContractError) as error:
        append(lib, replace_evidence(transferred, (lib.source.review_ref,)))
    assert code(error) == "unsupported_schema"
    append(lib, transferred)
    # Without a matching successful import receipt, local_verified cannot be recorded.
    with pytest.raises(ContractError) as error:
        append(
            lib, publication(lib, "local_verified", transferred.event_id, evidence_refs=(lib.ref,))
        )
    assert code(error) == "unsupported_schema"
    with pytest.raises(ContractError) as error:
        append(lib, replace_evidence(publication(lib, "local_verified", transferred.event_id), ()))
    assert code(error) == "invalid_schema"
    # A valid-looking receipt that the ledger never recorded is not the import proof.
    genuine = ImportReceipt.from_wire(
        lib.value.read(receipt_ref(lib), lib.access, 65536).data, lib.value.case.bound
    )
    forged = store(
        lib, genuine.model_copy(update={"import_id": str(uuid4())}), "kf.import-receipt.v1"
    )
    with pytest.raises(ContractError) as error:
        append(
            lib, publication(lib, "local_verified", transferred.event_id, evidence_refs=(forged,))
        )
    assert code(error) == "forbidden"
    other = other_library(lib)
    imported(other)
    with pytest.raises(ContractError) as error:
        append(
            lib,
            publication(
                lib, "local_verified", transferred.event_id, evidence_refs=(receipt_ref(other),)
            ),
        )
    assert code(error) == "forbidden"
    append(lib, publication(lib, "local_verified", transferred.event_id))


def test_validated_requires_local_import_before_it_is_recorded(library: Library) -> None:
    lib = library
    first = publication(lib, "candidate", None)
    append(lib, first)
    validated = publication(lib, "validated", first.event_id)
    # D08: verified closure is the local import; reviews and policy alone do not suffice.
    for pin in ("trusted", None):
        with pytest.raises(ContractError) as error:
            append(lib, validated, pin=pin)
        assert code(error) == "unavailable"
    assert [event[1] for event in events(lib)] == ["candidate"]
    failed_import_not_verified(lib)
    imported(lib)
    append(lib, validated)
    assert [event[1] for event in events(lib)] == ["candidate", "validated"]


def test_validated_requires_supported_capabilities_of_the_trusted_pin(library: Library) -> None:
    lib = library
    first = publication(lib, "candidate", None)
    append(lib, first)
    imported(lib)
    validated = publication(lib, "validated", first.event_id)
    narrower = replace(lib.pin, capabilities=())
    with pytest.raises(ContractError) as error:
        append(lib, validated, pin=narrower)
    assert code(error) == "unsupported_capability"
    # Capability checks need operator configuration: no pin, or one for another release.
    with pytest.raises(ContractError) as error:
        append(lib, validated, pin=None)
    assert code(error) == "forbidden"
    with pytest.raises(ContractError) as error:
        append(lib, validated, pin=replace(lib.pin, release_digest=lib.old_digest))
    assert code(error) == "forbidden"
    assert [event[1] for event in events(lib)] == ["candidate"]
    append(lib, validated)
    assert [event[1] for event in events(lib)] == ["candidate", "validated"]


@contextmanager
def scopes(lib: Library, granted: frozenset[str]) -> Iterator[None]:
    """Run as an operator with fewer scopes; the store authorizer follows case.access."""
    before, context = lib.value.case.access, lib.value.release
    reduced = AccessContext(PROJECT, ACTOR, granted)
    lib.value.case.access = reduced
    lib.value.release = replace(context, access=reduced)
    try:
        yield
    finally:
        lib.value.case.access, lib.value.release = before, context


def restore_policy(lib: Library) -> Any:
    return lib.value.case.policy


def test_published_requires_valid_grant_and_current_permission(library: Library) -> None:
    lib = library
    tail = advance(lib, "local_verified")
    stale = policy_ref(lib, "stale.v0")
    baseline = lib.value.case.policy
    cases: list[tuple[str, Any, str]] = [
        (
            "expired",
            {"publication_authorization_ref": grant(lib, expires_at=EXPIRED)},
            "authorization_expired",
        ),
        (
            "not yet valid",
            {
                "publication_authorization_ref": grant(
                    lib, authorized_at=LATER, expires_at="2026-10-27T00:00:00.000Z"
                )
            },
            "forbidden",
        ),
        (
            "other release",
            {"publication_authorization_ref": grant(lib, release_digest=lib.old_digest)},
            "forbidden",
        ),
        (
            "stale grant policy",
            {"publication_authorization_ref": grant(lib, policy_ref=stale)},
            "permission_unknown",
        ),
        ("stale record policy", {"policy_ref": stale}, "permission_unknown"),
        (
            "unknown grant",
            {"publication_authorization_ref": store_grant_like_policy(lib)},
            "invalid_schema",
        ),
    ]
    for label, overrides, expected in cases:
        with pytest.raises(ContractError) as error:
            append(lib, publication(lib, "published", tail, **overrides))
        assert code(error) == expected, label
    for change, expected in (
        ({"publish": "deny"}, "forbidden"),
        ({"publish": "unknown"}, "permission_unknown"),
        ({"read": "deny"}, "forbidden"),
    ):
        revoke_a(lib, **change)
        with pytest.raises(ContractError) as error:
            append(lib, publication(lib, "published", tail))
        assert code(error) == expected
        lib.value.case.policy = baseline
    set_held(lib, True)
    with pytest.raises(ContractError) as error:
        append(lib, publication(lib, "published", tail))
    assert code(error) == "determinism_conflict"
    set_held(lib, False)
    with scopes(lib, frozenset({"read", "extract", "auditMetadataRead"})):
        with pytest.raises(ContractError) as error:
            append(lib, publication(lib, "published", tail))
        assert code(error) == "forbidden"
    assert [event[1] for event in events(lib)] == list(STAGES[:4])
    append(lib, publication(lib, "published", tail))
    assert [event[1] for event in events(lib)] == list(STAGES[:5])


def store_grant_like_policy(lib: Library) -> Ref:
    """A ref with the right shape but a schema that is not a publication grant."""
    return policy_ref(lib).model_copy(update={"artifact_schema": "kf.publication-authorization.v1"})


def activation(
    lib: Library, digest: str, expected: str | None, **overrides: Any
) -> ActivationRecord:
    fields: dict[str, Any] = {
        "schema_version": "kf.activation.v1",
        "project_id": PROJECT,
        "next_release_digest": digest,
        "actor_id": ACTOR,
        "activated_at": TIME,
    }
    if expected is not None:
        fields["expected_previous_release_digest"] = expected
    return ActivationRecord(**{**fields, **overrides})


def move(
    lib: Library, record: ActivationRecord, *, approved: bool = True, **overrides: Any
) -> None:
    if approved:
        operator(lib.value).operations.add(("activate_release", record_bytes(record)))
    arguments: dict[str, Any] = {"release": lib.value.release, **overrides}
    activate(record, lib.access, lib.ledger, **arguments)


def history(lib: Library) -> list[tuple[int, str | None, str]]:
    with lib.ledger.transaction() as tx:
        rows = tx.connection.execute(
            sql.SQL(
                "SELECT version,expected_previous_release_digest,release_digest FROM {} "
                "WHERE pointer_id='active' ORDER BY version"
            ).format(tx.table("activation_history"))
        ).fetchall()
    return [(int(row[0]), row[1], str(row[2])) for row in rows]


def pointer_version(lib: Library) -> int:
    with lib.ledger.transaction() as tx:
        found = tx.connection.execute(
            sql.SQL("SELECT version FROM {} WHERE pointer_id='active'").format(
                tx.table("active_releases")
            )
        ).fetchone()
    return 0 if found is None else int(found[0])


def other_library(lib: Library) -> Library:
    """The earlier build as an independent candidate with its own pin."""
    ref = release_ref_of(lib, lib.old_digest)
    model = LibraryRelease.from_wire(
        lib.value.read(ref, lib.access, 65536).data, lib.value.case.bound
    )
    pin = replace(lib.pin, release_digest=ref.digest)
    return replace(lib, ref=ref, model=model, pin=pin, old_digest=lib.digest)


def test_activation_is_cas_over_published_locally_verified_releases(library: Library) -> None:
    lib = library
    first = lib.digest
    # Neither an unverified candidate nor a merely local_verified release is eligible.
    with pytest.raises(ContractError) as error:
        move(lib, activation(lib, first, None))
    assert code(error) == "forbidden"
    advance(lib, "local_verified")
    with pytest.raises(ContractError) as error:
        move(lib, activation(lib, first, None))
    assert code(error) == "forbidden"
    tail = events(lib)[-1][0]
    published = publication(lib, "published", tail)
    append(lib, published)
    with pytest.raises(ContractError) as error:
        move(lib, activation(lib, first, None, activated_at=EARLIER), approved=False)
    assert code(error) == "forbidden"
    with pytest.raises(ContractError) as error:
        move(lib, activation(lib, first, first))
    assert code(error) == "activation_conflict"
    assert active_digest(lib) is None and history(lib) == []
    move(lib, activation(lib, first, None))
    assert active_digest(lib) == first and pointer_version(lib) == 1
    # A stale first-activation view (nothing active) cannot overwrite the pointer.
    with pytest.raises(ContractError) as error:
        move(lib, activation(lib, first, None))
    assert code(error) == "activation_conflict"
    with pytest.raises(ContractError) as error:
        move(lib, activation(lib, first, "f" * 64))
    assert code(error) == "activation_conflict"
    assert pointer_version(lib) == 1
    # Rollback targets must be eligible published releases; retired ones are not.
    other = other_library(lib)
    advance(other, "retired")
    with pytest.raises(ContractError) as error:
        move(lib, activation(lib, other.digest, first))
    assert code(error) == "forbidden"
    assert active_digest(lib) == first and pointer_version(lib) == 1
    again = activation(lib, first, first, activated_at=TIME)
    move(lib, again)
    assert pointer_version(lib) == 2
    assert history(lib) == [(1, None, first), (2, first, first)]


def test_activation_derives_eligibility_from_current_authority(library: Library) -> None:
    lib = library
    advance(lib, "published")
    baseline = lib.value.case.policy
    for change, expected in (
        ({"publish": "deny"}, "forbidden"),
        ({"read": "unknown"}, "permission_unknown"),
        ({"extract": "deny"}, "forbidden"),
    ):
        revoke_a(lib, **change)
        with pytest.raises(ContractError) as error:
            move(lib, activation(lib, lib.digest, None))
        assert code(error) == expected
        lib.value.case.policy = baseline
    set_held(lib, True)
    lib.value.reads.clear()
    with pytest.raises(ContractError) as error:
        move(lib, activation(lib, lib.digest, None))
    assert code(error) == "determinism_conflict"
    set_held(lib, False)
    withdraw_asset(lib)
    with pytest.raises(ContractError) as error:
        move(lib, activation(lib, lib.digest, None))
    assert code(error) == "forbidden"
    assert b_content_reads(lib) == 0
    with lib.ledger.transaction() as tx:
        tx.connection.execute(sql.SQL("DELETE FROM {}").format(tx.table("admission_withdrawals")))
    # The grant is checked against the trusted clock at activation time too.
    later = replace(lib.value.release, clock=lambda: "2026-10-27T00:00:00.000Z")
    with pytest.raises(ContractError) as error:
        move(lib, activation(lib, lib.digest, None, activated_at=LATER), release=later)
    assert code(error) == "authorization_expired"
    for overrides in ({"actor_id": B_SOURCE},):
        with pytest.raises(ContractError):
            move(lib, activation(lib, lib.digest, None, **overrides))
    operator(lib.value).wrong_binding = True
    with pytest.raises(ContractError):
        move(lib, activation(lib, lib.digest, None))
    operator(lib.value).wrong_binding = False
    assert active_digest(lib) is None and history(lib) == []
    move(lib, activation(lib, lib.digest, None))
    assert active_digest(lib) == lib.digest
    tail = events(lib)[-1][0]
    append(lib, publication(lib, "retired", tail))
    # Retirement ends eligibility for any later activation, including re-activation.
    with pytest.raises(ContractError) as error:
        move(lib, activation(lib, lib.digest, lib.digest))
    assert code(error) == "forbidden"
    assert pointer_version(lib) == 1


def test_concurrent_stale_activations_cannot_both_win(library: Library) -> None:
    lib = library
    advance(lib, "published")
    other = other_library(lib)
    advance(other, "published")
    records = [activation(lib, lib.digest, None), activation(lib, other.digest, None)]
    for record in records:
        operator(lib.value).operations.add(("activate_release", record_bytes(record)))
    outcomes: list[str] = []
    barrier = threading.Barrier(2)

    def run(record: ActivationRecord) -> None:
        barrier.wait()
        try:
            activate(record, lib.access, lib.ledger, release=lib.value.release)
            outcomes.append("won")
        except ContractError as error:
            outcomes.append(error.code)

    threads = [threading.Thread(target=run, args=(record,)) for record in records]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["activation_conflict", "won"]
    assert pointer_version(lib) == 1 and len(history(lib)) == 1


def self_hash_without_pin_rejected(lib: Library) -> bool:
    """A self-supplied digest, with a wrong/foreign pin or none at all, is never trusted."""
    span = span_of(lib, 0, 9)
    bad = replace(lib.pin, release_digest="f" * 64)
    for call in (
        lambda: lib.import_(pin=bad),
        lambda: resolve(lib, span, pin=bad),
        lambda: resolve(lib, span, release_digest="f" * 64),
        lambda: import_release(
            lib.ref, lib.access, lib.ledger, lib.value.release.store, release=lib.value.release
        ),
    ):
        with pytest.raises((ContractError, TypeError)):
            call()
    return True


def stale_activation_rejected(lib: Library, digest: str, expected: str | None) -> bool:
    before = pointer_version(lib)
    with pytest.raises(ContractError) as error:
        move(lib, activation(lib, digest, expected))
    assert code(error) == "activation_conflict"
    return pointer_version(lib) == before


def held_source_unavailable(lib: Library) -> bool:
    set_held(lib, True)
    with pytest.raises(ContractError) as error:
        resolve(lib, span_of(lib, 0, 9))
    return code(error) == "determinism_conflict"


def test_pin_hold_and_activation_cas(library: Library) -> None:
    lib = library
    advance(lib, "published")
    assert self_hash_without_pin_rejected(lib)
    move(lib, activation(lib, lib.digest, None))
    assert active_digest(lib) == lib.digest
    assert stale_activation_rejected(lib, lib.digest, None)
    assert resolve(lib, span_of(lib, 0, 9)).text == "Synthetic"
    lib.value.reads.clear()
    assert held_source_unavailable(lib)
    assert b_content_reads(lib) == 0
    assert revision_of_digest(lib) not in lib.value.reads


# --- Phase 3 review round 1 regression (I4): failures are durable, never advancing ----------


def incidents(lib: Library) -> list[tuple[str, str | None, str, Any]]:
    with lib.ledger.transaction() as tx:
        rows = tx.connection.execute(
            sql.SQL(
                "SELECT kind,stage,error_code,receipt_ref FROM {} WHERE release_digest=%s "
                "ORDER BY incident_id"
            ).format(tx.table("release_incidents")),
            (lib.digest,),
        ).fetchall()
    return sorted(((row[0], row[1], row[2], row[3]) for row in rows), key=repr)


def tamper_text(lib: Library) -> tuple[Path, bytes]:
    revision = json.loads(lib.value.read(lib.source.revision_ref, lib.access, 65536).data)
    digest = revision["textRef"]["digest"]
    blob = lib.root / "sha256" / digest[:2] / digest
    good = blob.read_bytes()
    blob.write_bytes(b"Synthetic tex!")
    return blob, good


def test_failed_import_durably_records_a_failed_receipt_and_incident(library: Library) -> None:
    lib = library
    seed_active(lib, lib.old_digest)
    lib.allow_import()
    # Rejected before the release is trusted: no incident for a mismatched pin.
    with pytest.raises(ContractError):
        lib.import_(pin=replace(lib.pin, store_id="elsewhere"))
    assert incidents(lib) == []
    blob, good = tamper_text(lib)
    with pytest.raises(ContractError) as error:
        lib.import_()
    assert code(error) == "hash_mismatch"
    ((kind, stage, reason, stored),) = incidents(lib)
    assert (kind, stage, reason) == ("import", None, "hash_mismatch")
    raw = lib.value.read(Ref.model_validate(stored), lib.access, 65536).data
    failed = ImportReceipt.from_wire(raw, lib.value.case.bound)
    assert failed.status == "failed" and failed.verified_artifacts == ()
    assert failed.release_ref == lib.ref
    assert [reason.code for reason in failed.reasons] == ["hash_mismatch"]
    # Nothing but the stable error code: no source text, no private path.
    assert b"Synthetic" not in raw and str(lib.root).encode() not in raw
    # The stage did not advance and the active pointer was untouched.
    failed_import_not_verified(lib)
    assert active_digest(lib) == lib.old_digest
    # A later good import still succeeds and the failure record stays.
    blob.write_bytes(good)
    assert lib.import_().status == "local_verified"
    assert len(incidents(lib)) == 1 and lib.row()[0] is True


def test_failed_import_during_disk_full_still_records_an_incident(library: Library) -> None:
    lib = library
    lib.allow_import()
    lib.disk.full = True
    with pytest.raises(ContractError) as error:
        lib.import_()
    assert code(error) == "storage_full"
    assert incidents(lib) == [("import", None, "storage_full", None)]
    failed_import_not_verified(lib)


def test_failed_reimport_records_an_incident_and_keeps_local_verification(
    library: Library,
) -> None:
    lib = library
    imported(lib)
    verified, stored = lib.row()
    set_held(lib, True)
    with pytest.raises(ContractError) as error:
        lib.import_()
    assert code(error) == "determinism_conflict"
    assert [(row[0], row[2]) for row in incidents(lib)] == [("import", "determinism_conflict")]
    assert lib.row() == (verified, stored) == (True, stored)


def test_failed_publication_transition_records_an_incident_at_the_confirmed_stage(
    library: Library,
) -> None:
    lib = library
    first = publication(lib, "candidate", None)
    append(lib, first)
    validated = publication(lib, "validated", first.event_id)
    with pytest.raises(ContractError) as error:
        append(lib, validated)
    assert code(error) == "unavailable"
    assert incidents(lib) == [("publication", "validated", "unavailable", None)]
    # The confirmed stage is unchanged and nothing was marked verified.
    assert [event[1] for event in events(lib)] == ["candidate"]
    failed_import_not_verified(lib)
    # An exact replay of an already recorded event fails nothing and records nothing.
    append(lib, first)
    assert len(incidents(lib)) == 1
