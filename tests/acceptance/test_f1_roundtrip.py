"""Cross-system offline acceptance: the real CLI, ledger and Dagster over fake remote transport.

Nothing here contacts a network, a model or a provider. The remote worker, the evidence authority
and the release approval are test-owned doubles that script facts; every policy under test (claims,
reservations, reconciliation, review, release, import, reads, recovery) is the production code.
`AcceptanceReport` exists only in test output: it is never a live success claim.
"""

from __future__ import annotations

import importlib
import importlib.abc
import io
import json
import socket
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

import psycopg
import pytest
from conftest import approved_database_dsn
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

_INTEGRATION = str(Path(__file__).resolve().parents[1] / "integration")
if _INTEGRATION not in sys.path:
    sys.path.append(_INTEGRATION)
for _sibling in ("adapters", "unit"):
    _path = str(Path(__file__).resolve().parents[1] / _sibling)
    if _path not in sys.path:
        sys.path.append(_path)

import test_cli as cli_case  # noqa: E402
import test_dagster as dagster_case  # noqa: E402
import test_execution_control as execution_case  # noqa: E402
import test_import_publication as import_case  # noqa: E402
import test_release_build as release_build  # noqa: E402
from test_execution_control import Case, Executor  # noqa: E402
from test_ledger_db import ACTOR, ASSET, PROJECT, TIME, encoded  # noqa: E402

from conscience_foundry.cli.config import TrustedServices  # noqa: E402
from conscience_foundry.contracts.canonical import RevisionReview  # noqa: E402
from conscience_foundry.contracts.common import Reason, Ref  # noqa: E402
from conscience_foundry.contracts.execution import ResultManifest  # noqa: E402
from conscience_foundry.contracts.release import ReleaseSource  # noqa: E402
from conscience_foundry.ledger.db import Ledger  # noqa: E402
from conscience_foundry.orchestration.assets import (  # noqa: E402
    ADMISSION,
    PROCESSING,
    RECONCILIATION,
    build_definitions,
)
from conscience_foundry.policy.access import AccessContext  # noqa: E402

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "public" / "f1_cases.json"
SOURCE_TEXT = b"Synthetic text"
SCOPES = frozenset({"read", "extract", "remoteTransfer", "auditMetadataRead", "publish"})
MODEL_AND_CONSUMER_PACKAGES = frozenset(
    {"openai", "anthropic", "torch", "transformers", "langgraph", "langchain", "laya", "agora_eve"}
)
CONSUMER_TABLES = ("publications", "active_releases", "activation_history")
LOCAL_DIRECTORIES = frozenset({"objects", "inputs", "operator", "contracts", "schemas"})


@dataclass(frozen=True)
class AcceptanceReport:
    """Test-only record of one case; it is printed to test output and written nowhere else."""

    case_id: str
    spec_refs: tuple[str, ...]
    outcome: Literal["pass", "fail", "not_run"]
    evidence_refs: tuple[str, ...]

    def line(self) -> str:
        return "ACCEPTANCE " + json.dumps(
            {
                "caseId": self.case_id,
                "specRefs": list(self.spec_refs),
                "outcome": self.outcome,
                "evidenceRefs": list(self.evidence_refs),
            },
            sort_keys=True,
        )


def emit(report: AcceptanceReport) -> None:
    print(report.line())


def load_fixture() -> dict[str, Any]:
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


# --- ambient guards ----------------------------------------------------------------------------


@dataclass
class NetworkProbe:
    """Counts every attempt to leave the process; the suite-wide denial still raises."""

    attempts: list[str] = field(default_factory=list)


def watch_network(mp: pytest.MonkeyPatch) -> NetworkProbe:
    probe = NetworkProbe()
    database = Path(conninfo_to_dict(approved_database_dsn())["host"])
    already_denied_connect = socket.socket.connect
    already_denied_create = socket.create_connection
    already_denied_resolve = socket.getaddrinfo

    def connect(sock: socket.socket, address: object) -> None:
        # The approved local database socket is the only non-network peer a test may reach.
        if not (sock.family == socket.AF_UNIX and str(address).startswith(str(database))):
            probe.attempts.append("connect")
        already_denied_connect(sock, address)

    def create(*args: Any, **kwargs: Any) -> Any:
        probe.attempts.append("create_connection")
        return already_denied_create(*args, **kwargs)

    def resolve(*args: Any, **kwargs: Any) -> Any:
        probe.attempts.append("getaddrinfo")
        return already_denied_resolve(*args, **kwargs)

    mp.setattr(socket.socket, "connect", connect)
    mp.setattr(socket, "create_connection", create)
    mp.setattr(socket, "getaddrinfo", resolve)
    return probe


class ImportTrap(importlib.abc.MetaPathFinder):
    """Records an attempt to import any model or consumer package; it never supplies one."""

    def __init__(self) -> None:
        self.attempts: list[str] = []

    def find_spec(self, fullname: str, path: object = None, target: object = None) -> None:
        if fullname.split(".")[0] in MODEL_AND_CONSUMER_PACKAGES:
            self.attempts.append(fullname.split(".")[0])


def trap_imports(mp: pytest.MonkeyPatch) -> ImportTrap:
    loaded = MODEL_AND_CONSUMER_PACKAGES & set(sys.modules)
    assert not loaded, "a model or consumer package is already loaded: " + ", ".join(sorted(loaded))
    trap = ImportTrap()
    mp.setattr(sys, "meta_path", [trap, *sys.meta_path])
    return trap


@contextmanager
def fresh_ledger() -> Iterator[Ledger]:
    """A new migrated schema in the already approved disposable database; always dropped."""
    dsn = approved_database_dsn()

    def connect() -> psycopg.Connection[tuple[object, ...]]:
        return psycopg.connect(dsn, connect_timeout=3)

    database = Ledger(connect, schema="cf_test_" + uuid4().hex)
    database.migrate()
    try:
        yield database
    finally:
        with connect() as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(database.schema))
            )


# --- the real flow -----------------------------------------------------------------------------


class Flow:
    """The vertical flow driven only through the operator CLI against a real ledger.

    Sources A (selected) and B (excluded) are admitted; the remote worker is a scripted double.
    """

    def __init__(
        self,
        ledger: Ledger,
        tmp: Path,
        mp: pytest.MonkeyPatch,
        *,
        source: bytes = SOURCE_TEXT,
        lost: bool = False,
    ) -> None:
        self.ledger, self.tmp, self.mp = ledger, tmp, mp
        data = release_build.two_sources(source)
        mp.setattr(execution_case, "admission", lambda: data)
        case = Case(tmp, source_bytes=source)
        excluded = data.report.entries[1].snapshot_ref
        assert excluded is not None
        case.store.put_verified(io.BytesIO(b"Excluded synthetic source"), excluded, case.access)
        # One trusted context for every step, so the store's authority never has to be swapped.
        case.access = AccessContext(PROJECT, ACTOR, SCOPES)
        case.control = replace(case.control, access=case.access)
        cli_case.register(case, ledger)
        self.case = case
        self.operator = import_case.Operator()
        self.value = release_build.ReleaseCase(case, ledger)
        self.value.authority = self.operator
        self.value.release = replace(self.value.release, authority=self.operator)
        self.executor = Executor(case, lost=lost)
        self.minted: list[str] = []
        self.env = cli_case.database_env(tmp, mp, ledger, case)
        self.attempt: Any = None
        self.release_ref: Ref | None = None
        self.now = TIME
        self.database_down = False

    @property
    def services(self) -> TrustedServices:
        return TrustedServices(
            evidence_authority=self.case.authority,
            release_authority=self.operator,
            executor=self.executor,
            transport_grants=self._grants,
            connect=self._connect,
            clock=lambda: self.now,
        )

    def _connect(self, dsn: str) -> Any:
        if self.database_down:
            raise psycopg.OperationalError("password=SECRETMARK server closed the connection")
        return psycopg.connect(dsn, connect_timeout=3)

    def _grants(self, plan: Any, attempt: Any, plan_ref: Any) -> Any:
        assert attempt.state == "dispatching"
        self.minted.append(plan_ref.digest)
        return self.case.grants(attempt_id=attempt.attempt_id)

    def run(self, *argv: str) -> cli_case.Result:
        return self.env.invoke(*argv, services=self.services)

    def ref_file(self, name: str, ref: Any) -> str:
        return cli_case.ref_file(self.env, name, ref)

    def prepare(self) -> None:
        plan = self.env.input("plan.json", encoded(self.case.plan))
        auth = self.env.input("authorization.json", encoded(self.case.auth))
        assert self.run("prepare-run", "--plan", plan, "--execute").exit == 0
        assert self.run("authorize-run", "--authorization", auth, "--execute").exit == 0

    def dispatch_args(self) -> list[str]:
        return [
            "--plan-ref",
            self.ref_file("plan-ref.json", self.case.plan_ref),
            "--authorization-ref",
            self.ref_file("authorization-ref.json", self.case.auth_ref),
            "--evidence-ref",
            self.ref_file("estimate.json", self.case.estimate),
            "--asset-id",
            ASSET,
        ]

    def dispatch(self) -> cli_case.Result:
        return self.run("dispatch", *self.dispatch_args(), "--execute")

    def reconcile(self, attempt_id: str) -> cli_case.Result:
        return self.run("reconcile", "--attempt-id", attempt_id, "--execute")

    def settle(self) -> tuple[Ref, str]:
        """Dispatch, let the scripted worker finish, reconcile; return result ref and attempt id."""
        dispatched = self.dispatch()
        assert dispatched.exit == 0 and dispatched.payload["attempt"]["state"] == "running"
        found = dispatched.payload["attempt"]
        attempt = type("Attempt", (), {})()
        attempt.attempt_id, attempt.remote_call_id = found["attemptId"], found.get("remoteCallId")
        self.attempt = attempt
        result_ref = self.executor.success(attempt)
        done = self.reconcile(attempt.attempt_id)
        assert done.exit == 0 and done.payload["selection"]["outcome"] == "selected", done.raw
        return result_ref, attempt.attempt_id

    def revision_ref(self, result_ref: Ref) -> Ref:
        result = ResultManifest.from_wire(
            self.value.read(result_ref, self.case.access, 65536).data, self.case.bound
        )
        assert result.document_revision_ref is not None
        return result.document_revision_ref

    def submit_review(
        self, revision_ref: Ref, *, decision: str = "accepted"
    ) -> tuple[cli_case.Result, Ref | None]:
        logical = json.loads(self.value.read(revision_ref, self.case.access, 65536).data)[
            "revisionId"
        ]
        review = RevisionReview(
            schema_version="kf.revision-review.v1",
            project_id=PROJECT,
            revision_id=logical,
            decision=decision,  # type: ignore[arg-type]
            actor_id=ACTOR,
            policy_version=self.case.policy.policy_version,
            reviewed_at=TIME,
            reason=Reason(code="unavailable", message="Synthetic operator decision"),
        )
        raw = encoded(review)
        self.operator.allowed.add(("record_review", raw))
        reviewed = self.run(
            "review",
            "--review",
            self.env.input(f"review-{decision}.json", raw),
            "--operation-key",
            self.case.plan.operation_key,
            "--revision-ref",
            self.ref_file("revision-ref.json", revision_ref),
            "--evidence-ref",
            self.ref_file("report-ref.json", self.case.data.report_ref),
            "--execute",
        )
        review_ref = (
            Ref.model_validate(reviewed.payload["reviewRef"]) if reviewed.exit == 0 else None
        )
        return reviewed, review_ref

    def review(self, revision_ref: Ref, *, decision: str = "accepted") -> ReleaseSource:
        reviewed, review_ref = self.submit_review(revision_ref, decision=decision)
        assert reviewed.exit == 0 and review_ref is not None, reviewed.raw
        return ReleaseSource(
            source_id=self.case.data.report.entries[0].source_id,
            revision_ref=revision_ref,
            review_ref=review_ref,
        )

    def build(self, source: ReleaseSource) -> cli_case.Result:
        self.value.allow_build((source,))
        selection = {
            "schemaVersion": "cfoundry.release-selection.v1",
            "sources": [json.loads(source.model_dump_json(by_alias=True))],
            "admissionReportRefs": [
                json.loads(self.case.data.report_ref.model_dump_json(by_alias=True))
            ],
        }
        path = self.env.input("selection.json", json.dumps(selection))
        built = self.run("build-release", "--selection", path, "--execute")
        if built.exit == 0:
            self.release_ref = Ref.model_validate(built.payload["releaseRef"])
        return built

    def pin_release(self, ref: Ref) -> None:
        self.env.pins = [
            {
                "releaseDigest": ref.digest,
                "storeId": cli_case.STORE_ID,
                "consumerContract": import_case.CONSUMER,
                "capabilities": ["canonical_text"],
            }
        ]
        self.env.write_config()

    def allow_import(self, ref: Ref) -> None:
        raw = release_build.approval_request(
            {"projectId": PROJECT, "releaseDigest": ref.digest, "storeId": import_case.STORE_ID}
        )
        self.operator.operations.add(("import_release", raw))

    def import_release(self, ref: Ref) -> cli_case.Result:
        return self.run(
            "import-release", "--release-ref", self.ref_file("release.json", ref), "--execute"
        )

    def read_span(self, digest: str, span: Any, output: Path | None = None) -> cli_case.Result:
        arguments = [
            "read-span",
            "--release-digest",
            digest,
            "--span",
            self.env.input(f"span-{uuid4().hex}.json", span.model_dump_json(by_alias=True)),
        ]
        if output is not None:
            arguments += ["--output", str(output)]
        return self.run(*arguments)

    def rows(self, table: str) -> int:
        return cli_case.count(self.ledger, table)

    def finish_to_release(self) -> tuple[ReleaseSource, Ref]:
        """Prepare, dispatch, reconcile, review and build via the CLI; the release stays private."""
        self.prepare()
        result_ref, _ = self.settle()
        source = self.review(self.revision_ref(result_ref))
        built = self.build(source)
        assert built.exit == 0 and built.payload["published"] is False, built.raw
        assert self.release_ref is not None
        return source, self.release_ref

    def verified(self) -> tuple[ReleaseSource, Ref]:
        source, ref = self.finish_to_release()
        self.pin_release(ref)
        self.allow_import(ref)
        imported = self.import_release(ref)
        assert imported.exit == 0 and imported.payload["receipt"]["status"] == "local_verified"
        return source, ref

    def span(self, source: ReleaseSource, start: int, end: int, **overrides: Any) -> Any:
        revision = json.loads(self.value.read(source.revision_ref, self.case.access, 65536).data)
        from conscience_foundry.contracts.canonical import DocumentSpan

        fields: dict[str, Any] = {
            "schema_version": "kf.document-span.v1",
            "project_id": PROJECT,
            "source_id": source.source_id,
            "revision_id": revision["revisionId"],
            "section_id": "body",
            "start": start,
            "end": end,
            "offset_unit": "unicode_scalar",
        }
        return DocumentSpan(**{**fields, **overrides})

    def dagster(self, *stages: str) -> Any:
        """Run Dagster partition stages over the same ledger, returning the in-process result."""
        control = dagster_case.LedgerControl(self.case, self.ledger, self.executor)
        definitions = build_definitions(control, dagster_case.project_config())
        return dagster_case.Instance(dagster_case.key_for()).run(
            definitions, dagster_case.key_for(), *stages
        )

    def dagster_pass(self) -> int:
        """Run the Dagster partition over the same ledger; return how many remote submits ran."""
        run = self.dagster(ADMISSION, PROCESSING, RECONCILIATION)
        assert run.success, dagster_case.failure_codes(run)
        return self.executor.calls

    def set_permission(self, source_id: str, **permissions: str) -> None:
        sources = tuple(
            source.model_copy(update=permissions) if source.source_id == source_id else source
            for source in self.case.policy.sources
        )
        self.case.policy = self.case.policy.model_copy(update={"sources": sources})

    def fresh_estimate(self) -> None:
        """A new reservation needs fresh estimate evidence bound to the same capability facts."""
        self.case.estimate = self.case.proof()
        self.case.authority.estimates[self.case.estimate.digest] = next(
            iter(self.case.authority.estimates.values())
        )

    def stray_files(self) -> list[str]:
        """Files outside the operator-owned local directories: any would be a hidden effect."""
        found = []
        for path in self.tmp.rglob("*"):
            relative = path.relative_to(self.tmp)
            if path.is_file() and relative.parts[0] not in LOCAL_DIRECTORIES:
                found.append(str(relative))
        return sorted(found)


@dataclass
class RoundtripOutcome:
    result: str
    model_calls: int
    consumer_side_effects: int
    network_attempts: int
    remote_submits: int
    evidence: list[str]


def execute_roundtrip(ledger: Ledger, tmp: Path, mp: pytest.MonkeyPatch) -> RoundtripOutcome:
    network = watch_network(mp)
    trap = trap_imports(mp)
    flow = Flow(ledger, tmp, mp)
    source, ref = flow.finish_to_release()
    # Building is private and local: nothing is published, activated or imported yet.
    assert flow.rows("publications") == flow.rows("active_releases") == 0
    unimported = flow.read_span(ref.digest, flow.span(source, 0, 9))
    assert unimported.exit != 0 and "Synthetic" not in unimported.raw  # not locally verified yet
    flow.pin_release(ref)
    flow.allow_import(ref)
    imported = flow.import_release(ref)
    assert imported.exit == 0, imported.raw
    status = imported.payload["receipt"]["status"]
    slice_path = tmp / "slice.txt"
    read = flow.read_span(ref.digest, flow.span(source, 0, 9), slice_path)
    assert read.exit == 0 and slice_path.read_bytes() == b"Synthetic"
    assert read.payload["independentlyVerified"] is False  # a slice alone is not proof
    flow.env.assert_redacted(read)
    # The partition runs over the same ledger: it observes the selection and submits nothing.
    submits = flow.dagster_pass()
    consumer = sum(flow.rows(table) for table in CONSUMER_TABLES)
    consumer += len([name for name in flow.stray_files() if name != "slice.txt"])
    return RoundtripOutcome(
        result=status,
        model_calls=len(trap.attempts),
        consumer_side_effects=consumer,
        network_attempts=len(network.attempts),
        remote_submits=submits,
        evidence=[
            "cli:prepare-run>authorize-run>dispatch>reconcile>review>build-release>import-release>"
            "read-span",
            f"ledger:attempts={flow.rows('attempts')}",
            f"ledger:operation_results={flow.rows('operation_results')}",
            "dagster:partition_resubmits=0",
        ],
    )


@pytest.mark.database
def test_f1_offline_roundtrip(
    ledger: Ledger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outcome = execute_roundtrip(ledger, tmp_path, monkeypatch)
    result = outcome.result
    model_calls = outcome.model_calls
    consumer_side_effects = outcome.consumer_side_effects
    assert result == "local_verified"
    assert model_calls == 0
    assert consumer_side_effects == 0
    assert outcome.network_attempts == 0
    assert outcome.remote_submits == 1  # one fake submit in the whole flow, Dagster added none
    emit(
        AcceptanceReport(
            "F1-offline-roundtrip", ("U1-U7", "A01-A12"), "pass", tuple(outcome.evidence)
        )
    )


@pytest.mark.database
def test_guards_record_the_escapes_they_claim_to_catch(monkeypatch: pytest.MonkeyPatch) -> None:
    network = watch_network(monkeypatch)
    trap = trap_imports(monkeypatch)
    with pytest.raises(ImportError):
        importlib.import_module("laya.model")
    assert trap.attempts == ["laya"]
    with pytest.raises(RuntimeError):  # the suite-wide denial still refuses
        socket.create_connection(("192.0.2.1", 9))
    with pytest.raises(RuntimeError):
        socket.getaddrinfo("example.invalid", 80)
    assert network.attempts == ["create_connection", "getaddrinfo"]
