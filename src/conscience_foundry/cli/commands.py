"""Explicit operator commands over the existing vertical flow; each is a thin ledger call.

A command runs only after (1) a private config names the operator and grants that exact command,
(2) the trusted adapters it needs are present, and (3) `--execute` is given for anything that
changes state or reaches outside the process. Without `--execute` a command is a dry run that
touches no database, store, adapter or network. Library gates (pause barriers, current policy,
reservations, approvals) run again inside each call; a request document can carry no authority,
so any actor or grant it names is only compared against the config and refused if it differs.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal, get_args

import psycopg
from pydantic import BeforeValidator, Field, TypeAdapter, ValidationError

from conscience_foundry.cli.config import (
    Runtime,
    TrustedServices,
    load_config,
    load_limits,
    read_input,
    read_trusted,
    resolve_dsn,
)
from conscience_foundry.contracts.admission import IntakeManifest
from conscience_foundry.contracts.canonical import DocumentSpan, RevisionReview
from conscience_foundry.contracts.common import (
    ArtifactLocation,
    ContractError,
    Digest,
    ErrorCode,
    Id,
    Reason,
    Ref,
    WireModel,
)
from conscience_foundry.contracts.execution import ExecutionPlan, RunAuthorization, StageAttempt
from conscience_foundry.contracts.project import PolicyArtifact, ProfileDescriptor, ProjectConfig
from conscience_foundry.contracts.registry import (
    SCHEMA_MODELS,
    ContractSet,
    technical_metadata_binding,
)
from conscience_foundry.contracts.release import (
    ActivationRecord,
    PublicationRecord,
    ReleaseSource,
)
from conscience_foundry.execution.control import (
    cancel_attempt,
    dispatch,
    reconcile,
    set_pause,
)
from conscience_foundry.execution.evidence import (
    admission_evidence,
    budget_context,
    current_policy,
    encoded,
    read_model,
    source_asset,
)
from conscience_foundry.execution.ports import ManualRetry, TransportGrants
from conscience_foundry.ledger.attempts import load_attempt
from conscience_foundry.ledger.budget import install_run_authorization
from conscience_foundry.ledger.db import (
    AdmissionRegistrationEvidence,
    PauseState,
    register_admission,
)
from conscience_foundry.release.build import build_release, record_review
from conscience_foundry.release.importer import import_release
from conscience_foundry.release.publication import activate, append_publication
from conscience_foundry.release.read import resolve_span
from conscience_foundry.storage.custody import inspect_intake

Status = Literal["ok", "dry_run", "blocked", "failed"]

BLOCKED_CODES = frozenset(
    {
        "config_required",
        "config_invalid",
        "config_insecure",
        "config_in_repository",
        "credential_unavailable",
        "credential_invalid",
        "grant_missing",
        "adapter_unavailable",
        "pin_missing",
        "paused",
        "forbidden",
        "permission_unknown",
        "budget_unconfigured",
        "budget_exhausted",
        "authorization_expired",
        "dispatch_unknown",
        "activation_conflict",
        "unsupported_capability",
        "unsupported_schema",
        "limits_missing",
        "admission_blocked",
    }
)
"""Deliberate refusals; anything else is a failure of the work itself."""
UNSETTLED_STATES = frozenset({"failed", "unknown_outcome"})


@dataclass(frozen=True)
class Outcome:
    status: Status
    code: str | None = None
    data: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class Invocation:
    args: argparse.Namespace
    runtime: Runtime | None

    @property
    def rt(self) -> Runtime:
        assert self.runtime is not None
        return self.runtime


@dataclass(frozen=True)
class Command:
    name: str
    summary: str
    arguments: Callable[[argparse.ArgumentParser], None]
    handler: Callable[[Invocation], Outcome]
    needs: tuple[str, ...] = ()
    effect: bool = True
    stateful: bool = True


# --- request-file helpers -------------------------------------------------------------------


def _ok(**data: object) -> Outcome:
    return Outcome("ok", None, data)


def _dump(value: WireModel) -> dict[str, Any]:
    return value.model_dump(mode="json", by_alias=True, exclude_none=True)


def _id(value: object) -> Id:
    try:
        return TypeAdapter(Id).validate_python(value)
    except ValidationError:
        raise ContractError("invalid_schema") from None


def _digest(value: object) -> Digest:
    try:
        return TypeAdapter(Digest).validate_python(value)
    except ValidationError:
        raise ContractError("invalid_schema") from None


def _document[Model: WireModel](
    rt: Runtime, path: str, model: type[Model], schema: str
) -> tuple[bytes, Model]:
    bound = rt.limit(schema)
    data = read_input(path, bound.max_json_bytes)
    return data, model.from_wire(data, bound)


def _ref_file(rt: Runtime, path: str) -> Ref:
    return _document(rt, path, Ref, "kf.artifact-ref.v1")[1]


def _ref(rt: Runtime, data: bytes, schema: str) -> Ref:
    return Ref(
        schema_version="kf.artifact-ref.v1",
        project_id=rt.config.project_id,
        digest=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        media_type="application/json",
        artifact_schema=schema,
        locations=(),
    )


def _install(rt: Runtime, data: bytes, ref: Ref) -> Ref:
    return rt.store.put_verified(io.BytesIO(data), ref, rt.access)


def _require_operator(rt: Runtime, project_id: str, actor_id: str | None) -> None:
    """A record's own actor/project fields are claims; only the config's operator counts."""
    if project_id != rt.config.project_id:
        raise ContractError("forbidden")
    if actor_id is not None and actor_id != rt.config.operator.actor_id:
        raise ContractError("forbidden")


def _attempt(rt: Runtime, attempt_id: Id) -> StageAttempt:
    control = rt.control
    with rt.ledger.transaction() as tx:
        reference, _, _, _ = load_attempt(tx, rt.config.project_id, attempt_id)
    return read_model(reference, StageAttempt, control)[1]


def _attempt_outcome(attempt: StageAttempt, **extra: object) -> Outcome:
    data = {"attempt": _dump(attempt), **extra}
    if attempt.state in UNSETTLED_STATES:
        # A failure or an unknown outcome is never success; funds stay held until reconciled.
        return Outcome("failed", attempt.state, data)
    return Outcome("ok", None, data)


def _pause_data(state: PauseState) -> dict[str, object]:
    return {
        "scope": state.scope,
        "projectId": state.project_id,
        "runId": state.run_id,
        "paused": state.paused,
        "version": state.version,
    }


# --- validate ---------------------------------------------------------------------------------


def _validate_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--schema", required=True, help="registered JSON schema id")
    parser.add_argument("--input", required=True, help="document to check")
    parser.add_argument("--limits", required=True, help="operator limits-by-schema file")


def _validate(inv: Invocation) -> Outcome:
    args = inv.args
    model = SCHEMA_MODELS.get(args.schema)
    if model is None:
        raise ContractError("unsupported_schema")
    bound = load_limits(args.limits).get(args.schema)
    if bound is None:
        raise ContractError("limits_missing")
    data = read_input(args.input, bound.max_json_bytes)
    model.from_wire(data, bound)
    return _ok(
        schema=args.schema, valid=True, digest=hashlib.sha256(data).hexdigest(), sizeBytes=len(data)
    )


# --- admit / prepare-run / authorize-run -------------------------------------------------------


def _admit_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--manifest", required=True, help="intake manifest document")


def _admit(inv: Invocation) -> Outcome:
    rt, args = inv.rt, inv.args
    settings = rt.config.admission
    if settings is None:
        raise ContractError("config_invalid")
    manifest_bound = rt.limit("kf.intake.v1")
    manifest_bytes = read_input(args.manifest, manifest_bound.max_json_bytes)
    manifest = IntakeManifest.from_wire(manifest_bytes, manifest_bound)
    project = ProjectConfig.from_wire(
        read_trusted(settings.project_config_path, rt.limit("kf.project.v1").max_json_bytes),
        rt.limit("kf.project.v1"),
    )
    profile = ProfileDescriptor.from_wire(
        read_trusted(settings.profile_path, rt.limit("kf.profile.v1").max_json_bytes),
        rt.limit("kf.profile.v1"),
    )
    bundle = ContractSet.from_wire(
        read_trusted(settings.contract_set_path, rt.limit("kf.contract-set.v1").max_json_bytes),
        rt.limit("kf.contract-set.v1"),
    )
    binding = technical_metadata_binding(
        bundle, project_id=rt.config.project_id, limits_by_schema=rt.limits
    )
    policy_bytes = rt.read_policy_bytes()
    policy = PolicyArtifact.from_wire(policy_bytes, rt.limit("kf.policy.v1"))
    store = rt.store
    report = inspect_intake(
        manifest,
        project,
        policy,
        rt.access,
        store,
        manifest_bytes=manifest_bytes,
        policy_bytes=policy_bytes,
        profile=profile,
        metadata_binding=binding,
        input_roots={root.root_id: Path(root.path) for root in settings.input_roots},
        limits_by_schema=rt.limits,
        checked_at=rt.clock(),
    )
    report_bytes = report.model_dump_json(by_alias=True).encode("utf-8")
    manifest_ref = _ref(rt, manifest_bytes, "kf.intake.v1")
    report_ref = _ref(rt, report_bytes, "kf.admission-report.v1")
    _install(rt, manifest_bytes, manifest_ref)
    _install(rt, report_bytes, report_ref)
    _install(rt, policy_bytes, manifest.policy_ref)
    with rt.ledger.transaction() as tx:
        register_admission(
            manifest_ref,
            report,
            report_ref,
            tx,
            evidence=AdmissionRegistrationEvidence(
                manifest_bytes=manifest_bytes,
                report_bytes=report_bytes,
                policy_bytes=policy_bytes,
                pinned_policy=policy,
                limits_by_schema=rt.limits,
            ),
        )
    entries = [
        {
            "assetId": entry.asset_id,
            "status": entry.status,
            "reasonCodes": [reason.code for reason in entry.reasons],
        }
        for entry in report.entries
    ]
    data = {
        "registered": True,
        "manifestRef": _dump(manifest_ref),
        "reportRef": _dump(report_ref),
        "entries": entries,
    }
    if any(entry.status != "admitted" for entry in report.entries):
        # The report preserves every row; an operator must see that not everything was admitted.
        return Outcome("blocked", "admission_blocked", data)
    return Outcome("ok", None, data)


def _prepare_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--plan", required=True, help="execution plan document")


def _prepare_run(inv: Invocation) -> Outcome:
    rt, args = inv.rt, inv.args
    data, plan = _document(rt, args.plan, ExecutionPlan, "kf.execution-plan.v1")
    _require_operator(rt, plan.project_id, None)
    ref = _ref(rt, data, "kf.execution-plan.v1")
    control = rt.control
    _install(rt, data, ref)
    with rt.ledger.transaction() as tx:
        # Only an already registered admission report can open a run; this refuses otherwise.
        tx.create_run(plan.project_id, plan.run_id, plan.admission_report_ref.digest)
        _, manifest, report = admission_evidence(plan, tx, control)
        source_asset(plan, manifest, report, control)
    return _ok(
        planRef=_dump(ref),
        runId=plan.run_id,
        admissionReportDigest=plan.admission_report_ref.digest,
    )


def _authorize_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--authorization", required=True, help="run authorization document")
    parser.add_argument("--previous-authorization-id", help="authorization this one replaces")


def _authorize_run(inv: Invocation) -> Outcome:
    rt, args = inv.rt, inv.args
    data, auth = _document(rt, args.authorization, RunAuthorization, "kf.run-authorization.v1")
    # The document's actor is a claim. It must be the configured operator before anything else.
    _require_operator(rt, auth.project_id, auth.actor_id)
    previous = _id(args.previous_authorization_id) if args.previous_authorization_id else None
    ref = _ref(rt, data, "kf.run-authorization.v1")
    control = rt.control
    _install(rt, data, ref)
    with rt.ledger.transaction() as tx:
        install_run_authorization(
            auth,
            ref,
            data,
            tx,
            context=budget_context(control, tx=tx),
            expected_previous_authorization_id=previous,
        )
    return _ok(
        authorizationRef=_dump(ref), authorizationId=auth.authorization_id, runId=auth.run_id
    )


# --- dispatch / reconcile / cancel / pause / resume -------------------------------------------


class ManualRetryRequest(WireModel):
    schema_version: Literal["cfoundry.manual-retry.v1"]
    evidence_ref: Ref
    expected_snapshot_digest: Digest
    unresolved_attempt_ids: Annotated[
        tuple[Id, ...], BeforeValidator(lambda v: tuple(v) if isinstance(v, list) else v)
    ] = Field(min_length=1)


def _dispatch_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--plan-ref", required=True, help="artifact reference of the plan")
    parser.add_argument("--authorization-ref", required=True, help="reference of the run grant")
    parser.add_argument("--evidence-ref", required=True, help="reference of the estimate evidence")
    parser.add_argument("--asset-id", required=True)
    parser.add_argument("--manual-retry", help="duplicate-charge-risk retry request document")


def _dispatch(inv: Invocation) -> Outcome:
    rt, args = inv.rt, inv.args
    services = rt.services
    executor, transport = services.executor, services.transport_grants
    if executor is None or transport is None:
        raise ContractError("adapter_unavailable")
    control = rt.control
    plan_ref = _ref_file(rt, args.plan_ref)
    authorization_ref = _ref_file(rt, args.authorization_ref)
    evidence_ref = _ref_file(rt, args.evidence_ref)
    asset_id = _id(args.asset_id)
    retry = None
    if args.manual_retry:
        request = _document(rt, args.manual_retry, ManualRetryRequest, "kf.artifact-ref.v1")[1]
        retry = ManualRetry(
            request.evidence_ref,
            request.expected_snapshot_digest,
            tuple(request.unresolved_attempt_ids),
        )
    _, plan = read_model(plan_ref, ExecutionPlan, control)
    _, authorization = read_model(authorization_ref, RunAuthorization, control)
    _require_operator(rt, plan.project_id, authorization.actor_id)
    # Effect boundary: transport scope is minted outside the ledger, so the current policy and
    # the durable pause barriers are read first. The ledger repeats every gate inside dispatch.
    current_policy(control, plan.project_id)
    with rt.ledger.transaction() as tx:
        tx.lock(plan.project_id, plan.run_id)
        if (
            tx.get_pause("project", plan.project_id, None).paused
            or tx.get_pause("run", plan.project_id, plan.run_id).paused
        ):
            raise ContractError("paused")
    grants = transport(plan, plan_ref)
    if type(grants) is not TransportGrants:
        raise ContractError("forbidden")
    attempt = dispatch(
        plan,
        authorization,
        rt.access,
        rt.ledger,
        executor,
        grants,
        control=control,
        plan_ref=plan_ref,
        authorization_ref=authorization_ref,
        asset_id=asset_id,
        evidence_ref=evidence_ref,
        manual_retry=retry,
    )
    return _attempt_outcome(attempt)


def _attempt_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--attempt-id", required=True)


def _reconcile(inv: Invocation) -> Outcome:
    rt, args = inv.rt, inv.args
    executor = rt.services.executor
    if executor is None:
        raise ContractError("adapter_unavailable")
    attempt_id = _id(args.attempt_id)
    selected = reconcile(attempt_id, rt.ledger, executor, rt.store, control=rt.control)
    return _attempt_outcome(
        _attempt(rt, attempt_id), selection=_dump(selected) if selected is not None else None
    )


def _reason_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--reason-code", required=True, choices=get_args(ErrorCode))
    parser.add_argument("--reason-message", required=True)
    parser.add_argument("--evidence-ref", required=True, help="reference of operator evidence")


def _cancel_arguments(parser: argparse.ArgumentParser) -> None:
    _attempt_argument(parser)
    _reason_arguments(parser)


def _cancel(inv: Invocation) -> Outcome:
    rt, args = inv.rt, inv.args
    executor = rt.services.executor
    if executor is None:
        raise ContractError("adapter_unavailable")
    attempt_id = _id(args.attempt_id)
    attempt = cancel_attempt(
        attempt_id,
        rt.ledger,
        executor,
        control=rt.control,
        reason=Reason(code=args.reason_code, message=args.reason_message),
        evidence_ref=_ref_file(rt, args.evidence_ref),
    )
    return _attempt_outcome(attempt)


def _pause_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--scope", required=True, choices=("project", "run"))
    parser.add_argument("--run-id", help="required for run scope")
    parser.add_argument("--expected-version", required=True, type=_version)
    _reason_arguments(parser)


def _version(value: str) -> int:
    if not value.isdigit() or len(value) > 15:
        raise argparse.ArgumentTypeError("invalid")
    return int(value)


def _set_pause(inv: Invocation, paused: bool) -> Outcome:
    rt, args = inv.rt, inv.args
    if (args.scope == "run") != (args.run_id is not None):
        raise ContractError("invalid_schema")
    run_id = _id(args.run_id) if args.run_id is not None else None
    state = set_pause(
        args.scope,
        rt.config.project_id,
        run_id,
        paused,
        args.expected_version,
        rt.access,
        rt.ledger,
        control=rt.control,
        reason=Reason(code=args.reason_code, message=args.reason_message),
        evidence_ref=_ref_file(rt, args.evidence_ref),
    )
    return _ok(pause=_pause_data(state))


def _pause(inv: Invocation) -> Outcome:
    return _set_pause(inv, True)


def _resume(inv: Invocation) -> Outcome:
    return _set_pause(inv, False)


# --- review / release -------------------------------------------------------------------------


def _review_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--review", required=True, help="revision review document")
    parser.add_argument("--operation-key", required=True)
    parser.add_argument("--revision-ref", required=True)
    parser.add_argument("--evidence-ref", required=True)


def _review(inv: Invocation) -> Outcome:
    rt, args = inv.rt, inv.args
    data, review = _document(rt, args.review, RevisionReview, "kf.revision-review.v1")
    _require_operator(rt, review.project_id, review.actor_id)
    ref = record_review(
        review,
        rt.access,
        rt.ledger,
        rt.store,
        release=rt.release,
        operation_key=_digest(args.operation_key),
        revision_ref=_ref_file(rt, args.revision_ref),
        review_bytes=data,
        evidence_ref=_ref_file(rt, args.evidence_ref),
    )
    return _ok(reviewRef=_dump(ref), decision=review.decision)


class ReleaseSelection(WireModel):
    schema_version: Literal["cfoundry.release-selection.v1"]
    sources: Annotated[
        tuple[ReleaseSource, ...], BeforeValidator(lambda v: tuple(v) if isinstance(v, list) else v)
    ] = Field(min_length=1)
    admission_report_refs: Annotated[
        tuple[Ref, ...], BeforeValidator(lambda v: tuple(v) if isinstance(v, list) else v)
    ] = Field(min_length=1)


def _build_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--selection", required=True, help="selected reviewed sources document")


def _build_release(inv: Invocation) -> Outcome:
    rt, args = inv.rt, inv.args
    _, selection = _document(rt, args.selection, ReleaseSelection, "kf.library-release.v1")
    candidate = build_release(
        tuple(selection.sources),
        tuple(selection.admission_report_refs),
        rt.access,
        rt.ledger,
        rt.store,
        release=rt.release,
    )
    raw = encoded(candidate)
    digest = hashlib.sha256(raw).hexdigest()
    reference = Ref(
        schema_version="kf.artifact-ref.v1",
        project_id=rt.config.project_id,
        digest=digest,
        size_bytes=len(raw),
        media_type="application/json",
        artifact_schema="kf.library-release.v1",
        locations=(
            ArtifactLocation(
                store_id=rt.config.object_store.store_id,
                object_key=f"sha256/{digest[:2]}/{digest}",
            ),
        ),
    )
    return _ok(
        releaseRef=_dump(reference),
        releaseDigest=digest,
        releaseId=candidate.release_id,
        sourceCount=len(candidate.source_entries),
        published=False,
    )


def _import_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--release-ref", required=True, help="artifact reference of the release")


def _import_release(inv: Invocation) -> Outcome:
    rt, args = inv.rt, inv.args
    release_ref = _ref_file(rt, args.release_ref)
    receipt = import_release(
        release_ref,
        rt.access,
        rt.ledger,
        rt.store,
        release=rt.release,
        pin=rt.pin(release_ref.digest),
    )
    return _ok(receipt=_dump(receipt), published=False)


def _record_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--record", required=True, help="lifecycle record document")


def _publish(inv: Invocation) -> Outcome:
    rt, args = inv.rt, inv.args
    _, record = _document(rt, args.record, PublicationRecord, "kf.publication-record.v1")
    _require_operator(rt, record.project_id, record.actor_id)
    try:
        pin = rt.pin(record.release_digest)
    except ContractError:
        pin = None  # only the validated stage needs one; the ledger refuses without it
    append_publication(record, rt.access, rt.ledger, release=rt.release, pin=pin)
    return _ok(eventId=record.event_id, stage=record.stage, releaseDigest=record.release_digest)


def _activate(inv: Invocation) -> Outcome:
    rt, args = inv.rt, inv.args
    _, record = _document(rt, args.record, ActivationRecord, "kf.activation.v1")
    _require_operator(rt, record.project_id, record.actor_id)
    activate(record, rt.access, rt.ledger, release=rt.release)
    return _ok(activeReleaseDigest=record.next_release_digest)


def _span_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--release-digest", required=True)
    parser.add_argument("--span", required=True, help="document span document")
    parser.add_argument("--output", help="new private file for the slice text; never printed")


def _read_span(inv: Invocation) -> Outcome:
    rt, args = inv.rt, inv.args
    digest = _digest(args.release_digest)
    _, span = _document(rt, args.span, DocumentSpan, "kf.document-span.v1")
    resolved = resolve_span(
        rt.access, digest, span, rt.ledger, rt.store, release=rt.release, pin=rt.pin(digest)
    )
    written = False
    if args.output:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(args.output, flags, 0o600)
        except OSError:
            raise ContractError("unavailable") from None
        with os.fdopen(fd, "wb") as handle:
            handle.write(resolved.text.encode("utf-8"))
        written = True
    return _ok(
        revisionId=resolved.revision_id,
        textDigest=resolved.text_digest,
        span=_dump(span),
        scalars=len(resolved.text),
        textWritten=written,
        independentlyVerified=False,
    )


# --- registry and dispatch --------------------------------------------------------------------

DATABASE = "database"
EVIDENCE = "evidence_authority"
RELEASE_AUTHORITY = "release_authority"
EXECUTOR = "executor"
TRANSPORT = "transport_grants"

COMMANDS: tuple[Command, ...] = (
    Command(
        "validate",
        "check a document against a registered schema",
        _validate_arguments,
        _validate,
        effect=False,
        stateful=False,
    ),
    Command(
        "admit",
        "snapshot and register an intake manifest's admission report",
        _admit_arguments,
        _admit,
        (DATABASE,),
    ),
    Command(
        "prepare-run",
        "open a run for a registered admission and an exact plan",
        _prepare_arguments,
        _prepare_run,
        (DATABASE,),
    ),
    Command(
        "authorize-run",
        "install an exact run authorization for the configured operator",
        _authorize_arguments,
        _authorize_run,
        (DATABASE, EVIDENCE),
    ),
    Command(
        "dispatch",
        "claim and submit one attempt through the ledger",
        _dispatch_arguments,
        _dispatch,
        (DATABASE, EVIDENCE, EXECUTOR, TRANSPORT),
    ),
    Command(
        "reconcile",
        "observe an existing attempt; never submits",
        _attempt_argument,
        _reconcile,
        (DATABASE, EVIDENCE, EXECUTOR),
    ),
    Command(
        "cancel",
        "request cancellation of an attempt",
        _cancel_arguments,
        _cancel,
        (DATABASE, EVIDENCE, EXECUTOR),
    ),
    Command("pause", "set a durable pause barrier", _pause_arguments, _pause, (DATABASE, EVIDENCE)),
    Command(
        "resume", "clear a durable pause barrier", _pause_arguments, _resume, (DATABASE, EVIDENCE)
    ),
    Command(
        "review",
        "record an operator review of a revision",
        _review_arguments,
        _review,
        (DATABASE, RELEASE_AUTHORITY),
    ),
    Command(
        "build-release",
        "assemble a private release candidate",
        _build_arguments,
        _build_release,
        (DATABASE, RELEASE_AUTHORITY),
    ),
    Command(
        "import-release",
        "verify a pinned release locally",
        _import_arguments,
        _import_release,
        (DATABASE, RELEASE_AUTHORITY),
    ),
    Command(
        "publish",
        "append one publication lifecycle event",
        _record_argument,
        _publish,
        (DATABASE, RELEASE_AUTHORITY),
    ),
    Command(
        "activate",
        "move the active release pointer",
        _record_argument,
        _activate,
        (DATABASE, RELEASE_AUTHORITY),
    ),
    Command(
        "read-span",
        "read one exact slice from a pinned, locally verified release",
        _span_arguments,
        _read_span,
        (DATABASE,),
        effect=False,
    ),
)
BY_NAME: Mapping[str, Command] = {command.name: command for command in COMMANDS}


def classify(error: ContractError) -> Outcome:
    return Outcome("blocked" if error.code in BLOCKED_CODES else "failed", error.code)


def _preflight(runtime: Runtime, command: Command) -> list[tuple[str, str]]:
    blockers: list[tuple[str, str]] = []
    for need in command.needs:
        if need == DATABASE:
            try:
                resolve_dsn(runtime.config.ledger)
            except ContractError as error:
                blockers.append(("database_credential", error.code))
        elif getattr(runtime.services, need) is None:
            blockers.append((need, "adapter_unavailable"))
    return blockers


def run_command(command: Command, args: argparse.Namespace, services: TrustedServices) -> Outcome:
    """Gate, then execute one command; every failure becomes a stable, redacted code."""
    try:
        if not command.stateful:
            return with_flag(command.handler(Invocation(args, None)), executed=True)
        if args.config is None:
            return Outcome("blocked", "config_required", {"executed": False})
        config = load_config(args.config)
        if not config.operator.grants.allows(command.name):
            return Outcome("blocked", "grant_missing", {"executed": False})
        runtime = Runtime(config, services, command.name)
        try:
            blockers = _preflight(runtime, command)
            if blockers:
                return Outcome(
                    "blocked",
                    blockers[0][1],
                    {"executed": False, "blockers": [name for name, _ in blockers]},
                )
            if command.effect and not args.execute:
                return Outcome("dry_run", None, {"executed": False, "blockers": []})
            return with_flag(command.handler(Invocation(args, runtime)), executed=True)
        finally:
            runtime.close()
    except ContractError as error:
        return classify(error)
    except psycopg.Error:
        return Outcome("failed", "unavailable")
    except Exception:
        return Outcome("failed", "internal_error")


def with_flag(outcome: Outcome, *, executed: bool) -> Outcome:
    return Outcome(outcome.status, outcome.code, {**outcome.data, "executed": executed})
