"""`preflight` and `run-pilot`: dry live-acceptance preparation and its separately granted run.

``preflight`` is a pure local check of an operator packet and its evidence files: it reads files,
touches no database, store, adapter or network, and a ready report only says the packet is
internally consistent. It never starts anything.

``run-pilot`` orchestrates only the existing CLI commands, and only when all of these hold:

* the operator config grants ``run-pilot`` (its own grant category), as for every command;
* ``--execute`` is given (otherwise the generic dry run stops before this module is reached);
* a fresh preflight of the exact packet is ready, with every blocking gate closed by trusted
  deployment code, which is attested from the runtime wiring (``attested_gates``; nothing in a
  file can close one);
* a separately recorded ``LiveGrant`` names this exact packet digest, this actor, a live window,
  and exactly the ordered commands in the steps document.

Four steps have their documents checked against that preflighted packet before anything runs:
``prepare-run`` must name the packet's pinned plan (``planDigest``); ``authorize-run`` must name a
RunAuthorization for that plan and run, within the packet's cap, actor and expiry;
``reserve-storage`` must name that plan's run and the packet's reviewed estimate (``estimateRef``)
as its evidence; ``dispatch`` must name that same plan, that same authorization (it must have been
authorized earlier in this pilot) and the reviewed estimate as its evidence reference. The other
steps' arguments are not inspected here: the asset is bound through the plan's ``operation_key``,
and ``backup`` and ``reconcile`` take only what their own commands and gates accept. The
reconcile step's ``--attempt-id`` may be the literal ``@dispatch``, accepted only after a dispatch
step, and replaced by the attempt id that dispatch step returned. These check reads and each
command's later read of the same operator-owned step files happen separately, by path; the files
are not locked or pinned between them, so they belong in the operator's private directory and a
file edited in between is not detected here; the authorization bytes are pinned by digest, so a
changed authorization file is refused by the evidence authority.

With a live config section (``cli.live``) the pilot holds the live runtime: the evidence authority
approves only the authorization checked here, and one Modal session is opened before the first
dispatch or reconcile step and exited after the last one, on every exit. A Ctrl-C inside those
steps is handled by the step itself while the session is open (the attempt is cancelled through
the ledger, or marked ``unknown_outcome``); ``run-pilot`` then only exits the app and reports
``interrupted`` (exit 130). Every report states the residual risks (``residual_risks``).

Each step is then run through the same gated ``run_command`` with ``--execute``, so every library
gate, config grant and adapter requirement of that command still applies. Manual retry and a second
dispatch are refused here. The first step that is not ``ok`` halts the pilot. Completing the steps
is never reported as acceptance: that needs independent verification this command does not claim.

A grant is single use. Before the first step a marker for its ``grantId`` is created exclusively
(``O_EXCL``, fsynced) in ``pilot-used-grants/`` beside the operator config file, which must be
private to the operator. A rerun of the same grant is refused, even after a halted or failed pilot,
so a second paid attempt always needs a newly recorded grant (no paid automatic retry). The grant
window and the packet expiry are re-checked before every step. The cost estimate covers one
attempt plus run storage; it does not cover ``maxAttemptsPerOperation`` above 1.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from collections.abc import Callable
from contextlib import ExitStack
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any, Literal, NoReturn

from pydantic import BeforeValidator, Field

from conscience_foundry.cli import live
from conscience_foundry.cli.commands import (
    BY_NAME,
    Command,
    Invocation,
    Outcome,
    Status,
    classify,
    run_command,
)
from conscience_foundry.cli.config import (
    CONFIG_MAX_BYTES,
    TrustedServices,
    _bootstrap,
    read_trusted,
)
from conscience_foundry.cli.live import RESIDUAL_RISKS
from conscience_foundry.contracts.common import ContractError, Id, Ref, ScalarString, WireModel
from conscience_foundry.contracts.execution import ExecutionPlan, RunAuthorization
from conscience_foundry.operator.packet import (
    PILOT_STEP_COMMANDS,
    SCOPED_EXECUTOR_STORE,
    STAGING_STORE_TRANSFER,
    LiveGrant,
    PreflightEvidence,
    PreflightPacket,
    PreflightReport,
    live_grant_blockers,
    packet_digest,
    preflight,
)
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.staging_s3 import readable_refs

__all__ = ["PILOT_COMMANDS", "USED_GRANTS", "attested_gates", "run_command"]

BLOCKED = "preflight_blocked"
ATTEMPT_TOKEN = "@dispatch"
"""A reconcile step's ``--attempt-id`` that stands for the attempt an earlier dispatch returned."""
SESSION_STEPS = frozenset({"dispatch", "reconcile"})
"""The steps that run while the live session is open."""
USED_GRANTS = "pilot-used-grants"
"""Directory, beside the trusted operator config file, holding one marker per consumed grant."""


def _array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class PilotStep(WireModel):
    command: Annotated[ScalarString, Field(min_length=1)]
    argv: Annotated[tuple[ScalarString, ...], BeforeValidator(_array)]


class PilotSteps(WireModel):
    schema_version: Literal["cfoundry.pilot-steps.v1"]
    steps: Annotated[tuple[PilotStep, ...], BeforeValidator(_array), Field(min_length=1)]


class _StepParser(argparse.ArgumentParser):
    """A step's own argument parser: any problem is a refusal; nothing is echoed or exits."""

    def error(self, message: str) -> NoReturn:
        raise ContractError("invalid_schema")

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        raise ContractError("invalid_schema")


# -- gate attestation ---------------------------------------------------------------------------

_PROBE_ATTEMPTS = (
    "00000000-0000-0000-0000-00000000a001",
    "00000000-0000-0000-0000-00000000a002",
)
"""Two synthetic attempt ids: a reader or issuer fixed to one attempt fails the other probe."""
_PROBE_TIME = "2999-01-01T00:00:00.000Z"


def _probe_ref(project_id: Id, label: str) -> dict[str, object]:
    data = f"cf.gate-probe.{label}".encode()
    return {
        "schemaVersion": "cf.artifact-ref.v1",
        "projectId": project_id,
        "digest": hashlib.sha256(data).hexdigest(),
        "sizeBytes": len(data),
        "mediaType": "application/json",
        "artifactSchema": f"cf.gate-probe.{label}.v1",
        "locations": [],
    }


def _probe_plan(project_id: Id) -> ExecutionPlan:
    """A synthetic, valid plan with every kind of readable object; it names nothing real."""
    return ExecutionPlan.model_validate(
        {
            "schemaVersion": "cf.execution-plan.v1",
            "projectId": project_id,
            "runId": "00000000-0000-0000-0000-00000000b001",
            "planId": "00000000-0000-0000-0000-00000000b002",
            "executionConfigRef": _probe_ref(project_id, "config"),
            "admissionReportRef": _probe_ref(project_id, "report"),
            "extractionSpecRef": _probe_ref(project_id, "spec"),
            "policyRef": _probe_ref(project_id, "policy"),
            "profileId": "gate_probe",
            "profileVersion": "gate-probe.v1",
            "contractSetRef": _probe_ref(project_id, "contracts"),
            "limitsRefs": [_probe_ref(project_id, "limits")],
            "inputRefs": [_probe_ref(project_id, "input")],
            "operationKey": hashlib.sha256(b"cf.gate-probe.operation").hexdigest(),
            "resources": {
                "cpuMilli": 1,
                "memoryMiB": 1,
                "gpuCount": 0,
                "maxWallSeconds": 1,
                "maxOutputBytes": 1,
                "maxConcurrentAttempts": 1,
                "maxAttemptsPerOperation": 1,
                "automaticRetries": 0,
            },
            "budget": {
                "currency": "USD",
                "maxRunCost": "1",
                "maxAttemptCost": "1",
                "tariffRef": _probe_ref(project_id, "tariff"),
                "authorizationId": "00000000-0000-0000-0000-00000000b003",
                "validUntil": _PROBE_TIME,
            },
            "expiresAt": _PROBE_TIME,
        }
    )


def _reader_is_scoped(reader_for: object, project_id: Id) -> bool:
    """True only when the factory returns, per probe, a reader bound to exactly that attempt."""
    if not callable(reader_for):
        return False
    for attempt_id in _PROBE_ATTEMPTS:
        scope = reader_for(project_id, attempt_id).scope
        if type(scope) is not tuple or scope != (project_id, attempt_id):
            return False
    return True


def _issuer_scopes_match(services: TrustedServices, project_id: Id) -> bool:
    """True only when the issuer would mint exactly the plan's read keys and the attempt prefix.

    The expected keys follow the staging layout (``{prefix}/{project}/sha256/{aa}/{digest}`` for
    reads, ``{prefix}/{project}/attempts/{attempt}/`` for writes); the prefix itself is taken from
    the issuer's write scope, which must end in exactly that attempt path.
    """
    scopes = services.issuer_scopes
    if not callable(scopes):
        return False
    plan = _probe_plan(project_id)
    for attempt_id in _PROBE_ATTEMPTS:
        reported = scopes(plan, attempt_id)
        if type(reported) is not tuple or len(reported) != 2:
            return False
        read_keys, write_prefix = reported
        tail = f"/{project_id}/attempts/{attempt_id}/"
        if (
            type(read_keys) is not frozenset
            or type(write_prefix) is not str
            or not write_prefix.endswith(tail)
            or len(write_prefix) == len(tail)
        ):
            return False
        base = write_prefix.removesuffix(tail)
        expected = frozenset(
            f"{base}/{ref.project_id}/sha256/{ref.digest[:2]}/{ref.digest}"
            for ref in readable_refs(plan)
        )
        if read_keys != expected:
            return False
    return True


def _holds(check: Callable[[], bool]) -> bool:
    """Any failure to establish the attestation leaves the gate open."""
    try:
        return check() is True
    except Exception:
        return False


def attested_gates(services: TrustedServices, project_id: Id) -> frozenset[str]:
    """The blocking gates the runtime wiring itself proves closed; a missing piece closes none.

    * ``staging_store_transfer``: the inputs can be staged (``stage_inputs``) and
      ``staged_reader`` returns, for a synthetic project and attempt, a reader scoped to exactly
      that pair (an unscoped or fixed-scope reader fails the probe);
    * ``executor_scoped_store``: the executor's ``reader_for`` passes the same probe and
      ``issuer_scopes`` reports exactly the probe plan's read keys and the attempt prefix.

    Nothing here comes from a file, a flag or the operator packet.
    """
    closed: set[str] = set()
    if (
        services.staged_reader is not None
        and services.stage_inputs is not None
        and _holds(lambda: _reader_is_scoped(services.staged_reader, project_id))
    ):
        closed.add(STAGING_STORE_TRANSFER)
    if (
        services.executor is not None
        and services.issuer_scopes is not None
        and _holds(lambda: _issuer_scopes_match(services, project_id))
        and _holds(
            lambda: _reader_is_scoped(getattr(services.executor, "reader_for", None), project_id)
        )
    ):
        closed.add(SCOPED_EXECUTOR_STORE)
    return frozenset(closed)


# -- loading ----------------------------------------------------------------------------------


def _read(path: str) -> bytes:
    """Operator-owned file: regular, not a link, owned by us and not writable by others."""
    return read_trusted(path, CONFIG_MAX_BYTES)


def _parse[Model: WireModel](model: type[Model], data: bytes) -> Model:
    return model.from_wire(data, _bootstrap(len(data)))


def _load_packet(args: argparse.Namespace) -> PreflightPacket:
    return _parse(PreflightPacket, _read(args.packet))


def _load_evidence(args: argparse.Namespace) -> PreflightEvidence:
    def optional(path: str | None) -> bytes | None:
        return _read(path) if path is not None else None

    return PreflightEvidence(
        manifest=optional(args.manifest),
        plan=optional(args.plan),
        capabilities=optional(args.capabilities),
        estimate=optional(args.estimate),
        backup=optional(args.backup_evidence),
    )


def _report_data(report: PreflightReport) -> dict[str, object]:
    return {
        "ready": report.ready,
        "packetDigest": report.packet_digest,
        "blockers": [{"code": r.code, "message": r.message} for r in report.blockers],
        "gates": [
            {"id": g.gate_id, "state": g.state, "blocking": g.blocking, "detail": g.detail}
            for g in report.gates
        ],
        "localChecks": report.local_checks,
        "providerCapability": report.provider_capability,
        "paidPilot": report.paid_pilot,
        "pilotStarted": False,
    }


def _check(inv: Invocation) -> tuple[PreflightPacket, PreflightEvidence, PreflightReport]:
    """One read of the packet and evidence: the same bytes are checked, bound and granted."""
    rt, args = inv.rt, inv.args
    packet, evidence = _load_packet(args), _load_evidence(args)
    report = preflight(
        packet,
        rt.access,
        evidence=evidence,
        now=rt.clock(),
        closed_gates=attested_gates(rt.services, rt.access.project_id),
    )
    return packet, evidence, report


# -- preflight --------------------------------------------------------------------------------


def _evidence_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--packet", required=True, help="operator preflight packet document")
    parser.add_argument("--manifest", help="intake manifest bytes the packet binds")
    parser.add_argument("--plan", help="canonical execution plan bytes the packet binds")
    parser.add_argument("--capabilities", help="capability record the packet binds")
    parser.add_argument("--estimate", help="reviewed cost estimate the packet binds")
    parser.add_argument("--backup-evidence", help="independent backup evidence the packet binds")


def _preflight(inv: Invocation) -> Outcome:
    _, _, report = _check(inv)
    data = _report_data(report)
    if report.ready:
        return Outcome("ok", None, data)
    return Outcome("blocked", BLOCKED, data)


# -- run-pilot --------------------------------------------------------------------------------


def _pilot_arguments(parser: argparse.ArgumentParser) -> None:
    _evidence_arguments(parser)
    parser.add_argument("--grant", help="separately recorded live grant for this exact packet")
    parser.add_argument("--steps", required=True, help="ordered pilot steps document")


def _forbidden() -> NoReturn:
    raise ContractError("forbidden")


def _same_ref(left: Ref, right: Ref) -> bool:
    return (
        left.project_id,
        left.artifact_schema,
        left.digest,
        left.size_bytes,
        left.media_type,
    ) == (right.project_id, right.artifact_schema, right.digest, right.size_bytes, right.media_type)


class _Binding:
    """Ties every step's documents to the preflighted packet; any other argument is refused."""

    def __init__(
        self, packet: PreflightPacket, evidence: PreflightEvidence, context: AccessContext
    ) -> None:
        if (
            packet.contract_limits is None
            or packet.estimate_ref is None
            or packet.max_run_usd is None
            or packet.expires_at is None
            or evidence.plan is None
        ):
            _forbidden()
        self.packet, self.context = packet, context
        self.limits = packet.contract_limits
        self.estimate_ref = packet.estimate_ref
        self.max_run = Decimal(packet.max_run_usd)
        self.expires_at = packet.expires_at
        self.plan = ExecutionPlan.from_wire(evidence.plan, self.limits)
        self.authorized: str | None = None

    def _read(self, path: str) -> bytes:
        return read_trusted(path, self.limits.max_json_bytes, missing="input_unreadable")

    def _ref(self, path: str) -> Ref:
        return Ref.from_wire(self._read(path), self.limits)

    def check(self, name: str, parsed: argparse.Namespace) -> None:
        packet = self.packet
        if name == "prepare-run":
            if hashlib.sha256(self._read(parsed.plan)).hexdigest() != packet.plan_digest:
                _forbidden()
        elif name == "authorize-run":
            data = self._read(parsed.authorization)
            auth = RunAuthorization.from_wire(data, self.limits)
            if (
                auth.project_id != packet.project_id
                or auth.project_id != self.context.project_id
                or auth.actor_id != self.context.actor_id
                or auth.run_id != self.plan.run_id
                or packet.plan_digest not in auth.allowed_plan_digests
                or Decimal(auth.max_run_cost) > self.max_run
                or auth.expires_at > self.expires_at
            ):
                _forbidden()
            self.authorized = hashlib.sha256(data).hexdigest()
        elif name == "reserve-storage":
            if parsed.run_id != self.plan.run_id or not _same_ref(
                self._ref(parsed.evidence), self.estimate_ref
            ):
                _forbidden()
        elif name == "dispatch":
            plan_ref = self._ref(parsed.plan_ref)
            if (
                self.authorized is None  # no earlier step of this pilot authorizes it
                or plan_ref.project_id != packet.project_id
                or plan_ref.digest != packet.plan_digest
                or self._ref(parsed.authorization_ref).digest != self.authorized
                or not _same_ref(self._ref(parsed.evidence_ref), self.estimate_ref)
            ):
                _forbidden()


def _planned_steps(
    document: PilotSteps, grant: LiveGrant, config: str | None, binding: _Binding
) -> list[tuple[Command, argparse.Namespace]]:
    names = tuple(step.command for step in document.steps)
    if names != tuple(grant.commands):
        raise ContractError("forbidden")  # the grant names exactly these commands, in order
    if any(name not in PILOT_STEP_COMMANDS or name not in BY_NAME for name in names):
        raise ContractError("forbidden")
    if names.count("dispatch") > 1:
        raise ContractError("forbidden")  # no second paid dispatch under one grant
    planned: list[tuple[Command, argparse.Namespace]] = []
    for step in document.steps:
        command = BY_NAME[step.command]
        parser = _StepParser(prog=command.name, add_help=False, allow_abbrev=False)
        command.arguments(parser)
        parsed = parser.parse_args(list(step.argv))
        if getattr(parsed, "manual_retry", None) is not None:
            raise ContractError("forbidden")  # duplicate-charge-risk retry is never granted here
        if getattr(parsed, "attempt_id", None) == ATTEMPT_TOKEN and (
            command.name != "reconcile" or "dispatch" not in names[: len(planned)]
        ):
            raise ContractError("forbidden")  # only an earlier dispatch can supply the attempt
        binding.check(command.name, parsed)
        parsed.command, parsed.config, parsed.execute = command.name, config, True
        planned.append((command, parsed))
    return planned


def _consume_grant(config: str | None, grant: LiveGrant, packet: PreflightPacket) -> None:
    """Durably mark the grant used, before any step; a second use is refused, not retried."""
    if config is None:
        raise ContractError("config_required")
    folder = Path(config).absolute().parent / USED_GRANTS
    try:
        os.mkdir(folder, 0o700)
    except FileExistsError:
        pass
    except OSError:
        raise ContractError("unavailable") from None
    try:
        information = os.lstat(folder)
    except OSError:
        raise ContractError("unavailable") from None
    if (
        not stat.S_ISDIR(information.st_mode)
        or information.st_uid != os.geteuid()
        or information.st_mode & 0o022
    ):
        raise ContractError("config_insecure")  # anyone able to delete a marker could replay it
    marker = folder / hashlib.sha256(grant.grant_id.encode()).hexdigest()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(marker, flags, 0o600)
    except FileExistsError:
        raise ContractError("forbidden") from None  # this grant was already used
    except OSError:
        raise ContractError("unavailable") from None
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(
                json.dumps(
                    {"grantId": grant.grant_id, "packetDigest": packet_digest(packet)}
                ).encode()
            )
            handle.flush()
            os.fsync(handle.fileno())
        directory = os.open(folder, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        raise ContractError("unavailable") from None


def _report(status: Status, code: str | None, data: dict[str, Any] | None = None) -> Outcome:
    """Every run-pilot report states what this runtime cannot recover or settle by itself."""
    return Outcome(status, code, {**(data or {}), "residual_risks": list(RESIDUAL_RISKS)})


def _run_pilot(inv: Invocation) -> Outcome:
    try:
        return _pilot(inv)
    except ContractError as error:
        refused = classify(error)
        return _report(refused.status, refused.code)


def _session_span(planned: list[tuple[Command, argparse.Namespace]]) -> tuple[int, int] | None:
    """The first and last step that run under the live session, if any does."""
    indexes = [i for i, (command, _) in enumerate(planned) if command.name in SESSION_STEPS]
    return (indexes[0], indexes[-1]) if indexes else None


def _pilot(inv: Invocation) -> Outcome:
    rt, args = inv.rt, inv.args
    packet, evidence, report = _check(inv)
    if not report.ready:
        return _report("blocked", BLOCKED, _report_data(report))
    if args.grant is None:
        raise ContractError("grant_missing")
    grant = _parse(LiveGrant, _read(args.grant))
    refused = live_grant_blockers(packet, report, grant, rt.access, rt.clock())
    if refused:
        return _report(
            "blocked",
            refused[0].code,
            {"blockers": [{"code": r.code, "message": r.message} for r in refused]},
        )
    binding = _Binding(packet, evidence, rt.access)
    planned = _planned_steps(_parse(PilotSteps, _read(args.steps)), grant, args.config, binding)
    # The live runtime is built from what was just verified, before the grant is spent.
    runtime = live.pilot(rt, packet, evidence, binding.plan, binding.authorized)
    _consume_grant(args.config, grant, packet)  # from here the grant is spent, whatever happens
    span = _session_span(planned) if runtime is not None else None
    results: list[dict[str, Any]] = []
    dispatched: str | None = None
    index = 0

    def halted(status: Status, code: str) -> Outcome:
        # Inner payloads are never echoed; a halted pilot is never partial success.
        return _report(
            status,
            code,
            {"steps": results, "haltedAt": index, "paidPilotAcceptance": "not_established"},
        )

    try:
        with ExitStack() as stack:
            for index, (command, parsed) in enumerate(planned):
                moment = rt.clock()
                if moment >= grant.expires_at or moment >= binding.expires_at:
                    return halted("blocked", "authorization_expired")
                services = rt.services
                if runtime is not None:
                    within = span is not None and span[0] <= index <= span[1]
                    if span is not None and index == span[0]:
                        try:
                            stack.enter_context(runtime.session)
                        except ContractError as error:
                            results.append(
                                {"command": command.name, "outcome": "blocked", "code": error.code}
                            )
                            return halted("blocked", error.code)
                    services = runtime.services(session_open=within)
                if getattr(parsed, "attempt_id", None) == ATTEMPT_TOKEN:
                    if dispatched is None:
                        return halted("blocked", "forbidden")
                    parsed = argparse.Namespace(**{**vars(parsed), "attempt_id": dispatched})
                outcome = run_command(command, parsed, services)
                if command.name == "dispatch":
                    dispatched = _dispatched_attempt(outcome)
                if span is not None and index == span[1]:
                    stack.close()  # the session ends with the last step that needs it
                entry: dict[str, Any] = {"command": command.name, "outcome": outcome.status}
                if outcome.code is not None:
                    entry["code"] = outcome.code
                results.append(entry)
                if outcome.status != "ok":
                    status = outcome.status if outcome.status in ("blocked", "failed") else "failed"
                    return halted(status, outcome.code or "internal_error")
    except KeyboardInterrupt:
        # The step already stopped its attempt while the session was open; the session has now
        # been exited by the stack. Nothing else is done here.
        results.append({"command": planned[index][0].name, "outcome": "interrupted"})
        return halted("interrupted", "interrupted")
    return _report("ok", None, {"steps": results, "paidPilotAcceptance": "not_established"})


def _dispatched_attempt(outcome: Outcome) -> str | None:
    attempt = outcome.data.get("attempt")
    found = attempt.get("attemptId") if isinstance(attempt, dict) else None
    return found if type(found) is str and found else None


PILOT_COMMANDS: tuple[Command, ...] = (
    Command(
        "preflight",
        "check a live acceptance packet and its evidence locally; never executes",
        _evidence_arguments,
        _preflight,
        effect=False,
    ),
    Command(
        "run-pilot",
        "run the granted pilot steps through the existing commands",
        _pilot_arguments,
        _run_pilot,
        always={"residual_risks": list(RESIDUAL_RISKS)},
    ),
)
