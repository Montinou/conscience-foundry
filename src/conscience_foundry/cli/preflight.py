"""`preflight` and `run-pilot`: dry live-acceptance preparation and its separately granted run.

``preflight`` is a pure local check of an operator packet and its evidence files: it reads files,
touches no database, store, adapter or network, and a ready report only says the packet is
internally consistent. It never starts anything.

``run-pilot`` orchestrates only the existing CLI commands, and only when all of these hold:

* the operator config grants ``run-pilot`` (its own grant category), as for every command;
* ``--execute`` is given (otherwise the generic dry run stops before this module is reached);
* a fresh preflight of the exact packet is ready, with every blocking gate closed by trusted
  deployment code (``TrustedServices.pilot_gates_closed``; nothing in a file can close one);
* a separately recorded ``LiveGrant`` names this exact packet digest, this actor, a live window,
  and exactly the ordered commands in the steps document.

The steps' own arguments are bound to that preflighted packet before anything runs: the plan a step
prepares or dispatches must be the packet's pinned plan (``planDigest``), the dispatch evidence
reference must be the packet's reviewed estimate (``estimateRef``), and the authorization must be
one the pilot itself authorizes for that plan and run, within the packet's cap, actor and expiry
(the dispatched authorization must be that same file). Any other argument is refused before a
first step runs. These files are read once, here, from operator-private paths; they are not locked
against a later edit, so they belong in the operator's private directory.

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
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any, Literal, NoReturn

from pydantic import BeforeValidator, Field

from conscience_foundry.cli.commands import (
    BY_NAME,
    Command,
    Invocation,
    Outcome,
    run_command,
)
from conscience_foundry.cli.config import CONFIG_MAX_BYTES, _bootstrap, read_trusted
from conscience_foundry.contracts.common import ContractError, Ref, ScalarString, WireModel
from conscience_foundry.contracts.execution import ExecutionPlan, RunAuthorization
from conscience_foundry.operator.packet import (
    PILOT_STEP_COMMANDS,
    LiveGrant,
    PreflightEvidence,
    PreflightPacket,
    PreflightReport,
    live_grant_blockers,
    packet_digest,
    preflight,
)
from conscience_foundry.policy.access import AccessContext

__all__ = ["PILOT_COMMANDS", "USED_GRANTS", "run_command"]

BLOCKED = "preflight_blocked"
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
        closed_gates=rt.services.pilot_gates_closed,
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


def _run_pilot(inv: Invocation) -> Outcome:
    rt, args = inv.rt, inv.args
    packet, evidence, report = _check(inv)
    if not report.ready:
        return Outcome("blocked", BLOCKED, _report_data(report))
    if args.grant is None:
        raise ContractError("grant_missing")
    grant = _parse(LiveGrant, _read(args.grant))
    refused = live_grant_blockers(packet, report, grant, rt.access, rt.clock())
    if refused:
        return Outcome(
            "blocked",
            refused[0].code,
            {"blockers": [{"code": r.code, "message": r.message} for r in refused]},
        )
    binding = _Binding(packet, evidence, rt.access)
    planned = _planned_steps(_parse(PilotSteps, _read(args.steps)), grant, args.config, binding)
    _consume_grant(args.config, grant, packet)  # from here the grant is spent, whatever happens
    results: list[dict[str, Any]] = []
    for index, (command, parsed) in enumerate(planned):
        moment = rt.clock()
        if moment >= grant.expires_at or moment >= binding.expires_at:
            return Outcome(
                "blocked",
                "authorization_expired",
                {"steps": results, "haltedAt": index, "paidPilotAcceptance": "not_established"},
            )
        outcome = run_command(command, parsed, rt.services)
        entry: dict[str, Any] = {"command": command.name, "outcome": outcome.status}
        if outcome.code is not None:
            entry["code"] = outcome.code
        results.append(entry)
        if outcome.status != "ok":
            # Inner payloads are never echoed; a halted pilot is never partial success.
            status = outcome.status if outcome.status in ("blocked", "failed") else "failed"
            return Outcome(
                status,
                outcome.code or "internal_error",
                {"steps": results, "haltedAt": index, "paidPilotAcceptance": "not_established"},
            )
    return Outcome(
        "ok",
        None,
        {"steps": results, "paidPilotAcceptance": "not_established"},
    )


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
    ),
)
