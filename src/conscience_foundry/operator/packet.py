"""Dry preflight and the separately authorized live acceptance packet.

A ``PreflightPacket`` is the exact set of operator-supplied values a paid live pilot would run
under. Preflight is a pure local check over that packet and the evidence documents its references
bind: it opens no network connection, calls no provider and executes nothing. Trust model:

* Every live value (provider, region, deployment, tariff, limits, caps, backup, expiry) is optional
  *on the wire* and a runtime blocker when absent. Nothing in this module supplies, infers or
  defaults one; a synthetic test value is never a default.
* Evidence documents are bound by hash to the packet's references and parsed under the packet's
  own finite limits. An unverifiable, mismatched or expired document blocks.
* Cost is exact decimal arithmetic. An unknown cost is a blocker, never zero, and the estimate is
  an operator-reviewed claim checked against the pinned plan envelope and the one shared run cap;
  it is not a guarantee about provider billing. It covers one attempt plus run storage; it does
  not cover ``maxAttemptsPerOperation`` above 1 (listed as an advisory item in every report).
* Carry-forward gates are listed, never silently assumed: a blocking gate stays open unless
  trusted deployment code attests it closed (``closed_gates``); neither the packet nor any wire
  document can. Deferred minors stay visible as advisory items.
* A ``LiveGrant`` is a separate record bound to the packet's digest. A changed packet has a new
  digest and so needs a new grant. A ready report is only data: it never starts anything, and the
  paid pilot's own acceptance is always reported as ``not_run`` here. A grant is single use: that
  is enforced by ``run-pilot`` (``cli/preflight.py``), not by this pure module.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated, Any, Literal, NamedTuple, Self, cast, get_args

from pydantic import (
    BeforeValidator,
    Field,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    model_validator,
)
from pydantic.json_schema import SkipJsonSchema

from conscience_foundry.contracts.admission import IntakeManifest
from conscience_foundry.contracts.codec import hash_jcs
from conscience_foundry.contracts.common import (
    ContractError,
    ContractLimits,
    Digest,
    ErrorCode,
    Id,
    Instant,
    Money,
    Reason,
    Ref,
    ScalarString,
    Version,
    WireModel,
)
from conscience_foundry.contracts.execution import ExecutionPlan, ResourceEnvelope
from conscience_foundry.contracts.release import RetentionPolicy
from conscience_foundry.execution.capabilities import CapabilityRecord, validate_capabilities
from conscience_foundry.execution.evidence import encoded
from conscience_foundry.policy.access import AccessContext

PACKET_SCHEMA = "cfoundry.preflight-packet.v1"

STAGING_STORE_TRANSFER = "staging_store_transfer"
SCOPED_EXECUTOR_STORE = "executor_scoped_store"
PLATFORM_RESTART_BOUND = "platform_restart_bound"
BLOCKING_GATES = (STAGING_STORE_TRANSFER, SCOPED_EXECUTOR_STORE, PLATFORM_RESTART_BOUND)
"""Gates that block live acceptance. Only the first two can be attested closed, and only by
trusted code; the restart bound is closed solely by concrete capability evidence."""
ATTESTABLE_GATES = frozenset({STAGING_STORE_TRANSFER, SCOPED_EXECUTOR_STORE})
ADVISORY_GATES = (
    "manual_retry_decision_binding",
    "t19_read_span_dry_contract",
    "t19_read_span_output_not_unlinked",
    "t19_inside_repository_lexical",
    "t19_dsn_service_passfile",
    "t19_orphan_blobs_and_remote_call_id",
    "estimate_covers_one_attempt",
)
"""Deferred minors recorded in the task ledger; listed, never hidden, never silently blocking."""

_GATE_DETAIL = {
    STAGING_STORE_TRANSFER: (
        "no staging-to-store transfer exists: verify_result reads only the local store, so a "
        "remote result cannot be verified and imported"
    ),
    SCOPED_EXECUTOR_STORE: (
        "the remote executor must be wired with a store scoped to the plan and attempt "
        "(scoped_to) before any live use"
    ),
    PLATFORM_RESTART_BOUND: (
        "platform crash restarts must be evidenced as bounded for the exact deployment; "
        "function retries=0 and a finite timeout are not that evidence"
    ),
    "manual_retry_decision_binding": (
        "a manual-retry decision is bound by time, not by attempt id (must be fixed before any "
        "F4 use); the pilot refuses manual retry"
    ),
    "t19_read_span_dry_contract": "read-span runs without --execute although it is not a dry run",
    "t19_read_span_output_not_unlinked": "a failed span output write leaves its created file",
    "t19_inside_repository_lexical": "the in-repository check is lexical; links bypass it",
    "t19_dsn_service_passfile": "a ledger DSN may name service or passfile files implicitly",
    "estimate_covers_one_attempt": (
        "the reviewed estimate covers one attempt plus run storage, not maxAttemptsPerOperation "
        "above 1; a plan allowing more attempts is not covered by it"
    ),
    "t19_orphan_blobs_and_remote_call_id": (
        "documents installed before a ledger refusal stay as orphan blobs; dispatch and "
        "reconcile print the remote call id"
    ),
}

PILOT_STEP_COMMANDS = ("backup", "prepare-run", "authorize-run", "dispatch", "reconcile")
"""The existing commands a granted pilot may orchestrate; nothing else is reachable."""
REQUIRED_SCOPES = ("extract", "remoteTransfer")

Name = Annotated[ScalarString, StringConstraints(min_length=1)]
Label = Annotated[str, StringConstraints(strict=True, pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
Category = Literal["compute", "startup", "restart", "transfer", "storage"]
Scope = Literal["attempt", "run_storage"]
CATEGORIES: tuple[Category, ...] = get_args(Category)
_ATTEMPT_ONLY = frozenset({"compute", "startup", "restart"})
_ERROR_CODES = frozenset(get_args(ErrorCode))
_INSTANT = TypeAdapter(Instant)


def _array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def omitted() -> Any:
    """Optional on the wire by omission only: absence is reported, never filled."""
    return Field(default=None, exclude_if=lambda value: value is None)


# -- wire records -----------------------------------------------------------------------------


class CostLine(WireModel):
    category: Category
    scope: Scope
    status: Literal["estimated", "unknown"]
    amount_usd: Money | SkipJsonSchema[None] = omitted()
    tariff_ref: Ref
    basis: Name

    @model_validator(mode="after")
    def amount_follows_status(self) -> Self:
        if (self.status == "unknown") != (self.amount_usd is None):
            raise ValueError("cost amount contradicts cost status")
        return self


class CostEstimate(WireModel):
    """An operator-reviewed claim. Evidence for the pinned tariff, not a billing guarantee."""

    schema_version: Literal["cfoundry.cost-estimate.v1"]
    project_id: Id
    currency: Literal["USD"]
    tariff_ref: Ref
    max_attempt_usd: Money
    run_storage_usd: Money
    lines: Annotated[tuple[CostLine, ...], BeforeValidator(_array), Field(min_length=1)]
    reviewed_by: Id
    reviewed_at: Instant
    valid_until: Instant


class BackupEvidence(WireModel):
    """Concrete independent-backup evidence. Different-device mechanics are never sufficient."""

    schema_version: Literal["cfoundry.backup-evidence.v1"]
    project_id: Id
    backup_store_id: Name
    independence: Literal["verified", "unverified"]
    restore_evidence_ref: Ref | SkipJsonSchema[None] = omitted()
    valid_until: Instant


class PreflightPacket(WireModel):
    schema_version: Literal["cfoundry.preflight-packet.v1"]
    project_id: Id
    manifest_digest: Digest
    plan_digest: Digest
    provider: Label | SkipJsonSchema[None] = omitted()
    region: Label | SkipJsonSchema[None] = omitted()
    deployment_version: Version | SkipJsonSchema[None] = omitted()
    image_digest: Digest | SkipJsonSchema[None] = omitted()
    dependency_lock_digest: Digest | SkipJsonSchema[None] = omitted()
    capabilities_ref: Ref | SkipJsonSchema[None] = omitted()
    tariff_ref: Ref | SkipJsonSchema[None] = omitted()
    estimate_ref: Ref | SkipJsonSchema[None] = omitted()
    policy_ref: Ref | SkipJsonSchema[None] = omitted()
    destination_ref: Ref | SkipJsonSchema[None] = omitted()
    backup_ref: Ref | SkipJsonSchema[None] = omitted()
    contract_limits: ContractLimits | SkipJsonSchema[None] = omitted()
    resources: ResourceEnvelope | SkipJsonSchema[None] = omitted()
    max_run_usd: Money | SkipJsonSchema[None] = omitted()
    max_attempt_usd: Money | SkipJsonSchema[None] = omitted()
    retention: RetentionPolicy | SkipJsonSchema[None] = omitted()
    expires_at: Instant | SkipJsonSchema[None] = omitted()


class LiveGrant(WireModel):
    """The separately recorded authorization for exactly one packet digest."""

    schema_version: Literal["cfoundry.live-grant.v1"]
    grant_id: Id
    project_id: Id
    packet_digest: Digest
    actor_id: Id
    commands: Annotated[tuple[Name, ...], BeforeValidator(_array), Field(min_length=1)]
    granted_at: Instant
    expires_at: Instant

    @model_validator(mode="after")
    def window(self) -> Self:
        if self.granted_at >= self.expires_at:
            raise ValueError("invalid grant window")
        return self


# -- inputs and results ------------------------------------------------------------------------


@dataclass(frozen=True)
class PreflightEvidence:
    """Operator-supplied document bytes; each is verified against the packet before use."""

    manifest: bytes | None = field(default=None, repr=False)
    plan: bytes | None = field(default=None, repr=False)
    capabilities: bytes | None = field(default=None, repr=False)
    estimate: bytes | None = field(default=None, repr=False)
    backup: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True)
class GateItem:
    gate_id: str
    state: Literal["open", "closed", "advisory"]
    blocking: bool
    detail: str


@dataclass(frozen=True)
class PreflightReport:
    """Local code checks, provider capability and the paid pilot are reported separately."""

    ready: bool
    blockers: tuple[Reason, ...]
    packet_digest: Digest
    gates: tuple[GateItem, ...] = ()
    local_checks: Literal["pass", "blocked"] = "pass"
    provider_capability: Literal["evidenced", "blocked"] = "evidenced"
    paid_pilot: Literal["not_run"] = "not_run"


class _Finding(NamedTuple):
    category: Literal["local", "provider"]
    reason: Reason


def packet_digest(packet: PreflightPacket) -> Digest:
    if type(packet) is not PreflightPacket:
        raise ContractError("invalid_schema")
    return hash_jcs(PACKET_SCHEMA, packet.model_dump(mode="json", by_alias=True, exclude_none=True))


def cost_totals(estimate: CostEstimate) -> tuple[Decimal | None, Decimal | None]:
    """Exact ``(attempt, run_storage)`` sums; a scope with any unknown line is ``None``, not 0."""
    totals: list[Decimal | None] = []
    for scope in ("attempt", "run_storage"):
        lines = [line for line in estimate.lines if line.scope == scope]
        if any(line.amount_usd is None for line in lines):
            totals.append(None)
        else:
            totals.append(sum((Decimal(line.amount_usd or "0") for line in lines), Decimal(0)))
    return totals[0], totals[1]


def _identity(ref: Ref) -> tuple[object, ...]:
    return ref.project_id, ref.artifact_schema, ref.digest, ref.size_bytes, ref.media_type


def _utc_now() -> Instant:
    moment = datetime.now(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


class _Check:
    """Accumulates findings for one preflight; every blocker is reported, none short-circuits."""

    def __init__(self, packet: PreflightPacket, context: AccessContext, now: Instant) -> None:
        self.packet, self.context, self.now = packet, context, now
        self.findings: list[_Finding] = []

    def add(
        self,
        code: ErrorCode,
        message: str,
        *,
        provider: bool = False,
    ) -> None:
        reason = Reason(code=code, message=message)
        self.findings.append(_Finding("provider" if provider else "local", reason))

    def code(self, error: ContractError) -> ErrorCode:
        return cast(ErrorCode, error.code) if error.code in _ERROR_CODES else "invalid_schema"

    def document[Model: WireModel](
        self,
        name: str,
        data: bytes | None,
        reference: Ref | Digest | None,
        model: type[Model],
        *,
        provider: bool = False,
    ) -> Model | None:
        """Require, hash-bind and parse one evidence document under the packet's own limits."""
        if data is None:
            self.add("unavailable", f"evidence:missing:{name}", provider=provider)
            return None
        if reference is None:
            return None  # the missing reference is already a blocker; nothing to bind to
        digest = reference if isinstance(reference, str) else reference.digest
        size = None if isinstance(reference, str) else reference.size_bytes
        if hashlib.sha256(data).hexdigest() != digest or (size is not None and len(data) != size):
            self.add("hash_mismatch", f"evidence:digest:{name}", provider=provider)
            return None
        limits = self.packet.contract_limits
        if limits is None:
            return None  # without finite limits nothing is parsed; that is its own blocker
        try:
            return model.from_wire(data, limits)
        except ContractError as error:
            self.add(self.code(error), f"evidence:invalid:{name}", provider=provider)
            return None


_MISSING: tuple[tuple[str, str, ErrorCode, bool], ...] = (
    ("provider", "provider", "unavailable", False),
    ("region", "region", "unavailable", False),
    ("deployment_version", "deploymentVersion", "unavailable", False),
    ("image_digest", "imageDigest", "unavailable", False),
    ("dependency_lock_digest", "dependencyLockDigest", "unavailable", False),
    ("capabilities_ref", "capabilitiesRef", "unsupported_capability", True),
    ("tariff_ref", "tariffRef", "budget_unconfigured", False),
    ("estimate_ref", "estimateRef", "budget_unconfigured", False),
    ("policy_ref", "policyRef", "unavailable", False),
    ("destination_ref", "destinationRef", "unsupported_capability", False),
    ("backup_ref", "backupRef", "unsupported_capability", False),
    ("contract_limits", "contractLimits", "limits_missing", False),
    ("resources", "resources", "limits_missing", False),
    ("max_run_usd", "maxRunUsd", "budget_unconfigured", False),
    ("max_attempt_usd", "maxAttemptUsd", "budget_unconfigured", False),
    ("retention", "retention", "limits_missing", False),
    ("expires_at", "expiresAt", "unavailable", False),
)


def _check_header(check: _Check) -> None:
    packet, context = check.packet, check.context
    if packet.expires_at is not None and check.now >= packet.expires_at:
        check.add("authorization_expired", "packet:expired")
    if packet.project_id != context.project_id:
        check.add("forbidden", "access:project")
    for scope in REQUIRED_SCOPES:
        if scope not in context.scopes:
            check.add("forbidden", f"access:scope:{scope}")
    for attribute, wire_name, code, provider in _MISSING:
        if getattr(packet, attribute) is None:
            check.add(code, f"missing:{wire_name}", provider=provider)


def _check_plan(check: _Check, plan: ExecutionPlan, data: bytes) -> None:
    packet = check.packet
    if plan.project_id != packet.project_id:
        check.add("forbidden", "binding:project")
    if encoded(plan) != data:
        # Every grant and adapter digests the canonical serialization of the plan.
        check.add("hash_mismatch", "plan:noncanonical")
    if packet.policy_ref is not None and _identity(plan.policy_ref) != _identity(packet.policy_ref):
        check.add("forbidden", "binding:policy")
    if packet.tariff_ref is not None and _identity(plan.budget.tariff_ref) != _identity(
        packet.tariff_ref
    ):
        check.add("forbidden", "binding:tariff")
    if packet.resources is not None and plan.resources != packet.resources:
        check.add("forbidden", "binding:resources")
    if packet.max_run_usd is not None and Decimal(packet.max_run_usd) != Decimal(
        plan.budget.max_run_cost
    ):
        check.add("forbidden", "binding:max_run_usd")
    if packet.max_attempt_usd is not None and Decimal(packet.max_attempt_usd) != Decimal(
        plan.budget.max_attempt_cost
    ):
        check.add("forbidden", "binding:max_attempt_usd")
    if packet.expires_at is not None and packet.expires_at > plan.budget.valid_until:
        check.add("authorization_expired", "packet:outlives_plan")


def _check_manifest(check: _Check, manifest: IntakeManifest) -> None:
    packet = check.packet
    if manifest.project_id != packet.project_id:
        check.add("forbidden", "binding:manifest_project")
    if packet.policy_ref is not None and _identity(manifest.policy_ref) != _identity(
        packet.policy_ref
    ):
        check.add("forbidden", "binding:policy")


def _restart_bound_evidenced(record: CapabilityRecord) -> bool:
    return (
        record.platform_restart_bound == "bounded"
        and record.max_platform_restarts is not None
        and record.total_bound_seconds is not None
    )


def _check_capability(check: _Check, record: CapabilityRecord, plan: ExecutionPlan | None) -> None:
    packet = check.packet
    if not _restart_bound_evidenced(record):
        check.add(
            "unsupported_capability",
            f"gate:{PLATFORM_RESTART_BOUND}",
            provider=True,
        )
    if plan is not None:
        try:
            validate_capabilities(record, plan)
        except ContractError as error:
            check.add(check.code(error), f"capability:rejected:{error.code}", provider=True)
    if packet.deployment_version is not None and record.deployment_version != (
        packet.deployment_version
    ):
        check.add("unsupported_capability", "capability:deployment", provider=True)
    if packet.image_digest is not None and record.image_digest != packet.image_digest:
        check.add("unsupported_capability", "capability:image", provider=True)
    if packet.expires_at is not None and record.valid_until < packet.expires_at:
        check.add("authorization_expired", "capability:expires", provider=True)
    if check.now >= record.valid_until:
        check.add("authorization_expired", "capability:expires", provider=True)


def _check_estimate(check: _Check, estimate: CostEstimate, plan: ExecutionPlan | None) -> None:
    packet, context = check.packet, check.context
    if estimate.project_id != packet.project_id:
        check.add("forbidden", "estimate:project")
    pinned = packet.tariff_ref
    if (pinned is not None and _identity(estimate.tariff_ref) != _identity(pinned)) or any(
        _identity(line.tariff_ref) != _identity(estimate.tariff_ref) for line in estimate.lines
    ):
        check.add("forbidden", "estimate:tariff")
    if estimate.reviewed_by != context.actor_id:
        check.add("forbidden", "estimate:reviewer")
    if check.now >= estimate.valid_until or (
        packet.expires_at is not None and estimate.valid_until < packet.expires_at
    ):
        check.add("authorization_expired", "estimate:expires")
    for category in CATEGORIES:
        lines = [line for line in estimate.lines if line.category == category]
        if not lines:
            check.add("budget_unconfigured", f"estimate:category_missing:{category}")
        elif len(lines) > 1:
            check.add("budget_unconfigured", f"estimate:category_duplicate:{category}")
        for line in lines:
            if line.status == "unknown":
                check.add("budget_unconfigured", f"estimate:unknown_cost:{category}")
            if (category in _ATTEMPT_ONLY and line.scope != "attempt") or (
                category == "storage" and line.scope != "run_storage"
            ):
                check.add("budget_unconfigured", f"estimate:category_scope:{category}")
    attempt, storage = cost_totals(estimate)
    declared_attempt, declared_storage = (
        Decimal(estimate.max_attempt_usd),
        Decimal(estimate.run_storage_usd),
    )
    if attempt is not None and attempt != declared_attempt:
        check.add("budget_unconfigured", "estimate:sum_mismatch:attempt")
    if storage is not None and storage != declared_storage:
        check.add("budget_unconfigured", "estimate:sum_mismatch:run_storage")
    if declared_attempt <= 0 or declared_storage <= 0:
        check.add("budget_unconfigured", "estimate:nonpositive")
    if plan is not None:
        if declared_attempt > Decimal(plan.budget.max_attempt_cost):
            check.add("budget_exhausted", "estimate:exceeds_attempt_cap")
        if declared_attempt + declared_storage > Decimal(plan.budget.max_run_cost):
            check.add("budget_exhausted", "estimate:exceeds_run_cap")


def _check_backup(check: _Check, backup: BackupEvidence) -> None:
    packet = check.packet
    if backup.project_id != packet.project_id:
        check.add("forbidden", "backup:project")
    if backup.independence != "verified":
        check.add("unsupported_capability", "backup:independence")
    if backup.restore_evidence_ref is None:
        check.add("unsupported_capability", "backup:restore_evidence")
    elif backup.restore_evidence_ref.project_id != packet.project_id:
        check.add("forbidden", "backup:project")
    if check.now >= backup.valid_until or (
        packet.expires_at is not None and backup.valid_until < packet.expires_at
    ):
        check.add("authorization_expired", "backup:expires")


def preflight(
    packet: PreflightPacket,
    context: AccessContext,
    *,
    evidence: PreflightEvidence | None = None,
    now: Instant | None = None,
    closed_gates: frozenset[str] = frozenset(),
) -> PreflightReport:
    """Check a packet and its evidence locally. No network, no provider call, nothing executed.

    ``closed_gates`` is supplied only by trusted deployment code (never by the packet or a wire
    document); it can close only the attestable gates, so an unknown name closes nothing.
    """
    if type(packet) is not PreflightPacket or type(context) is not AccessContext:
        raise ContractError("invalid_schema")
    if evidence is not None and type(evidence) is not PreflightEvidence:
        raise ContractError("invalid_schema")
    moment = now if now is not None else _utc_now()
    try:
        _INSTANT.validate_python(moment)
    except ValidationError:
        raise ContractError("invalid_schema") from None
    digest = packet_digest(packet)
    held = evidence if evidence is not None else PreflightEvidence()
    check = _Check(packet, context, moment)
    _check_header(check)

    manifest = check.document("manifest", held.manifest, packet.manifest_digest, IntakeManifest)
    plan_bytes = held.plan
    plan = check.document("plan", plan_bytes, packet.plan_digest, ExecutionPlan)
    record = check.document(
        "capabilities",
        held.capabilities,
        packet.capabilities_ref,
        CapabilityRecord,
        provider=True,
    )
    estimate = check.document("estimate", held.estimate, packet.estimate_ref, CostEstimate)
    backup = check.document("backup", held.backup, packet.backup_ref, BackupEvidence)
    if manifest is not None:
        _check_manifest(check, manifest)
    if plan is not None and plan_bytes is not None:
        _check_plan(check, plan, plan_bytes)
    if record is not None:
        _check_capability(check, record, plan)
    if estimate is not None:
        _check_estimate(check, estimate, plan)
    if backup is not None:
        _check_backup(check, backup)
    if packet.retention is not None and not packet.retention.backup_required:
        check.add("unsupported_capability", "retention:backup_not_required")

    gates: list[GateItem] = []
    for gate in (STAGING_STORE_TRANSFER, SCOPED_EXECUTOR_STORE):
        closed = gate in closed_gates and gate in ATTESTABLE_GATES
        gates.append(GateItem(gate, "closed" if closed else "open", True, _GATE_DETAIL[gate]))
        if not closed:
            check.add("unsupported_capability", f"gate:{gate}", provider=True)
    evidenced = record is not None and _restart_bound_evidenced(record)
    gates.append(
        GateItem(
            PLATFORM_RESTART_BOUND,
            "closed" if evidenced else "open",
            True,
            _GATE_DETAIL[PLATFORM_RESTART_BOUND],
        )
    )
    gates.extend(GateItem(gate, "advisory", False, _GATE_DETAIL[gate]) for gate in ADVISORY_GATES)

    blockers = tuple(finding.reason for finding in check.findings)
    return PreflightReport(
        ready=not blockers,
        blockers=blockers,
        packet_digest=digest,
        gates=tuple(gates),
        local_checks=("blocked" if any(f.category == "local" for f in check.findings) else "pass"),
        provider_capability=(
            "blocked" if any(f.category == "provider" for f in check.findings) else "evidenced"
        ),
        paid_pilot="not_run",
    )


def live_grant_blockers(
    packet: PreflightPacket,
    report: PreflightReport,
    grant: LiveGrant,
    context: AccessContext,
    now: Instant,
) -> tuple[Reason, ...]:
    """Reasons the separately recorded grant does not authorize this exact packet right now."""
    if (
        type(packet) is not PreflightPacket
        or type(report) is not PreflightReport
        or type(grant) is not LiveGrant
        or type(context) is not AccessContext
    ):
        raise ContractError("invalid_schema")
    try:
        _INSTANT.validate_python(now)
    except ValidationError:
        raise ContractError("invalid_schema") from None
    digest = packet_digest(packet)
    found: list[Reason] = []

    def refuse(code: ErrorCode, message: str) -> None:
        found.append(Reason(code=code, message=message))

    if report.packet_digest != digest:
        refuse("forbidden", "grant:report_digest")
    if not report.ready:
        refuse("forbidden", "grant:not_ready")
    if grant.packet_digest != digest:
        refuse("forbidden", "grant:packet_changed")  # a changed packet needs a new grant
    if grant.project_id != packet.project_id or grant.project_id != context.project_id:
        refuse("forbidden", "grant:project")
    if grant.actor_id != context.actor_id:
        refuse("forbidden", "grant:actor")
    if any(command not in PILOT_STEP_COMMANDS for command in grant.commands):
        refuse("forbidden", "grant:command")
    if now < grant.granted_at or now >= grant.expires_at:
        refuse("authorization_expired", "grant:window")
    if packet.expires_at is None or grant.expires_at > packet.expires_at:
        refuse("forbidden", "grant:outlives_packet")
    return tuple(found)
