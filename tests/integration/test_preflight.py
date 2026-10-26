"""Dry preflight and the separately authorized live acceptance packet, on synthetic data only.

Nothing here reaches a provider, a network or a database. Every price, region, deployment and
digest below is a test-only value: none is a default of the code under test, and a green preflight
never starts, authorizes or proves anything remote (the paid pilot stays ``not_run``).
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from pydantic_core import PydanticUndefined
from test_cli import ALL_GRANTS, Env, Spy, file_names, write_private
from test_ledger_db import admission
from test_ledger_db import limits as base_limits

from conscience_foundry.cli import preflight as pilot_cli
from conscience_foundry.cli.commands import Outcome
from conscience_foundry.cli.config import TrustedServices
from conscience_foundry.contracts.common import ContractError, Reason
from conscience_foundry.contracts.execution import ExecutionPlan
from conscience_foundry.execution.capabilities import CapabilityRecord
from conscience_foundry.execution.evidence import encoded
from conscience_foundry.operator.packet import (
    ADVISORY_GATES,
    BLOCKING_GATES,
    PLATFORM_RESTART_BOUND,
    SCOPED_EXECUTOR_STORE,
    STAGING_STORE_TRANSFER,
    BackupEvidence,
    CostEstimate,
    LiveGrant,
    PreflightEvidence,
    PreflightPacket,
    PreflightReport,
    cost_totals,
    live_grant_blockers,
    packet_digest,
    preflight,
)
from conscience_foundry.policy.access import AccessContext

PROJECT = "00000000-0000-0000-0000-000000000001"
ACTOR = "00000000-0000-0000-0000-000000000003"
RUN = "00000000-0000-0000-0000-000000000002"
OTHER = "00000000-0000-0000-0000-0000000000ff"
ASSET = "00000000-0000-0000-0000-000000000004"
NOW = "2030-01-01T00:00:00.000Z"
PACKET_EXPIRY = "2030-01-01T01:00:00.000Z"
PLAN_EXPIRY = "2030-01-01T02:00:00.000Z"
GRANT_EXPIRY = "2030-01-01T00:30:00.000Z"
LATER = "2030-01-01T00:45:00.000Z"
CLOSED = frozenset({STAGING_STORE_TRANSFER, SCOPED_EXECUTOR_STORE})
CONTEXT = AccessContext(PROJECT, ACTOR, frozenset({"read", "extract", "remoteTransfer"}))
CATEGORY_AMOUNTS = {
    "compute": ("attempt", "0.80"),
    "startup": ("attempt", "0.20"),
    "restart": ("attempt", "0.30"),
    "transfer": ("attempt", "0.20"),
    "storage": ("run_storage", "0.40"),
}
CAMEL = {
    "provider": "provider",
    "region": "region",
    "deployment_version": "deploymentVersion",
    "image_digest": "imageDigest",
    "dependency_lock_digest": "dependencyLockDigest",
    "capabilities_ref": "capabilitiesRef",
    "tariff_ref": "tariffRef",
    "estimate_ref": "estimateRef",
    "policy_ref": "policyRef",
    "destination_ref": "destinationRef",
    "backup_ref": "backupRef",
    "contract_limits": "contractLimits",
    "resources": "resources",
    "max_run_usd": "maxRunUsd",
    "max_attempt_usd": "maxAttemptUsd",
    "retention": "retention",
    "expires_at": "expiresAt",
}


def ref(data: bytes, schema: str) -> dict[str, Any]:
    return {
        "schemaVersion": "kf.artifact-ref.v1",
        "projectId": PROJECT,
        "digest": hashlib.sha256(data).hexdigest(),
        "sizeBytes": len(data),
        "mediaType": "application/json",
        "artifactSchema": schema,
        "locations": [],
    }


TARIFF = ref(b"synthetic tariff", "kf.tariff.v1")
DESTINATION = ref(b"synthetic destination", "kf.destination.v1")
RESTORE = ref(b"synthetic restore drill", "kf.restore-evidence.v1")
LOCK = hashlib.sha256(b"synthetic lock").hexdigest()
IMAGE = "a" * 64
CODE = "b" * 64


def plan_document(manifest_policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": "kf.execution-plan.v1",
        "projectId": PROJECT,
        "runId": RUN,
        "planId": "00000000-0000-0000-0000-000000000005",
        "executionConfigRef": ref(b"synthetic config", "kf.execution-config.v1"),
        "admissionReportRef": ref(b"synthetic report", "kf.admission-report.v1"),
        "extractionSpecRef": ref(b"synthetic spec", "kf.extraction-spec.v1"),
        "policyRef": manifest_policy,
        "profileId": "technical_minimal",
        "profileVersion": "synthetic.v1",
        "contractSetRef": ref(b"synthetic contracts", "kf.contract-set.v1"),
        "limitsRefs": [ref(b"synthetic limits", "kf.contract-limits.v1")],
        "inputRefs": [ref(b"synthetic input", "kf.raw-original.v1")],
        "operationKey": "c" * 64,
        "resources": {
            "cpuMilli": 1000,
            "memoryMiB": 512,
            "gpuCount": 0,
            "maxWallSeconds": 600,
            "maxOutputBytes": 65536,
            "maxConcurrentAttempts": 1,
            "maxAttemptsPerOperation": 1,
            "automaticRetries": 0,
        },
        "budget": {
            "currency": "USD",
            "maxRunCost": "4.00",
            "maxAttemptCost": "1.50",
            "tariffRef": TARIFF,
            "authorizationId": "00000000-0000-0000-0000-000000000008",
            "validUntil": PLAN_EXPIRY,
        },
        "expiresAt": PLAN_EXPIRY,
    }


def estimate_document() -> dict[str, Any]:
    return {
        "schemaVersion": "cfoundry.cost-estimate.v1",
        "projectId": PROJECT,
        "currency": "USD",
        "tariffRef": TARIFF,
        "maxAttemptUsd": "1.50",
        "runStorageUsd": "0.40",
        "lines": [
            {
                "category": category,
                "scope": scope,
                "status": "estimated",
                "amountUsd": amount,
                "tariffRef": TARIFF,
                "basis": f"synthetic basis for {category}",
            }
            for category, (scope, amount) in CATEGORY_AMOUNTS.items()
        ],
        "reviewedBy": ACTOR,
        "reviewedAt": NOW,
        "validUntil": PLAN_EXPIRY,
    }


def capability_document(plan_wire: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": "kf.modal-capability-record.v1",
        "projectId": PROJECT,
        "executionConfigRef": plan_wire["executionConfigRef"],
        "sdkVersion": "synthetic-sdk.1",
        "deploymentVersion": "synthetic.deployment.v1",
        "imageDigest": IMAGE,
        "codeDigest": CODE,
        "cpuMilli": 1000,
        "memoryMiB": 512,
        "gpuCount": 0,
        "functionRetries": 0,
        "startupTimeoutSeconds": 60,
        "schedulingTimeoutSeconds": 120,
        "executionTimeoutSeconds": 300,
        "platformRestartBound": "bounded",
        "maxPlatformRestarts": 0,
        "totalBoundSeconds": 480,
        "cancellation": "terminates_containers",
        "deadlineEnforcement": "entry_and_every_bounded_step",
        "validUntil": PLAN_EXPIRY,
        "sourceEvidenceRefs": [ref(b"synthetic evidence", "kf.capability-source.v1")],
    }


def backup_document() -> dict[str, Any]:
    return {
        "schemaVersion": "cfoundry.backup-evidence.v1",
        "projectId": PROJECT,
        "backupStoreId": "synthetic-backup",
        "independence": "verified",
        "restoreEvidenceRef": RESTORE,
        "validUntil": PLAN_EXPIRY,
    }


def wire(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class Case:
    packet: PreflightPacket
    evidence: PreflightEvidence
    packet_wire: dict[str, Any]
    documents: dict[str, bytes] = field(default_factory=dict)

    def run(
        self,
        *,
        now: str = NOW,
        closed: frozenset[str] = CLOSED,
        context: AccessContext = CONTEXT,
        evidence: PreflightEvidence | None = None,
    ) -> PreflightReport:
        return preflight(
            self.packet,
            context,
            evidence=self.evidence if evidence is None else evidence,
            now=now,
            closed_gates=closed,
        )


Edit = Callable[[dict[str, Any]], None]


def build(
    *,
    packet: Edit | None = None,
    plan: Edit | None = None,
    estimate: Edit | None = None,
    capability: Edit | None = None,
    backup: Edit | None = None,
    bind: bool = True,
) -> Case:
    """Documents first, then a packet whose refs bind their exact bytes (unless told otherwise)."""
    base = admission()
    manifest_bytes = base.evidence.manifest_bytes
    policy_ref = json.loads(manifest_bytes)["policyRef"]
    plan_wire = plan_document(policy_ref)
    if plan:
        plan(plan_wire)
    plan_bytes = encoded(ExecutionPlan.model_validate(plan_wire))
    estimate_wire = estimate_document()
    if estimate:
        estimate(estimate_wire)
    capability_wire = capability_document(plan_wire)
    if capability:
        capability(capability_wire)
    backup_wire = backup_document()
    if backup:
        backup(backup_wire)
    documents = {
        "estimate": wire(estimate_wire),
        "capabilities": wire(capability_wire),
        "backup": wire(backup_wire),
    }
    packet_wire: dict[str, Any] = {
        "schemaVersion": "cfoundry.preflight-packet.v1",
        "projectId": PROJECT,
        "manifestDigest": hashlib.sha256(manifest_bytes).hexdigest(),
        "planDigest": hashlib.sha256(plan_bytes).hexdigest(),
        "provider": "synthetic-provider",
        "region": "synthetic-region-1",
        "deploymentVersion": "synthetic.deployment.v1",
        "imageDigest": IMAGE,
        "dependencyLockDigest": LOCK,
        "capabilitiesRef": ref(documents["capabilities"], "kfx.capability-evidence.v1"),
        "tariffRef": TARIFF,
        "estimateRef": ref(documents["estimate"], "kfx.cost-estimate.v1"),
        "policyRef": policy_ref,
        "destinationRef": DESTINATION,
        "backupRef": ref(documents["backup"], "kfx.backup-evidence.v1"),
        "contractLimits": json.loads(base_limits().model_dump_json(by_alias=True)),
        "resources": plan_wire["resources"],
        "maxRunUsd": plan_wire["budget"]["maxRunCost"],
        "maxAttemptUsd": plan_wire["budget"]["maxAttemptCost"],
        "retention": {
            "schemaVersion": "kf.retention.v1",
            "policyVersion": "synthetic.v1",
            "minStagingAgeSeconds": 60,
            "fundedStagingHorizonSeconds": 86400,
            "escalationLeadSeconds": 3600,
            "backupRequired": True,
            "auditRetentionSeconds": 604800,
        },
        "expiresAt": PACKET_EXPIRY,
    }
    if packet:
        packet(packet_wire)
    parsed = PreflightPacket.model_validate(packet_wire)
    return Case(
        parsed,
        PreflightEvidence(
            manifest=manifest_bytes,
            plan=plan_bytes,
            capabilities=documents["capabilities"],
            estimate=documents["estimate"],
            backup=documents["backup"],
        ),
        packet_wire,
        documents,
    )


def messages(report: PreflightReport) -> list[str]:
    return [reason.message for reason in report.blockers]


def blocked_on(report: PreflightReport, fragment: str) -> bool:
    return not report.ready and any(fragment in message for message in messages(report))


def drop(*names: str) -> Edit:
    def edit(wire_packet: dict[str, Any]) -> None:
        for name in names:
            del wire_packet[name]

    return edit


def lines_of(wire_estimate: dict[str, Any]) -> list[dict[str, Any]]:
    lines: list[dict[str, Any]] = wire_estimate["lines"]
    return lines


# -- the packet itself ------------------------------------------------------------------------


def test_complete_packet_is_ready_only_as_dry_preparation() -> None:
    report = build().run()
    assert report.ready and report.blockers == ()
    assert report.local_checks == "pass" and report.provider_capability == "evidenced"
    assert report.paid_pilot == "not_run"  # a green preflight never claims a paid pilot
    assert report.packet_digest == packet_digest(build().packet)


@pytest.mark.parametrize("name", sorted(CAMEL))
def test_missing_values_and_unknown_platform_bounds_block(name: str) -> None:
    """Every operator value is a runtime blocker when absent; nothing fills a default."""
    case = build(packet=drop(CAMEL[name]))
    report = case.run()
    assert not report.ready
    assert blocked_on(report, f"missing:{CAMEL[name]}")
    assert getattr(case.packet, name) is None  # preflight neither fills nor mutates the value
    assert report.local_checks == "blocked" or report.provider_capability == "blocked"


def test_no_defaults_for_missing_tariff_region_backup_or_limits() -> None:
    for name, info in PreflightPacket.model_fields.items():
        assert info.default in (None, PydanticUndefined), name
        assert info.default_factory is None, name
    by_field = {
        "tariff_ref": "budget_unconfigured",
        "region": "unavailable",
        "backup_ref": "unsupported_capability",
        "contract_limits": "limits_missing",
        "resources": "limits_missing",
        "max_attempt_usd": "budget_unconfigured",
    }
    for name, code in by_field.items():
        report = build(packet=drop(CAMEL[name])).run()
        assert code in [reason.code for reason in report.blockers], name
    # a wire packet that omits them parses (and then blocks); it is never completed on the way in
    empty = PreflightPacket.model_validate(
        {
            "schemaVersion": "cfoundry.preflight-packet.v1",
            "projectId": PROJECT,
            "manifestDigest": "d" * 64,
            "planDigest": "e" * 64,
        }
    )
    report = preflight(empty, CONTEXT, now=NOW, closed_gates=CLOSED)
    assert not report.ready
    for name in CAMEL.values():
        assert blocked_on(report, f"missing:{name}"), name
    assert blocked_on(report, "evidence:missing:plan")


@pytest.mark.parametrize("bound", ["unbounded", "unknown"])
def test_unbounded_restart_capability_blocks(bound: str) -> None:
    """retries=0 and finite timeouts are not evidence that platform crash restarts are bounded."""

    def unbounded(record: dict[str, Any]) -> None:
        record["platformRestartBound"] = bound
        record.pop("maxPlatformRestarts")
        record.pop("totalBoundSeconds")

    case = build(capability=unbounded)
    assert (
        CapabilityRecord.model_validate(
            json.loads(case.evidence.capabilities or b"")
        ).function_retries
        == 0
    )
    report = case.run()
    assert blocked_on(report, f"gate:{PLATFORM_RESTART_BOUND}")
    assert report.provider_capability == "blocked"
    gate = next(item for item in report.gates if item.gate_id == PLATFORM_RESTART_BOUND)
    assert gate.state == "open" and gate.blocking
    # The same record with an evidenced bound is what closes the gate, not the retries value.
    closed = next(item for item in build().run().gates if item.gate_id == PLATFORM_RESTART_BOUND)
    assert closed.state == "closed"


@pytest.mark.parametrize(
    ("edit", "fragment"),
    [
        (lambda r: r.update(cancellation="request_only"), "capability:rejected"),
        (lambda r: r.update(deadlineEnforcement="entry_only"), "capability:rejected"),
        (lambda r: r.update(gpuCount=1), "capability:rejected"),
        (lambda r: r.update(deploymentVersion="other.deployment"), "capability:deployment"),
        (lambda r: r.update(imageDigest="f" * 64), "capability:image"),
        (lambda r: r.update(validUntil="2030-01-01T00:30:00.000Z"), "capability:expires"),
    ],
)
def test_capability_evidence_must_fit_the_plan_and_packet(
    edit: Callable[[dict[str, Any]], object], fragment: str
) -> None:
    report = build(capability=lambda record: edit(record)).run()
    assert blocked_on(report, fragment), messages(report)


def test_carry_forward_gates_are_explicit_and_only_trusted_code_closes_them() -> None:
    case = build()
    open_report = case.run(closed=frozenset())
    assert not open_report.ready
    for gate in (STAGING_STORE_TRANSFER, SCOPED_EXECUTOR_STORE):
        assert blocked_on(open_report, f"gate:{gate}"), gate
        item = next(g for g in open_report.gates if g.gate_id == gate)
        assert item.state == "open" and item.blocking
        # one attested gate does not close the other, and an unknown name closes nothing
        only = case.run(closed=frozenset({gate, "no_such_gate"}))
        assert not only.ready
        assert not blocked_on(only, f"gate:{gate}")
    both = case.run(closed=CLOSED)
    assert both.ready
    assert {g.gate_id for g in both.gates if g.state == "closed"} >= CLOSED
    # deferred minors stay visible as advisory items, never hidden and never silently blocking
    advisory = {g.gate_id for g in both.gates if g.state == "advisory"}
    assert advisory == set(ADVISORY_GATES) and "manual_retry_decision_binding" in advisory
    assert all(not g.blocking for g in both.gates if g.state == "advisory")
    assert set(BLOCKING_GATES) >= {STAGING_STORE_TRANSFER, SCOPED_EXECUTOR_STORE}


def test_packet_documents_cannot_attest_a_gate() -> None:
    wire_packet = build().packet_wire | {"closedGates": [STAGING_STORE_TRANSFER]}
    with pytest.raises(Exception):  # noqa: B017  unknown wire fields are rejected, not obeyed
        PreflightPacket.model_validate(wire_packet)


# -- cost estimate ---------------------------------------------------------------------------


def test_unknown_cost_not_zero() -> None:
    def unknown(wire_estimate: dict[str, Any]) -> None:
        line = next(x for x in lines_of(wire_estimate) if x["category"] == "restart")
        line["status"] = "unknown"
        del line["amountUsd"]

    case = build(estimate=unknown)
    estimate = CostEstimate.model_validate(json.loads(case.evidence.estimate or b""))
    assert cost_totals(estimate) == (None, Decimal("0.40"))  # the attempt total is unknown, not 0
    report = case.run()
    assert blocked_on(report, "estimate:unknown_cost:restart")
    assert not report.ready
    # the same sums with the line declared zero-with-evidence is a different, explicit claim
    explicit = build(
        estimate=lambda e: (
            lines_of(e)[2].update(amountUsd="0")
            or e.update(maxAttemptUsd="1.20")
            or lines_of(e)[2].update(basis="no restarts allowed")
        )
    )
    assert not blocked_on(explicit.run(), "unknown_cost")


def test_estimate_must_cover_every_category_exactly_once() -> None:
    def omit(wire_estimate: dict[str, Any]) -> None:
        wire_estimate["lines"] = [x for x in lines_of(wire_estimate) if x["category"] != "restart"]
        wire_estimate["maxAttemptUsd"] = "1.20"

    def twice(wire_estimate: dict[str, Any]) -> None:
        lines_of(wire_estimate).append(dict(lines_of(wire_estimate)[0]))
        wire_estimate["maxAttemptUsd"] = "2.30"

    assert blocked_on(build(estimate=omit).run(), "estimate:category_missing:restart")
    assert blocked_on(build(estimate=twice).run(), "estimate:category_duplicate:compute")


def test_estimate_scope_sums_and_caps_use_exact_decimals() -> None:
    def storage_on_attempt(wire_estimate: dict[str, Any]) -> None:
        lines_of(wire_estimate)[4]["scope"] = "attempt"

    assert blocked_on(build(estimate=storage_on_attempt).run(), "estimate:category_scope:storage")

    def off_by_a_cent(wire_estimate: dict[str, Any]) -> None:
        wire_estimate["maxAttemptUsd"] = "1.49"

    assert blocked_on(build(estimate=off_by_a_cent).run(), "estimate:sum_mismatch:attempt")

    def storage_sum(wire_estimate: dict[str, Any]) -> None:
        wire_estimate["runStorageUsd"] = "0.41"

    assert blocked_on(build(estimate=storage_sum).run(), "estimate:sum_mismatch:run_storage")

    # 0.1 + 0.2 is exactly 0.3 in decimal (and not in binary floating point)
    def tenth(wire_estimate: dict[str, Any]) -> None:
        wire_estimate["maxAttemptUsd"] = "0.3"
        wire_estimate["lines"] = [
            {**lines_of(wire_estimate)[0], "category": "compute", "amountUsd": "0.1"},
            {**lines_of(wire_estimate)[1], "category": "startup", "amountUsd": "0.2"},
            {**lines_of(wire_estimate)[2], "category": "restart", "amountUsd": "0"},
            {**lines_of(wire_estimate)[3], "category": "transfer", "amountUsd": "0"},
            lines_of(wire_estimate)[4],
        ]

    assert not blocked_on(build(estimate=tenth).run(), "sum_mismatch")

    def over_attempt_cap(wire_estimate: dict[str, Any]) -> None:
        lines_of(wire_estimate)[0]["amountUsd"] = "0.81"
        wire_estimate["maxAttemptUsd"] = "1.51"

    assert blocked_on(build(estimate=over_attempt_cap).run(), "estimate:exceeds_attempt_cap")

    def over_shared_cap(wire_estimate: dict[str, Any]) -> None:
        lines_of(wire_estimate)[4]["amountUsd"] = "2.51"
        wire_estimate["runStorageUsd"] = "2.51"

    # each part fits its own bound, but attempt 1.50 + storage 2.51 exceeds the run cap 4.00
    assert blocked_on(build(estimate=over_shared_cap).run(), "estimate:exceeds_run_cap")

    def free(wire_estimate: dict[str, Any]) -> None:
        for line in lines_of(wire_estimate):
            line["amountUsd"] = "0"
        wire_estimate["maxAttemptUsd"] = "0"
        wire_estimate["runStorageUsd"] = "0"

    assert blocked_on(build(estimate=free).run(), "estimate:nonpositive")


def test_estimate_binds_tariff_reviewer_and_validity() -> None:
    def other_tariff(wire_estimate: dict[str, Any]) -> None:
        wire_estimate["tariffRef"] = ref(b"another tariff", "kf.tariff.v1")

    def other_line_tariff(wire_estimate: dict[str, Any]) -> None:
        lines_of(wire_estimate)[1]["tariffRef"] = ref(b"another tariff", "kf.tariff.v1")

    def stranger(wire_estimate: dict[str, Any]) -> None:
        wire_estimate["reviewedBy"] = OTHER

    def short(wire_estimate: dict[str, Any]) -> None:
        wire_estimate["validUntil"] = "2030-01-01T00:30:00.000Z"

    assert blocked_on(build(estimate=other_tariff).run(), "estimate:tariff")
    assert blocked_on(build(estimate=other_line_tariff).run(), "estimate:tariff")
    assert blocked_on(build(estimate=stranger).run(), "estimate:reviewer")
    assert blocked_on(build(estimate=short).run(), "estimate:expires")


def test_packet_spend_caps_must_equal_the_plan_envelope() -> None:
    def wider(wire_packet: dict[str, Any]) -> None:
        wire_packet["maxRunUsd"] = "5.00"

    def narrower(wire_packet: dict[str, Any]) -> None:
        wire_packet["maxAttemptUsd"] = "1.00"

    assert blocked_on(build(packet=wider).run(), "binding:max_run_usd")
    assert blocked_on(build(packet=narrower).run(), "binding:max_attempt_usd")


# -- evidence bytes and bindings --------------------------------------------------------------


def test_every_evidence_document_is_required_and_hash_bound() -> None:
    case = build()
    nothing = case.run(evidence=PreflightEvidence())
    for name in ("manifest", "plan", "capabilities", "estimate", "backup"):
        assert blocked_on(nothing, f"evidence:missing:{name}"), name
    tampered = PreflightEvidence(
        manifest=case.evidence.manifest,
        plan=case.evidence.plan,
        capabilities=(case.evidence.capabilities or b"") + b" ",
        estimate=(case.evidence.estimate or b"") + b" ",
        backup=(case.evidence.backup or b"") + b" ",
    )
    report = case.run(evidence=tampered)
    for name in ("capabilities", "estimate", "backup"):
        assert blocked_on(report, f"evidence:digest:{name}"), name
    swapped = PreflightEvidence(
        manifest=(case.evidence.manifest or b"") + b" ",
        plan=(case.evidence.plan or b"") + b" ",
        capabilities=case.evidence.capabilities,
        estimate=case.evidence.estimate,
        backup=case.evidence.backup,
    )
    report = case.run(evidence=swapped)
    assert blocked_on(report, "evidence:digest:manifest")
    assert blocked_on(report, "evidence:digest:plan")


def test_plan_must_be_the_pinned_canonical_plan() -> None:
    case = build()
    pretty = json.dumps(json.loads(case.evidence.plan or b""), indent=2).encode()
    wire_packet = case.packet_wire | {"planDigest": hashlib.sha256(pretty).hexdigest()}
    reordered = PreflightEvidence(
        manifest=case.evidence.manifest,
        plan=pretty,
        capabilities=case.evidence.capabilities,
        estimate=case.evidence.estimate,
        backup=case.evidence.backup,
    )
    report = preflight(
        PreflightPacket.model_validate(wire_packet),
        CONTEXT,
        evidence=reordered,
        now=NOW,
        closed_gates=CLOSED,
    )
    assert blocked_on(report, "plan:noncanonical")

    def other_tariff(wire_plan: dict[str, Any]) -> None:
        wire_plan["budget"]["tariffRef"] = ref(b"another tariff", "kf.tariff.v1")

    def other_resources(wire_packet: dict[str, Any]) -> None:
        wire_packet["resources"] = wire_packet["resources"] | {"cpuMilli": 500}

    def other_policy(wire_plan: dict[str, Any]) -> None:
        wire_plan["policyRef"] = ref(b"another policy", "kf.policy.v1")

    # the packet in each case is pinned to the plan bytes it was built with, so only the binding
    # between the packet's own values and that plan can block
    assert blocked_on(build(plan=other_tariff).run(), "binding:tariff")
    assert blocked_on(build(packet=other_resources).run(), "binding:resources")
    assert blocked_on(build(plan=other_policy).run(), "binding:policy")


# -- backup, retention and access -------------------------------------------------------------


def test_independent_backup_evidence_must_be_concrete() -> None:
    def unverified(wire_backup: dict[str, Any]) -> None:
        wire_backup["independence"] = "unverified"

    def no_restore(wire_backup: dict[str, Any]) -> None:
        del wire_backup["restoreEvidenceRef"]

    def expiring(wire_backup: dict[str, Any]) -> None:
        wire_backup["validUntil"] = "2030-01-01T00:30:00.000Z"

    def other_project(wire_backup: dict[str, Any]) -> None:
        wire_backup["projectId"] = OTHER

    assert blocked_on(build(backup=unverified).run(), "backup:independence")
    assert blocked_on(build(backup=no_restore).run(), "backup:restore_evidence")
    assert blocked_on(build(backup=expiring).run(), "backup:expires")
    assert blocked_on(build(backup=other_project).run(), "backup:project")
    BackupEvidence.model_validate(json.loads(build().evidence.backup or b""))

    def optional_backup(wire_packet: dict[str, Any]) -> None:
        wire_packet["retention"]["backupRequired"] = False

    assert blocked_on(build(packet=optional_backup).run(), "retention:backup_not_required")


def test_access_context_must_match_and_hold_the_transfer_scope() -> None:
    case = build()
    other = AccessContext(OTHER, ACTOR, frozenset({"read", "extract", "remoteTransfer"}))
    assert blocked_on(case.run(context=other), "access:project")
    weak = AccessContext(PROJECT, ACTOR, frozenset({"read"}))
    report = case.run(context=weak)
    assert blocked_on(report, "access:scope:remoteTransfer")
    assert blocked_on(report, "access:scope:extract")


# -- digest, expiry and the separate grant ----------------------------------------------------


_GRANT_IDS = itertools.count(0xA1)


def grant_for(
    case: Case,
    *,
    grant_id: str | None = None,
    packet_digest_value: str | None = None,
    actor: str = ACTOR,
    granted_at: str = NOW,
    expires_at: str = GRANT_EXPIRY,
    commands: tuple[str, ...] = ("backup", "prepare-run"),
) -> LiveGrant:
    return LiveGrant.model_validate(
        {
            "schemaVersion": "cfoundry.live-grant.v1",
            "grantId": grant_id or f"00000000-0000-0000-0000-{next(_GRANT_IDS):012x}",
            "projectId": PROJECT,
            "packetDigest": packet_digest_value or packet_digest(case.packet),
            "actorId": actor,
            "commands": list(commands),
            "grantedAt": granted_at,
            "expiresAt": expires_at,
        }
    )


def grant_blockers(
    case: Case, grant: LiveGrant, *, now: str = NOW, report: PreflightReport | None = None
) -> list[Reason]:
    return list(live_grant_blockers(case.packet, report or case.run(), grant, CONTEXT, now))


def test_packet_digest_and_authorization_expiry() -> None:
    case = build()
    assert grant_blockers(case, grant_for(case)) == []  # the exact packet is authorized

    def change(wire_packet: dict[str, Any]) -> None:
        wire_packet["region"] = "synthetic-region-2"

    changed = build(packet=change)
    assert packet_digest(changed.packet) != packet_digest(case.packet)
    stale = grant_for(case)  # a grant recorded for the earlier packet
    reasons = grant_blockers(changed, stale)
    assert any("grant:packet_changed" in reason.message for reason in reasons)
    assert grant_blockers(changed, grant_for(changed)) == []  # only a new grant covers it


@pytest.mark.parametrize("name", sorted(CAMEL))
def test_every_packet_field_changes_the_digest(name: str) -> None:
    base = build()
    changes: dict[str, Any] = {
        "provider": "other-provider",
        "region": "other-region",
        "deployment_version": "other.deployment",
        "image_digest": "9" * 64,
        "dependency_lock_digest": "8" * 64,
        "capabilities_ref": ref(b"x1", "kf.x.v1"),
        "tariff_ref": ref(b"x2", "kf.x.v1"),
        "estimate_ref": ref(b"x3", "kf.x.v1"),
        "policy_ref": ref(b"x4", "kf.x.v1"),
        "destination_ref": ref(b"x5", "kf.x.v1"),
        "backup_ref": ref(b"x6", "kf.x.v1"),
        "contract_limits": base.packet_wire["contractLimits"] | {"maxJsonBytes": 1},
        "resources": base.packet_wire["resources"] | {"cpuMilli": 1},
        "max_run_usd": "9",
        "max_attempt_usd": "9",
        "retention": base.packet_wire["retention"] | {"auditRetentionSeconds": 1},
        "expires_at": "2030-01-01T00:59:59.000Z",
    }

    def edit(wire_packet: dict[str, Any]) -> None:
        wire_packet[CAMEL[name]] = changes[name]

    assert packet_digest(build(packet=edit).packet) != packet_digest(base.packet)
    # omitting the value is a change too: a dropped binding can never reuse the old grant
    assert packet_digest(build(packet=drop(CAMEL[name])).packet) != packet_digest(base.packet)


def test_grant_is_bound_to_actor_window_and_a_ready_report() -> None:
    case = build()
    expired = grant_blockers(case, grant_for(case), now=GRANT_EXPIRY)
    assert [reason.code for reason in expired] == ["authorization_expired"]
    early = grant_blockers(case, grant_for(case, granted_at=LATER, expires_at=PACKET_EXPIRY))
    assert [reason.code for reason in early] == ["authorization_expired"]
    stranger = grant_blockers(case, grant_for(case, actor=OTHER))
    assert any("grant:actor" in reason.message for reason in stranger)
    long_lived = grant_blockers(case, grant_for(case, expires_at=PLAN_EXPIRY))
    assert any("grant:outlives_packet" in reason.message for reason in long_lived)
    not_ready = case.run(closed=frozenset())
    assert not not_ready.ready
    blocked = grant_blockers(case, grant_for(case), report=not_ready)
    assert any("grant:not_ready" in reason.message for reason in blocked)
    swapped = PreflightReport(True, (), "0" * 64)  # a report for some other packet
    assert any(
        "grant:report_digest" in reason.message
        for reason in grant_blockers(case, grant_for(case), report=swapped)
    )
    unknown_command = grant_blockers(case, grant_for(case, commands=("restore",)))
    assert any("grant:command" in reason.message for reason in unknown_command)


def test_packet_expiry_is_a_blocker() -> None:
    case = build()
    assert case.run(now=PACKET_EXPIRY).blockers[0].code == "authorization_expired"
    beyond_plan = build(packet=lambda p: p.update(expiresAt="2030-01-01T03:00:00.000Z"))
    assert blocked_on(beyond_plan.run(), "packet:outlives_plan")


def test_parsing_a_packet_cannot_dispatch_or_grant() -> None:
    """Parsing and preflight are pure: no adapter exists to call, and a ready report is data."""
    case = build()
    wire_text = json.dumps(case.packet_wire)
    parsed = PreflightPacket.from_wire(wire_text.encode(), base_limits())
    assert parsed == case.packet
    report = case.run()
    assert report.ready
    assert not hasattr(report, "execute") and not hasattr(report, "grant")
    with pytest.raises(ContractError):
        preflight(object(), CONTEXT)  # type: ignore[arg-type]


# -- the CLI commands ------------------------------------------------------------------------


PILOT_GRANTS = {**ALL_GRANTS, "pilot": ["preflight", "run-pilot"]}


class Cli:
    """A packet and its evidence on disk, in a private operator directory, plus services."""

    def __init__(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: Case | None = None
    ) -> None:
        self.env = Env(tmp_path, monkeypatch, grants=PILOT_GRANTS)
        self.case = case or build()
        self.calls: list[str] = []
        self.write()

    def write(self) -> None:
        private = self.env.private
        evidence = self.case.evidence
        self.packet = write_private(private / "packet.json", wire(self.case.packet_wire))
        self.manifest = write_private(private / "manifest.json", evidence.manifest or b"")
        self.plan = write_private(private / "plan.json", evidence.plan or b"")
        self.capabilities = write_private(
            private / "capabilities.json", evidence.capabilities or b""
        )
        self.estimate = write_private(private / "estimate.json", evidence.estimate or b"")
        self.backup = write_private(private / "backup.json", evidence.backup or b"")

    def services(self, closed: frozenset[str] = CLOSED) -> TrustedServices:
        return TrustedServices(
            evidence_authority=Spy("evidence", self.calls),
            release_authority=Spy("release", self.calls),
            executor=Spy("executor", self.calls),
            transport_grants=lambda *args: self.calls.append("transport") or Spy("g", self.calls),
            connect=self.env.connect,
            clock=lambda: NOW,
            pilot_gates_closed=closed,
        )

    def evidence_args(self) -> list[str]:
        return [
            "--packet", str(self.packet),
            "--manifest", str(self.manifest),
            "--plan", str(self.plan),
            "--capabilities", str(self.capabilities),
            "--estimate", str(self.estimate),
            "--backup-evidence", str(self.backup),
        ]  # fmt: skip

    def grant(self, grant: LiveGrant | None = None) -> Path:
        value = grant or grant_for(self.case)
        return write_private(
            self.env.private / "grant.json", wire(value.model_dump(mode="json", by_alias=True))
        )

    def pilot_steps(self) -> list[dict[str, Any]]:
        """The granted default: a backup, then the exact plan the packet pins."""
        return [BACKUP_STEP, {"command": "prepare-run", "argv": ["--plan", str(self.plan)]}]

    def document(self, name: str, data: bytes) -> Path:
        return write_private(self.env.private / name, data)

    def bound_steps(
        self,
        *,
        plan: bytes | None = None,
        authorization: Edit | None = None,
        plan_ref: dict[str, Any] | None = None,
        evidence_ref: dict[str, Any] | None = None,
        authorization_ref: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """prepare-run, authorize-run and dispatch with files that bind the packet unless edited."""
        plan_bytes = self.case.evidence.plan or b""
        auth_wire: dict[str, Any] = {
            "schemaVersion": "kf.run-authorization.v1",
            "authorizationId": "00000000-0000-0000-0000-000000000009",
            "projectId": PROJECT,
            "runId": RUN,
            "admissionReportDigest": "d" * 64,
            "allowedPlanDigests": [hashlib.sha256(plan_bytes).hexdigest()],
            "maxRunCost": "4.00",
            "maxConcurrentAttempts": 1,
            "actorId": ACTOR,
            "authorizedAt": NOW,
            "expiresAt": GRANT_EXPIRY,
        }
        if authorization:
            authorization(auth_wire)
        auth_bytes = wire(auth_wire)
        plan_path = self.document("step-plan.json", plan if plan is not None else plan_bytes)
        auth_path = self.document("step-authorization.json", auth_bytes)
        plan_file = self.document(
            "step-plan-ref.json", wire(plan_ref or ref(plan_bytes, "kf.execution-plan.v1"))
        )
        auth_file = self.document(
            "step-authorization-ref.json",
            wire(authorization_ref or ref(auth_bytes, "kf.run-authorization.v1")),
        )
        estimate_file = self.document(
            "step-estimate-ref.json", wire(evidence_ref or self.case.packet_wire["estimateRef"])
        )
        return [
            {"command": "prepare-run", "argv": ["--plan", str(plan_path)]},
            {"command": "authorize-run", "argv": ["--authorization", str(auth_path)]},
            {
                "command": "dispatch",
                "argv": [
                    "--plan-ref", str(plan_file),
                    "--authorization-ref", str(auth_file),
                    "--evidence-ref", str(estimate_file),
                    "--asset-id", ASSET,
                ],
            },
        ]  # fmt: skip

    def steps(self, steps: list[dict[str, Any]]) -> Path:
        document = {"schemaVersion": "cfoundry.pilot-steps.v1", "steps": steps}
        return write_private(self.env.private / "steps.json", wire(document))


@pytest.fixture
def cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Cli:
    return Cli(tmp_path, monkeypatch)


def test_preflight_command_reports_ready_without_executing_anything(cli: Cli) -> None:
    before = file_names(cli.env.tmp)
    result = cli.env.invoke("preflight", *cli.evidence_args(), services=cli.services())
    assert result.exit == 0, result.raw
    assert result.payload["outcome"] == "ok" and result.payload["ready"] is True
    assert result.payload["pilotStarted"] is False
    assert result.payload["paidPilot"] == "not_run"
    assert result.payload["packetDigest"] == packet_digest(cli.case.packet)
    assert result.payload["blockers"] == []
    assert cli.calls == []  # no adapter, transport, executor or evidence authority was touched
    assert cli.env.connects == []  # no database either
    assert file_names(cli.env.tmp) == before  # nothing written
    cli.env.assert_redacted(result)


def test_preflight_command_blocks_with_stable_codes_and_every_open_gate(cli: Cli) -> None:
    result = cli.env.invoke("preflight", *cli.evidence_args(), services=cli.services(frozenset()))
    assert result.exit == 3 and result.code == "preflight_blocked"
    assert result.payload["ready"] is False and result.payload["pilotStarted"] is False
    gates = {item["id"]: item for item in result.payload["gates"]}
    assert gates[STAGING_STORE_TRANSFER]["state"] == "open"
    assert gates[SCOPED_EXECUTOR_STORE]["state"] == "open"
    assert gates["manual_retry_decision_binding"]["state"] == "advisory"
    assert result.payload["providerCapability"] == "blocked"
    assert {item["code"] for item in result.payload["blockers"]} == {"unsupported_capability"}
    # the CLI itself never supplies an attestation: only trusted services can close a gate
    assert (
        cli.env.invoke(
            "preflight", *cli.evidence_args(), services=TrustedServices(clock=lambda: NOW)
        ).exit
        == 3
    )
    cli.env.assert_redacted(result)


def test_preflight_command_without_evidence_files_lists_each_missing_document(cli: Cli) -> None:
    result = cli.env.invoke("preflight", "--packet", str(cli.packet), services=cli.services())
    assert result.exit == 3 and result.code == "preflight_blocked"
    texts = " ".join(item["message"] for item in result.payload["blockers"])
    for name in ("manifest", "plan", "capabilities", "estimate", "backup"):
        assert f"evidence:missing:{name}" in texts


def test_preflight_and_run_pilot_need_their_own_grant_and_a_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bare = Cli(tmp_path, monkeypatch)
    env = Env(tmp_path / "bare", monkeypatch, grants=ALL_GRANTS)
    arguments = ["preflight", "--packet", str(bare.packet)]
    denied = env.invoke(*arguments, services=bare.services())
    assert denied.exit == 3 and denied.code == "grant_missing"
    unconfigured = bare.env.invoke(*arguments, config=False)
    assert unconfigured.exit == 3 and unconfigured.code == "config_required"
    pilot = env.invoke(
        "run-pilot", "--packet", str(bare.packet), "--steps", str(bare.packet), "--execute"
    )
    assert pilot.exit == 3 and pilot.code == "grant_missing" and pilot.payload["executed"] is False


class Recorder:
    """Stands in for the existing command runner: records what run-pilot orchestrates."""

    def __init__(self, outcomes: dict[str, Outcome] | None = None) -> None:
        self.ran: list[tuple[str, bool, str | None, dict[str, Any]]] = []
        self.outcomes = outcomes or {}

    def __call__(self, command: Any, args: Any, services: Any) -> Outcome:
        self.ran.append((command.name, args.execute, args.config, vars(args).copy()))
        return self.outcomes.get(command.name, Outcome("ok", None, {"secret": "SECRETMARK"}))


BACKUP_STEP = {"command": "backup", "argv": ["--manifest-output", "manifest-out.json"]}


def pilot(cli: Cli, *extra: str, closed: frozenset[str] = CLOSED, execute: bool = True) -> Any:
    argv = [
        "run-pilot",
        *cli.evidence_args(),
        "--grant",
        str(cli.grant()),
        "--steps",
        str(cli.steps(cli.pilot_steps())),
        *extra,
    ]
    if execute:
        argv.append("--execute")
    return cli.env.invoke(*argv, services=cli.services(closed))


def test_run_pilot_without_execute_is_a_dry_run_that_touches_nothing(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = Recorder()
    monkeypatch.setattr(pilot_cli, "run_command", recorder)
    before = file_names(cli.env.tmp)
    result = pilot(cli, execute=False)
    assert result.exit == 0 and result.payload["outcome"] == "dry_run"
    assert result.payload["executed"] is False
    assert recorder.ran == [] and cli.calls == [] and cli.env.connects == []
    assert file_names(cli.env.tmp) == sorted(
        [*before, "operator/grant.json", "operator/steps.json"]
    )


def test_a_ready_preflight_alone_never_runs_the_pilot(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = Recorder()
    monkeypatch.setattr(pilot_cli, "run_command", recorder)
    ready = cli.env.invoke("preflight", *cli.evidence_args(), services=cli.services())
    assert ready.payload["ready"] is True
    assert recorder.ran == []
    # --execute without a recorded grant still runs nothing
    result = cli.env.invoke(
        "run-pilot",
        *cli.evidence_args(),
        "--steps",
        str(cli.steps(cli.pilot_steps())),
        "--execute",
        services=cli.services(),
    )
    assert result.exit == 3 and result.code == "grant_missing"
    assert recorder.ran == []


def test_run_pilot_runs_existing_commands_in_order_with_execute_and_the_same_config(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = Recorder()
    monkeypatch.setattr(pilot_cli, "run_command", recorder)
    result = pilot(cli)
    assert result.exit == 0, result.raw
    assert [name for name, *_ in recorder.ran] == ["backup", "prepare-run"]
    for _, execute, config, _parsed in recorder.ran:
        assert execute is True and config == str(cli.env.config_path)
    assert recorder.ran[0][3]["manifest_output"] == "manifest-out.json"
    assert result.payload["outcome"] == "ok" and result.payload["executed"] is True
    assert [step["command"] for step in result.payload["steps"]] == ["backup", "prepare-run"]
    # steps ran; that is not acceptance, and inner payloads are never echoed
    assert result.payload["paidPilotAcceptance"] == "not_established"
    assert "SECRETMARK" not in result.raw
    cli.env.assert_redacted(result)


def test_run_pilot_halts_at_the_first_unsettled_step(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = Recorder({"backup": Outcome("blocked", "adapter_unavailable")})
    monkeypatch.setattr(pilot_cli, "run_command", recorder)
    result = pilot(cli)
    assert result.exit == 3 and result.code == "adapter_unavailable"
    assert [name for name, *_ in recorder.ran] == ["backup"]
    assert result.payload["haltedAt"] == 0
    failing = Recorder({"backup": Outcome("failed", "unavailable")})
    monkeypatch.setattr(pilot_cli, "run_command", failing)
    again = pilot(cli)
    assert again.exit == 1 and again.code == "unavailable"
    assert [name for name, *_ in failing.ran] == ["backup"]


def test_changed_packet_requires_new_grant(cli: Cli, monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = Recorder()
    monkeypatch.setattr(pilot_cli, "run_command", recorder)
    first = pilot(cli)
    assert first.exit == 0
    stale = cli.grant()  # recorded for the packet as it is now
    cli.case = build(packet=lambda wire_packet: wire_packet.update(region="synthetic-region-2"))
    cli.write()
    recorder.ran.clear()
    argv = [
        "run-pilot",
        *cli.evidence_args(),
        "--grant",
        str(stale),
        "--steps",
        str(cli.steps(cli.pilot_steps())),
        "--execute",
    ]
    second = cli.env.invoke(*argv, services=cli.services())
    assert second.exit == 3 and second.code == "forbidden"
    assert recorder.ran == []
    renewed = cli.grant(grant_for(cli.case))
    argv[argv.index(str(stale))] = str(renewed)
    assert cli.env.invoke(*argv, services=cli.services()).exit == 0
    assert [name for name, *_ in recorder.ran] == ["backup", "prepare-run"]


def test_run_pilot_refuses_an_expired_grant_and_unready_preflight(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = Recorder()
    monkeypatch.setattr(pilot_cli, "run_command", recorder)
    expired = cli.grant(
        grant_for(
            cli.case, granted_at="2029-12-31T00:00:00.000Z", expires_at="2029-12-31T01:00:00.000Z"
        )
    )
    argv = [
        "run-pilot",
        *cli.evidence_args(),
        "--grant",
        str(expired),
        "--steps",
        str(cli.steps(cli.pilot_steps())),
        "--execute",
    ]
    result = cli.env.invoke(*argv, services=cli.services())
    assert result.exit == 3 and result.code == "authorization_expired"
    unready = pilot(cli, closed=frozenset())
    assert unready.exit == 3 and unready.code == "preflight_blocked"
    assert recorder.ran == []


def _wrong_commands(cli: Cli) -> list[dict[str, Any]]:
    return [{"command": "backup", "argv": ["--manifest-output", "m.json"]}]  # not what was granted


def _extra_dispatch(cli: Cli) -> list[dict[str, Any]]:
    return [*cli.pilot_steps(), {"command": "dispatch", "argv": []}]


def _unknown_command(cli: Cli) -> list[dict[str, Any]]:
    return [{"command": "restore", "argv": ["--manifest", "m.json"]}, cli.pilot_steps()[1]]


def _reordered(cli: Cli) -> list[dict[str, Any]]:
    return [cli.pilot_steps()[1], BACKUP_STEP]  # order is part of the grant


def _bad_arguments(cli: Cli) -> list[dict[str, Any]]:
    return [{"command": "backup", "argv": ["--bogus"]}, cli.pilot_steps()[1]]


@pytest.mark.parametrize(
    "build_steps", [_wrong_commands, _extra_dispatch, _unknown_command, _reordered, _bad_arguments]
)
def test_run_pilot_steps_must_match_the_grant_and_existing_command_arguments(
    cli: Cli, monkeypatch: pytest.MonkeyPatch, build_steps: Callable[[Cli], list[dict[str, Any]]]
) -> None:
    recorder = Recorder()
    monkeypatch.setattr(pilot_cli, "run_command", recorder)
    argv = [
        "run-pilot",
        *cli.evidence_args(),
        "--grant",
        str(cli.grant()),
        "--steps",
        str(cli.steps(build_steps(cli))),
        "--execute",
    ]
    result = cli.env.invoke(*argv, services=cli.services())
    assert result.exit in (2, 3, 1), result.raw
    assert result.payload["outcome"] in {"blocked", "failed"}
    assert recorder.ran == []


def test_run_pilot_never_relaxes_the_manual_retry_or_double_dispatch_rules(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = Recorder()
    monkeypatch.setattr(pilot_cli, "run_command", recorder)
    dispatch = [
        "--plan-ref", "p.json", "--authorization-ref", "a.json", "--evidence-ref", "e.json",
        "--asset-id", "00000000-0000-0000-0000-000000000004",
    ]  # fmt: skip
    retried = [{"command": "dispatch", "argv": [*dispatch, "--manual-retry", "r.json"]}]
    twice = [{"command": "dispatch", "argv": dispatch}] * 2
    for steps in (retried, twice):
        commands = tuple(step["command"] for step in steps)
        grant = cli.grant(grant_for(cli.case, commands=commands))
        argv = [
            "run-pilot",
            *cli.evidence_args(),
            "--grant",
            str(grant),
            "--steps",
            str(cli.steps(steps)),
            "--execute",
        ]
        result = cli.env.invoke(*argv, services=cli.services())
        assert result.exit == 3 and result.code == "forbidden", steps
    assert recorder.ran == []


def test_run_pilot_through_the_real_commands_blocks_without_adapters(cli: Cli) -> None:
    """No recorder: the real backup command refuses before any database or network contact."""
    steps = [BACKUP_STEP]
    grant = cli.grant(grant_for(cli.case, commands=("backup",)))
    argv = [
        "run-pilot",
        *cli.evidence_args(),
        "--grant",
        str(grant),
        "--steps",
        str(cli.steps(steps)),
        "--execute",
    ]
    services = TrustedServices(
        connect=cli.env.connect, clock=lambda: NOW, pilot_gates_closed=CLOSED
    )
    result = cli.env.invoke(*argv, services=services)
    assert result.exit == 3 and result.payload["outcome"] == "blocked", result.raw
    assert result.payload["haltedAt"] == 0
    assert cli.env.connects == []
    cli.env.assert_redacted(result)


# -- fix round 1: steps are bound to the preflighted packet; a grant is single use ----------------

BOUND_COMMANDS = ("prepare-run", "authorize-run", "dispatch")


def bound_argv(cli: Cli, steps: list[dict[str, Any]], grant: LiveGrant | None = None) -> list[str]:
    commands = tuple(step["command"] for step in steps)
    value = grant or grant_for(cli.case, commands=commands)
    return [
        "run-pilot",
        *cli.evidence_args(),
        "--grant",
        str(cli.grant(value)),
        "--steps",
        str(cli.steps(steps)),
        "--execute",
    ]


def test_run_pilot_runs_steps_whose_files_bind_the_packet(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = Recorder()
    monkeypatch.setattr(pilot_cli, "run_command", recorder)
    result = cli.env.invoke(*bound_argv(cli, cli.bound_steps()), services=cli.services())
    assert result.exit == 0, result.raw
    assert [name for name, *_ in recorder.ran] == list(BOUND_COMMANDS)


def _other_plan(cli: Cli) -> list[dict[str, Any]]:
    return cli.bound_steps(plan=b"another plan that never passed the packet checks")


def _auth_for_other_plan(cli: Cli) -> list[dict[str, Any]]:
    return cli.bound_steps(authorization=lambda a: a.update(allowedPlanDigests=["e" * 64]))


def _auth_over_cap(cli: Cli) -> list[dict[str, Any]]:
    return cli.bound_steps(authorization=lambda a: a.update(maxRunCost="4.01"))


def _auth_outlives_packet(cli: Cli) -> list[dict[str, Any]]:
    return cli.bound_steps(authorization=lambda a: a.update(expiresAt="2030-01-02T00:00:00.000Z"))


def _auth_other_run(cli: Cli) -> list[dict[str, Any]]:
    return cli.bound_steps(authorization=lambda a: a.update(runId=OTHER))


def _auth_other_actor(cli: Cli) -> list[dict[str, Any]]:
    return cli.bound_steps(authorization=lambda a: a.update(actorId=OTHER))


def _dispatch_other_plan(cli: Cli) -> list[dict[str, Any]]:
    return cli.bound_steps(plan_ref=ref(b"another plan", "kf.execution-plan.v1"))


def _dispatch_other_estimate(cli: Cli) -> list[dict[str, Any]]:
    return cli.bound_steps(evidence_ref=ref(b"an estimate nobody reviewed", "kfx.cost-estimate.v1"))


def _dispatch_other_authorization(cli: Cli) -> list[dict[str, Any]]:
    return cli.bound_steps(authorization_ref=ref(b"another grant", "kf.run-authorization.v1"))


def _dispatch_without_authorize(cli: Cli) -> list[dict[str, Any]]:
    steps = cli.bound_steps()
    return [steps[0], steps[2]]  # nothing in this pilot binds the authorization it dispatches


@pytest.mark.parametrize(
    "build_steps",
    [
        _other_plan,
        _auth_for_other_plan,
        _auth_over_cap,
        _auth_outlives_packet,
        _auth_other_run,
        _auth_other_actor,
        _dispatch_other_plan,
        _dispatch_other_estimate,
        _dispatch_other_authorization,
        _dispatch_without_authorize,
    ],
)
def test_run_pilot_refuses_step_arguments_the_packet_did_not_preflight(
    cli: Cli, monkeypatch: pytest.MonkeyPatch, build_steps: Callable[[Cli], list[dict[str, Any]]]
) -> None:
    recorder = Recorder()
    monkeypatch.setattr(pilot_cli, "run_command", recorder)
    result = cli.env.invoke(*bound_argv(cli, build_steps(cli)), services=cli.services())
    assert result.exit == 3 and result.code == "forbidden", result.raw
    assert recorder.ran == []  # refused before any step, and so before any paid effect


def used_grants(cli: Cli) -> list[str]:
    folder = cli.env.private / "pilot-used-grants"
    return sorted(path.name for path in folder.iterdir()) if folder.is_dir() else []


def test_a_live_grant_is_single_use_across_run_pilot_invocations(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = Recorder()
    monkeypatch.setattr(pilot_cli, "run_command", recorder)
    argv = bound_argv(
        cli, cli.pilot_steps(), grant_for(cli.case, commands=("backup", "prepare-run"))
    )
    first = cli.env.invoke(*argv, services=cli.services())
    assert first.exit == 0, first.raw
    assert len(used_grants(cli)) == 1
    recorder.ran.clear()
    again = cli.env.invoke(*argv, services=cli.services())  # same grant inside its window
    assert again.exit == 3 and again.code == "forbidden", again.raw
    assert recorder.ran == []
    fresh = cli.env.invoke(*bound_argv(cli, cli.pilot_steps()), services=cli.services())
    assert fresh.exit == 0  # a newly recorded grant is a new authorization


def test_a_halted_or_failed_pilot_still_consumes_its_grant(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = Recorder({"backup": Outcome("failed", "unavailable")})
    monkeypatch.setattr(pilot_cli, "run_command", recorder)
    argv = bound_argv(
        cli, cli.pilot_steps(), grant_for(cli.case, commands=("backup", "prepare-run"))
    )
    assert cli.env.invoke(*argv, services=cli.services()).exit == 1
    recorder.ran.clear()
    again = cli.env.invoke(*argv, services=cli.services())
    assert again.exit == 3 and again.code == "forbidden"
    assert recorder.ran == []  # no paid automatic retry by rerunning the same grant


def test_the_grant_is_marked_used_before_the_first_step_runs(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[list[str]] = []

    def inspect(command: Any, args: Any, services: Any) -> Outcome:
        seen.append(used_grants(cli))
        return Outcome("failed", "unavailable")  # even a crash after this point cannot be rerun

    monkeypatch.setattr(pilot_cli, "run_command", inspect)
    cli.env.invoke(*bound_argv(cli, cli.pilot_steps()), services=cli.services())
    assert [len(names) for names in seen] == [1]


def test_a_refused_pilot_does_not_consume_its_grant(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = Recorder()
    monkeypatch.setattr(pilot_cli, "run_command", recorder)
    argv = bound_argv(
        cli, cli.pilot_steps(), grant_for(cli.case, commands=("backup", "prepare-run"))
    )
    blocked = cli.env.invoke(*argv, services=cli.services(frozenset()))
    assert blocked.code == "preflight_blocked" and used_grants(cli) == []
    assert cli.env.invoke(*argv, services=cli.services()).exit == 0  # nothing was spent


def test_an_untrusted_marker_location_blocks_before_any_step(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = Recorder()
    monkeypatch.setattr(pilot_cli, "run_command", recorder)
    folder = cli.env.private / "pilot-used-grants"
    folder.mkdir(mode=0o700)
    folder.chmod(0o777)  # anyone could delete a marker and replay the grant
    result = cli.env.invoke(*bound_argv(cli, cli.pilot_steps()), services=cli.services())
    assert result.exit == 3 and result.payload["outcome"] == "blocked", result.raw
    assert recorder.ran == []


def test_the_grant_window_and_packet_expiry_are_rechecked_before_each_step(
    cli: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = {"now": NOW}

    def advance(command: Any, args: Any, services: Any) -> Outcome:
        ran.append(command.name)
        clock["now"] = LATER  # past the grant window (GRANT_EXPIRY) but inside the packet's
        return Outcome("ok", None, {})

    ran: list[str] = []
    monkeypatch.setattr(pilot_cli, "run_command", advance)
    services = dataclasses.replace(cli.services(), clock=lambda: clock["now"])
    result = cli.env.invoke(*bound_argv(cli, cli.pilot_steps()), services=services)
    assert ran == ["backup"]  # the second step never starts
    assert result.exit == 3 and result.code == "authorization_expired", result.raw
    assert result.payload["haltedAt"] == 1
    assert result.payload["paidPilotAcceptance"] == "not_established"


def test_the_report_states_the_estimate_covers_one_attempt_plus_storage() -> None:
    report = build().run()
    gates = {item.gate_id: item for item in report.gates}
    item = gates["estimate_covers_one_attempt"]
    assert item.state == "advisory" and item.blocking is False
    assert "one attempt" in item.detail and "maxAttemptsPerOperation" in item.detail


def test_packet_files_are_digest_stable_wire_documents() -> None:
    case = build()
    first = packet_digest(case.packet)
    again = packet_digest(PreflightPacket.from_wire(wire(case.packet_wire), base_limits()))
    assert first == again
