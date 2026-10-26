"""Dagster asset partitions that call the same durable ledger controls as the CLI.

The ledger owns reservations, claims, pauses, acceptance and selection. This module only schedules
intent: it asks an injected, stateless `ExecutionControl` facade for the ledger's view of one
exact operation, reconciles unresolved attempts before ever asking for a new claim, and records an
asset materialization only after the ledger shows a verified selected result. A Dagster run id,
partition key or earlier materialization never substitutes for operation, plan or attempt
identity. Runs are in process; no daemon, webserver or remote service is started here.
"""

# No `from __future__ import annotations`: Dagster inspects the context annotation as a class.

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

import dagster as dg
from pydantic import TypeAdapter, ValidationError

from conscience_foundry.contracts.accounting import OperationResultRecord
from conscience_foundry.contracts.common import ContractError, Digest, Id
from conscience_foundry.contracts.execution import AttemptState
from conscience_foundry.contracts.project import ProjectConfig

PARTITIONS_NAME = "kf_f1_asset_partitions"
JOB_NAME = "kf_f1_partition_job"
ADMISSION = "kf_admission"
PROCESSING = "kf_processing"
RECONCILIATION = "kf_reconciliation"
RELEASE_CANDIDATE = "kf_release_candidate"
GROUP_NAME = "kf_f1"
PAID_STAGES = (PROCESSING, RECONCILIATION)

_ID = TypeAdapter(Id)
_DIGEST = TypeAdapter(Digest)
_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_TERMINAL: frozenset[AttemptState] = frozenset({"succeeded", "failed", "cancelled"})


class RetryIntent(dg.Config):
    """Per-run operator intent: a run never pays again after a failed attempt by default."""

    retry_after_failure: bool = False


@dataclass(frozen=True)
class PartitionIdentity:
    """The stable scheduling tuple; never an operation, cache or authority identity."""

    project_id: Id
    asset_id: Id
    extraction_spec_digest: Digest


@dataclass(frozen=True)
class AdmissionView:
    admitted: bool
    admission_report_digest: Digest | None


@dataclass(frozen=True)
class AttemptView:
    attempt_id: Id
    plan_id: Id
    state: AttemptState


@dataclass(frozen=True)
class OperationView:
    """Ledger state of the partition's current exact operation (never the last materialization)."""

    operation_key: Digest
    paused: bool
    held: bool
    attempts: tuple[AttemptView, ...]
    selected: OperationResultRecord | None


@dataclass(frozen=True)
class CandidateView:
    release_digest: Digest
    operation_key: Digest


class ExecutionControl(Protocol):
    """Thin injected facade over the T8/T13/T14 functions; it holds no state of its own.

    Every method delegates to the ledger-gated functions the CLI uses, so authorization,
    reservation, concurrency, pause and retry rules apply identically to a Dagster run.
    `reconcile` observes an existing attempt and never creates one. `release_candidate` returns
    `None` until the ledger holds the accepted review that T14 requires; approval is never
    produced by materializing an asset.
    """

    def admission(self, partition: PartitionIdentity) -> AdmissionView: ...
    def operation(self, partition: PartitionIdentity) -> OperationView: ...
    def dispatch(self, partition: PartitionIdentity) -> AttemptView: ...
    def reconcile(
        self, partition: PartitionIdentity, attempt_id: Id
    ) -> OperationResultRecord | None: ...
    def release_candidate(self, partition: PartitionIdentity) -> CandidateView | None: ...


def partition_key(project_id: Id, asset_id: Id, extraction_spec_digest: Digest) -> str:
    """Encode the tuple unambiguously: validated fixed-form components never contain ':'."""
    try:
        parts = (
            _ID.validate_python(project_id),
            _ID.validate_python(asset_id),
            _DIGEST.validate_python(extraction_spec_digest),
        )
    except ValidationError:
        raise ContractError("invalid_schema") from None
    return ":".join(parts)


def parse_partition_key(key: str) -> PartitionIdentity:
    parts = key.split(":") if type(key) is str else []
    if len(parts) != 3:
        raise ContractError("invalid_schema")
    project_id, asset_id, digest = parts
    if partition_key(project_id, asset_id, digest) != key:
        raise ContractError("invalid_schema")
    return PartitionIdentity(project_id, asset_id, digest)


def _fail(stage: str, code: str) -> dg.Failure:
    """A stable, redacted, non-retryable failure; never a raw message or provider payload."""
    return dg.Failure(
        description=f"{stage}: {code}",
        metadata={"kf_stage": stage, "kf_code": code},
        allow_retries=False,
    )


def _guard[Result](stage: str, call: Callable[[], Result]) -> Result:
    try:
        return call()
    except dg.Failure:
        raise
    except ContractError as error:
        code = error.code if _CODE.fullmatch(error.code) else "control_error"
        raise _fail(stage, code) from None
    except Exception:
        raise _fail(stage, "control_unavailable") from None


def _partition(key: str, config: ProjectConfig, stage: str) -> PartitionIdentity:
    try:
        partition = parse_partition_key(key)
    except ContractError:
        raise _fail(stage, "invalid_partition") from None
    if partition.project_id != config.project_id:
        raise _fail(stage, "forbidden")
    return partition


def _view(control: ExecutionControl, partition: PartitionIdentity, stage: str) -> OperationView:
    view = _guard(stage, lambda: control.operation(partition))
    if (
        type(view) is not OperationView
        or type(view.attempts) is not tuple
        or not all(type(attempt) is AttemptView for attempt in view.attempts)
        or not _digest(view.operation_key)
    ):
        raise _fail(stage, "control_error")
    return view


def _digest(value: object) -> bool:
    try:
        _DIGEST.validate_python(value)
    except ValidationError:
        return False
    return True


def _verified(
    view: OperationView, partition: PartitionIdentity, stage: str
) -> tuple[OperationResultRecord, AttemptView]:
    """The ledger's selected result for this exact operation, or a refusal to materialize."""
    record = view.selected
    if view.held:
        raise _fail(stage, "integrity_hold")
    if record is None:
        raise _fail(stage, "result_unverified")
    if type(record) is not OperationResultRecord:
        raise _fail(stage, "control_error")
    if record.project_id != partition.project_id or record.operation_key != view.operation_key:
        raise _fail(stage, "result_unverified")
    if record.outcome == "conflict":
        raise _fail(stage, "integrity_hold")
    attempts = [item for item in view.attempts if item.attempt_id == record.attempt_id]
    if len(attempts) != 1 or attempts[0].state != "succeeded":
        raise _fail(stage, "result_unverified")
    return record, attempts[0]


def _identity(partition: PartitionIdentity, stage: str) -> dict[str, str]:
    return {
        "kf_stage": stage,
        "kf_project_id": partition.project_id,
        "kf_asset_id": partition.asset_id,
        "kf_extraction_spec_digest": partition.extraction_spec_digest,
    }


def _materialized(
    partition: PartitionIdentity,
    stage: str,
    view: OperationView,
    record: OperationResultRecord,
    attempt: AttemptView,
) -> dict[str, str]:
    return _identity(partition, stage) | {
        "kf_operation_key": view.operation_key,
        "kf_plan_id": attempt.plan_id,
        "kf_attempt_id": attempt.attempt_id,
        "kf_result_digest": record.selected_result_ref.digest,
        "kf_selection_outcome": record.outcome,
    }


def _observe(
    control: ExecutionControl, partition: PartitionIdentity, attempt_id: Id, stage: str
) -> None:
    # The returned selection record is deliberately ignored: the next ledger read is the
    # authority for what, if anything, is selected.
    _guard(stage, lambda: control.reconcile(partition, attempt_id))


def _settle(
    control: ExecutionControl,
    partition: PartitionIdentity,
    stage: str,
    *,
    may_dispatch: bool,
    retry_after_failure: bool = False,
) -> dict[str, str]:
    view = _view(control, partition, stage)
    # Existing attempts are observed first. A reconcile is never a fresh dispatch, so a rerun or
    # backfill of an unknown outcome cannot resubmit or reserve again.
    pending = [
        item
        for item in view.attempts
        if item.state not in _TERMINAL or (item.state == "succeeded" and view.selected is None)
    ]
    for item in pending:
        _observe(control, partition, item.attempt_id, stage)
    if pending:
        view = _view(control, partition, stage)
    if view.held or view.selected is not None:
        record, attempt = _verified(view, partition, stage)
        return _materialized(partition, stage, view, record, attempt)
    if not any(item.state not in _TERMINAL for item in view.attempts):
        if not may_dispatch:
            raise _fail(stage, "no_attempt" if not view.attempts else "no_verified_result")
        if view.paused:
            raise _fail(stage, "paused")
        if not retry_after_failure and any(item.state == "failed" for item in view.attempts):
            # Includes an attempt this very run just reconciled to failed: paying again after a
            # proven failure is an operator decision, never a side effect of a rerun or backfill.
            raise _fail(stage, "retry_requires_intent")
        # The ledger repeats every gate (pause, authorization, reservation, concurrency, duplicate
        # risk) inside this call; the view above is only an early, advisory refusal.
        fresh = _guard(stage, lambda: control.dispatch(partition))
        if type(fresh) is not AttemptView:
            raise _fail(stage, "control_error")
        _observe(control, partition, fresh.attempt_id, stage)
        view = _view(control, partition, stage)
        if view.held or view.selected is not None:
            record, attempt = _verified(view, partition, stage)
            return _materialized(partition, stage, view, record, attempt)
    if any(item.state == "succeeded" for item in view.attempts):
        raise _fail(stage, "result_unverified")  # a worker status alone is not verification
    if any(item.state == "unknown_outcome" for item in view.attempts):
        raise _fail(stage, "unresolved_attempt")
    raise _fail(stage, "result_pending")


def build_definitions(control: ExecutionControl, config: ProjectConfig) -> dg.Definitions:
    """Four partitioned assets over one injected control; no asset per token or chunk."""
    partitions = dg.DynamicPartitionsDefinition(name=PARTITIONS_NAME)
    no_retry = dg.RetryPolicy(max_retries=0)  # paid stages: Dagster never retries on its own

    def stage_asset(
        name: str,
        deps: tuple[str, ...],
        body: Callable[[PartitionIdentity, bool], Mapping[str, str]],
        description: str,
    ) -> dg.AssetsDefinition:
        project = config  # the asset below takes Dagster's own `config` parameter

        def asset() -> Callable[..., dg.AssetsDefinition]:
            return dg.asset(
                name=name,
                deps=list(deps),
                partitions_def=partitions,
                group_name=GROUP_NAME,
                description=description,
                retry_policy=no_retry if name in PAID_STAGES else None,
            )

        if name != PROCESSING:

            @asset()
            def stage(context: dg.AssetExecutionContext) -> dg.MaterializeResult[None]:
                return dg.MaterializeResult(
                    metadata=dict(body(_partition(context.partition_key, config, name), False))
                )

            return stage

        @asset()
        def configurable_stage(
            context: dg.AssetExecutionContext, config: RetryIntent
        ) -> dg.MaterializeResult[None]:
            partition = _partition(context.partition_key, project, name)
            return dg.MaterializeResult(
                metadata=dict(body(partition, config.retry_after_failure))
            )

        return configurable_stage

    def admission(partition: PartitionIdentity, _retry: bool) -> Mapping[str, str]:
        view = _guard(ADMISSION, lambda: control.admission(partition))
        if type(view) is not AdmissionView or view.admitted is not True:
            raise _fail(ADMISSION, "not_admitted")
        if view.admission_report_digest is None or not _digest(view.admission_report_digest):
            raise _fail(ADMISSION, "control_error")
        return _identity(partition, ADMISSION) | {
            "kf_admission_report_digest": view.admission_report_digest
        }

    def processing(partition: PartitionIdentity, retry_after_failure: bool) -> Mapping[str, str]:
        return _settle(
            control,
            partition,
            PROCESSING,
            may_dispatch=True,
            retry_after_failure=retry_after_failure,
        )

    def reconciliation(partition: PartitionIdentity, _retry: bool) -> Mapping[str, str]:
        return _settle(control, partition, RECONCILIATION, may_dispatch=False)

    def release_candidate(partition: PartitionIdentity, _retry: bool) -> Mapping[str, str]:
        view = _view(control, partition, RELEASE_CANDIDATE)
        record, attempt = _verified(view, partition, RELEASE_CANDIDATE)
        candidate = _guard(RELEASE_CANDIDATE, lambda: control.release_candidate(partition))
        if candidate is None:
            raise _fail(RELEASE_CANDIDATE, "approval_required")
        if (
            type(candidate) is not CandidateView
            or candidate.operation_key != view.operation_key
            or not _digest(candidate.release_digest)
        ):
            raise _fail(RELEASE_CANDIDATE, "result_unverified")
        return _materialized(partition, RELEASE_CANDIDATE, view, record, attempt) | {
            "kf_release_digest": candidate.release_digest
        }

    assets = [
        stage_asset(ADMISSION, (), admission, "Ledger-registered admission for the asset."),
        stage_asset(
            PROCESSING,
            (ADMISSION,),
            processing,
            "Reconcile, or claim through the ledger, then record the verified selected result.",
        ),
        stage_asset(
            RECONCILIATION,
            (ADMISSION,),
            reconciliation,
            "Observe existing attempts only; never dispatches.",
        ),
        stage_asset(
            RELEASE_CANDIDATE,
            (PROCESSING,),
            release_candidate,
            "Release candidate assembled by the ledger after accepted review; not an approval.",
        ),
    ]
    job = dg.define_asset_job(
        JOB_NAME,
        selection=dg.AssetSelection.assets(*assets),
        description="All F1 stages for the selected partitions, in process, without retries.",
        tags={"dagster/max_retries": "0"},
        executor_def=dg.in_process_executor,
    )
    return dg.Definitions(assets=assets, jobs=[job])
