"""Executor over an injected Modal SDK; fail-closed, no automatic retries, no deployment.

Trust model:

* The SDK is an injected protocol. Importing this module never imports the SDK,
  deploys an app or touches the network; building the real SDK wrapper, the
  deployment and its credentials are separately authorized live actions.
* ``submit`` refuses, before any SDK call, unless the exact deployment is
  pinned (app, function, image, code, SDK, destination) and a capability record
  evidences every bound the plan relies on (see ``capabilities``). Function
  retries set to zero is recorded as insufficient on its own
  (``PLATFORM_RETRY_CAVEAT``): readiness is never inferred from it.
* A spawn is attempted at most once per attempt per executor. A lost response,
  an SDK exception or a missing call id is ``Submission(None, None)``: an unknown
  outcome the control side must reconcile, never a proven failure and never a
  reason to spawn again. The in-memory claim guard is only this instance's
  defence; the durable dispatch claim lives in the control-side ledger.
* ``observe``/``cancel`` map what the SDK reports to attempt states without
  inventing certainty. A timeout, expired output, SDK error or unreadable result
  is ``unknown_outcome`` (``cancel_requested`` while a cancel stands): expired
  output does not mean no work happened or nothing is owed. A cancel request is
  only a request until the SDK reports the call cancelled.
* Every observation carries a stored evidence record that names only the
  attempt, the call id and the states; no grant material, payload or provider
  response is retained or logged. Independent attestation of that evidence stays
  with the control-side evidence authority.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Literal, Protocol

from pydantic import TypeAdapter

from conscience_foundry.contracts.common import (
    ContractError,
    ContractLimits,
    Digest,
    Instant,
    Ref,
)
from conscience_foundry.contracts.execution import (
    AttemptState,
    ExecutionPlan,
    ResultManifest,
    StageAttempt,
)
from conscience_foundry.execution.capabilities import CapabilityRecord, validate_capabilities
from conscience_foundry.execution.ports import Observation, Submission, TransportGrants
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.local import ObjectStore

_INSTANT = TypeAdapter(Instant)
OBSERVATION_SCHEMA = "kf.modal-call-observation.v1"


@dataclass(frozen=True)
class ModalPin:
    """The one deployment this executor may call; every field is operator supplied."""

    app_name: str
    function_name: str
    deployment_version: str
    image_digest: Digest
    code_digest: Digest
    sdk_version: str
    destination_id: str


@dataclass(frozen=True)
class ModalPoll:
    """What a wrapper around the real SDK reports for one function call, never raw payloads.

    The wrapper owns mapping SDK exceptions onto these states. ``completed`` carries the
    function's return value: the JSON reference of the result manifest.
    """

    state: Literal[
        "pending", "completed", "remote_error", "cancelled", "timed_out", "output_expired"
    ]
    result: bytes | None = field(default=None, repr=False)


class ModalSdk(Protocol):
    def spawn(self, function: str, payload: Mapping[str, object]) -> str: ...
    def poll(self, call_id: str) -> ModalPoll: ...
    def cancel(self, call_id: str) -> None: ...


EvidenceSink = Callable[[str, bytes], Ref]
"""Stores a private evidence record under a schema id and returns its reference."""


@dataclass
class ModalExecutor:
    sdk: ModalSdk = field(repr=False)
    pin: ModalPin
    record: CapabilityRecord = field(repr=False)
    execution_config_digest: Digest
    store: ObjectStore = field(repr=False)
    access: AccessContext
    limits: ContractLimits = field(repr=False)
    clock: Callable[[], Instant] = field(repr=False)
    evidence: EvidenceSink = field(repr=False)
    _claimed: set[str] = field(default_factory=set, init=False, repr=False)

    # -- submit ---------------------------------------------------------------------

    def submit(
        self, plan: ExecutionPlan, attempt: StageAttempt, grants: TransportGrants
    ) -> Submission:
        plan_bytes = self._admit(plan, attempt, grants)
        # Claimed before the call: whatever happens next, this instance never spawns twice.
        self._claimed.add(attempt.attempt_id)
        payload: dict[str, object] = {
            "plan_bytes": plan_bytes,
            "attempt_bytes": attempt.model_dump_json(by_alias=True, exclude_none=True).encode(),
            "grants": {
                "project_id": grants.project_id,
                "plan_digest": grants.plan_digest,
                "attempt_id": grants.attempt_id,
                "destination_id": grants.destination_id,
                "expires_at": grants.expires_at,
                "material": list(grants.material),
                "output_scope": grants.output_scope,
            },
        }
        try:
            call_id = self.sdk.spawn(self.pin.function_name, payload)
        except Exception:
            return Submission(None, None)
        if type(call_id) is not str or not call_id:
            return Submission(None, None)
        return Submission(call_id, True)

    def _admit(self, plan: ExecutionPlan, attempt: StageAttempt, grants: TransportGrants) -> bytes:
        if type(plan) is not ExecutionPlan or type(attempt) is not StageAttempt:
            raise ContractError("invalid_schema")
        if type(grants) is not TransportGrants:
            raise ContractError("forbidden")
        validate_capabilities(self.record, plan)
        pin, record = self.pin, self.record
        if (
            record.deployment_version != pin.deployment_version
            or record.image_digest != pin.image_digest
            or record.code_digest != pin.code_digest
            or record.sdk_version != pin.sdk_version
        ):
            raise ContractError("unsupported_capability")  # evidence is for another deployment
        plan_bytes = plan.model_dump_json(by_alias=True, exclude_none=True).encode()
        if (
            plan.execution_config_ref.digest != self.execution_config_digest
            or grants.destination_id != pin.destination_id
            or grants.project_id != plan.project_id
            or grants.attempt_id != attempt.attempt_id
            or grants.plan_digest != hashlib.sha256(plan_bytes).hexdigest()
            or attempt.project_id != plan.project_id
            or attempt.plan_id != plan.plan_id
            or attempt.operation_key != plan.operation_key
            or attempt.state != "dispatching"
            or attempt.remote_call_id is not None
        ):
            raise ContractError("forbidden")
        if attempt.attempt_id in self._claimed:
            raise ContractError("dispatch_unknown")  # never spawn again without reconciliation
        try:
            _INSTANT.validate_python(grants.expires_at)
        except Exception:
            raise ContractError("forbidden") from None
        deadline = min(
            plan.expires_at, plan.budget.valid_until, grants.expires_at, record.valid_until
        )
        if self._now() >= deadline:
            raise ContractError("authorization_expired")
        return plan_bytes

    def _now(self) -> Instant:
        try:
            now = self.clock()
            _INSTANT.validate_python(now)
        except Exception:
            raise ContractError("unavailable") from None
        return now

    # -- observe / cancel -----------------------------------------------------------

    def observe(self, attempt: StageAttempt) -> Observation:
        return self._observe(attempt, action="observe")

    def cancel(self, attempt: StageAttempt) -> Observation:
        call_id = attempt.remote_call_id
        if not call_id:
            return self._finish("cancel", attempt, "no_call_id", "unknown_outcome", None)
        try:
            self.sdk.cancel(call_id)
        except Exception:
            # The request may or may not have been delivered: uncertain, never "cancelled".
            raise ContractError("dispatch_unknown") from None
        return self._observe(attempt, action="cancel")

    def _observe(
        self, attempt: StageAttempt, *, action: Literal["observe", "cancel"]
    ) -> Observation:
        call_id = attempt.remote_call_id
        unresolved: AttemptState = "cancel_requested" if action == "cancel" else "unknown_outcome"
        if not call_id:
            return self._finish(action, attempt, "no_call_id", "unknown_outcome", None)
        try:
            poll = self.sdk.poll(call_id)
        except Exception:
            return self._finish(action, attempt, "poll_error", unresolved, None)
        if type(poll) is not ModalPoll:
            return self._finish(action, attempt, "unrecognized", unresolved, None)
        if poll.state == "pending":
            state: AttemptState = "cancel_requested" if action == "cancel" else "running"
            return self._finish(action, attempt, poll.state, state, None)
        if poll.state == "cancelled":
            return self._finish(action, attempt, poll.state, "cancelled", None)
        if poll.state == "remote_error":
            return self._finish(action, attempt, poll.state, "failed", None)
        if poll.state == "completed":
            outcome = self._result(attempt, poll.result)
            if outcome is None:
                return self._finish(action, attempt, "result_unverified", unresolved, None)
            return self._finish(action, attempt, poll.state, outcome[0], outcome[1])
        # timed_out, output_expired and anything unrecognized prove neither effect nor absence.
        sdk_state = poll.state if poll.state in {"timed_out", "output_expired"} else "unrecognized"
        return self._finish(action, attempt, sdk_state, unresolved, None)

    def _result(
        self, attempt: StageAttempt, raw: bytes | None
    ) -> tuple[Literal["succeeded", "failed"], Ref] | None:
        """Verify the nominated manifest by hash from the store; anything less is unresolved."""
        try:
            if type(raw) is not bytes:
                return None
            ref = Ref.from_wire(raw, self.limits)
            if (
                ref.project_id != attempt.project_id
                or ref.artifact_schema != "kf.result.v1"
                or ref.media_type != "application/json"
                or ref.size_bytes > self.limits.max_output_bytes
            ):
                return None
            value = self.store.read_verified(ref, self.access, ref.size_bytes)
            manifest = ResultManifest.from_wire(value.data, self.limits)
            if (
                hashlib.sha256(value.data).hexdigest() != ref.digest
                or (manifest.project_id, manifest.plan_id, manifest.operation_key)
                != (attempt.project_id, attempt.plan_id, attempt.operation_key)
                or manifest.attempt_id != attempt.attempt_id
            ):
                return None
            return manifest.status, ref
        except Exception:
            return None

    def _finish(
        self,
        action: str,
        attempt: StageAttempt,
        sdk_state: str,
        state: AttemptState,
        result_ref: Ref | None,
    ) -> Observation:
        record = json.dumps(
            {
                "action": action,
                "attemptId": attempt.attempt_id,
                "observedState": state,
                "remoteCallId": attempt.remote_call_id,
                "schemaVersion": OBSERVATION_SCHEMA,
                "sdkState": sdk_state,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        try:
            evidence = self.evidence(OBSERVATION_SCHEMA, record)
        except Exception:
            raise ContractError("unavailable") from None
        if type(evidence) is not Ref:
            raise ContractError("unavailable")
        return Observation(state, result_ref, None, evidence)
