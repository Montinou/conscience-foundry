"""The live composition root: the trusted services a ``live`` config section stands for.

Trust model:

* ``build_services`` turns the operator's config into ``TrustedServices``. Without a ``live``
  section it returns the empty services, exactly as before. With one, every value comes from that
  section (no defaults); the parent access-key id is read from the environment variable the config
  names, and a missing one is ``credential_unavailable``. Building opens no session, reads no
  token, mints nothing and touches no network: the R2 client is built on its first request and the
  ``modal`` SDK is imported only when a pilot opens its session (``execution.modal_live``).
* One ``R2CredentialIssuer`` backs both ``issuer_scopes`` (what preflight probes) and the
  ``transport_grants`` minting, and its bucket and prefix must be the staging config's, so what is
  attested is what is minted.
* The control side's staging store uses the ledger's storage gate (``ledger_storage_gate``) for
  every billable request, the operator's access context for every authorization, and the parent R2
  credential (key id from the config's variable, secret derived from the parent token) on its own
  side only; the worker gets only the two temporary credentials.
* The live executor and evidence authority exist only under ``run-pilot``: outside it the services
  carry a ``PilotOnlyExecutor`` and a ``BillingDocumentAuthority``, so a standalone live
  ``dispatch`` refuses with ``live_requires_pilot`` before any ledger or provider contact, a
  standalone ``reconcile`` can at most leave the attempt ``unknown_outcome``, and the one fact a
  standalone command can have attested is an attempt's final bill, from the operator's billing
  document (``record-billing``).
* ``pilot`` builds, inside ``run-pilot``, the session-backed ``ModalExecutor`` and the
  ``LocalEvidenceAuthority`` from what the pilot itself verified: the packet's capability record
  (checked against this code, image and SDK), the packet's estimate, the plan it pinned, and the
  authorization it checked against the packet (the only grant the authority will approve).
* ``await_terminal`` and ``interrupted`` are the reconcile and dispatch steps' handling of the
  deadline and of Ctrl-C: the cancel is recorded with the session's private deadline token
  (reason ``limit_exceeded``) before it goes out, an unconfirmed one is marked
  ``unknown_outcome``, and nothing is ever recorded as failed or succeeded from a doubt.
* No secret, credential or signed URL appears in a ``repr``, an error or a record.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from decimal import Decimal
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, Any, Literal

from psycopg import sql
from pydantic import StringConstraints

from conscience_foundry.cli.authorities import (
    LocalEvidenceAuthority,
    LocalReleaseAuthority,
    PlanPin,
    checked_billing,
)
from conscience_foundry.cli.config import (
    LiveSettings,
    Runtime,
    RuntimeConfig,
    StagingSettings,
    TrustedServices,
    load_limits,
    now,
)
from conscience_foundry.contracts.accounting import BudgetEvent
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
    WireModel,
)
from conscience_foundry.contracts.execution import ExecutionConfig, ExecutionPlan, StageAttempt
from conscience_foundry.contracts.registry import registered_schema_ids
from conscience_foundry.execution.capabilities import CapabilityRecord, validate_capabilities
from conscience_foundry.execution.control import cancel_attempt, mark_unknown_outcome
from conscience_foundry.execution.evidence import encoded, identity, read_model
from conscience_foundry.execution.modal_adapter import OBSERVATION_SCHEMA, ModalExecutor, ModalPin
from conscience_foundry.execution.modal_live import (
    LiveFunctionOptions,
    LiveModalSession,
    canonical_json,
    code_digest,
    image_spec,
    live_payload_extras,
    sdk_version,
)
from conscience_foundry.execution.ports import (
    BillingFacts,
    BudgetProof,
    Observation,
    TransportGrants,
)
from conscience_foundry.ledger.attempts import load_attempt
from conscience_foundry.ledger.budget import ledger_storage_gate
from conscience_foundry.operator.packet import CostEstimate, PreflightEvidence, PreflightPacket
from conscience_foundry.policy.access import AccessContext
from conscience_foundry.storage.r2 import R2CredentialIssuer, r2_static_client
from conscience_foundry.storage.staging_s3 import S3Client, S3StagingStore, credential_scopes

if TYPE_CHECKING:
    from conscience_foundry.execution.ports import Executor

__all__ = [
    "BILLING_SCHEMA",
    "LIVE_REQUIRES_PILOT",
    "OBSERVATION_SCHEMA",
    "RESIDUAL_RISKS",
    "STOP_SCHEMA",
    "BillingDocumentAuthority",
    "BillingRecord",
    "LivePilot",
    "LiveWiring",
    "PilotOnlyAuthority",
    "PilotOnlyExecutor",
    "await_terminal",
    "build_services",
    "claimed_attempt",
    "cloudflare_http",
    "interrupted",
    "interrupted_dispatch",
    "open_session",
    "pilot",
    "require_bound_issuer",
]

LIVE_REQUIRES_PILOT = "live_requires_pilot"
STOP_SCHEMA = "cf.live-stop.v1"
"""The control side's own record of a deadline or interrupt stop, cited by the cancel."""
ESTIMATE_SCHEMA = "cfoundry.cost-estimate.v1"
STOP_REASON: ErrorCode = "limit_exceeded"
RESIDUAL_RISKS = (
    "controller death leaves unknown_outcome",
    "a crash before publish_result loses a paid result",
    "costs stay estimated until billed",
)
"""Stated in every ``run-pilot`` report: what this runtime cannot recover or settle by itself."""
CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"
"""The provider's API base, part of its contract like the R2 endpoint; not an operator value."""
_SETTLED = frozenset({"cancel_requested", "cancelled", "unknown_outcome", "succeeded", "failed"})
_PROBE_PROJECT = "00000000-0000-0000-0000-00000000c001"
_PROBE_ATTEMPT = "00000000-0000-0000-0000-00000000c002"


# -- evidence decoders ----------------------------------------------------------------------------

_OBSERVATION_KEYS = frozenset(
    {"action", "attemptId", "observedState", "remoteCallId", "schemaVersion", "sdkState"}
)
_STOP_KEYS = frozenset({"attemptId", "recordedAt", "remoteCallId", "schemaVersion", "trigger"})


def _record_decoder(
    schema: str, keys: frozenset[str]
) -> Callable[[bytes, ContractLimits], Mapping[str, object]]:
    """A strict decoder for a small control-side record: exactly ``keys``, under the bounds."""

    def decode(data: bytes, limits: ContractLimits) -> Mapping[str, object]:
        if type(data) is not bytes or len(data) > limits.max_json_bytes:
            raise ContractError("limit_exceeded")
        try:
            value = json.loads(data)
        except Exception:
            raise ContractError("invalid_schema") from None
        if (
            type(value) is not dict
            or set(value) != keys
            or value.get("schemaVersion") != schema
            or not all(
                item is None or (type(item) is str and len(item) <= limits.max_string_scalars)
                for item in value.values()
            )
        ):
            raise ContractError("invalid_schema")
        return MappingProxyType(value)

    return decode


def _pinned_decoder(digests: frozenset[str]) -> Callable[[bytes, ContractLimits], object]:
    """Decodes only documents the operator pinned by digest; their content is not interpreted."""

    def decode(data: bytes, limits: ContractLimits) -> Mapping[str, object]:
        if type(data) is not bytes or len(data) > limits.max_json_bytes:
            raise ContractError("limit_exceeded")
        digest = hashlib.sha256(data).hexdigest()
        if digest not in digests:
            raise ContractError("forbidden")
        return MappingProxyType({"digest": digest})

    return decode


def _decoders(config: ExecutionConfig) -> Mapping[str, Callable[[bytes, ContractLimits], object]]:
    """The live decoders plus the pinned execution config's own tariff and resource policy.

    The ledger reads both documents as evidence of the plan it verifies; the authority accepts
    exactly the documents the pinned config names, by digest, under their own schema ids.
    """
    pinned: dict[str, set[str]] = {}
    for ref in (config.tariff_ref, config.resource_policy_ref):
        if ref.artifact_schema in LIVE_DECODERS or ref.artifact_schema in registered_schema_ids():
            raise ContractError("unsupported_schema")
        pinned.setdefault(ref.artifact_schema, set()).add(ref.digest)
    return MappingProxyType(
        {
            **LIVE_DECODERS,
            **{schema: _pinned_decoder(frozenset(found)) for schema, found in pinned.items()},
        }
    )


LIVE_DECODERS: Mapping[str, Callable[[bytes, ContractLimits], object]] = MappingProxyType(
    {
        ESTIMATE_SCHEMA: CostEstimate.from_wire,
        OBSERVATION_SCHEMA: _record_decoder(OBSERVATION_SCHEMA, _OBSERVATION_KEYS),
        STOP_SCHEMA: _record_decoder(STOP_SCHEMA, _STOP_KEYS),
    }
)
"""The evidence schemas a live run cites; the operator's limits file must bound each one."""


# -- the provider API and the control side's R2 client --------------------------------------------


def cloudflare_http(timeout_seconds: int) -> Callable[[str, Mapping[str, Any]], Mapping[str, Any]]:
    """The Cloudflare API caller, each request bounded by the operator's configured timeout.

    It POSTs one request with the token read from the variable the request names. Only
    ``R2CredentialIssuer`` calls it, and it maps every failure to ``unavailable`` without the
    cause, so neither the token nor a response body reaches an error or a log.
    """
    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ContractError("config_invalid")

    def post(path: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        variable = request["tokenEnv"]
        token = os.environ.get(variable, "") if type(variable) is str else ""
        if not token or type(path) is not str or not path.startswith("/accounts/"):
            raise ContractError("credential_unavailable")
        message = urllib.request.Request(
            CLOUDFLARE_API + path,
            data=json.dumps(request["body"], separators=(",", ":")).encode("utf-8"),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(message, timeout=timeout_seconds) as response:  # noqa: S310
            answer = json.loads(response.read())
        if not isinstance(answer, Mapping):
            raise ContractError("unavailable")
        return answer

    return post


def _env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ContractError("credential_unavailable")
    return value


class _ControlClient:
    """The control side's R2 client, built on its first request from the parent credential.

    R2 derives an API token's S3 secret as the SHA-256 of the token value; the key id and the
    token are read from the variables the config names only when a request is made.
    """

    def __init__(self, settings: LiveSettings) -> None:
        self._settings = settings
        self._client: S3Client | None = None

    def __repr__(self) -> str:
        return "_ControlClient()"

    def _built(self) -> S3Client:
        if self._client is None:
            settings = self._settings
            key_id = _env(settings.parent_access_key_id_env)
            secret = hashlib.sha256(_env(settings.parent_token_env).encode("utf-8")).hexdigest()
            self._client = r2_static_client(settings.r2_account_id, key_id, secret)
        return self._client

    def put_object(self, **kwargs: Any) -> Mapping[str, Any]:
        return self._built().put_object(**kwargs)

    def head_object(self, **kwargs: Any) -> Mapping[str, Any]:
        return self._built().head_object(**kwargs)

    def get_object(self, **kwargs: Any) -> Mapping[str, Any]:
        return self._built().get_object(**kwargs)


def _never(_ref: Ref, _context: AccessContext) -> bool:
    """A read-only view funds nothing: every billable request through it is refused."""
    return False


@contextmanager
def _runtime(config: RuntimeConfig, clock: Callable[[], Instant]) -> Iterator[Runtime]:
    """A private runtime over the same config: its ledger, local store and access context.

    Its command name grants no library action, so it can read and gate but never authorize.
    """
    runtime = Runtime(config, TrustedServices(clock=clock), "live-wiring")
    try:
        yield runtime
    finally:
        runtime.close()


def require_bound_issuer(issuer: R2CredentialIssuer, staging: StagingSettings) -> None:
    """The issuer mints for exactly the staging bucket and prefix the stores use."""
    try:
        probe = _probe_plan()
        _, minted = issuer.scopes(probe, _PROBE_ATTEMPT)
        _, staged = credential_scopes(staging.prefix, probe, _PROBE_ATTEMPT)
    except Exception:
        raise ContractError("config_invalid") from None
    if issuer.bucket != staging.bucket or issuer.prefix != staging.prefix or minted != staged:
        raise ContractError("config_invalid")


def _probe_plan() -> ExecutionPlan:
    from conscience_foundry.cli.preflight import _probe_plan as probe

    return probe(_PROBE_PROJECT)


# -- the wiring -----------------------------------------------------------------------------------


def _authority(config: RuntimeConfig) -> Callable[[Ref, AccessContext, str], None]:
    """The same store authority the runtime uses: this project and this operator only."""
    access = AccessContext(
        config.project_id, config.operator.actor_id, frozenset(config.operator.scopes)
    )

    def authorize(ref: Ref, context: AccessContext, effect: str) -> None:
        if ref.project_id != config.project_id or context != access:
            raise ContractError("forbidden")

    return authorize


def _execution_config(runtime: Runtime, plan: ExecutionPlan) -> ExecutionConfig:
    """The plan's execution config, read by its hash-pinned reference from the local store."""
    return read_model(plan.execution_config_ref, ExecutionConfig, runtime.control)[1]


@dataclass(frozen=True)
class LiveWiring:
    """What a ``live`` section wires; ``session`` is set only by ``run-pilot`` while it is open."""

    config: RuntimeConfig = field(repr=False)
    issuer: R2CredentialIssuer = field(repr=False)
    client: S3Client = field(repr=False)
    clock: Callable[[], Instant] = field(repr=False)
    modal_module: object | None = field(default=None, repr=False)
    session: LiveModalSession | None = field(default=None, repr=False)

    @property
    def settings(self) -> LiveSettings:
        settings = self.config.live
        if settings is None:
            raise ContractError("config_invalid")
        return settings

    def _store(
        self, destination_id: str, gate: Callable[[Ref, AccessContext], bool]
    ) -> S3StagingStore:
        return S3StagingStore(
            self.settings.staging.to_config(destination_id),
            self.client,
            authorize=_authority(self.config),
            storage_reserved=gate,
            clock=self.clock,
            credential_issuer=self.issuer,
        )

    def reader_for(self, project_id: Id, attempt_id: Id) -> S3StagingStore:
        """A read-only view of one attempt's prefix; it mints, writes and funds nothing.

        A destination id names minted grants only, so the view uses the endpoint label.
        """
        return self._store(self.settings.staging.endpoint_id, _never).attempt_reader(
            project_id, attempt_id
        )

    def stage_inputs(self, plan: ExecutionPlan, context: AccessContext) -> tuple[Ref, ...]:
        """Put every object the worker reads at its shared key, under the run's storage funds."""
        with _runtime(self.config, self.clock) as runtime:
            if context != runtime.access or plan.project_id != runtime.config.project_id:
                raise ContractError("forbidden")
            store = self._store(
                self.settings.staging.endpoint_id, ledger_storage_gate(runtime.ledger, plan.run_id)
            )
            return store.stage_inputs(plan, runtime.store, context)

    def transport_grants(
        self, plan: ExecutionPlan, attempt: StageAttempt, plan_ref: Ref
    ) -> TransportGrants:
        """Mint the attempt's two temporary credentials through the one configured issuer."""
        with _runtime(self.config, self.clock) as runtime:
            if plan.project_id != runtime.config.project_id:
                raise ContractError("forbidden")
            destination = _execution_config(runtime, plan).remote_destination_id
            store = self._store(destination, ledger_storage_gate(runtime.ledger, plan.run_id))
            grants = store.grant_transport(plan, attempt, runtime.access)
        _, write_prefix = self.issuer.scopes(plan, attempt.attempt_id)
        if grants.output_scope != f"{self.issuer.bucket}/{write_prefix}".encode():
            raise ContractError("forbidden")  # what is minted is what the issuer reports
        return grants


class PilotOnlyExecutor:
    """The live executor outside ``run-pilot``: it reads attempt prefixes and runs nothing."""

    def __init__(self, reader_for: Callable[[Id, Id], S3StagingStore]) -> None:
        self.reader_for = reader_for

    def __repr__(self) -> str:
        return "PilotOnlyExecutor()"

    def submit(self, *_args: object) -> Any:
        raise ContractError(LIVE_REQUIRES_PILOT)

    def observe(self, _attempt: StageAttempt) -> Observation:
        raise ContractError(LIVE_REQUIRES_PILOT)  # the control side records an unknown outcome

    def cancel(self, _attempt: StageAttempt) -> Observation:
        raise ContractError(LIVE_REQUIRES_PILOT)


class PilotOnlyAuthority:
    """The live evidence authority outside ``run-pilot``: it attests nothing."""

    decoders: Mapping[str, Callable[[bytes, ContractLimits], object]] = LIVE_DECODERS

    def __repr__(self) -> str:
        return "PilotOnlyAuthority()"

    def _refuse(self, *_args: object) -> Any:
        raise ContractError(LIVE_REQUIRES_PILOT)

    budget = observation = control = transport = _refuse


BILLING_SCHEMA = "cfoundry.billing-record.v1"
"""The operator's record of what one attempt was actually billed (from the provider's export)."""


class BillingRecord(WireModel):
    """One attempt's actual bill, as the operator read it from the provider's billing export.

    Only an ``actual`` amount can be recorded: an estimate is not a bill.
    """

    schema_version: Literal["cfoundry.billing-record.v1"]
    project_id: Id
    attempt_id: Id
    currency: Literal["USD"]
    cost_status: Literal["actual"]
    amount_usd: Money
    source: Annotated[ScalarString, StringConstraints(min_length=1)]
    recorded_by: Id
    recorded_at: Instant


def _opaque(data: bytes, limits: ContractLimits) -> Mapping[str, object]:
    """A bounded document whose content is not interpreted: only its digest is kept."""
    if type(data) is not bytes or len(data) > limits.max_json_bytes:
        raise ContractError("limit_exceeded")
    return MappingProxyType({"digest": hashlib.sha256(data).hexdigest()})


class BillingDocumentAuthority(PilotOnlyAuthority):
    """The live evidence authority outside ``run-pilot``: it attests one thing only.

    ``record-billing`` settles an attempt from the operator's billing document, cited as its
    evidence. The facts are that document's own figures, read from the exact bytes the ledger
    cites, for this project, this attempt, this operator and exactly the requested amount, and
    then checked like every billing source (``checked_billing``). Every other purpose and every
    other kind of fact is refused (``live_requires_pilot``), and nothing is ever ``actual``
    without such a document.
    """

    def __init__(self, config: RuntimeConfig) -> None:
        self._config = config
        # The ledger re-verifies the attempt's plan, which reads the plan config's tariff and
        # resource policy as evidence. Those documents are hash-checked against the pinned
        # config's references before they are decoded; their content is never a fact here. Only
        # the evidence schemas the operator bounds in its own limits file are decodable.
        operator = {
            schema: _opaque
            for schema in load_limits(config.limits_path)
            if schema not in registered_schema_ids()
            and schema not in LIVE_DECODERS
            and schema != BILLING_SCHEMA
        }
        self.decoders: Mapping[str, Callable[[bytes, ContractLimits], object]] = MappingProxyType(
            {**operator, **LIVE_DECODERS, BILLING_SCHEMA: BillingRecord.from_wire}
        )

    def __repr__(self) -> str:
        return "BillingDocumentAuthority()"

    def budget(self, proof: BudgetProof) -> Any:  # type: ignore[override]
        claim = proof.claim
        if claim.purpose != "final_billing":
            raise ContractError(LIVE_REQUIRES_PILOT)
        data, evidence = proof.evidence_bytes, claim.evidence_ref
        try:
            limits = load_limits(self._config.limits_path)
            record = BillingRecord.from_wire(data, limits[BILLING_SCHEMA])
            event = BudgetEvent.from_wire(claim.request_bytes, limits["cf.budget-event.v1"])
        except Exception:
            raise ContractError("forbidden") from None
        if (
            evidence.artifact_schema != BILLING_SCHEMA
            or type(data) is not bytes
            or hashlib.sha256(data).hexdigest() != evidence.digest
            or len(data) != evidence.size_bytes
            or record.project_id != claim.project_id
            or record.project_id != self._config.project_id
            or claim.attempt_id is None
            or record.attempt_id != claim.attempt_id
            or record.recorded_by != proof.authorization.actor_id
            or event.event_type != "settle"
            or event.cost_status != "actual"
            or event.attempt_id != record.attempt_id
            or event.amount_usd is None
            or Decimal(event.amount_usd) != Decimal(record.amount_usd)
            or identity(event.evidence_ref) != identity(evidence)
        ):
            raise ContractError("forbidden")
        return checked_billing(
            BillingFacts(proof.binding, "actual", record.amount_usd, True, True, False), proof
        )


def _policy_digest(config: RuntimeConfig) -> Digest:
    """The digest of the project's current policy, through the runtime's own policy lookup."""
    with _runtime(config, now) as runtime:
        return hashlib.sha256(encoded(runtime.current_policy(config.project_id))).hexdigest()


def _release_authority(config: RuntimeConfig) -> LocalReleaseAuthority:
    """Approves the configured project's release actions while its policy is the one pinned now."""
    return LocalReleaseAuthority(
        config.project_id,
        _policy_digest(config),
        current_policy_digest=lambda: _policy_digest(config),
    )


def build_services(
    config: RuntimeConfig, *, modal_module: object | None = None, http: object | None = None
) -> TrustedServices:
    """The trusted services the config's ``live`` section stands for; none without one.

    ``modal_module`` replaces ``import modal`` for the session (tests inject a fake); ``http`` is
    the Cloudflare API caller (``cloudflare_http`` when omitted).
    """
    settings = config.live
    if settings is None:
        return TrustedServices()
    if config.project_max_live_attempts is None:
        raise ContractError("config_invalid")  # a live section always carries the project cap
    if http is not None and not callable(http):
        raise ContractError("invalid_schema")
    clock = now
    issuer = R2CredentialIssuer(
        account_id=settings.r2_account_id,
        bucket=settings.staging.bucket,
        prefix=settings.staging.prefix,
        parent_access_key_id=_env(settings.parent_access_key_id_env),
        token_env=settings.parent_token_env,
        total_bound_seconds=settings.total_bound_seconds,
        clock=clock,
        http=http if http is not None else cloudflare_http(settings.cloudflare_timeout_seconds),
    )
    require_bound_issuer(issuer, settings.staging)
    wiring = LiveWiring(config, issuer, _ControlClient(settings), clock, modal_module)
    return TrustedServices(
        evidence_authority=BillingDocumentAuthority(config),
        release_authority=_release_authority(config),
        executor=PilotOnlyExecutor(wiring.reader_for),
        transport_grants=wiring.transport_grants,
        clock=clock,
        staged_reader=wiring.reader_for,
        stage_inputs=wiring.stage_inputs,
        issuer_scopes=issuer.scopes,
        live=wiring,
    )


# -- the pilot ------------------------------------------------------------------------------------


class _Clock:
    def __init__(self, clock: Callable[[], Instant]) -> None:
        self._clock = clock

    def now(self) -> Instant:
        return self._clock()


@dataclass(frozen=True)
class LivePilot:
    """The live runtime ``run-pilot`` holds: one session and the services bound to it."""

    session: LiveModalSession = field(repr=False)
    base: TrustedServices = field(repr=False)
    wiring: LiveWiring = field(repr=False)

    def services(self, *, session_open: bool) -> TrustedServices:
        """The pilot's services; the session is reachable only while it is open."""
        return replace(
            self.base, live=replace(self.wiring, session=self.session if session_open else None)
        )


def _sink(runtime: Runtime) -> Callable[[str, bytes], Ref]:
    """Stores an executor evidence record in the local store and returns its reference."""

    def store(schema: str, data: bytes) -> Ref:
        ref = _local_ref(runtime, schema, data)
        return runtime.store.put_verified(io.BytesIO(data), ref, runtime.access)

    return store


def _local_ref(runtime: Runtime, schema: str, data: bytes) -> Ref:
    return Ref(
        schema_version="cf.artifact-ref.v1",
        project_id=runtime.config.project_id,
        digest=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        media_type="application/json",
        artifact_schema=schema,
        locations=(),
    )


def _deployed(record: CapabilityRecord, options: LiveFunctionOptions, modal: object | None) -> None:
    """The record describes this code, this image and this SDK, or the pilot does not start."""
    image = hashlib.sha256(canonical_json(image_spec(options))).hexdigest()
    if (
        record.code_digest != code_digest()
        or record.image_digest != image
        or record.deployment_version != "ephemeral-" + record.code_digest[:16]
        or record.sdk_version != sdk_version(modal)
        or record.cpu_milli != options.cpu_milli
        or record.memory_mib != options.memory_mib
        or record.startup_timeout_seconds != options.startup_timeout_seconds
        or record.execution_timeout_seconds != options.execution_timeout_seconds
    ):
        raise ContractError("unsupported_capability")


def pilot(
    runtime: Runtime,
    packet: PreflightPacket,
    evidence: PreflightEvidence,
    plan: ExecutionPlan,
    approved_grant_digest: Digest | None,
) -> LivePilot | None:
    """The live executor and authority for one pilot, or ``None`` when nothing live is wired.

    Everything comes from what the pilot verified before any step: the packet-bound capability
    record, estimate and plan, and the authorization digest it checked against the packet.
    """
    wiring = runtime.services.live
    if wiring is None:
        return None
    settings = wiring.settings
    limits = packet.contract_limits
    if (
        packet.estimate_ref is None
        or limits is None
        or evidence.capabilities is None
        or evidence.estimate is None
        or hashlib.sha256(evidence.estimate).hexdigest() != packet.estimate_ref.digest
    ):
        raise ContractError("forbidden")
    record = CapabilityRecord.from_wire(evidence.capabilities, limits)
    validate_capabilities(record, plan)
    options = LiveFunctionOptions.from_settings(settings)
    _deployed(record, options, wiring.modal_module)
    if record.total_bound_seconds != settings.total_bound_seconds:
        raise ContractError("unsupported_capability")
    config = _execution_config(runtime, plan)
    # The ledger reads the reviewed estimate by its packet reference: install the very bytes.
    runtime.store.put_verified(io.BytesIO(evidence.estimate), packet.estimate_ref, runtime.access)
    plan_bytes = encoded(plan)
    plan_ref = _local_ref(runtime, "cf.execution-plan.v1", plan_bytes)
    session = LiveModalSession(
        settings.modal_profile,
        options,
        settings.total_bound_seconds,
        _Clock(wiring.clock),
        modal=wiring.modal_module,
    )
    executor = ModalExecutor(
        sdk=session,
        pin=ModalPin(
            app_name=settings.app_name,
            function_name=settings.function_name,
            deployment_version=record.deployment_version,
            image_digest=record.image_digest,
            code_digest=record.code_digest,
            sdk_version=record.sdk_version,
            destination_id=config.remote_destination_id,
        ),
        record=record,
        execution_config_digest=plan.execution_config_ref.digest,
        reader_for=wiring.reader_for,
        access=runtime.access,
        limits=runtime.limit("cf.result.v1"),
        clock=wiring.clock,
        evidence=_sink(runtime),
        payload_extras=live_payload_extras(settings),
    )
    authority = LocalEvidenceAuthority(
        _decoders(config),
        session,
        wiring.issuer,
        packet.estimate_ref,
        None,
        "live",
        plans=(PlanPin(plan_ref, plan, config),),
        limits_by_schema=runtime.limits,
        approved_grant_digest=approved_grant_digest,
    )
    base = replace(runtime.services, executor=executor, evidence_authority=authority)
    return LivePilot(session, base, wiring)


# -- deadline and interrupt -----------------------------------------------------------------------


def open_session(services: TrustedServices) -> LiveModalSession | None:
    """The pilot's open session, or ``None`` outside a pilot's dispatch and reconcile steps."""
    return services.live.session if services.live is not None else None


def _stop_record(
    runtime: Runtime, attempt_id: Id, call_id: str | None, trigger: Literal["deadline", "interrupt"]
) -> Ref:
    data = json.dumps(
        {
            "attemptId": attempt_id,
            "recordedAt": runtime.clock(),
            "remoteCallId": call_id,
            "schemaVersion": STOP_SCHEMA,
            "trigger": trigger,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    ref = _local_ref(runtime, STOP_SCHEMA, data)
    return runtime.store.put_verified(io.BytesIO(data), ref, runtime.access)


def _current(runtime: Runtime, attempt_id: Id) -> StageAttempt:
    with runtime.ledger.transaction() as tx:
        reference, _, _, _ = load_attempt(tx, runtime.config.project_id, attempt_id)
    return read_model(reference, StageAttempt, runtime.control)[1]


def _stop(
    runtime: Runtime,
    executor: Executor,
    session: LiveModalSession,
    attempt_id: Id,
    trigger: Literal["deadline", "interrupt"],
) -> None:
    """Cancel through the ledger with the session's token; an unconfirmed cancel is unknown.

    The cancel is recorded (``cancel_requested``) before it goes out; the executor's cancel then
    reaches the session. Whenever the cancel is not confirmed as recorded (it failed in any way,
    or left the attempt dispatching or running), the attempt is marked ``unknown_outcome`` with
    the same token. Neither ever asserts a failure or a success. Only a stop record that cannot
    be written at all, or a mark the ledger refuses, raises.
    """
    control = runtime.control
    token = session.deadline_token
    reason = Reason(code=STOP_REASON, message=f"live {trigger} stop")
    try:
        call_id = _current(runtime, attempt_id).remote_call_id
    except Exception:
        call_id = None  # the record still names the attempt; the call id is only context
    evidence = _stop_record(runtime, attempt_id, call_id, trigger)
    state: str | None = None
    try:
        state = cancel_attempt(
            attempt_id,
            runtime.ledger,
            executor,
            control=control,
            reason=reason,
            evidence_ref=evidence,
            deadline_token=token,
        ).state
    except Exception:
        state = None  # not confirmed: fall back to the unknown mark
    if state not in _SETTLED:
        mark_unknown_outcome(
            attempt_id,
            runtime.ledger,
            control=control,
            reason=reason,
            evidence_ref=evidence,
            deadline_token=token,
        )


def _terminate_own_calls(session: LiveModalSession) -> None:
    """Backstop after the ledger has recorded the stop: no call of this session keeps running."""
    for call_id, record in tuple(session.records.items()):
        if not record.terminated and not record.completed:
            try:
                session.cancel(call_id)
            except ContractError:
                pass  # the attempt is already recorded as cancel requested or unknown


def await_terminal(
    runtime: Runtime, executor: Executor, session: LiveModalSession, attempt_id: Id
) -> None:
    """The reconcile step's wait: until the call ends, or its deadline cancels it.

    The deadline callback always goes through the ledger with the session's token. A Ctrl-C
    while waiting stops the attempt the same way, then propagates. Whatever the wait reports, the
    reconcile that follows observes and records the call itself.
    """
    attempt = _current(runtime, attempt_id)
    call_id = attempt.remote_call_id
    if call_id is None or call_id not in session.records:
        return  # not a call of this session: the reconcile can attest at most unknown_outcome

    def on_deadline() -> None:
        _stop(runtime, executor, session, attempt_id, "deadline")

    try:
        session.poll_until_terminal(call_id, on_deadline)
    except KeyboardInterrupt:
        interrupted(runtime, executor, session, attempt_id)
        raise
    except ContractError:
        pass  # the observation below records it; a doubt is never a terminal state


def interrupted(
    runtime: Runtime, executor: Executor, session: LiveModalSession, attempt_id: Id | None
) -> None:
    """Ctrl-C inside a dispatch or reconcile step, while the session is still open.

    The attempt (when one was claimed) is stopped through the ledger with the token, then every
    call of the session is terminated. Nothing raised here replaces the interrupt.
    """
    try:
        if attempt_id is not None:
            _stop(runtime, executor, session, attempt_id, "interrupt")
    except Exception:
        pass  # the attempt stays as recorded: never running from this process's point of view
    finally:
        _terminate_own_calls(session)


def interrupted_dispatch(
    runtime: Runtime, executor: Executor, session: LiveModalSession, plan: ExecutionPlan
) -> None:
    """Ctrl-C inside the dispatch step: find the attempt it claimed, if any, and stop it.

    A lookup that fails stops nothing in the ledger but still terminates the session's calls;
    nothing raised here replaces the interrupt.
    """
    try:
        attempt_id = claimed_attempt(runtime, plan)
    except Exception:
        attempt_id = None
    interrupted(runtime, executor, session, attempt_id)


def claimed_attempt(runtime: Runtime, plan: ExecutionPlan) -> Id | None:
    """The one attempt of this plan's operation a dispatch claimed but did not settle."""
    with runtime.ledger.transaction() as tx:
        rows = tx.connection.execute(
            sql.SQL(
                "SELECT attempt_id::text FROM {} WHERE project_id=%s AND run_id=%s "
                "AND operation_key=%s AND state IN ('dispatching','running')"
            ).format(tx.table("attempts")),
            (plan.project_id, plan.run_id, plan.operation_key),
        ).fetchall()
    return str(rows[0][0]) if len(rows) == 1 else None
