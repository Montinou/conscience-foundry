"""Private bounded budget inputs and exact trusted evidence claims."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import TypeAdapter, ValidationError

from conscience_foundry.contracts.common import (
    ContractError,
    ContractLimits,
    Id,
    Instant,
    Ref,
    WireModel,
)
from conscience_foundry.contracts.project import PolicyArtifact
from conscience_foundry.policy.access import AccessContext


@dataclass(frozen=True)
class BudgetEvidenceClaim:
    """Exact request for independently verified evidence, never self-certification.

    The resolver must compare request amounts/pins against the durable evidence,
    authenticate its provenance and finality, and check current policy/horizon.
    ``reserve_storage`` additionally attests category allocation and the admitted
    set's exact configuration/tariff/limits/destination and funded horizon.
    """

    purpose: str
    evidence_ref: Ref
    project_id: Id
    run_id: Id
    reservation_id: Id | None
    attempt_id: Id | None
    now: Instant
    authorization_ref: Ref
    plan_ref: Ref | None
    execution_config_ref: Ref | None
    request_bytes: bytes = field(repr=False)
    request_digest: str
    expected_previous_authorization_id: Id | None = None


@dataclass(frozen=True)
class BudgetContext:
    now: Instant
    access: AccessContext
    current_policy: PolicyArtifact = field(repr=False)
    limits_by_schema: Mapping[str, ContractLimits] = field(repr=False)
    authorize: Callable[[str, Id, Id, Id], bool] = field(repr=False)
    verify_evidence: Callable[[BudgetEvidenceClaim], bool] = field(repr=False)


def _limits(context: BudgetContext, schema: str) -> ContractLimits:
    value = context.limits_by_schema.get(schema)
    if type(value) is not ContractLimits:
        raise ContractError("limits_missing")
    try:
        return ContractLimits.model_validate(value.model_dump())
    except ValidationError:
        raise ContractError("limits_missing") from None


def _context(context: BudgetContext, project: Id, run: Id, action: str) -> None:
    if type(context) is not BudgetContext or type(context.access) is not AccessContext:
        raise ContractError("forbidden")
    try:
        TypeAdapter(Instant).validate_python(context.now)
        TypeAdapter(Id).validate_python(run)
    except ValidationError:
        raise ContractError("invalid_schema") from None
    if (
        context.access.project_id != project
        or context.current_policy.schema_version != "kf.policy.v1"
        or context.current_policy.project_id != project
        or context.current_policy.effective_at > context.now
    ):
        raise ContractError("forbidden")
    try:
        allowed = context.authorize(action, project, run, context.access.actor_id)
    except Exception:
        raise ContractError("forbidden") from None
    if allowed is not True:
        raise ContractError("forbidden")


def _identity(ref: Ref) -> tuple[object, ...]:
    return ref.project_id, ref.artifact_schema, ref.digest, ref.size_bytes, ref.media_type


def _ref(data: bytes, ref: Ref, schema: str, project: Id) -> None:
    if type(data) is not bytes or type(ref) is not Ref:
        raise ContractError("invalid_schema")
    if (
        ref.schema_version != "kf.artifact-ref.v1"
        or ref.project_id != project
        or ref.artifact_schema != schema
        or ref.media_type != "application/json"
    ):
        raise ContractError("invalid_schema")
    if ref.size_bytes != len(data) or ref.digest != hashlib.sha256(data).hexdigest():
        raise ContractError("hash_mismatch")


def _parse[Model: WireModel](
    model: type[Model],
    data: bytes,
    ref: Ref,
    schema: str,
    project: Id,
    context: BudgetContext,
) -> Model:
    result = model.from_wire(data, _limits(context, schema))
    _ref(data, ref, schema, project)
    return result


def _stored_ref(value: Any) -> Ref:
    try:
        return Ref.model_validate(value)
    except ValidationError:
        raise ContractError("hash_mismatch") from None


def _proof(
    context: BudgetContext,
    purpose: str,
    evidence: Ref,
    run: Id,
    auth_ref: Ref,
    request: bytes,
    *,
    reservation: Id | None = None,
    attempt: Id | None = None,
    plan_ref: Ref | None = None,
    config_ref: Ref | None = None,
    expected_previous: Id | None = None,
) -> None:
    if type(evidence) is not Ref or evidence.project_id != context.access.project_id:
        raise ContractError("forbidden")
    claim = BudgetEvidenceClaim(
        purpose,
        evidence,
        context.access.project_id,
        run,
        reservation,
        attempt,
        context.now,
        auth_ref,
        plan_ref,
        config_ref,
        request,
        hashlib.sha256(request).hexdigest(),
        expected_previous,
    )
    try:
        allowed = context.verify_evidence(claim)
    except Exception:
        raise ContractError("forbidden") from None
    if allowed is not True:
        raise ContractError("forbidden")
