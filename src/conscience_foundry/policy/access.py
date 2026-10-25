"""Trusted, caller-supplied project authority; no authority is read from wire data."""

from dataclasses import dataclass

from pydantic import TypeAdapter, ValidationError

from conscience_foundry.contracts.common import ContractError, Id
from conscience_foundry.contracts.project import EFFECT_NAMES, PolicyArtifact


@dataclass(frozen=True)
class AccessContext:
    project_id: Id
    actor_id: Id
    scopes: frozenset[str]

    def __post_init__(self) -> None:
        try:
            TypeAdapter(Id).validate_python(self.project_id)
            TypeAdapter(Id).validate_python(self.actor_id)
        except ValidationError:
            raise ContractError("invalid_schema") from None
        if not isinstance(self.scopes, frozenset) or not self.scopes <= EFFECT_NAMES:
            raise ContractError("forbidden")


def require_permission(
    context: AccessContext, policy: PolicyArtifact, source_id: Id, effect: str
) -> None:
    """Require the exact trusted project scope and explicit current source permission."""
    if (
        context.project_id != policy.project_id
        or effect not in EFFECT_NAMES
        or effect not in context.scopes
    ):
        raise ContractError("forbidden")
    source = next((source for source in policy.sources if source.source_id == source_id), None)
    if source is None:
        raise ContractError("forbidden")
    permission = source.permission(effect)
    if permission == "unknown":
        raise ContractError("permission_unknown")
    if permission != "allow":
        raise ContractError("forbidden")
