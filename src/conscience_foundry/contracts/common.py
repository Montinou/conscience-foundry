"""Strict shared wire types; references contain storage identifiers, never grants."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    ValidationInfo,
    model_validator,
)
from pydantic.alias_generators import to_camel

MAX_SAFE_INTEGER = 9007199254740991


class ContractError(ValueError):
    """Stable redacted failure: no input bytes or provider payload in diagnostics."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def scalar_string(value: str) -> str:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError("invalid Unicode scalar string")
    return value


def instant_string(value: str) -> str:
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z", value):
        raise ValueError("expected UTC timestamp with fixed millisecond precision")
    datetime.fromisoformat(value)
    return value


ScalarString = Annotated[str, StringConstraints(strict=True), AfterValidator(scalar_string)]
Id = Annotated[
    str,
    StringConstraints(
        strict=True, pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ),
    AfterValidator(scalar_string),
]
Digest = Annotated[
    str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$"), AfterValidator(scalar_string)
]
Version = Annotated[
    str, StringConstraints(strict=True, min_length=1), AfterValidator(scalar_string)
]
Instant = Annotated[
    str,
    StringConstraints(
        strict=True, pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
    ),
    AfterValidator(instant_string),
]
Money = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[0-9]+(?:\.[0-9]{1,9})?$"),
    AfterValidator(scalar_string),
]
SafeInteger = Annotated[int, Field(strict=True, ge=0, le=MAX_SAFE_INTEGER)]
PositiveInteger = Annotated[int, Field(strict=True, gt=0, le=MAX_SAFE_INTEGER)]


def validate_wire_value(
    value: object, *, allow_null: bool = False, allow_models: bool = False
) -> None:
    """Reject Python-only/coercible values, unsafe integers and invalid strings."""
    pending: list[tuple[object, bool]] = [(value, False)]
    active: set[int] = set()
    while pending:
        item, leaving = pending.pop()
        if leaving:
            active.remove(id(item))
            continue
        if isinstance(item, (list, dict, tuple)):
            if id(item) in active:
                raise ValueError("cyclic value is not JSON")
            active.add(id(item))
            pending.append((item, True))
        if isinstance(item, str):
            scalar_string(item)
        elif item is None:
            if not allow_null:
                raise ValueError("explicit null is not permitted")
        elif allow_models and isinstance(item, WireModel):
            pending.append((item.model_dump(by_alias=True, exclude_none=True), False))
        elif isinstance(item, bool):
            continue
        elif isinstance(item, int):
            if item < 0 or item > MAX_SAFE_INTEGER:
                raise ValueError("integer outside wire range")
        elif isinstance(item, list) or (allow_models and isinstance(item, tuple)):
            pending.extend((child, False) for child in item)
        elif isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("object keys must be strings")
                scalar_string(key)
                pending.append((child, False))
        else:
            raise ValueError("unsupported wire value")


class WireModel(BaseModel):
    """Trusted Python construction plus a bounded, single wire admission path."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        alias_generator=to_camel,
        populate_by_name=True,
        json_schema_extra={"$schema": "https://json-schema.org/draft/2020-12/schema"},
    )

    @model_validator(mode="before")
    @classmethod
    def strict_values(cls, value: Any) -> Any:
        if isinstance(value, dict):
            validate_wire_value(value, allow_models=True)
        return value

    @classmethod
    def from_wire(cls, data: bytes, limits: ContractLimits) -> Self:
        from conscience_foundry.contracts.codec import load_json

        try:
            return cls.model_validate(
                load_json(data, limits), context={"limits": limits}, by_alias=True, by_name=False
            )
        except ValidationError:
            raise ContractError("invalid_schema") from None

    @classmethod
    def model_validate_json(cls, *args: Any, **kwargs: Any) -> Self:
        """Pydantic's JSON parser cannot bypass bounded duplicate/depth checks."""
        raise ContractError("limits_missing")


class ContractLimits(WireModel):
    schema_version: Literal["kf.contract-limits.v1"]
    version: Version
    max_json_bytes: PositiveInteger
    max_string_scalars: PositiveInteger
    max_array_items: PositiveInteger
    max_depth: PositiveInteger
    max_manifest_items: PositiveInteger
    max_source_bytes: PositiveInteger
    max_output_bytes: PositiveInteger
    max_error_message_scalars: PositiveInteger


ErrorCode = Literal[
    "invalid_schema",
    "unsupported_schema",
    "limits_missing",
    "limit_exceeded",
    "forbidden",
    "permission_unknown",
    "source_missing",
    "unsafe_path",
    "source_changed",
    "hash_mismatch",
    "unsupported_format",
    "invalid_encoding",
    "bom_rejected",
    "nul_rejected",
    "empty_text",
    "whitespace_only",
    "invalid_span",
    "revision_mismatch",
    "budget_unconfigured",
    "budget_exhausted",
    "authorization_expired",
    "dispatch_unknown",
    "remote_failed",
    "result_incomplete",
    "determinism_conflict",
    "storage_full",
    "artifact_missing",
    "schema_incompatible",
    "activation_conflict",
    "unsupported_capability",
    "unavailable",
]


class Reason(WireModel):
    code: ErrorCode
    message: ScalarString

    @model_validator(mode="after")
    def bounded_message(self, info: ValidationInfo) -> Self:
        if info.context and isinstance(info.context.get("limits"), ContractLimits):
            limits = info.context["limits"]
            if len(self.message) > limits.max_error_message_scalars:
                raise ValueError("diagnostic exceeds configured bound")
        return self


def safe_object_key(value: str) -> str:
    if (
        "\\" in value
        or "\x00" in value
        or ":" in value
        or any(segment in {"", ".", ".."} for segment in value.split("/"))
    ):
        raise ValueError("unsafe object key")
    return value


class ArtifactLocation(WireModel):
    store_id: Annotated[ScalarString, StringConstraints(min_length=1)]
    object_key: Annotated[ScalarString, AfterValidator(safe_object_key)]


class ArtifactRef(WireModel):
    schema_version: Literal["kf.artifact-ref.v1"]
    project_id: Id
    digest: Digest
    size_bytes: SafeInteger
    media_type: Annotated[ScalarString, StringConstraints(min_length=1)]
    artifact_schema: Version
    locations: Annotated[
        tuple[ArtifactLocation, ...],
        BeforeValidator(lambda value: tuple(value) if isinstance(value, list) else value),
    ]


Ref = ArtifactRef
