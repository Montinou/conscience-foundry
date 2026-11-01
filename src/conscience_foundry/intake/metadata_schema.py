"""Restricted metadata-schema subset: a bounded wire contract and a small interpreter.

Operator-supplied schema documents are untrusted input. Only a closed JSON-Schema-shaped subset is
admitted: one object (`additionalProperties: false`) whose properties are bounded strings
(`maxLength` <= 1024, optional `pattern`/`enum`), integers (optional `minimum`/`maximum`),
booleans, or one nested object of the same form (depth <= 2). `$ref`, `$id`, `format`, arrays,
numbers and every other keyword are outside the subset and refused as `invalid_schema`. The
interpreter evaluates metadata against the parsed document; it never loads code or resolves
references.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from typing import Annotated, Literal, Self

from pydantic import BeforeValidator, Field, model_validator
from pydantic.json_schema import SkipJsonSchema

from conscience_foundry.contracts.common import (
    MAX_SAFE_INTEGER,
    ContractError,
    ContractLimits,
    ScalarString,
    WireModel,
)

MAX_STRING_LENGTH = 1024
MAX_PROPERTIES = 64


_SYNTAX = frozenset("\\^$.*+?()[]{}|/")
_CLASS_ESCAPES = frozenset("dDwW")
_CONTROL_ESCAPES = {"n": "\n", "r": "\r", "t": "\t"}
_ANY = "[^\\n\\r\\u2028\\u2029]"
_QUANTIFIER = re.compile(r"\{(\d+)(?:,(\d*))?\}")


def translate_pattern(pattern: str) -> str:
    """Rewrite a pattern of the dialect shared by ECMAScript (`u` flag) and Python `re`.

    JSON Schema patterns are ECMA-262: `$` ends the input (Python's also matches before a final
    newline), `.` excludes four line terminators, and `\\d`/`\\w` are ASCII. Everything the two
    dialects read differently is refused: only literals, `.`, `^`, `$`, `\\d \\D \\w \\W \\b \\B`,
    escaped syntax characters, `\\n \\r \\t`, plain and `(?:` groups, `|`, bracket classes and
    greedy or lazy quantifiers are admitted. Raises `ValueError` outside that dialect.
    """
    out: list[str] = []
    depth = 0
    index = 0
    atom = False  # the previous token can take a quantifier
    while index < len(pattern):
        char = pattern[index]
        index += 1
        if char == "\\":
            if index >= len(pattern):
                raise ValueError("dangling escape")
            escaped = pattern[index]
            index += 1
            if escaped in _SYNTAX:
                out.append("\\" + escaped)
                atom = True
            elif escaped in _CLASS_ESCAPES:
                out.append("\\" + escaped)
                atom = True
            elif escaped in "bB":
                out.append("\\" + escaped)
                atom = False
            elif escaped in _CONTROL_ESCAPES:
                out.append("\\" + escaped)
                atom = True
            else:
                raise ValueError("unsupported escape")
        elif char == "[":
            end, text = _translate_class(pattern, index)
            out.append(text)
            index = end
            atom = True
        elif char == "(":
            if pattern.startswith("?", index):
                if not pattern.startswith("?:", index):
                    raise ValueError("unsupported group")
                index += 2
                out.append("(?:")
            else:
                out.append("(")
            depth += 1
            atom = False
        elif char == ")":
            if depth == 0:
                raise ValueError("unbalanced group")
            depth -= 1
            out.append(")")
            atom = True
        elif char == "|":
            out.append("|")
            atom = False
        elif char in "^$":
            out.append("^" if char == "^" else "\\Z")
            atom = False
        elif char == ".":
            out.append(_ANY)
            atom = True
        elif char in "*+?" or char == "{":
            if not atom:
                raise ValueError("nothing to repeat")
            if char == "{":
                match = _QUANTIFIER.match(pattern, index - 1)
                if match is None:
                    raise ValueError("malformed quantifier")
                index = match.end()
                out.append(match.group())
            else:
                out.append(char)
            if pattern.startswith("?", index):
                index += 1
                out.append("?")
            atom = False
        elif char in "]}":
            raise ValueError("unescaped bracket")
        else:
            out.append(char)
            atom = True
    if depth:
        raise ValueError("unbalanced group")
    return "".join(out)


def _translate_class(pattern: str, index: int) -> tuple[int, str]:
    out = ["["]
    if pattern.startswith("^", index):
        out.append("^")
        index += 1
    if pattern.startswith("]", index):
        raise ValueError("empty class")
    while index < len(pattern):
        char = pattern[index]
        index += 1
        if char == "]":
            out.append("]")
            return index, "".join(out)
        if char == "[":
            raise ValueError("nested class")
        if char == "\\":
            if index >= len(pattern):
                break
            escaped = pattern[index]
            index += 1
            if escaped not in _SYNTAX and escaped not in "-dDwWnrt":
                raise ValueError("unsupported escape")
            out.append("\\" + escaped)
        else:
            out.append(char)
    raise ValueError("unterminated class")


@cache
def _compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(translate_pattern(pattern), re.ASCII)


def _array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class StringRule(WireModel):
    type: Literal["string"]
    max_length: Annotated[int, Field(strict=True, ge=0, le=MAX_STRING_LENGTH)]
    pattern: ScalarString | SkipJsonSchema[None] = Field(
        default=None, exclude_if=lambda value: value is None
    )
    enum: (
        Annotated[
            tuple[ScalarString, ...],
            BeforeValidator(_array),
            Field(min_length=1, max_length=MAX_PROPERTIES),
        ]
        | SkipJsonSchema[None]
    ) = Field(default=None, exclude_if=lambda value: value is None)

    @model_validator(mode="after")
    def compilable_pattern(self) -> Self:
        if self.pattern is not None:
            try:
                _compiled(self.pattern)
            except (ValueError, re.error, OverflowError, RecursionError):
                raise ValueError("pattern does not compile") from None
        return self


class IntegerRule(WireModel):
    type: Literal["integer"]
    minimum: (
        Annotated[int, Field(strict=True, ge=0, le=MAX_SAFE_INTEGER)] | SkipJsonSchema[None]
    ) = Field(default=None, exclude_if=lambda value: value is None)
    maximum: (
        Annotated[int, Field(strict=True, ge=0, le=MAX_SAFE_INTEGER)] | SkipJsonSchema[None]
    ) = Field(default=None, exclude_if=lambda value: value is None)

    @model_validator(mode="after")
    def ordered_bounds(self) -> Self:
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("minimum exceeds maximum")
        return self


class BooleanRule(WireModel):
    type: Literal["boolean"]


class _ObjectRule(WireModel):
    type: Literal["object"]
    additional_properties: Literal[False]
    required: Annotated[
        tuple[ScalarString, ...],
        BeforeValidator(_array),
        Field(max_length=MAX_PROPERTIES),
    ] = ()

    def _check_required(self, names: frozenset[str]) -> None:
        if len(set(self.required)) != len(self.required) or not set(self.required) <= names:
            raise ValueError("required must be unique property names")


class NestedObjectRule(_ObjectRule):
    properties: Annotated[
        dict[ScalarString, StringRule | IntegerRule | BooleanRule],
        Field(max_length=MAX_PROPERTIES),
    ]

    @model_validator(mode="after")
    def required_declared(self) -> Self:
        self._check_required(frozenset(self.properties))
        return self


class MetadataSchemaDocument(_ObjectRule):
    """The registered wire model of `cf.metadata-schema.v1`: one subset document."""

    properties: Annotated[
        dict[ScalarString, StringRule | IntegerRule | BooleanRule | NestedObjectRule],
        Field(max_length=MAX_PROPERTIES),
    ]

    @model_validator(mode="after")
    def required_declared(self) -> Self:
        self._check_required(frozenset(self.properties))
        return self


type _Rule = StringRule | IntegerRule | BooleanRule | NestedObjectRule | MetadataSchemaDocument


def _fail() -> ContractError:
    return ContractError("invalid_schema")


def _check_object(rule: NestedObjectRule | MetadataSchemaDocument, value: object) -> None:
    if not isinstance(value, Mapping):
        raise _fail()
    if any(not isinstance(key, str) or key not in rule.properties for key in value):
        raise _fail()
    if any(name not in value for name in rule.required):
        raise _fail()
    for name, item in value.items():
        _check_value(rule.properties[name], item)


def _check_value(rule: _Rule, value: object) -> None:
    if isinstance(rule, (NestedObjectRule, MetadataSchemaDocument)):
        _check_object(rule, value)
    elif isinstance(rule, StringRule):
        if not isinstance(value, str) or len(value) > rule.max_length:
            raise _fail()
        if rule.enum is not None and value not in rule.enum:
            raise _fail()
        if rule.pattern is not None and _compiled(rule.pattern).search(value) is None:
            raise _fail()
    elif isinstance(rule, IntegerRule):
        if not isinstance(value, int) or isinstance(value, bool):
            raise _fail()
        if rule.minimum is not None and value < rule.minimum:
            raise _fail()
        if rule.maximum is not None and value > rule.maximum:
            raise _fail()
    elif not isinstance(value, bool):
        raise _fail()


@dataclass(frozen=True)
class MetadataSchema:
    """A parsed, subset-conformant document; evaluating it executes nothing operator-supplied."""

    document: MetadataSchemaDocument

    @classmethod
    def parse(cls, data: bytes, limits: ContractLimits) -> MetadataSchema:
        """Admit bytes through the bounded codec; outside the subset is `invalid_schema`."""
        return cls(MetadataSchemaDocument.from_wire(data, limits))

    def validate(self, metadata: Mapping[str, object]) -> None:
        """Raise `ContractError("invalid_schema")` unless metadata conforms to the document."""
        _check_object(self.document, metadata)
