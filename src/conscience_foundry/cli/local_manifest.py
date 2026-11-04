"""Read independently approved, exact-byte local quote and plan pins."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BeforeValidator

from conscience_foundry.cli.config import _read_fd
from conscience_foundry.cli.local_authority import LocalAllocationEstimate
from conscience_foundry.contracts.common import ContractError, ContractLimits, Id, Ref, WireModel
from conscience_foundry.contracts.execution import ExecutionPlan, LocalExecutionConfig
from conscience_foundry.execution.evidence import encoded


def _array(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class _Entry(WireModel):
    ref: Ref
    bytes_base64: str


class _Manifest(WireModel):
    schema_version: Literal["cfoundry.local-quote-manifest.v1"]
    project_id: Id
    authorization_ref: Ref
    plans: Annotated[tuple[_Entry, ...], BeforeValidator(_array)]
    configs: Annotated[tuple[_Entry, ...], BeforeValidator(_array)]
    estimates: Annotated[tuple[_Entry, ...], BeforeValidator(_array)]


@dataclass(frozen=True)
class LocalQuoteManifestPins:
    project_id: Id
    authorization_ref: Ref
    plans: tuple[tuple[Ref, bytes, ExecutionPlan], ...]
    configs: tuple[tuple[Ref, bytes, LocalExecutionConfig], ...]
    estimates: tuple[tuple[Ref, bytes, LocalAllocationEstimate], ...]


def _limit(limits: Mapping[str, ContractLimits], schema: str) -> ContractLimits:
    result = limits.get(schema)
    if type(result) is not ContractLimits:
        raise ContractError("limits_missing")
    return result


def _read_manifest(path: Path, limit: int) -> bytes:
    if not path.is_absolute() or any(part in ("..", "") for part in path.parts[1:]):
        raise ContractError("config_insecure")
    fds: list[int] = []
    links: list[tuple[int, str, int]] = []
    try:
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(root)
        for part in path.parts[1:-1]:
            parent = fds[-1]
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            fds.append(fd)
            links.append((parent, part, fd))
        for fd in fds:
            try:
                os.stat(".git", dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ContractError("config_insecure")
        fd = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=fds[-1],
        )
        try:
            information = os.fstat(fd)
            if (
                not stat.S_ISREG(information.st_mode)
                or information.st_uid != os.geteuid()
                or information.st_mode & 0o022
            ):
                raise ContractError("config_insecure")
        except BaseException:
            os.close(fd)
            raise
        data = _read_fd(fd, limit)
        for parent, name, fd in links:
            entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
            opened = os.fstat(fd)
            if not stat.S_ISDIR(entry.st_mode) or (entry.st_dev, entry.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                raise ContractError("config_insecure")
        return data
    except ContractError:
        raise
    except OSError:
        raise ContractError("config_insecure") from None
    finally:
        for fd in reversed(fds):
            os.close(fd)


def _decode(entry: _Entry, schema: str, project_id: Id, bound: ContractLimits) -> bytes:
    ref, text = entry.ref, entry.bytes_base64
    if (
        ref.project_id != project_id
        or ref.artifact_schema != schema
        or ref.media_type != "application/json"
        or ref.size_bytes > bound.max_json_bytes
    ):
        raise ContractError("forbidden")
    if len(text) != 4 * ((ref.size_bytes + 2) // 3):
        raise ContractError("invalid_schema")
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error):
        raise ContractError("invalid_schema") from None
    if (
        base64.b64encode(raw).decode("ascii") != text
        or len(raw) != ref.size_bytes
        or hashlib.sha256(raw).hexdigest() != ref.digest
    ):
        raise ContractError("hash_mismatch")
    return raw


def load_local_manifest(
    path: Path,
    *,
    project_id: Id,
    limits_by_schema: Mapping[str, ContractLimits],
    resource_policy_ref: Ref,
) -> LocalQuoteManifestPins:
    bound = _limit(limits_by_schema, "cf.metadata-schema.v1")
    manifest = _Manifest.from_wire(_read_manifest(path, bound.max_json_bytes), bound)
    auth = manifest.authorization_ref
    if (
        type(resource_policy_ref) is not Ref
        or resource_policy_ref.project_id != project_id
        or resource_policy_ref.artifact_schema != "cf.local-resource-policy.v1"
        or manifest.project_id != project_id
        or auth.project_id != project_id
        or auth.artifact_schema != "cf.run-authorization.v1"
        or auth.media_type != "application/json"
        or not manifest.plans
        or not manifest.configs
        or len(manifest.estimates) != 2
    ):
        raise ContractError("forbidden")
    seen: dict[str, Ref] = {}
    for entry in (*manifest.plans, *manifest.configs, *manifest.estimates):
        if entry.ref.digest in seen:
            raise ContractError("invalid_schema")
        seen[entry.ref.digest] = entry.ref
    plans = []
    for entry in manifest.plans:
        raw = _decode(
            entry,
            "cf.execution-plan.v1",
            project_id,
            _limit(limits_by_schema, "cf.execution-plan.v1"),
        )
        model = ExecutionPlan.from_wire(raw, _limit(limits_by_schema, "cf.execution-plan.v1"))
        if encoded(model) != raw or model.project_id != project_id:
            raise ContractError("forbidden")
        plans.append((entry.ref, raw, model))
    configs = []
    for entry in manifest.configs:
        raw = _decode(
            entry,
            "cf.local-execution-config.v1",
            project_id,
            _limit(limits_by_schema, "cf.local-execution-config.v1"),
        )
        config = LocalExecutionConfig.from_wire(
            raw, _limit(limits_by_schema, "cf.local-execution-config.v1")
        )
        if encoded(config) != raw or config.resource_policy_ref != resource_policy_ref:
            raise ContractError("forbidden")
        configs.append((entry.ref, raw, config))
    if {plan.execution_config_ref for _, _, plan in plans} != {ref for ref, _, _ in configs}:
        raise ContractError("forbidden")
    estimates = []
    for entry in manifest.estimates:
        raw = _decode(
            entry,
            "cfoundry.local-allocation-estimate.v1",
            project_id,
            _limit(limits_by_schema, "cfoundry.local-allocation-estimate.v1"),
        )
        estimate = LocalAllocationEstimate.from_wire(
            raw, _limit(limits_by_schema, "cfoundry.local-allocation-estimate.v1")
        )
        referenced = {ref for ref, _, _ in plans}
        quoted = set(estimate.plan_refs)
        mapped_configs = {plan.execution_config_ref for ref, _, plan in plans if ref in quoted}
        if (
            encoded(estimate) != raw
            or estimate.authorization_ref != auth
            or estimate.resource_policy_ref != resource_policy_ref
            or not quoted <= referenced
            or (estimate.scope == "run_storage" and quoted != referenced)
            or set(estimate.config_refs) != mapped_configs
        ):
            raise ContractError("forbidden")
        estimates.append((entry.ref, raw, estimate))
    if {estimate.scope for _, _, estimate in estimates} != {"attempt", "run_storage"}:
        raise ContractError("forbidden")
    return LocalQuoteManifestPins(project_id, auth, tuple(plans), tuple(configs), tuple(estimates))
