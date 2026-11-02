"""Build an intake, a withdrawal list, a new-sources list and a diff report from curated batches.

`build_intake` is a pure function of its inputs plus the bytes `read_root` returns: it validates the
batches, re-reads and re-hashes every file of the batch being built, replays the earlier batches
into an effective state, classifies the batch against it and returns canonical (RFC 8785) file
contents. It touches no ledger, database, clock or network. `write_outputs` then publishes the
files all-or-nothing: they are written into a private temporary directory beside the target, which
is renamed onto the target only when every file is in place.

Every metadata value is hashed and serialized through the signed-integer paths (the batch digest,
the identities and the canonical dumps), because a profile may bound a metadata field below zero.
"""

from __future__ import annotations

import errno
import hashlib
import os
import shutil
import stat
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, cast

import rfc8785
from pydantic import ValidationError

from conscience_foundry.contracts.admission import IntakeManifest
from conscience_foundry.contracts.common import (
    ArtifactLocation,
    ContractError,
    ContractLimits,
    Digest,
    Id,
    WireModel,
)
from conscience_foundry.contracts.intake import (
    CuratedBatch,
    IntakeDiff,
    NewSources,
    WithdrawalList,
    batch_digest,
)
from conscience_foundry.contracts.project import MetadataBinding, PolicyArtifact, ProjectConfig
from conscience_foundry.intake.diff import (
    Classification,
    CurrentAsset,
    EffectiveState,
    asset_of,
    classify,
    replay,
)
from conscience_foundry.intake.identity import batch_id, decision_id, source_id

if TYPE_CHECKING:
    from conscience_foundry.cli.config import AdmissionSettings

Status = Literal["ready", "policy_revision_needed"]
NEW_SOURCES = "new-sources.json"
DIFF_REPORT = "diff-report.json"
INTAKE = "intake.json"
WITHDRAWALS = "withdrawals.json"
_CAUSE_MESSAGE = {
    "changed": "Source replaced by a later batch",
    "missing": "Source absent from its batch key's approved set",
}
_CODE = {"changed": "source_changed", "missing": "source_missing"}
_TEMPORARY_PREFIX = ".build-intake-"


@dataclass(frozen=True)
class IntakeOutputs:
    """The canonical contents of every file to write, keyed by file name."""

    status: Status
    files: Mapping[str, bytes]
    diff: IntakeDiff

    def __post_init__(self) -> None:
        object.__setattr__(self, "files", MappingProxyType(dict(self.files)))


def _limit(limits_by_schema: Mapping[str, ContractLimits], schema: str) -> ContractLimits:
    found = limits_by_schema.get(schema)
    if found is None:
        raise ContractError("limits_missing")
    return found


def _canonical(value: object) -> bytes:
    try:
        return rfc8785.dumps(cast(Any, value))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ContractError("invalid_schema") from None


def _sha256(data: bytes) -> Digest:
    return hashlib.sha256(data).hexdigest()


def _document[Model: WireModel](
    value: dict[str, Any], model: type[Model], limits: ContractLimits
) -> tuple[bytes, Model]:
    """Canonical bytes of `value`, parsed back exactly as any consumer would parse them."""
    data = _canonical(value)
    return data, model.from_wire(data, limits)


def _parse(
    data: bytes, limits_by_schema: Mapping[str, ContractLimits]
) -> tuple[CuratedBatch, Digest]:
    batch = CuratedBatch.from_wire(data, _limit(limits_by_schema, "cf.curated-batch.v1"))
    return batch, batch_digest(data)


def _shared_context(batch: CuratedBatch, other: CuratedBatch) -> None:
    if (
        other.project_id != batch.project_id
        or other.producer.name != batch.producer.name
        or other.custody_root_label != batch.custody_root_label
    ):
        raise ContractError("invalid_schema")


def read_custody_file(root: Path, relative_path: str, limit: int) -> bytes:
    """Read one regular file under `root` without following any link, at most `limit` bytes.

    `unsafe_path` for a link, a non-regular file or a component that is not a directory,
    `artifact_missing` for an absent file and `limit_exceeded` for one larger than `limit`.
    """
    try:
        parts = ArtifactLocation(store_id="root", object_key=relative_path).object_key.split("/")
    except ValidationError:
        raise ContractError("unsafe_path") from None
    if not root.is_absolute() or any(part in {".", ".."} for part in root.parts):
        raise ContractError("unsafe_path")
    handle = -1
    try:
        handle = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        for part in (*root.parts[1:], *parts[:-1]):
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=handle)
            os.close(handle)
            handle = following
        file_handle = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=handle)
    except OSError as error:
        if handle >= 0:
            os.close(handle)
        if error.errno == errno.ENOENT:
            raise ContractError("artifact_missing") from None
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ContractError("unsafe_path") from None
        raise ContractError("unavailable") from None
    os.close(handle)
    with os.fdopen(file_handle, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ContractError("unsafe_path")
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ContractError("limit_exceeded")
    return data


def _rehash(
    batch: CuratedBatch, read_root: Callable[[str, str], bytes], settings: AdmissionSettings
) -> None:
    """Refuse the whole build unless every listed file still has its exported bytes."""
    label = batch.custody_root_label
    if label not in {root.root_id for root in settings.input_roots}:
        raise ContractError("config_invalid")
    for item in batch.items:  # every path is judged before the first byte is read
        try:
            ArtifactLocation(store_id=label, object_key=item.relative_path)
        except ValidationError:
            raise ContractError("unsafe_path") from None
    for item in batch.items:
        try:
            data = read_root(label, item.relative_path)
        except ContractError as error:
            if error.code == "artifact_missing":
                raise ContractError("source_missing") from None
            if error.code == "limit_exceeded":
                raise ContractError("source_changed") from None
            raise
        except OSError:
            raise ContractError("unavailable") from None
        if len(data) != item.size_bytes or _sha256(data) != item.sha256:
            raise ContractError("source_changed")


def _admitted_ids(state: EffectiveState) -> tuple[Id, ...]:
    ids = {asset.admitted_batch_id for asset in state.current.values()}
    return tuple(sorted(ids | set(state.withdrawn.values())))


def _withdrawal_entries(
    project_id: Id, classification: Classification, by_digest: Digest
) -> list[dict[str, Any]]:
    """One entry per replaced predecessor, then one per vanished asset, each by source key."""
    entries: list[dict[str, Any]] = []
    pairs: list[tuple[Literal["changed", "missing"], CurrentAsset]] = [
        *(("changed", classification.predecessors[key]) for key in classification.changed),
        *(("missing", asset) for asset in classification.missing_assets),
    ]
    for cause, asset in pairs:
        entries.append(
            {
                "batchId": asset.admitted_batch_id,
                "assetId": asset.asset_id,
                "sourceId": asset.source_id,
                "cause": cause,
                "decisionId": decision_id(
                    project_id, asset.admitted_batch_id, asset.asset_id, cause, by_digest
                ),
                "reason": {"code": _CODE[cause], "message": _CAUSE_MESSAGE[cause]},
            }
        )
    return entries


def build_intake(
    batch_bytes: bytes,
    previous: Sequence[bytes],
    *,
    settings: AdmissionSettings,
    project: ProjectConfig,
    policy: PolicyArtifact,
    binding: MetadataBinding,
    read_root: Callable[[str, str], bytes],
    limits_by_schema: Mapping[str, ContractLimits],
) -> IntakeOutputs:
    """Turn `batch_bytes` and the earlier batches into the canonical output files.

    Refusals, in order: inputs that are not valid batches of one project, producer and custody
    label (`invalid_schema`), a batch listed twice or among its own predecessors
    (`determinism_conflict`), an unknown custody label (`config_invalid`), an unsafe path
    (`unsafe_path`, before any read), a missing or altered file (`source_missing`,
    `source_changed`), metadata the profile's schema refuses (`invalid_schema`). Nothing is
    returned unless every check passed.
    """
    batch, digest = _parse(batch_bytes, limits_by_schema)
    if batch.project_id != project.project_id or policy.project_id != project.project_id:
        raise ContractError("invalid_schema")
    earlier = [_parse(data, limits_by_schema) for data in previous]
    digests = [item_digest for _, item_digest in earlier]
    if digest in digests or len(digests) != len(set(digests)):
        raise ContractError("determinism_conflict")
    for other, _ in earlier:
        _shared_context(batch, other)
    ordered = sorted(earlier, key=lambda pair: (pair[0].created_at, pair[1]))

    _rehash(batch, read_root, settings)
    for item in batch.items:
        binding.validate(binding.expected_schema_ref, dict(item.metadata))

    state = replay(batch.project_id, ordered)
    ident = batch_id(batch.project_id, batch.batch_key, digest)
    classification = classify(state, batch, ident)
    items = {item.source_key: item for item in batch.items}

    known = {entry.source_id for entry in policy.sources}
    new = [(source_id(batch.project_id, key), key) for key in classification.new]
    status: Status = "ready" if all(sid in known for sid, _ in new) else "policy_revision_needed"

    sources_data, _ = _document(
        {
            "schemaVersion": "cf.new-sources.v1",
            "projectId": batch.project_id,
            "batchDigest": digest,
            "sources": [{"sourceId": sid, "sourceKey": key} for sid, key in new],
        },
        NewSources,
        _limit(limits_by_schema, "cf.new-sources.v1"),
    )
    files: dict[str, bytes] = {NEW_SOURCES: sources_data}

    intake_digest: Digest | None = None
    entries: list[dict[str, Any]] = []
    if status == "ready":
        carried = sorted((*classification.new, *classification.changed))
        if carried:
            intake_data, _ = _document(
                {
                    "schemaVersion": "cf.intake.v1",
                    "projectId": batch.project_id,
                    "batchId": ident,
                    "profileId": project.profile_id,
                    "profileVersion": project.profile_version,
                    "policyRef": project.policy_ref.model_dump(
                        mode="json", by_alias=True, exclude_none=True
                    ),
                    "createdAt": batch.created_at,
                    "items": [
                        {
                            "assetId": asset_of(batch, items[key]),
                            "sourceId": source_id(batch.project_id, key),
                            "originalDigest": items[key].sha256,
                            "sizeBytes": items[key].size_bytes,
                            "mediaType": items[key].media_type,
                            "custodyRef": {
                                "rootId": batch.custody_root_label,
                                "relativePath": items[key].relative_path,
                            },
                            "metadata": items[key].model_dump(mode="json", by_alias=True)[
                                "metadata"
                            ],
                        }
                        for key in carried
                    ],
                },
                IntakeManifest,
                _limit(limits_by_schema, "cf.intake.v1"),
            )
            files[INTAKE] = intake_data
            intake_digest = _sha256(intake_data)
        entries = _withdrawal_entries(batch.project_id, classification, digest)

    classes = {
        "new": classification.new,
        "unchanged": classification.unchanged,
        "changed": classification.changed,
        "moved": classification.moved,
        "returned": classification.returned,
        "missing": classification.missing,
    }
    report: dict[str, Any] = {
        "schemaVersion": "cf.intake-diff.v1",
        "projectId": batch.project_id,
        "batchKey": batch.batch_key,
        "batchDigest": digest,
        "previousBatchDigests": [item_digest for _, item_digest in ordered],
        "status": status,
        "classes": {name: list(keys) for name, keys in classes.items()},
        "assumedAdmittedBatchIds": list(_admitted_ids(state)),
        "newSourcesDigest": _sha256(sources_data),
    }
    if intake_digest is not None:
        report["intakeDigest"] = intake_digest
    report_data, parsed = _document(
        report, IntakeDiff, _limit(limits_by_schema, "cf.intake-diff.v1")
    )
    files[DIFF_REPORT] = report_data

    if entries:
        withdrawals_data, _ = _document(
            {
                "schemaVersion": "cf.withdrawal-list.v1",
                "projectId": batch.project_id,
                "byBatchDigest": digest,
                "diffReportDigest": _sha256(report_data),
                "entries": entries,
            },
            WithdrawalList,
            _limit(limits_by_schema, "cf.withdrawal-list.v1"),
        )
        files[WITHDRAWALS] = withdrawals_data
    return IntakeOutputs(status=status, files=files, diff=parsed)


def write_outputs(files: Mapping[str, bytes], directory: Path) -> None:
    """Publish `files` as `directory`, all or nothing.

    `directory` must be absent or an empty directory (`config_invalid` otherwise, also when its
    parent does not exist). The files are written and synced in a private temporary directory
    beside it, which is then renamed onto it; on any failure the temporary directory is removed
    and `directory` is untouched.
    """
    parent = directory.parent
    if not parent.is_dir() or (directory.exists() and not _empty_directory(directory)):
        raise ContractError("config_invalid")
    try:
        staging = Path(tempfile.mkdtemp(prefix=_TEMPORARY_PREFIX, dir=parent))
    except OSError:
        raise ContractError("unavailable") from None
    try:
        for name, data in sorted(files.items()):
            descriptor = os.open(staging / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as target:
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
        try:
            os.rename(staging, directory)
        except OSError as error:
            if error.errno in {errno.ENOTEMPTY, errno.EEXIST, errno.ENOTDIR, errno.EISDIR}:
                raise ContractError("config_invalid") from None
            raise
    except ContractError:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    except OSError:
        shutil.rmtree(staging, ignore_errors=True)
        raise ContractError("unavailable") from None


def _empty_directory(path: Path) -> bool:
    return path.is_dir() and not path.is_symlink() and not any(path.iterdir())
