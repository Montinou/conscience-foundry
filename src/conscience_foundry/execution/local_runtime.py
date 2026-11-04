"""Fingerprint trusted host files; this is identity, not an OS sandbox."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import sys
import sysconfig
from pathlib import Path

from conscience_foundry.contracts.common import ContractError, Digest


def _usable(path: Path) -> bool:
    return (
        "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
        and path.name not in {"RECORD", "INSTALLER", "direct_url.json", "REQUESTED"}
    )


def _inventory() -> list[tuple[str, Path]]:
    entries: list[tuple[str, Path]] = [("interpreter", Path(sys.executable))]
    stdlib = Path(sysconfig.get_path("stdlib"))
    for path in stdlib.rglob("*"):
        if "site-packages" in path.parts or "dist-packages" in path.parts:
            continue
        if (
            path.is_file()
            and _usable(path)
            and (path.suffix == ".py" or path.suffix in {".so", ".pyd", ".dylib"})
        ):
            entries.append(("stdlib/" + path.relative_to(stdlib).as_posix(), path))
    package = Path(__file__).resolve().parent.parent
    for path in package.rglob("*.py"):
        if path.is_file() and _usable(path):
            entries.append(("package/" + path.relative_to(package).as_posix(), path))
    for dist in importlib.metadata.distributions():
        name = dist.metadata.get("Name")
        if not name or dist.files is None:
            raise ContractError("unavailable")
        for item in dist.files:
            relative = Path(str(item))
            if not _usable(relative):
                continue
            path = Path(str(dist.locate_file(item)))
            if not path.is_file():
                raise ContractError("unavailable")
            entries.append((f"distribution/{name}/{relative.as_posix()}", path))
    return sorted(entries, key=lambda entry: entry[0])


def _hash_file(path: Path) -> str:
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
        current = path.stat()

    def identity(stat: os.stat_result) -> tuple[int, int, int, int, int]:
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)

    if identity(before) != identity(after) or identity(after) != identity(current):
        raise ContractError("hash_mismatch")
    return digest


def runtime_manifest() -> dict[str, object]:
    try:
        entries = _inventory()
        labels = [label for label, _ in entries]
        if len(labels) != len(set(labels)):
            raise ContractError("invalid_schema")
        return {
            "os": [platform.system(), platform.release(), platform.version(), platform.machine()],
            "files": {label: _hash_file(path) for label, path in sorted(entries)},
        }
    except ContractError:
        raise
    except Exception:
        raise ContractError("unavailable") from None


def runtime_digest(manifest: dict[str, object]) -> Digest:
    try:
        return hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()
    except Exception:
        raise ContractError("invalid_schema") from None


def verify_runtime(expected: Digest) -> None:
    if type(expected) is not str or runtime_digest(runtime_manifest()) != expected:
        raise ContractError("hash_mismatch")
