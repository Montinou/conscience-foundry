"""Allowlist check for what may enter Git or a built distribution.

Two surfaces are checked with the same two-step rule. A private marker (handoff, imported
history, environment files, corpora, models, credentials, store or tooling directories, absolute
or escaping paths) is always a violation. Anything else must match an explicit allowlist; a path
that is merely not known to be private is still refused. Nothing is read or uploaded here.

    uv run python scripts/check_public_boundary.py [ARCHIVE ...]

Without arguments the prospective index (tracked plus stageable untracked files) is checked.
Each ARCHIVE is a wheel (.whl) or sdist (.tar.gz) whose members are checked too.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tarfile
import zipfile
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

PACKAGE = "conscience_foundry"

PRIVATE_NAMES = frozenset(
    {
        ".ds_store",
        "claude.md",
        "claude.local.md",
        "id_rsa",
        "id_ed25519",
        ".npmrc",
        ".netrc",
        ".pgpass",
        ".envrc",
    }
)
PRIVATE_COMPONENTS = frozenset(
    {
        "corpus",
        "raw_corpus",
        "imported",
        "imported_history",
        "history",
        "models",
        "weights",
        "checkpoints",
        "store",
        "stores",
        "objects",
        "secrets",
        ".methodology",
        ".triqual",
        ".claude",
        ".codex",
        ".git",
        ".venv",
    }
)
PRIVATE_SUFFIXES = (
    ".safetensors",
    ".ckpt",
    ".gguf",
    ".onnx",
    ".pt",
    ".pth",
    ".pem",
    ".key",
    ".p12",
    ".sqlite",
    ".sqlite3",
    ".dump",
    ".p8",
    ".tfstate",
)
PRIVATE_DOC_ROOT = "docs"
GUIDE = "docs/guide/f1.md"

INDEX_FILES = frozenset(
    {".gitignore", "LICENSE", "README.md", "pyproject.toml", "uv.lock", GUIDE}
)
# Exact shapes the repository ships under its source, schema, script and test trees. A tree prefix
# alone never allows a path: an unknown file type or name there is refused like any other.
INDEX_PATTERNS = (
    re.compile(rf"^src/{PACKAGE}/(?:[a-z0-9_]+/)*[A-Za-z0-9_]+\.py$"),
    re.compile(rf"^src/{PACKAGE}/ledger/migrations/[0-9]{{3}}_[a-z0-9_]+\.sql$"),
    re.compile(rf"^src/{PACKAGE}/py\.typed$"),
    re.compile(r"^schemas/[a-z0-9][a-z0-9.-]*\.(?:schema|rules)\.json$"),
    re.compile(r"^scripts/[a-z0-9_]+\.py$"),
    re.compile(r"^tests/(?:[a-z0-9_]+/)*[A-Za-z0-9_]+\.py$"),
    re.compile(r"^tests/fixtures/public/[a-z0-9_]+\.json$"),
    re.compile(r"^tests/js/(?:package\.json|package-lock\.json|schema_parity\.mjs)$"),
)
DEPENDENCY_TREES = frozenset({"node_modules"})

PACKAGE_MODULE = re.compile(rf"^{PACKAGE}/(?:[a-z0-9_]+/)*[A-Za-z0-9_]+\.py$")
PACKAGE_MIGRATION = re.compile(rf"^{PACKAGE}/ledger/migrations/[0-9]{{3}}_[a-z0-9_]+\.sql$")
PACKAGE_TYPED = re.compile(rf"^{PACKAGE}/py\.typed$")
PACKAGE_DIRECTORY = re.compile(rf"^{PACKAGE}(?:/[a-z0-9_]+)*/$")
DIST_INFO = re.compile(
    rf"^{PACKAGE}-[0-9][0-9A-Za-z.+!_-]*\.dist-info/"
    r"(?:METADATA|WHEEL|entry_points\.txt|top_level\.txt|RECORD|licenses/LICENSE)$"
)
SDIST_ROOT = re.compile(rf"^{PACKAGE}-[0-9][0-9A-Za-z.+!_-]*$")
SDIST_FILES = frozenset({"LICENSE", "PKG-INFO", "README.md", "pyproject.toml", "setup.cfg"})
EGG_INFO = re.compile(
    rf"^src/{PACKAGE}\.egg-info/"
    r"(?:PKG-INFO|SOURCES\.txt|dependency_links\.txt|entry_points\.txt|requires\.txt|top_level\.txt)$"
)


def _unsafe(path: str) -> bool:
    return (
        not path
        or path.startswith(("/", "~"))
        or "\\" in path
        or "\0" in path
        or re.match(r"^[A-Za-z]:", path) is not None
        or ".." in PurePosixPath(path).parts
    )


def _private_code(path: str) -> str | None:
    """Return why a path is private, or None; checked before any allowlist."""
    parts = PurePosixPath(path).parts
    lowered = [part.lower() for part in parts]
    name = lowered[-1] if lowered else ""
    if name in PRIVATE_NAMES or "handoff" in name:
        return "private_handoff"
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return "private_environment"
    if name.startswith("credentials") or name.endswith(PRIVATE_SUFFIXES):
        return "private_credential_or_model"
    if lowered and lowered[0] == PRIVATE_DOC_ROOT and path != GUIDE:
        return "private_historical_docs"
    if any(part in PRIVATE_COMPONENTS for part in lowered):
        return "private_directory"
    return None


def _index_allowed(path: str) -> bool:
    if path in INDEX_FILES:
        return True
    if DEPENDENCY_TREES & set(PurePosixPath(path).parts):
        return False
    return any(pattern.fullmatch(path) for pattern in INDEX_PATTERNS)


def _package_allowed(member: str) -> bool:
    parts = member.split("/", 1)
    if (
        len(parts) == 2
        and SDIST_ROOT.fullmatch(parts[0])
        and not parts[0].endswith(".dist-info")
    ):
        rest = parts[1]
        if rest == "" or rest in SDIST_FILES or EGG_INFO.fullmatch(rest):
            return True
        if rest in {"src/", f"src/{PACKAGE}.egg-info/"}:
            return True
        if rest.startswith(f"src/{PACKAGE}"):
            return _package_allowed(rest.removeprefix("src/"))
        return False
    return bool(
        PACKAGE_MODULE.fullmatch(member)
        or PACKAGE_MIGRATION.fullmatch(member)
        or PACKAGE_TYPED.fullmatch(member)
        or PACKAGE_DIRECTORY.fullmatch(member)
        or DIST_INFO.fullmatch(member)
    )


def _classify(scope: str, path: str) -> str | None:
    if _unsafe(path):
        return f"{scope}:unsafe_path:{path}"
    private = _private_code(path)
    if private is not None:
        return f"{scope}:{private}:{path}"
    allowed = _index_allowed(path) if scope == "index" else _package_allowed(path)
    return None if allowed else f"{scope}:not_allowlisted:{path}"


def check_public_boundary(
    index_paths: Sequence[str], package_members: Sequence[str]
) -> tuple[str, ...]:
    """Return sorted `scope:reason:path` violations; an empty tuple means the boundary holds."""
    found = {
        reason
        for scope, paths in (("index", index_paths), ("package", package_members))
        for path in paths
        if (reason := _classify(scope, path)) is not None
    }
    return tuple(sorted(found))


def prospective_index_paths(root: Path) -> list[str]:
    def listing(*arguments: str) -> list[str]:
        result = subprocess.run(
            ["git", *arguments, "-z"], cwd=root, check=True, capture_output=True, text=True
        )
        return [item for item in result.stdout.split("\0") if item]

    tracked = listing("ls-files")
    untracked = listing("ls-files", "--others", "--exclude-standard")
    return sorted({*tracked, *untracked})


def archive_members(archive: Path) -> list[str]:
    if archive.suffix == ".whl":
        with zipfile.ZipFile(archive) as wheel:
            return wheel.namelist()
    with tarfile.open(archive) as sdist:
        return [
            member.name + "/" if member.isdir() else member.name for member in sdist.getmembers()
        ]


def main(arguments: Sequence[str]) -> int:
    root = Path(__file__).resolve().parents[1]
    members: list[str] = []
    for argument in arguments:
        members.extend(archive_members(Path(argument)))
    violations = check_public_boundary(prospective_index_paths(root), members)
    for violation in violations:
        print(violation)
    if violations:
        return 1
    print("public boundary ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
