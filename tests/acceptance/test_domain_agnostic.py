"""The core names no producer or consumer.

The word list lives only in this file, and `tests/` is not scanned: existing tests name the old
consumer in deny-list assertions. Generic words such as "edition" are not banned; only the whole
words below are, matched case-insensitively.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BANNED = ("agora", "ágora", "curaduria", "curaduría", "work_key", "edition_key")
PATTERN = re.compile(
    r"(?<!\w)(?:" + "|".join(re.escape(word) for word in BANNED) + r")(?!\w)",
    re.IGNORECASE,
)
SCANNED_DIRECTORIES = ("src", "schemas", "scripts", "docs/guide")
SCANNED_FILES = ("README.md",)


def git_paths(*options: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", *options, "-z", "--", *SCANNED_DIRECTORIES, *SCANNED_FILES],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [item for item in result.stdout.split("\0") if item]


def scanned_paths() -> list[Path]:
    """Tracked files under the scanned locations, plus new ones a plain `git add` would stage."""
    listed = {*git_paths(), *git_paths("--others", "--exclude-standard")}
    return sorted(ROOT / name for name in listed if (ROOT / name).is_file())


def hits(paths: list[Path]) -> list[str]:
    found = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue  # a binary file names nobody
        for number, line in enumerate(text.splitlines(), start=1):
            if PATTERN.search(line):
                found.append(f"{path.name}:{number}")
    return found


def test_core_names_no_producer() -> None:
    paths = scanned_paths()
    assert any(path.parts[-3:-1] == ("conscience_foundry", "intake") for path in paths)
    assert hits(paths) == []


def test_the_scan_cannot_pass_vacuously(tmp_path: Path) -> None:
    probe = tmp_path / "probe.py"
    probe.write_text("value = {'work_key': 1}\n", encoding="utf-8")
    assert hits([probe]) == ["probe.py:1"]
    for word in BANNED:
        probe.write_text(f"# the {word.upper()} library\n", encoding="utf-8")
        assert hits([probe]) == ["probe.py:1"], word


def test_only_whole_words_and_the_listed_names_match(tmp_path: Path) -> None:
    probe = tmp_path / "probe.md"
    probe.write_text(
        "An edition of the work, an editions_key, agoraphobia and a network_key.\n",
        encoding="utf-8",
    )
    assert hits([probe]) == []
