"""Guard: the old `kf`/`kfx` identifier prefix must not survive anywhere in the shipped tree."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATTERN = re.compile(r"\bkfx?[._]")
SELF = "tests/acceptance/test_single_name.py"


def test_no_old_name_identifiers() -> None:
    files = subprocess.run(
        ["git", "ls-files", "src", "tests", "schemas", "scripts", "docs/guide"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    hits = [
        f
        for f in files
        if f != SELF and PATTERN.search((ROOT / f).read_text(encoding="utf-8", errors="ignore"))
    ]
    assert hits == []
