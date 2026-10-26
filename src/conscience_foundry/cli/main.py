"""`cfoundry`: argparse front end. It parses, dispatches and prints one JSON record; nothing else.

Exit codes: 0 ok or dry run, 1 failed, 2 usage error, 3 blocked by a gate. Every diagnostic is a
stable code; no message text, path, credential, driver error or document content is printed.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from collections.abc import Sequence
from typing import Any, NoReturn, TextIO

from conscience_foundry.cli.commands import COMMANDS, Outcome, run_command
from conscience_foundry.cli.config import TrustedServices
from conscience_foundry.cli.preflight import PILOT_COMMANDS

ALL_COMMANDS = (*COMMANDS, *PILOT_COMMANDS)
ALL_BY_NAME = {command.name: command for command in ALL_COMMANDS}
EXIT = {"ok": 0, "dry_run": 0, "failed": 1, "blocked": 3}
USAGE_EXIT = 2


class _Usage(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise _Usage  # argparse messages echo argument values; they are never shown


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="cfoundry",
        description="Explicit operator commands for the existing vertical flow. Stateful "
        "commands need --config; effects need --execute and a configured grant.",
        allow_abbrev=False,
    )
    parser.add_argument("--config", help="private operator configuration (mandatory for state)")
    commands = parser.add_subparsers(dest="command", parser_class=_Parser)
    for command in ALL_COMMANDS:
        child = commands.add_parser(command.name, help=command.summary, allow_abbrev=False)
        command.arguments(child)
        if command.effect:
            child.add_argument(
                "--execute",
                action="store_true",
                help="perform the effect; without it the command is a dry run",
            )
    return parser


def _emit(out: TextIO, command: str | None, outcome: Outcome) -> int:
    record: dict[str, Any] = {"command": command, "outcome": outcome.status}
    if outcome.code is not None:
        record["code"] = outcome.code
    record.update(outcome.data)
    out.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    return EXIT[outcome.status]


def main(
    argv: Sequence[str],
    *,
    services: TrustedServices | None = None,
    out: TextIO | None = None,
) -> int:
    stream = out if out is not None else sys.stdout
    parser = build_parser()
    try:
        with contextlib.redirect_stdout(stream):
            args = parser.parse_args(list(argv))
        if args.command is None:
            raise _Usage
    except _Usage:
        _emit(stream, None, Outcome("failed", "usage"))
        return USAGE_EXIT
    except SystemExit as stop:  # --help
        return stop.code if isinstance(stop.code, int) else 0
    return _emit(
        stream,
        args.command,
        run_command(ALL_BY_NAME[args.command], args, services or TrustedServices()),
    )


def run() -> None:
    """Console entry point: no adapters are installed, so effectful commands fail closed."""
    raise SystemExit(main(sys.argv[1:]))
