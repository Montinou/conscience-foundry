"""`cfoundry`: argparse front end. It parses, dispatches and prints one JSON record; nothing else.

Exit codes: 0 ok or dry run, 1 failed, 2 usage error, 3 blocked by a gate, 130 interrupted (a
``run-pilot`` stopped by Ctrl-C). Every diagnostic is a stable code; no message text, path,
credential, driver error or document content is printed.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from collections.abc import Sequence
from typing import Any, NoReturn, TextIO

from conscience_foundry.cli.commands import COMMANDS, Outcome, classify, run_command
from conscience_foundry.cli.config import TrustedServices, load_config
from conscience_foundry.cli.live import build_services
from conscience_foundry.cli.preflight import PILOT_COMMANDS
from conscience_foundry.contracts.common import ContractError

ALL_COMMANDS = (*COMMANDS, *PILOT_COMMANDS)
ALL_BY_NAME = {command.name: command for command in ALL_COMMANDS}
EXIT = {"ok": 0, "dry_run": 0, "failed": 1, "blocked": 3, "interrupted": 130}
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


def configured_services(argv: Sequence[str]) -> TrustedServices:
    """The trusted services the named config's ``live`` section stands for; none without one.

    An unparsable command line or an unreadable config yields no services: the command itself
    then reports that failure with its own stable code.
    """
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            args = build_parser().parse_args(list(argv))
        config = load_config(args.config) if args.config is not None else None
    except (_Usage, SystemExit, ContractError):
        return TrustedServices()
    return TrustedServices() if config is None else build_services(config)


def run() -> None:
    """Console entry point: the services come from the config, so a config without a ``live``
    section installs no adapter and effectful commands fail closed."""
    argv = sys.argv[1:]
    try:
        services = configured_services(argv)
    except ContractError as error:
        raise SystemExit(_emit(sys.stdout, None, classify(error))) from None
    raise SystemExit(main(argv, services=services))
