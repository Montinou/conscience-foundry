"""Offline default and explicit disposable-database opt-in for tests."""

from __future__ import annotations

import os
import re
import socket
import stat
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict


def approved_database_dsn() -> str:
    """Require independent explicit approval before any test connection."""
    dsn = os.environ.get("CF_TEST_POSTGRES_DSN", "")
    approval = os.environ.get("CF_TEST_POSTGRES_APPROVED_DSN", "")
    if not dsn or not approval or dsn != approval:
        raise ValueError("Database tests require independent explicit authorization")
    if any(
        option.envvar is not None and option.envvar.decode("ascii") in os.environ
        for option in psycopg.pq.Conninfo.get_defaults()
    ):
        raise ValueError("Database tests reject ambient libpq connection configuration")
    try:
        options = conninfo_to_dict(dsn)
        if set(options) - {"host", "port", "dbname", "user", "connect_timeout"}:
            raise ValueError
        database = options.get("dbname", "")
        host = Path(options.get("host", ""))
        port = int(options.get("port", "5432"))
        if (
            not re.fullmatch(r"cf_[a-z0-9_]*test[a-z0-9_]*", database)
            or not options.get("user")
            or not host.is_absolute()
            or not 1 <= port <= 65535
            or host.is_symlink()
        ):
            raise ValueError
        information = host.lstat()
        if (
            not stat.S_ISDIR(information.st_mode)
            or information.st_uid != os.getuid()
            or stat.S_IMODE(information.st_mode) != 0o700
        ):
            raise ValueError
    except (ValueError, OSError, psycopg.Error):
        raise ValueError(
            "Database tests require a private socket and disposable database"
        ) from None
    return dsn


@pytest.fixture
def ledger(request: pytest.FixtureRequest) -> Iterator[object]:
    """Own only a fresh synthetic schema on the already approved instance."""
    from conscience_foundry.ledger.db import Ledger

    if request.node.get_closest_marker("database") is None:
        pytest.fail("Disposable database fixture requires its explicit database marker")
    dsn = approved_database_dsn()
    schema = "cf_test_" + uuid4().hex

    def connect() -> psycopg.Connection[tuple[object, ...]]:
        try:
            return psycopg.connect(dsn, connect_timeout=3)
        except psycopg.Error:
            pytest.fail("Explicitly approved disposable database is unavailable")

    database = Ledger(connect, schema=schema)
    database.migrate()
    try:
        yield database
    finally:
        with connect() as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


@pytest.fixture(autouse=True)
def deny_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    database = request.node.get_closest_marker("database") is not None
    if database:
        try:
            options = conninfo_to_dict(approved_database_dsn())
        except ValueError:
            pytest.fail("Database tests require explicitly approved private socket configuration")
        allowed_socket = str(Path(options["host"]) / (".s.PGSQL." + options.get("port", "5432")))
    else:
        allowed_socket = None
    original_connect = socket.socket.connect

    def connect(sock: socket.socket, address: object) -> None:
        if (
            sock.family == socket.AF_UNIX
            and allowed_socket is not None
            and address == allowed_socket
        ):
            original_connect(sock, address)
            return
        raise RuntimeError("Network access is disabled in offline tests")

    def connect_ex(sock: socket.socket, address: object) -> int:
        connect(sock, address)
        return 0

    def create_connection(
        address: tuple[str, int], *args: object, **kwargs: object
    ) -> socket.socket:
        raise RuntimeError("Network access is disabled in offline tests")

    def getaddrinfo(host: object, port: object, *args: object, **kwargs: object) -> object:
        raise RuntimeError("Network access is disabled in offline tests")

    def sendto(*args: object, **kwargs: object) -> int:
        raise RuntimeError("Network access is disabled in offline tests")

    def deny_resolver(*args: object, **kwargs: object) -> object:
        raise RuntimeError("Network access is disabled in offline tests")

    for name in ("gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo"):
        monkeypatch.setattr(socket, name, deny_resolver)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket.socket, "sendto", sendto)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "create_connection", create_connection)
    yield
