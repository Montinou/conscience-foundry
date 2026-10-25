"""Offline default and explicit disposable-database opt-in for tests."""

from __future__ import annotations

import os
import socket
from collections.abc import Iterator
from urllib.parse import urlsplit

import pytest


@pytest.fixture(autouse=True)
def deny_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    database = request.node.get_closest_marker("database") is not None
    if database:
        dsn = os.environ.get("CF_TEST_DATABASE_URL", "")
        if os.environ.get("CF_TEST_ALLOW_DATABASE") != "1" or not dsn:
            pytest.fail("Database tests require explicit disposable database authorization")
        parsed = urlsplit(dsn)
        if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname:
            pytest.fail("Database tests require an explicit PostgreSQL URL")
        allowed = (parsed.hostname, parsed.port or 5432)
    else:
        allowed = None
    original_connect = socket.socket.connect
    original_getaddrinfo = socket.getaddrinfo
    original_create_connection = socket.create_connection
    allowed_addresses = {allowed} if allowed is not None else set()

    def connect(sock: socket.socket, address: object) -> None:
        if allowed is not None and isinstance(address, tuple) and address[:2] in allowed_addresses:
            original_connect(sock, address)
            return
        raise RuntimeError("Network access is disabled in offline tests")

    def connect_ex(sock: socket.socket, address: object) -> int:
        connect(sock, address)
        return 0

    def create_connection(
        address: tuple[str, int], *args: object, **kwargs: object
    ) -> socket.socket:
        if allowed is not None and address == allowed:
            return original_create_connection(address, *args, **kwargs)
        raise RuntimeError("Network access is disabled in offline tests")

    def getaddrinfo(host: object, port: object, *args: object, **kwargs: object) -> object:
        if allowed is not None and (host, port) == allowed:
            addresses = original_getaddrinfo(host, port, *args, **kwargs)
            for _family, _kind, _protocol, _name, address in addresses:
                allowed_addresses.add(address[:2])
            return addresses
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
