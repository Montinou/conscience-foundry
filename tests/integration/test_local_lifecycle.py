"""Local receipt and storage settlement command boundaries."""

from test_cli import Env
from test_ledger_db import RUN


def test_local_lifecycle_commands_require_their_own_grants(tmp_path, monkeypatch):
    env = Env(tmp_path, monkeypatch, grants={"execution": ["record-billing"]})
    attempt = "00000000-0000-0000-0000-000000000001"
    receipt = env.invoke("local-receipts", "--attempt-id", attempt, "--execute")
    close = env.invoke("close-local-storage", "--run-id", RUN, "--evidence", "unused", "--execute")
    assert receipt.code == "grant_missing"
    assert close.code == "grant_missing"
    assert not env.connects


def test_granted_local_commands_refuse_absent_local_wiring(tmp_path, monkeypatch):
    env = Env(
        tmp_path, monkeypatch, grants={"execution": ["local-receipts", "close-local-storage"]}
    )
    attempt = "00000000-0000-0000-0000-000000000001"
    receipt = env.invoke("local-receipts", "--attempt-id", attempt, "--execute")
    close = env.invoke("close-local-storage", "--run-id", RUN, "--evidence", "unused", "--execute")
    assert receipt.code == "adapter_unavailable"
    assert close.code == "adapter_unavailable"
    assert not env.connects
