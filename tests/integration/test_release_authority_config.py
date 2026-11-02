"""The opt-in local release authority: ``releaseAuthority`` builds one without a live section.

Offline and synthetic: the config is parsed from a document and ``build_services`` only reads
the operator's policy file; nothing reaches a ledger, a network or a provider.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

for _sibling in ("acceptance",):
    _path = str(Path(__file__).resolve().parents[1] / _sibling)
    if _path not in sys.path:
        sys.path.append(_path)

import test_cli as cli_case  # noqa: E402
import test_live_pilot_offline as live_case  # noqa: E402

from conscience_foundry.cli import live  # noqa: E402
from conscience_foundry.cli.authorities import LocalReleaseAuthority  # noqa: E402
from conscience_foundry.cli.config import (  # noqa: E402
    LocalReleaseAuthoritySettings,
    RuntimeConfig,
    TrustedServices,
)
from conscience_foundry.contracts.common import ContractError  # noqa: E402


def offline_document(tmp_path: Path, **changes: Any) -> dict[str, Any]:
    """A config with neither a live section nor a project cap, plus the operator's files."""
    document = live_case.config_document(tmp_path)
    del document["projectMaxLiveAttempts"], document["live"]
    policy = cli_case.admission().evidence.pinned_policy
    cli_case.write_private(tmp_path / "policy.json", policy.model_dump_json(by_alias=True))
    cli_case.write_private(
        tmp_path / "limits.json",
        json.dumps({"cf.policy.v1": cli_case.limits().model_dump(by_alias=True)}),
    )
    return document | changes


def test_local_entry_builds_release_authority_without_live(tmp_path: Path) -> None:
    config = live_case.parse_config(offline_document(tmp_path, releaseAuthority={"kind": "local"}))
    assert config.live is None
    assert config.release_authority == LocalReleaseAuthoritySettings(kind="local")
    services = live.build_services(config)
    authority = services.release_authority
    assert isinstance(authority, LocalReleaseAuthority)
    assert authority.project_id == live_case.PROJECT
    # nothing else is wired: no live runtime, executor or evidence authority
    assert services == TrustedServices(release_authority=authority)


def test_absent_entry_keeps_empty_services(tmp_path: Path) -> None:
    config = live_case.parse_config(offline_document(tmp_path))
    assert config.release_authority is None
    assert live.build_services(config) == TrustedServices()
    assert "releaseAuthority" not in config.model_dump(by_alias=True, exclude_none=True)


@pytest.mark.parametrize("entry", [None, {"kind": "local"}])
def test_live_and_local_build_one_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: dict[str, str] | None
) -> None:
    monkeypatch.setenv(live_case.KEY_ID_ENV, live_case.KEY_ID)
    monkeypatch.setenv(live_case.TOKEN_ENV, live_case.TOKEN)
    document = live_case.config_document(tmp_path)
    if entry is not None:
        document["releaseAuthority"] = entry
    offline_document(tmp_path)  # writes the policy and limits files
    built: list[object] = []
    original = live._release_authority

    def spy(config: RuntimeConfig) -> LocalReleaseAuthority:
        built.append(original(config))
        return built[-1]  # type: ignore[return-value]

    monkeypatch.setattr(live, "_release_authority", spy)
    services = live.build_services(live_case.parse_config(document), http=live_case.Cloudflare())
    assert services.live is not None and services.executor is not None
    assert len(built) == 1
    assert services.release_authority is built[0]


@pytest.mark.parametrize(
    "entry",
    [
        {"kind": "remote"},
        {"kind": "LOCAL"},
        {},
        {"kind": "local", "extra": 1},
        "local",
        None,
    ],
)
def test_unknown_kind_rejected(tmp_path: Path, entry: object) -> None:
    document = offline_document(tmp_path, releaseAuthority=entry)
    with pytest.raises(ContractError) as refused:
        live_case.parse_config(document)
    assert refused.value.code == "invalid_schema"
