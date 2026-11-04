"""Explicit local runtime configuration stays opt-in and bounded."""

from pathlib import Path

import pytest
from pydantic import ValidationError
from test_cli import Env
from test_ledger_db import reference

from conscience_foundry.cli.config import RuntimeConfig


def local_settings(root: Path) -> dict:
    return {
        "journalRoot": str(root / "journal"),
        "allocatorRoot": str(root / "allocator"),
        "bootstrapPath": str(root / "bootstrap.json"),
        "bootstrapDigest": "a" * 64,
        "attemptRoot": str(root / "attempt"),
        "runtimeManifestPath": str(root / "runtime.json"),
        "trustedQuoteManifestPath": str(root / "quotes.json"),
        "destinationId": "local-test",
        "attemptPriceUsd": "1",
        "storagePriceUsd": "1",
        "runStorageCapacityBytes": 10000,
        "operatorStorageCapacityBytes": 20000,
        "resourcePolicyRef": reference(b"policy", "cf.local-resource-policy.v1").model_dump(
            mode="json", by_alias=True
        ),
        "fundedFrom": "2026-01-01T00:00:00.000Z",
        "fundedUntil": "2027-01-01T00:00:00.000Z",
        "semantics": "cooperative",
    }


def test_local_settings_are_explicit_and_require_project_cap(tmp_path, monkeypatch):
    env = Env(tmp_path, monkeypatch)
    settings = local_settings(tmp_path)
    config = env.config() | {"localExecution": settings, "projectMaxLiveAttempts": 1}
    parsed = RuntimeConfig.model_validate(config)
    assert parsed.local_execution.destination_id == "local-test"
    with pytest.raises(ValidationError):
        RuntimeConfig.model_validate(env.config() | {"localExecution": settings})
    with pytest.raises(ValidationError):
        RuntimeConfig.model_validate(config | {"localExecution": settings | {"semantics": "hard"}})


@pytest.mark.parametrize(
    "update",
    [
        {"attemptPriceUsd": "0"},
        {"storagePriceUsd": "0"},
        {"fundedUntil": "2025-01-01T00:00:00.000Z"},
        {"runStorageCapacityBytes": 20001},
    ],
)
def test_invalid_local_funding_refused(tmp_path, monkeypatch, update):
    env = Env(tmp_path, monkeypatch)
    settings = local_settings(tmp_path) | update
    with pytest.raises(ValidationError):
        RuntimeConfig.model_validate(
            env.config() | {"localExecution": settings, "projectMaxLiveAttempts": 1}
        )


def manifest_fixture(tmp_path):
    import base64
    import json

    from test_execution_control import Case
    from test_ledger_db import PROJECT, TIME, reference

    from conscience_foundry.cli.local_authority import LocalAllocationEstimate
    from conscience_foundry.contracts.execution import LocalExecutionConfig
    from conscience_foundry.execution.evidence import encoded

    case = Case(tmp_path)
    limit = case.bound.model_copy(update={"max_string_scalars": 65536})
    resource = reference(b"resource", "cf.local-resource-policy.v1")
    config = LocalExecutionConfig(
        schema_version="cf.local-execution-config.v1",
        adapter_id="local",
        deployment_version="synthetic.v1",
        image_digest="a" * 64,
        tariff_ref=case.config.tariff_ref,
        resource_policy_ref=resource,
        local_destination_id="local",
    )
    config_raw = encoded(config)
    config_ref = reference(config_raw, config.schema_version)
    plan = case.plan.model_copy(update={"execution_config_ref": config_ref})
    plan_raw = encoded(plan)
    plan_ref = reference(plan_raw, plan.schema_version)
    auth = case.auth.model_copy(update={"allowed_plan_digests": (plan_ref.digest,)})
    auth_ref = reference(encoded(auth), auth.schema_version)

    def entry(ref, data):
        return {
            "ref": ref.model_dump(mode="json", by_alias=True),
            "bytesBase64": base64.b64encode(data).decode("ascii"),
        }

    estimates = []
    for scope in ("attempt", "run_storage"):
        quote = LocalAllocationEstimate(
            schema_version="cfoundry.local-allocation-estimate.v1",
            project_id=PROJECT,
            scope=scope,
            authorization_ref=auth_ref,
            plan_refs=(plan_ref,),
            config_refs=(config_ref,),
            resource_policy_ref=resource,
            funded_from=TIME,
            funded_until=auth.expires_at,
            ceiling_usd="1",
        )
        data = encoded(quote)
        estimates.append(entry(reference(data, quote.schema_version), data))
    document = {
        "schemaVersion": "cfoundry.local-quote-manifest.v1",
        "projectId": PROJECT,
        "authorizationRef": auth_ref.model_dump(mode="json", by_alias=True),
        "plans": [entry(plan_ref, plan_raw)],
        "configs": [entry(config_ref, config_raw)],
        "estimates": estimates,
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(document))
    bounds = {
        key: limit
        for key in (
            "cf.metadata-schema.v1",
            "cf.execution-plan.v1",
            "cf.local-execution-config.v1",
            "cfoundry.local-allocation-estimate.v1",
        )
    }
    return path, document, bounds


def test_manifest_loads_exact_independently_pinned_bytes(tmp_path):
    from test_ledger_db import PROJECT

    from conscience_foundry.cli.local_manifest import load_local_manifest

    path, document, bounds = manifest_fixture(tmp_path)
    before = path.read_bytes()
    pins = load_local_manifest(
        path,
        project_id=PROJECT,
        limits_by_schema=bounds,
        resource_policy_ref=reference(b"resource", "cf.local-resource-policy.v1"),
    )
    assert pins.project_id == PROJECT
    assert pins.authorization_ref.digest == document["authorizationRef"]["digest"]
    assert len(pins.plans) == len(pins.configs) == 1
    assert len(pins.estimates) == 2
    assert (
        load_local_manifest(
            path,
            project_id=PROJECT,
            limits_by_schema=bounds,
            resource_policy_ref=reference(b"resource", "cf.local-resource-policy.v1"),
        )
        == pins
    )
    assert path.read_bytes() == before


@pytest.mark.parametrize("mutation", ["tamper", "base64", "duplicate", "extra", "noncanonical"])
def test_manifest_refuses_invalid_pins(tmp_path, mutation):
    import base64
    import json

    from test_ledger_db import PROJECT, reference

    from conscience_foundry.cli.local_manifest import load_local_manifest
    from conscience_foundry.contracts.common import ContractError

    path, document, bounds = manifest_fixture(tmp_path)
    if mutation == "tamper":
        raw = bytearray(base64.b64decode(document["plans"][0]["bytesBase64"]))
        raw[-1] ^= 1
        document["plans"][0]["bytesBase64"] = base64.b64encode(raw).decode()
    elif mutation == "base64":
        document["plans"][0]["bytesBase64"] = "%%%%"
    elif mutation == "duplicate":
        document["configs"].append(document["configs"][0])
    elif mutation == "extra":
        document["surprise"] = True
    else:
        raw = base64.b64decode(document["plans"][0]["bytesBase64"])
        noncanonical = json.dumps(json.loads(raw), indent=2).encode()
        from conscience_foundry.cli.local_authority import LocalAllocationEstimate
        from conscience_foundry.execution.evidence import encoded

        new_ref = reference(noncanonical, "cf.execution-plan.v1")
        document["plans"][0] = {
            "ref": new_ref.model_dump(mode="json", by_alias=True),
            "bytesBase64": base64.b64encode(noncanonical).decode(),
        }
        for entry in document["estimates"]:
            quote = LocalAllocationEstimate.from_wire(
                base64.b64decode(entry["bytesBase64"]),
                bounds["cfoundry.local-allocation-estimate.v1"],
            ).model_copy(update={"plan_refs": (new_ref,)})
            quote_bytes = encoded(quote)
            entry.update(
                ref=reference(quote_bytes, quote.schema_version).model_dump(
                    mode="json", by_alias=True
                ),
                bytesBase64=base64.b64encode(quote_bytes).decode(),
            )
    path.write_text(json.dumps(document))
    expected = {"tamper": "hash_mismatch", "noncanonical": "forbidden"}.get(mutation)
    with pytest.raises(ContractError, match=expected):
        load_local_manifest(
            path,
            project_id=PROJECT,
            limits_by_schema=bounds,
            resource_policy_ref=reference(b"resource", "cf.local-resource-policy.v1"),
        )


def test_manifest_refuses_symlink_components_and_git_worktree(tmp_path):
    from test_ledger_db import PROJECT

    from conscience_foundry.cli.local_manifest import load_local_manifest
    from conscience_foundry.contracts.common import ContractError

    path, _, bounds = manifest_fixture(tmp_path)
    alias = tmp_path.parent / (tmp_path.name + "-link")
    alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ContractError):
        load_local_manifest(
            alias / path.name,
            project_id=PROJECT,
            limits_by_schema=bounds,
            resource_policy_ref=reference(b"resource", "cf.local-resource-policy.v1"),
        )
    (tmp_path / ".git").write_text("gitdir: /private/synthetic-worktree")
    with pytest.raises(ContractError):
        load_local_manifest(
            path,
            project_id=PROJECT,
            limits_by_schema=bounds,
            resource_policy_ref=reference(b"resource", "cf.local-resource-policy.v1"),
        )


def test_local_settings_reject_nonlocal_policy_schema(tmp_path, monkeypatch):
    env = Env(tmp_path, monkeypatch)
    bad = local_settings(tmp_path) | {
        "resourcePolicyRef": reference(b"bad", "cf.resource-policy.v1").model_dump(
            mode="json", by_alias=True
        )
    }
    with pytest.raises(ValidationError):
        RuntimeConfig.model_validate(
            env.config() | {"localExecution": bad, "projectMaxLiveAttempts": 1}
        )


def test_manifest_refuses_quote_policy_mismatch_even_with_valid_hash(tmp_path):
    import base64
    import json

    from test_ledger_db import PROJECT, reference

    from conscience_foundry.cli.local_authority import LocalAllocationEstimate
    from conscience_foundry.cli.local_manifest import load_local_manifest
    from conscience_foundry.contracts.common import ContractError
    from conscience_foundry.execution.evidence import encoded

    path, document, bounds = manifest_fixture(tmp_path)
    entry = document["estimates"][0]
    quote = LocalAllocationEstimate.from_wire(
        base64.b64decode(entry["bytesBase64"]), bounds["cfoundry.local-allocation-estimate.v1"]
    )
    quote = quote.model_copy(
        update={"resource_policy_ref": reference(b"other-policy", "cf.local-resource-policy.v1")}
    )
    data = encoded(quote)
    entry.update(
        ref=reference(data, quote.schema_version).model_dump(mode="json", by_alias=True),
        bytesBase64=base64.b64encode(data).decode(),
    )
    path.write_text(json.dumps(document))
    with pytest.raises(ContractError):
        load_local_manifest(
            path,
            project_id=PROJECT,
            limits_by_schema=bounds,
            resource_policy_ref=reference(b"resource", "cf.local-resource-policy.v1"),
        )


def test_manifest_refuses_wrong_operator_policy_ref(tmp_path):
    from test_ledger_db import PROJECT, reference

    from conscience_foundry.cli.local_manifest import load_local_manifest
    from conscience_foundry.contracts.common import ContractError

    path, _, bounds = manifest_fixture(tmp_path)
    wrong = reference(b"different", "cf.local-resource-policy.v1")
    with pytest.raises(ContractError):
        load_local_manifest(
            path, project_id=PROJECT, limits_by_schema=bounds, resource_policy_ref=wrong
        )


def test_manifest_supports_two_plans_with_shared_config_and_attempt_subset(tmp_path):
    import base64
    import json

    from test_ledger_db import PROJECT, reference

    from conscience_foundry.cli.local_authority import LocalAllocationEstimate
    from conscience_foundry.cli.local_manifest import load_local_manifest
    from conscience_foundry.contracts.execution import ExecutionPlan
    from conscience_foundry.execution.evidence import encoded

    path, document, bounds = manifest_fixture(tmp_path)
    original = ExecutionPlan.from_wire(
        base64.b64decode(document["plans"][0]["bytesBase64"]), bounds["cf.execution-plan.v1"]
    )
    second = original.model_copy(update={"plan_id": "00000000-0000-0000-0000-000000000099"})
    raw = encoded(second)
    second_ref = reference(raw, second.schema_version)
    document["plans"].append(
        {
            "ref": second_ref.model_dump(mode="json", by_alias=True),
            "bytesBase64": base64.b64encode(raw).decode(),
        }
    )
    storage = document["estimates"][1]
    quote = LocalAllocationEstimate.from_wire(
        base64.b64decode(storage["bytesBase64"]), bounds["cfoundry.local-allocation-estimate.v1"]
    )
    quote = quote.model_copy(update={"plan_refs": (*quote.plan_refs, second_ref)})
    raw_quote = encoded(quote)
    storage.update(
        ref=reference(raw_quote, quote.schema_version).model_dump(mode="json", by_alias=True),
        bytesBase64=base64.b64encode(raw_quote).decode(),
    )
    path.write_text(json.dumps(document))
    pins = load_local_manifest(
        path,
        project_id=PROJECT,
        limits_by_schema=bounds,
        resource_policy_ref=reference(b"resource", "cf.local-resource-policy.v1"),
    )
    assert len(pins.plans) == 2
    assert len(pins.configs) == 1
    assert {quote.scope: len(quote.plan_refs) for _, _, quote in pins.estimates} == {
        "attempt": 1,
        "run_storage": 2,
    }


def test_manifest_refuses_oversized_and_missing_installed_limit(tmp_path):
    from test_ledger_db import PROJECT

    from conscience_foundry.cli.local_manifest import load_local_manifest
    from conscience_foundry.contracts.common import ContractError

    path, _, bounds = manifest_fixture(tmp_path)
    policy = reference(b"resource", "cf.local-resource-policy.v1")
    small = dict(bounds)
    small["cf.metadata-schema.v1"] = small["cf.metadata-schema.v1"].model_copy(
        update={"max_json_bytes": 10}
    )
    with pytest.raises(ContractError):
        load_local_manifest(
            path, project_id=PROJECT, limits_by_schema=small, resource_policy_ref=policy
        )
    del small["cf.metadata-schema.v1"]
    with pytest.raises(ContractError, match="limits_missing"):
        load_local_manifest(
            path, project_id=PROJECT, limits_by_schema=small, resource_policy_ref=policy
        )


def test_manifest_refuses_extra_independently_hashed_config(tmp_path):
    import base64
    import json

    from test_ledger_db import PROJECT

    from conscience_foundry.cli.local_manifest import load_local_manifest
    from conscience_foundry.contracts.common import ContractError
    from conscience_foundry.contracts.execution import LocalExecutionConfig
    from conscience_foundry.execution.evidence import encoded

    path, document, bounds = manifest_fixture(tmp_path)
    config = LocalExecutionConfig.from_wire(
        base64.b64decode(document["configs"][0]["bytesBase64"]),
        bounds["cf.local-execution-config.v1"],
    ).model_copy(update={"local_destination_id": "extra"})
    data = encoded(config)
    document["configs"].append(
        {
            "ref": reference(data, config.schema_version).model_dump(mode="json", by_alias=True),
            "bytesBase64": base64.b64encode(data).decode(),
        }
    )
    path.write_text(json.dumps(document))
    with pytest.raises(ContractError):
        load_local_manifest(
            path,
            project_id=PROJECT,
            limits_by_schema=bounds,
            resource_policy_ref=reference(b"resource", "cf.local-resource-policy.v1"),
        )


def test_local_and_live_settings_are_mutually_exclusive(tmp_path, monkeypatch):
    from conscience_foundry.cli.config import LiveSettings

    env = Env(tmp_path, monkeypatch)
    document = env.config() | {
        "localExecution": local_settings(tmp_path),
        "projectMaxLiveAttempts": 1,
        "live": LiveSettings.model_construct(
            parent_access_key_id_env="KEY", parent_token_env="TOKEN"
        ),
    }
    with pytest.raises(ValidationError, match="mutually exclusive"):
        RuntimeConfig.model_validate(document)


def test_manifest_read_stays_bound_to_verified_parent_during_swap(tmp_path, monkeypatch):
    import os

    from conscience_foundry.cli.local_manifest import _read_manifest

    trusted = tmp_path / "trusted"
    trusted.mkdir()
    manifest = trusted / "manifest.json"
    manifest.write_bytes(b"approved")
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    (attacker / manifest.name).write_bytes(b"substituted")
    parked = tmp_path / "parked"
    original_open = os.open
    swapped = False

    def swap_on_final_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if os.fspath(path) in (os.fspath(manifest), manifest.name):
            swapped = True
            trusted.rename(parked)
            trusted.symlink_to(attacker, target_is_directory=True)
            try:
                return original_open(path, flags, *args, **kwargs)
            finally:
                trusted.unlink()
                parked.rename(trusted)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap_on_final_open)
    assert _read_manifest(manifest, 100) == b"approved"
    assert swapped
