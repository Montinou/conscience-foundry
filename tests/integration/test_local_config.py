"""Local and remote policy checks remain separate without invoking services."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from conscience_foundry.contracts.common import ContractError
from conscience_foundry.contracts.execution import (
    ExecutionConfig,
    LocalExecutionConfig,
    ResourceEnvelope,
)
from conscience_foundry.contracts.local_resource import LocalResourcePolicy
from conscience_foundry.execution import evidence

PROJECT = "00000000-0000-0000-0000-000000000001"


def ref(**changes):
    return {
        "schemaVersion": "cf.artifact-ref.v1",
        "projectId": PROJECT,
        "digest": "a" * 64,
        "sizeBytes": 17,
        "mediaType": "application/json",
        "artifactSchema": "synthetic.v1",
        "locations": [{"storeId": "synthetic", "objectKey": "sha256/synthetic"}],
    } | changes


def resources():
    return {
        "cpuMilli": 1000,
        "memoryMiB": 256,
        "gpuCount": 0,
        "maxWallSeconds": 30,
        "maxOutputBytes": 4096,
        "maxConcurrentAttempts": 1,
        "maxAttemptsPerOperation": 1,
        "automaticRetries": 0,
    }


def config(local: bool):
    common = {
        "adapterId": "test",
        "deploymentVersion": "v1",
        "imageDigest": "a" * 64,
        "tariffRef": ref(),
        "resourcePolicyRef": ref(artifactSchema="cf.local-resource-policy.v1"),
    }
    if local:
        return LocalExecutionConfig.model_validate(
            common
            | {"schemaVersion": "cf.local-execution-config.v1", "localDestinationId": "local"}
        )
    return ExecutionConfig.model_validate(
        common | {"schemaVersion": "cf.execution-config.v1", "remoteDestinationId": "remote"}
    )


@pytest.mark.parametrize("local", [True, False])
def test_verified_plan_requires_correct_permissions_and_destination(monkeypatch, local):
    cfg = config(local)
    plan = SimpleNamespace(
        project_id=PROJECT, resources=ResourceEnvelope.model_validate(resources())
    )
    historical = SimpleNamespace(
        config=cfg,
        model=plan,
        source_asset=SimpleNamespace(source_id="source"),
        data=b"plan",
        authorization=None,
        config_bytes=b"config",
    )
    monkeypatch.setattr(evidence, "historical_result_plan", lambda *args: historical)
    policy = LocalResourcePolicy.model_validate(
        {
            "schemaVersion": "cf.local-resource-policy.v1",
            "semantics": "cooperative",
            "maxCpuMilli": 1000,
            "maxMemoryMib": 256,
            "maxWallSeconds": 30,
            "maxOutputBytes": 4096,
            "maxConcurrentAttempts": 1,
            "maxAttemptsPerOperation": 1,
        }
    )
    monkeypatch.setattr(
        evidence,
        "read_artifact",
        lambda ref, *args, **kwargs: (
            b"data",
            policy if ref == cfg.resource_policy_ref else object(),
        ),
    )
    monkeypatch.setattr(
        evidence,
        "current_policy",
        lambda *args: SimpleNamespace(allowed_remote_destinations={"remote"}),
    )
    permissions = Mock()
    monkeypatch.setattr(evidence, "require_permission", permissions)
    # Check the authorization branch without constructing unrelated result state.
    monkeypatch.setattr(evidence, "VerifiedPlan", lambda *args: args)
    if local:
        monkeypatch.setattr(evidence, "validate_local_resources", lambda *args: None)
    evidence.verified_plan(None, None, None, SimpleNamespace(access=object()), spending=True)
    assert {c.args[-1] for c in permissions.call_args_list} == (
        {"read", "extract"} if local else {"read", "extract", "remoteTransfer"}
    )
    if not local:
        monkeypatch.setattr(
            evidence,
            "current_policy",
            lambda *args: SimpleNamespace(allowed_remote_destinations=set()),
        )
        with pytest.raises(ContractError):
            evidence.verified_plan(
                None, None, None, SimpleNamespace(access=object()), spending=True
            )


@pytest.mark.parametrize("local", [True, False])
def test_capability_destination_cross_binding_rejects_wrong_variant(monkeypatch, local):
    from dataclasses import replace

    from conscience_foundry.contracts.common import Ref
    from conscience_foundry.execution.ports import CapabilityFacts

    cfg = config(local)
    config_ref = Ref.model_validate(ref())
    envelope = ResourceEnvelope.model_validate(resources())
    plan = SimpleNamespace(
        config=cfg, model=SimpleNamespace(execution_config_ref=config_ref, resources=envelope)
    )
    capability = CapabilityFacts(
        config_ref,
        cfg.tariff_ref,
        cfg.resource_policy_ref,
        cfg.image_digest,
        "local" if local else "remote",
        envelope,
    )
    facts = SimpleNamespace(
        capabilities=(capability,),
        funded_from="2026-01-01T00:00:00.000Z",
        funded_until="2027-01-01T00:00:00.000Z",
        first_upload_at=None,
    )
    monkeypatch.setattr(evidence, "clock", lambda _: "2026-06-01T00:00:00.000Z")
    evidence._capabilities(facts, (plan,), None)
    facts.capabilities = (replace(capability, destination_id="remote" if local else "local"),)
    with pytest.raises(ContractError, match="unsupported_capability"):
        evidence._capabilities(facts, (plan,), None)
    other = Ref.model_validate(ref(digest="b" * 64))
    facts.capabilities = (replace(capability, execution_config_ref=other),)
    with pytest.raises(ContractError, match="unsupported_capability"):
        evidence._capabilities(facts, (plan,), None)


def test_historical_local_plan_validates_pinned_policy_and_image(monkeypatch):
    from conscience_foundry.contracts.canonical import ExtractionSpec
    from conscience_foundry.contracts.common import ContractLimits, Ref
    from conscience_foundry.contracts.execution import ExecutionPlan, RunAuthorization
    from conscience_foundry.contracts.registry import ContractSet

    cfg = config(True)
    plan_ref = Ref.model_validate(ref())
    envelope = ResourceEnvelope.model_validate(resources())
    plan = SimpleNamespace(
        project_id=PROJECT,
        run_id="run",
        budget=SimpleNamespace(authorization_id="auth", tariff_ref=cfg.tariff_ref),
        admission_report_ref=plan_ref,
        execution_config_ref=plan_ref,
        extraction_spec_ref=plan_ref,
        contract_set_ref=plan_ref,
        limits_refs=(plan_ref,),
        resources=envelope,
    )
    auth = SimpleNamespace(
        project_id=PROJECT,
        run_id="run",
        authorization_id="auth",
        allowed_plan_digests=(plan_ref.digest,),
        admission_report_digest=plan_ref.digest,
    )
    local_policy = LocalResourcePolicy.model_validate(
        {
            "schemaVersion": "cf.local-resource-policy.v1",
            "semantics": "cooperative",
            "maxCpuMilli": 1000,
            "maxMemoryMib": 256,
            "maxWallSeconds": 30,
            "maxOutputBytes": 4096,
            "maxConcurrentAttempts": 1,
            "maxAttemptsPerOperation": 1,
        }
    )
    spec = SimpleNamespace(image_digest=cfg.image_digest, limits_ref=plan_ref)
    values = {
        ExecutionPlan: plan,
        RunAuthorization: auth,
        LocalResourcePolicy: local_policy,
        ContractSet: object(),
        ExtractionSpec: spec,
        ContractLimits: object(),
    }
    monkeypatch.setattr(
        evidence, "read_model", lambda ref, model, control: (b"data", values[model])
    )
    monkeypatch.setattr(evidence, "read_artifact", lambda *args, **kwargs: (b"config", cfg))
    monkeypatch.setattr(evidence, "admission_evidence", lambda *args: (None, object(), object()))
    monkeypatch.setattr(evidence, "source_asset", lambda *args: object())
    result = evidence.historical_result_plan(plan_ref, plan_ref, None, None)
    assert result.config is cfg
    values[LocalResourcePolicy] = local_policy.model_copy(update={"semantics": "hard"})
    with pytest.raises(ContractError, match="unsupported_capability"):
        evidence.historical_result_plan(plan_ref, plan_ref, None, None)
    values[LocalResourcePolicy] = local_policy
    spec.image_digest = "b" * 64
    with pytest.raises(ContractError, match="unsupported_capability"):
        evidence.historical_result_plan(plan_ref, plan_ref, None, None)


def test_local_dispatch_refuses_before_reservation_or_mint(monkeypatch):
    from contextlib import contextmanager

    from conscience_foundry.execution import control as dispatch_control

    access = SimpleNamespace(project_id=PROJECT)
    transaction = SimpleNamespace(
        lock=Mock(),
        connection=SimpleNamespace(
            execute=Mock(side_effect=AssertionError("passed local pre-claim gate"))
        ),
        table=lambda name: name,
    )
    plan = SimpleNamespace(run_id="run")
    auth = object()

    class Ledger:
        @contextmanager
        def transaction(self):
            yield transaction

    monkeypatch.setattr(dispatch_control, "authorize", lambda *args: None)
    monkeypatch.setattr(
        dispatch_control,
        "verified_plan",
        lambda *args, **kwargs: SimpleNamespace(
            config=config(True), model=plan, authorization=auth, data=b"plan"
        ),
    )
    monkeypatch.setattr(dispatch_control, "encoded", lambda _: b"plan")
    reserve = Mock()
    monkeypatch.setattr(dispatch_control, "reserve_attempt", reserve)
    issuer = Mock()
    with pytest.raises(ContractError, match="adapter_unavailable"):
        dispatch_control.dispatch(
            plan,
            auth,
            access,
            Ledger(),
            object(),
            issuer,
            control=SimpleNamespace(access=access),
            plan_ref=None,
            authorization_ref=None,
            asset_id="asset",
            evidence_ref=None,
        )
    reserve.assert_not_called()
    issuer.assert_not_called()


@pytest.mark.parametrize(
    ("local", "scopes", "destinations", "allowed", "wrong_schema", "denied_effect"),
    [
        (True, {"read", "extract"}, set(), True, False, None),
        (True, {"read", "extract"}, set(), False, False, "read"),
        (True, {"read", "extract"}, set(), False, False, "extract"),
        (False, {"read", "extract", "remoteTransfer"}, {"remote"}, False, False, "remoteTransfer"),
        (True, {"read", "extract"}, set(), False, True, None),
        (True, {"read"}, set(), False, False, None),
        (True, {"extract"}, set(), False, False, None),
        (False, {"read", "extract", "remoteTransfer"}, {"remote"}, True, False, None),
        (False, {"read", "extract", "remoteTransfer"}, {"remote"}, False, True, None),
        (False, {"read", "extract"}, {"remote"}, False, False, None),
        (False, {"read", "extract", "remoteTransfer"}, set(), False, False, None),
    ],
)
def test_reserve_attempt_checks_locality_permissions_without_database(
    monkeypatch, local, scopes, destinations, allowed, wrong_schema, denied_effect
):
    import hashlib
    from contextlib import nullcontext

    from conscience_foundry.contracts.common import ContractLimits, Ref
    from conscience_foundry.contracts.execution import ExecutionPlan, RunAuthorization
    from conscience_foundry.ledger import _budget_inputs, budget
    from conscience_foundry.policy.access import AccessContext

    cfg = config(local)
    raw = cfg.model_dump_json(by_alias=True).encode()
    schema = (
        ("cf.execution-config.v1" if local else "cf.local-execution-config.v1")
        if wrong_schema
        else cfg.schema_version
    )
    cfg_ref = Ref.model_validate(
        ref(artifactSchema=schema, digest=hashlib.sha256(raw).hexdigest(), sizeBytes=len(raw))
    )
    plan_ref = Ref.model_validate(ref())
    auth_ref = Ref.model_validate(ref())
    plan = ExecutionPlan.model_construct(
        project_id=PROJECT,
        run_id="run",
        execution_config_ref=cfg_ref,
        budget=SimpleNamespace(tariff_ref=cfg.tariff_ref, max_attempt_cost="1"),
        admission_report_ref=plan_ref,
    )
    auth = RunAuthorization.model_construct(authorization_id="auth")
    source = SimpleNamespace(
        source_id="source", permission=lambda effect: "deny" if effect == denied_effect else "allow"
    )
    policy = SimpleNamespace(
        project_id=PROJECT, sources=(source,), allowed_remote_destinations=destinations
    )
    access = AccessContext(PROJECT, PROJECT, frozenset(scopes))
    context = SimpleNamespace(access=access, current_policy=policy, now="2026-01-01T00:00:00.000Z")
    limits = ContractLimits.model_validate(
        {
            "schemaVersion": "cf.contract-limits.v1",
            "version": "v1",
            "maxJsonBytes": 131072,
            "maxStringScalars": 1024,
            "maxArrayItems": 256,
            "maxDepth": 32,
            "maxManifestItems": 16,
            "maxSourceBytes": 8192,
            "maxOutputBytes": 16384,
            "maxErrorMessageScalars": 128,
        }
    )
    original_parse = budget._parse

    def parse(model, data, reference, schema, project, context):
        if model is ExecutionPlan:
            return plan
        if model is RunAuthorization:
            return auth
        return original_parse(model, data, reference, schema, project, context)

    monkeypatch.setattr(budget, "_parse", parse)
    monkeypatch.setattr(_budget_inputs, "_limits", lambda *args: limits)
    monkeypatch.setattr(budget, "_limits", lambda *args: limits)
    monkeypatch.setattr(budget, "_context", lambda *args: None)
    monkeypatch.setattr(budget, "validate_plan_authorization", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        budget,
        "_installed",
        lambda *args: (
            "auth",
            None,
            None,
            None,
            auth_ref.model_dump(mode="json", by_alias=True),
            None,
            None,
            None,
            plan_ref.digest,
        ),
    )
    monkeypatch.setattr(budget, "_spending", lambda *args, **kwargs: None)
    monkeypatch.setattr(budget, "_admitted", lambda *args: "source")

    class ReachedProof(Exception):
        pass

    monkeypatch.setattr(
        budget, "_proof", lambda *args, **kwargs: (_ for _ in ()).throw(ReachedProof())
    )
    tx = SimpleNamespace(connection=SimpleNamespace(transaction=nullcontext))
    with pytest.raises(ReachedProof if allowed else ContractError):
        budget.reserve_attempt(
            plan,
            auth,
            plan_ref,
            tx,
            context=context,
            plan_ref=plan_ref,
            plan_bytes=b"plan",
            authorization_ref=auth_ref,
            authorization_bytes=b"auth",
            admission=None,
            asset_id=PROJECT,
            execution_config_bytes=raw,
        )
