"""Authenticated exact-byte task schema installation."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from psycopg import sql
from psycopg.types.json import Jsonb

from conscience_foundry.contracts.common import ContractError, Ref
from conscience_foundry.contracts.enrichment import TaskSchemaInstallation
from conscience_foundry.contracts.extensions import EnrichmentSpec
from conscience_foundry.contracts.project import PolicyArtifact
from conscience_foundry.contracts.task_schema_registry import TaskSchemaRegistry
from conscience_foundry.enrichment.context import EnrichmentContext, approve
from conscience_foundry.enrichment.schema import validate_schema
from conscience_foundry.execution.evidence import (
    clock,
    encoded,
    put_record,
    read_model,
)
from conscience_foundry.ledger.db import Ledger, LedgerTxn
from conscience_foundry.ledger.enrichment import require_enrichment_schema


class _VerificationContext:
    def __init__(self, context: EnrichmentContext) -> None:
        self.access = context.access
        self.store = context.store
        self.clock = context.clock
        self.limits_by_schema = context.limits_by_schema
        self.output_store_id = context.output_store_id
        self.current_policy = lambda project: context.current_policy()


def _raw_schema(ref: Ref, context: EnrichmentContext) -> bytes:
    if (
        type(ref) is not Ref
        or ref.project_id != context.access.project_id
        or ref.artifact_schema != "json-schema.2020-12"
        or ref.media_type != "application/json"
    ):
        raise ContractError("forbidden")
    limits = context.limits_by_schema.get("json-schema.2020-12")
    if limits is None:
        raise ContractError("limits_missing")
    ceiling = min(limits.max_output_bytes, limits.max_json_bytes)
    if ref.size_bytes > ceiling:
        raise ContractError("limit_exceeded")
    value = context.store.read_verified(ref, context.access, ceiling)
    raw = value.data
    if (
        type(raw) is not bytes
        or len(raw) != ref.size_bytes
        or hashlib.sha256(raw).hexdigest() != ref.digest
        or value.digest != ref.digest
    ):
        raise ContractError("hash_mismatch")
    validate_schema(raw, limits=limits)
    return raw


def _id(ref: Ref) -> dict[str, Any]:
    return ref.model_dump(mode="json", by_alias=True)


def install_task_schemas(
    spec_ref: Ref, *, policy_ref: Ref, evidence_ref: Ref, ledger: Ledger, context: EnrichmentContext
) -> Ref:
    if type(context) is not EnrichmentContext:
        raise ContractError("forbidden")
    v = _VerificationContext(context)
    now = clock(v)
    _, spec = read_model(spec_ref, EnrichmentSpec, v)
    policy_bytes, policy = read_model(policy_ref, PolicyArtifact, v)
    if (
        encoded(context.current_policy()) != policy_bytes
        or policy.project_id != context.access.project_id
        or policy.effective_at > now
    ):
        raise ContractError("forbidden")
    # Installation evidence is operator metadata, never an unchecked source read.
    from conscience_foundry.enrichment.registration import _read_spec_metadata

    _read_spec_metadata(evidence_ref, context)
    _raw_schema(spec.input_schema_ref, context)
    _raw_schema(spec.output_schema_ref, context)
    request = json.dumps(
        {
            "specRef": _id(spec_ref),
            "inputSchemaRef": _id(spec.input_schema_ref),
            "outputSchemaRef": _id(spec.output_schema_ref),
            "policyRef": _id(policy_ref),
            "evidenceRef": _id(evidence_ref),
            "actorId": context.access.actor_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    with ledger.transaction() as tx:
        require_enrichment_schema(tx)
        tx.lock(context.access.project_id)
        table = sql.Identifier(tx.schema, "enrichment_task_schemas")
        row = tx.connection.execute(
            sql.SQL(
                "SELECT spec_ref,installation_ref,input_schema_ref,output_schema_ref "
                "FROM {} WHERE project_id=%s AND spec_digest=%s"
            ).format(table),
            (context.access.project_id, spec_ref.digest),
        ).fetchone()
        state_bytes = json.dumps(
            {
                "policyDigest": hashlib.sha256(policy_bytes).hexdigest(),
                "existing": None if row is None else list(row),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        state = hashlib.sha256(
            b"cf.enrichment-schema-installation.state.v1\n" + state_bytes
        ).hexdigest()
        approve(
            context,
            "install_task_schemas",
            request,
            state,
            (spec_ref, spec.input_schema_ref, spec.output_schema_ref, policy_ref, evidence_ref),
        )
        if row is not None:
            if (
                Ref.model_validate(row[0]) != spec_ref
                or Ref.model_validate(row[2]) != spec.input_schema_ref
                or Ref.model_validate(row[3]) != spec.output_schema_ref
            ):
                raise ContractError("determinism_conflict")
            existing_ref = Ref.model_validate(row[1])
            _, existing = read_model(existing_ref, TaskSchemaInstallation, v)
            if (
                existing.spec_ref,
                existing.input_schema_ref,
                existing.output_schema_ref,
                existing.policy_ref,
                existing.evidence_ref,
                existing.actor_id,
            ) != (
                spec_ref,
                spec.input_schema_ref,
                spec.output_schema_ref,
                policy_ref,
                evidence_ref,
                context.access.actor_id,
            ):
                raise ContractError("determinism_conflict")
            if encoded(context.current_policy()) != policy_bytes:
                raise ContractError("unavailable")
            return existing_ref
        receipt = TaskSchemaInstallation(
            schema_version="cf.enrichment-schema-installation.v1",
            project_id=context.access.project_id,
            spec_ref=spec_ref,
            input_schema_ref=spec.input_schema_ref,
            output_schema_ref=spec.output_schema_ref,
            policy_ref=policy_ref,
            actor_id=context.access.actor_id,
            evidence_ref=evidence_ref,
            installed_at=now,
        )
        receipt_ref = put_record(receipt, v)
        if encoded(context.current_policy()) != policy_bytes:
            raise ContractError("unavailable")
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {} (project_id,spec_digest,spec_ref,installation_ref,input_schema_ref,"
                "output_schema_ref) VALUES (%s,%s,%s,%s,%s,%s)"
            ).format(table),
            (
                context.access.project_id,
                spec_ref.digest,
                Jsonb(_id(spec_ref)),
                Jsonb(_id(receipt_ref)),
                Jsonb(_id(spec.input_schema_ref)),
                Jsonb(_id(spec.output_schema_ref)),
            ),
        )
        return receipt_ref


def load_task_schemas(
    installation_ref: Ref, *, spec_ref: Ref, tx: LedgerTxn, context: EnrichmentContext
) -> TaskSchemaRegistry:
    require_enrichment_schema(tx)
    row = tx.connection.execute(
        sql.SQL(
            "SELECT spec_ref,installation_ref,input_schema_ref,output_schema_ref "
            "FROM {} WHERE project_id=%s AND spec_digest=%s"
        ).format(sql.Identifier(tx.schema, "enrichment_task_schemas")),
        (context.access.project_id, spec_ref.digest),
    ).fetchone()
    if (
        row is None
        or Ref.model_validate(row[0]) != spec_ref
        or Ref.model_validate(row[1]) != installation_ref
    ):
        raise ContractError("forbidden")
    _, receipt = read_model(installation_ref, TaskSchemaInstallation, _VerificationContext(context))
    if (
        receipt.spec_ref != spec_ref
        or receipt.input_schema_ref != Ref.model_validate(row[2])
        or receipt.output_schema_ref != Ref.model_validate(row[3])
    ):
        raise ContractError("hash_mismatch")
    return TaskSchemaRegistry(
        context.access.project_id,
        spec_ref,
        installation_ref,
        (
            (receipt.input_schema_ref, _raw_schema(receipt.input_schema_ref, context)),
            (receipt.output_schema_ref, _raw_schema(receipt.output_schema_ref, context)),
        ),
    )
