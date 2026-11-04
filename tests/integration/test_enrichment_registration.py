"""Additive enrichment storage on a disposable ledger."""

import pytest
from psycopg import sql

from conscience_foundry.contracts.common import ContractError
from conscience_foundry.ledger.db import Ledger

pytestmark = pytest.mark.database


def test_explicit_install_reinstall_and_digest_drift(ledger: Ledger) -> None:
    from conscience_foundry.ledger.enrichment import (
        install_enrichment_schema,
        require_enrichment_schema,
    )

    with ledger.transaction() as tx:
        with pytest.raises(ContractError, match="schema_incompatible"):
            require_enrichment_schema(tx)
    install_enrichment_schema(ledger)
    install_enrichment_schema(ledger)
    with ledger.transaction() as tx:
        require_enrichment_schema(tx)
        tx.connection.execute(
            sql.SQL("COMMENT ON TABLE {} IS 'wrong'").format(
                sql.Identifier(tx.schema, "enrichment_operations")
            )
        )
    with pytest.raises(ContractError, match="schema_incompatible"):
        install_enrichment_schema(ledger)


def test_partial_install_refused_without_mutation(ledger: Ledger) -> None:
    from conscience_foundry.ledger.enrichment import install_enrichment_schema

    with ledger.transaction() as tx:
        tx.connection.execute(
            sql.SQL("CREATE TABLE {} (id integer)").format(
                sql.Identifier(tx.schema, "enrichment_operations")
            )
        )
    with pytest.raises(ContractError, match="schema_incompatible"):
        install_enrichment_schema(ledger)
    with ledger.transaction() as tx:
        assert (
            tx.connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_tables "
                "WHERE schemaname=%s AND tablename LIKE 'enrichment_%%'",
                (tx.schema,),
            ).fetchone()[0]
            == 1
        )


def test_install_is_atomic_and_preserves_existing_base_data(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    import psycopg

    import conscience_foundry.ledger.enrichment as module

    project = "00000000-0000-0000-0000-000000000001"
    with ledger.transaction() as tx:
        before = tx.connection.execute(
            sql.SQL("SELECT version,migration_digest FROM {}.schema_version").format(
                sql.Identifier(tx.schema)
            )
        ).fetchone()
        tx.connection.execute(
            sql.SQL("INSERT INTO {}.projects VALUES (%s)").format(sql.Identifier(tx.schema)),
            (project,),
        )
    original = module.migration_text
    monkeypatch.setattr(module, "migration_text", lambda: original() + "\nINVALID SQL;")
    with pytest.raises(psycopg.Error):
        module.install_enrichment_schema(ledger)
    with ledger.transaction() as tx:
        assert (
            tx.connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_tables "
                "WHERE schemaname=%s AND tablename LIKE 'enrichment_%%'",
                (tx.schema,),
            ).fetchone()[0]
            == 0
        )
        assert (
            tx.connection.execute(
                sql.SQL("SELECT version,migration_digest FROM {}.schema_version").format(
                    sql.Identifier(tx.schema)
                )
            ).fetchone()
            == before
        )
        assert (
            tx.connection.execute(
                sql.SQL("SELECT project_id::text FROM {}.projects").format(
                    sql.Identifier(tx.schema)
                )
            ).fetchone()[0]
            == project
        )
    monkeypatch.setattr(module, "migration_text", original)
    module.install_enrichment_schema(ledger)
    with ledger.transaction() as tx:
        assert (
            tx.connection.execute(
                sql.SQL("SELECT version,migration_digest FROM {}.schema_version").format(
                    sql.Identifier(tx.schema)
                )
            ).fetchone()
            == before
        )
        assert (
            tx.connection.execute(
                sql.SQL("SELECT project_id::text FROM {}.projects").format(
                    sql.Identifier(tx.schema)
                )
            ).fetchone()[0]
            == project
        )


def test_operation_rows_bind_valid_reference_and_existing_operation(ledger: Ledger) -> None:
    import psycopg
    from psycopg.types.json import Jsonb

    from conscience_foundry.ledger.enrichment import install_enrichment_schema

    project = "00000000-0000-0000-0000-000000000001"
    asset = "00000000-0000-0000-0000-000000000002"
    digest = "a" * 64
    install_enrichment_schema(ledger)
    with ledger.transaction() as tx:
        schema = sql.Identifier(tx.schema)
        tx.connection.execute(
            sql.SQL("INSERT INTO {}.projects VALUES (%s)").format(schema), (project,)
        )
        tx.connection.execute(
            sql.SQL("INSERT INTO {}.assets VALUES (%s,%s,%s,%s,%s)").format(schema),
            (project, asset, asset, digest, 1),
        )
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {}.operations(project_id,operation_key,asset_id) VALUES (%s,%s,%s)"
            ).format(schema),
            (project, digest, asset),
        )
    insert = sql.SQL(
        "INSERT INTO {}.enrichment_operations"
        "(project_id,operation_key,operation_ref,operation_digest) VALUES (%s,%s,%s,%s)"
    ).format(sql.Identifier(ledger.schema))
    with pytest.raises(psycopg.errors.CheckViolation):
        with ledger.transaction() as tx:
            tx.connection.execute(insert, (project, digest, Jsonb({}), digest))
    with ledger.transaction() as tx:
        tx.connection.execute(
            insert,
            (
                project,
                digest,
                Jsonb(
                    {
                        "digest": digest,
                        "projectId": project,
                        "artifactSchema": "cf.enrichment-operation.v1",
                    }
                ),
                digest,
            ),
        )
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with ledger.transaction() as tx:
            tx.connection.execute(
                insert,
                (
                    project,
                    "b" * 64,
                    Jsonb(
                        {
                            "digest": "b" * 64,
                            "projectId": project,
                            "artifactSchema": "cf.enrichment-operation.v1",
                        }
                    ),
                    "b" * 64,
                ),
            )


def test_task_schema_installation_requires_existing_project(ledger: Ledger) -> None:
    import psycopg
    from psycopg.types.json import Jsonb

    from conscience_foundry.ledger.enrichment import install_enrichment_schema

    project = "00000000-0000-0000-0000-000000000001"
    digest = "a" * 64
    install_enrichment_schema(ledger)

    def ref(role: str) -> Jsonb:
        return Jsonb({"digest": digest, "projectId": project, "artifactSchema": role})

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with ledger.transaction() as tx:
            tx.connection.execute(
                sql.SQL("INSERT INTO {}.enrichment_task_schemas VALUES (%s,%s,%s,%s,%s,%s)").format(
                    sql.Identifier(tx.schema)
                ),
                (
                    project,
                    digest,
                    ref("cf.enrichment-spec.v1"),
                    ref("cf.enrichment-schema-installation.v1"),
                    ref("json-schema.2020-12"),
                    ref("json-schema.2020-12"),
                ),
            )


def test_selection_cannot_rebind_result_metadata(ledger: Ledger) -> None:
    from uuid import uuid4

    import psycopg
    from psycopg.types.json import Jsonb

    from conscience_foundry.ledger.enrichment import install_enrichment_schema

    ids = [str(uuid4()) for _ in range(8)]
    project, asset, batch, run, auth, plan, reservation, attempt = ids
    op, request_digest, result_digest = "a" * 64, "b" * 64, "c" * 64

    def ref(role: str, digest: str) -> dict:
        return {
            "schemaVersion": "cf.artifact-ref.v1",
            "projectId": project,
            "digest": digest,
            "sizeBytes": 1,
            "mediaType": "application/json",
            "artifactSchema": role,
            "locations": [],
        }

    install_enrichment_schema(ledger)
    with ledger.transaction() as tx:
        schema = sql.Identifier(tx.schema)

        def put(query: str, values: tuple) -> None:
            tx.connection.execute(sql.SQL(query).format(schema), values)

        put("INSERT INTO {}.projects VALUES (%s)", (project,))
        put("INSERT INTO {}.assets VALUES (%s,%s,%s,%s,%s)", (project, asset, asset, op, 1))
        put("INSERT INTO {}.batches VALUES (%s,%s,%s,%s)", (project, batch, op, Jsonb({})))
        put(
            "INSERT INTO {}.admission_reports VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (project, op, batch, op, Jsonb({}), Jsonb({}), "v1", "2026-01-01Z"),
        )
        put(
            "INSERT INTO {}.runs(project_id,run_id,admission_report_digest) VALUES (%s,%s,%s)",
            (project, run, op),
        )
        put(
            "INSERT INTO {}.authorizations VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (project, auth, run, Jsonb({}), [], 1, 1, asset, "2026-01-01Z", "2026-02-01Z"),
        )
        put(
            "INSERT INTO {}.operations(project_id,operation_key,asset_id) VALUES (%s,%s,%s)",
            (project, op, asset),
        )
        put(
            "INSERT INTO {}.plans VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (project, plan, run, op, Jsonb({}), auth, op),
        )
        put(
            "INSERT INTO {}.reservations(project_id,reservation_id,run_id,authorization_id,"
            "operation_key,scope,reserved_usd,outstanding_usd,settled_usd) "
            "VALUES (%s,%s,%s,%s,%s,'attempt',1,1,0)",
            (project, reservation, run, auth, op),
        )
        put(
            "INSERT INTO {}.attempts(project_id,attempt_id,run_id,plan_id,operation_key,"
            "attempt_number,reservation_id,state,created_at) "
            "VALUES (%s,%s,%s,%s,%s,1,%s,'reserved','2026-01-01Z')",
            (project, attempt, run, plan, op, reservation),
        )
        put(
            "INSERT INTO {}.enrichment_operations VALUES (%s,%s,%s,%s)",
            (project, op, Jsonb(ref("cf.enrichment-operation.v1", op)), op),
        )
        put(
            "INSERT INTO {}.enrichment_requests VALUES (%s,%s,%s,%s,%s)",
            (
                project,
                op,
                attempt,
                Jsonb(ref("cf.enrichment-request.v1", request_digest)),
                request_digest,
            ),
        )
        put(
            "INSERT INTO {}.enrichment_results VALUES (%s,%s,%s,%s,%s,%s)",
            (
                project,
                op,
                attempt,
                result_digest,
                Jsonb(ref("cf.enrichment-result.v1", result_digest)),
                None,
            ),
        )
    # A valid full reference can carry many locations; the database must not impose
    # an index-tuple-sized ceiling on its serialized metadata.
    large_ref = ref("cf.enrichment-result.v1", "d" * 64) | {
        "locations": [{"storeId": "synthetic", "objectKey": str(uuid4())} for _ in range(250)]
    }
    with ledger.transaction() as tx:
        tx.connection.execute(
            sql.SQL("INSERT INTO {}.enrichment_results VALUES (%s,%s,%s,%s,%s,%s)").format(
                sql.Identifier(tx.schema)
            ),
            (project, op, attempt, "d" * 64, Jsonb(large_ref), None),
        )
    wrong = ref("cf.enrichment-result.v1", result_digest) | {"sizeBytes": 2}
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with ledger.transaction() as tx:
            tx.connection.execute(
                sql.SQL(
                    "INSERT INTO {}.enrichment_selections(project_id,operation_key,event_id,"
                    "result_attempt_id,result_digest,result_ref,evidence_ref,record_ref) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)"
                ).format(sql.Identifier(tx.schema)),
                (
                    project,
                    op,
                    str(uuid4()),
                    attempt,
                    result_digest,
                    Jsonb(wrong),
                    Jsonb(ref("synthetic.evidence.v1", op)),
                    Jsonb(ref("synthetic.record.v1", op)),
                ),
            )
    insert = sql.SQL(
        "INSERT INTO {}.enrichment_selections(project_id,operation_key,event_id,"
        "result_attempt_id,result_digest,result_ref,evidence_ref,record_ref) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)"
    ).format(sql.Identifier(ledger.schema))

    def event() -> tuple:
        return (
            project,
            op,
            str(uuid4()),
            attempt,
            result_digest,
            Jsonb(ref("cf.enrichment-result.v1", result_digest)),
            Jsonb(ref("synthetic.evidence.v1", op)),
            Jsonb(ref("synthetic.record.v1", op)),
        )

    root_event = event()
    with ledger.transaction() as tx:
        tx.connection.execute(insert, root_event)
    with pytest.raises(psycopg.errors.UniqueViolation):
        with ledger.transaction() as tx:
            tx.connection.execute(insert, event())
    child_event_id = str(uuid4())
    with ledger.transaction() as tx:
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {}.enrichment_selections(project_id,operation_key,event_id,"
                "previous_event_id,result_attempt_id,result_digest,result_ref,"
                "evidence_ref,record_ref) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            ).format(sql.Identifier(tx.schema)),
            (
                project,
                op,
                child_event_id,
                root_event[2],
                attempt,
                "d" * 64,
                Jsonb(large_ref),
                Jsonb(ref("synthetic.evidence.v1", op)),
                Jsonb(ref("synthetic.record.v1", op)),
            ),
        )
        selected = tx.connection.execute(
            sql.SQL(
                "SELECT result_ref FROM {}.enrichment_selections "
                "WHERE project_id=%s AND event_id=%s"
            ).format(sql.Identifier(tx.schema)),
            (project, child_event_id),
        ).fetchone()
        assert selected is not None and selected[0] == large_ref
    with pytest.raises(psycopg.errors.CheckViolation):
        with ledger.transaction() as tx:
            tx.connection.execute(
                sql.SQL(
                    "UPDATE {}.enrichment_results SET result_ref=%s "
                    "WHERE project_id=%s AND result_digest=%s"
                ).format(sql.Identifier(tx.schema)),
                (Jsonb(wrong), project, result_digest),
            )


def test_install_task_schemas_requires_explicit_authority_and_exact_replay(
    ledger: Ledger, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import io
    import json

    from test_execution_control import Case
    from test_ledger_db import PROJECT, reference

    from conscience_foundry.contracts.extensions import EnrichmentSpec
    from conscience_foundry.enrichment.context import EnrichmentContext
    from conscience_foundry.enrichment.task_schemas import install_task_schemas, load_task_schemas
    from conscience_foundry.ledger.enrichment import install_enrichment_schema

    case = Case(tmp_path)
    raw = json.dumps(
        {
            "type": "object",
            "properties": {"x": {"type": "string", "maxLength": 8}},
            "additionalProperties": False,
        },
        separators=(",", ":"),
    ).encode()
    schema_ref = reference(raw, "json-schema.2020-12")
    case.store.put_verified(io.BytesIO(raw), schema_ref, case.access)
    other = case.limits_ref
    spec = EnrichmentSpec(
        schema_version="cf.enrichment-spec.v1",
        spec_id="test",
        task_id="test",
        profile_id="technical_minimal",
        profile_version="synthetic.v1",
        input_schema_ref=schema_ref,
        output_schema_ref=schema_ref,
        prompt_ref=other,
        context_policy_ref=other,
        model_route_ref=other,
        generation_settings_ref=other,
        validation_policy_ref=other,
        review_policy_ref=other,
        execution_limits_ref=other,
        runtime_ref=other,
    )
    spec_ref = case.put(spec)
    policy_ref = case.put(case.policy)

    class Authority:
        allow = False
        proofs = []

        def approve(self, proof):
            self.proofs.append(proof)
            return self.allow

    authority = Authority()
    context = EnrichmentContext(
        access=case.access,
        store=case.store,
        clock=lambda: "2026-10-25T00:00:00.000Z",
        limits_by_schema=case.schemas,
        output_store_id="synthetic",
        current_policy=lambda: case.policy,
        authority=authority,
    )
    install_enrichment_schema(ledger)
    with ledger.transaction() as tx:
        tx.create_project(PROJECT)
    with pytest.raises(ContractError):
        install_task_schemas(
            spec_ref, policy_ref=policy_ref, evidence_ref=other, ledger=ledger, context=context
        )
    authority.allow = 1
    with pytest.raises(ContractError):
        install_task_schemas(
            spec_ref, policy_ref=policy_ref, evidence_ref=other, ledger=ledger, context=context
        )
    authority.allow = True
    # Administrative evidence cannot make the store read another source's content.
    original_read = case.store.read_verified
    evidence_reads = []

    def record_read(ref, access, limit):
        if ref == case.original:
            evidence_reads.append(ref)
        return original_read(ref, access, limit)

    monkeypatch.setattr(case.store, "read_verified", record_read)
    with pytest.raises(ContractError, match="forbidden"):
        install_task_schemas(
            spec_ref,
            policy_ref=policy_ref,
            evidence_ref=case.original,
            ledger=ledger,
            context=context,
        )
    assert evidence_reads == []
    first = install_task_schemas(
        spec_ref, policy_ref=policy_ref, evidence_ref=other, ledger=ledger, context=context
    )
    second = install_task_schemas(
        spec_ref, policy_ref=policy_ref, evidence_ref=other, ledger=ledger, context=context
    )
    assert first == second
    from dataclasses import replace

    with pytest.raises(ContractError):
        install_task_schemas(
            spec_ref,
            policy_ref=policy_ref,
            evidence_ref=other,
            ledger=ledger,
            context=replace(context, clock=lambda: "not-an-instant"),
        )
    assert len(authority.proofs) == 4
    assert authority.proofs[2].state_digest != authority.proofs[3].state_digest
    # A private administrative evidence object is pinned and bounded, not
    # interpreted as a new registered core artifact.
    private_raw = b'{"operator":"synthetic"}'
    private_ref = reference(private_raw, "operator.install-evidence.v1")
    case.store.put_verified(io.BytesIO(private_raw), private_ref, case.access)
    private_spec_ref = case.put(spec.model_copy(update={"spec_id": "private-evidence"}))
    with pytest.raises(ContractError, match="limits_missing"):
        install_task_schemas(
            private_spec_ref,
            policy_ref=policy_ref,
            evidence_ref=private_ref,
            ledger=ledger,
            context=context,
        )
    private_context = replace(
        context, limits_by_schema={**case.schemas, private_ref.artifact_schema: case.bound}
    )
    private_receipt = install_task_schemas(
        private_spec_ref,
        policy_ref=policy_ref,
        evidence_ref=private_ref,
        ledger=ledger,
        context=private_context,
    )
    assert private_receipt == install_task_schemas(
        private_spec_ref,
        policy_ref=policy_ref,
        evidence_ref=private_ref,
        ledger=ledger,
        context=private_context,
    )
    assert private_ref in authority.proofs[-1].evidence_refs
    with ledger.transaction() as tx:
        registry = load_task_schemas(first, spec_ref=spec_ref, tx=tx, context=context)
    assert registry.permits(schema_ref, raw)
    with ledger.transaction() as tx:
        with pytest.raises(ContractError):
            load_task_schemas(
                first.model_copy(update={"digest": "f" * 64}),
                spec_ref=spec_ref,
                tx=tx,
                context=context,
            )
    with pytest.raises(ContractError):
        install_task_schemas(
            spec_ref, policy_ref=policy_ref, evidence_ref=policy_ref, ledger=ledger, context=context
        )


def test_canonical_snapshot_excludes_enrichment_operations(release_case) -> None:  # noqa: F811
    from psycopg.types.json import Jsonb
    from test_ledger_db import ASSET, PROJECT, reference

    from conscience_foundry.ledger.enrichment import install_enrichment_schema
    from conscience_foundry.release.coverage import capture

    install_enrichment_schema(release_case.ledger)
    operation_key = "a" * 64
    ref = reference(b"synthetic enrichment operation", "cf.enrichment-operation.v1")
    with release_case.ledger.transaction() as tx:
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {}.operations(project_id,operation_key,asset_id,held) "
                "VALUES (%s,%s,%s,true)"
            ).format(sql.Identifier(tx.schema)),
            (PROJECT, operation_key, ASSET),
        )
        tx.connection.execute(
            sql.SQL(
                "INSERT INTO {}.enrichment_operations(project_id,operation_key,operation_ref,"
                "operation_digest) VALUES (%s,%s,%s,%s)"
            ).format(sql.Identifier(tx.schema)),
            (PROJECT, operation_key, Jsonb(ref.model_dump(mode="json", by_alias=True)), ref.digest),
        )
    with release_case.ledger.transaction() as tx:
        snapshot = capture((release_case.case.data.report_ref,), tx, release_case.release)
    assert operation_key not in {row["operation_key"] for row in snapshot.rows["operations"]}


from test_release_build import release_case  # noqa: E402,F401


def test_verified_canonical_requires_current_accepted_review(release_case) -> None:  # noqa: F811
    from test_ledger_db import ASSET
    from test_release_build import produced_revision

    from conscience_foundry.enrichment.context import EnrichmentContext
    from conscience_foundry.enrichment.registration import verify_canonical_input
    from conscience_foundry.policy.access import AccessContext

    case = release_case.case
    revision_ref = produced_revision(release_case)
    old_access = case.access
    rich_access = AccessContext(
        old_access.project_id, old_access.actor_id, old_access.scopes | {"enrich"}
    )
    case.access = rich_access
    context = EnrichmentContext(
        access=rich_access,
        store=case.store,
        clock=lambda: "2026-10-25T00:00:00.000Z",
        limits_by_schema=case.schemas,
        output_store_id="synthetic",
        current_policy=lambda: case.policy,
        authority=None,
    )
    with release_case.ledger.transaction() as tx:
        with pytest.raises(ContractError):
            verify_canonical_input(revision_ref, case.data.report_ref, tx=tx, context=context)
    case.access = old_access
    release_case.review(revision_ref)
    case.access = rich_access
    with release_case.ledger.transaction() as tx:
        value = verify_canonical_input(revision_ref, case.data.report_ref, tx=tx, context=context)
    assert value.revision.asset_id == ASSET
    assert value.text == b"Synthetic text"
    # A second admitted source is consulted for metadata only: audit remains
    # required, but its text must not be read or require content permissions.
    from test_release_build import B_SOURCE

    original_policy = case.policy
    other_ref = case.data.report.entries[1].snapshot_ref
    assert other_ref is not None
    case.policy = case.policy.model_copy(
        update={
            "sources": tuple(
                source.model_copy(update={"read": "deny", "extract": "deny", "enrich": "deny"})
                if source.source_id == B_SOURCE
                else source
                for source in original_policy.sources
            )
        }
    )
    release_case.reads.clear()
    with release_case.ledger.transaction() as tx:
        assert (
            verify_canonical_input(revision_ref, case.data.report_ref, tx=tx, context=context).text
            == b"Synthetic text"
        )
    assert other_ref.digest not in release_case.reads
    case.policy = original_policy
    with release_case.ledger.transaction() as tx:
        with pytest.raises(ContractError, match="forbidden"):
            verify_canonical_input(
                revision_ref.model_copy(
                    update={"project_id": "00000000-0000-0000-0000-000000000002"}
                ),
                case.data.report_ref,
                tx=tx,
                context=context,
            )
    from conscience_foundry.contracts.canonical import DocumentSpan
    from conscience_foundry.enrichment.registration import _verify_omitted_ref

    span = DocumentSpan(
        schema_version="cf.document-span.v1",
        project_id=value.revision.project_id,
        source_id=value.source_id,
        revision_id=value.revision.revision_id,
        section_id=value.revision.sections[0].section_id,
        start=0,
        end=2,
        offset_unit="unicode_scalar",
    )
    span_ref = case.put(span)
    _verify_omitted_ref(span_ref, value, revision_ref=revision_ref, context=context)
    _verify_omitted_ref(value.revision.text_ref, value, revision_ref=revision_ref, context=context)
    with pytest.raises(ContractError):
        _verify_omitted_ref(case.limits_ref, value, revision_ref=revision_ref, context=context)
    reduced = AccessContext(
        rich_access.project_id, rich_access.actor_id, rich_access.scopes - {"enrich"}
    )
    case.access = reduced
    context = EnrichmentContext(
        access=reduced,
        store=case.store,
        clock=context.clock,
        limits_by_schema=case.schemas,
        output_store_id="synthetic",
        current_policy=context.current_policy,
        authority=None,
    )
    with release_case.ledger.transaction() as tx:
        with pytest.raises(ContractError):
            verify_canonical_input(revision_ref, case.data.report_ref, tx=tx, context=context)
    for missing in ("extract", "auditMetadataRead"):
        reduced = AccessContext(
            rich_access.project_id, rich_access.actor_id, rich_access.scopes - {missing}
        )
        case.access = reduced
        reduced_context = EnrichmentContext(
            access=reduced,
            store=case.store,
            clock=context.clock,
            limits_by_schema=case.schemas,
            output_store_id="synthetic",
            current_policy=context.current_policy,
            authority=None,
        )
        with release_case.ledger.transaction() as tx:
            with pytest.raises(ContractError):
                verify_canonical_input(
                    revision_ref, case.data.report_ref, tx=tx, context=reduced_context
                )
    from dataclasses import replace
    from uuid import uuid4

    from test_release_build import withdraw

    from conscience_foundry.contracts.common import Reason

    case.access = rich_access
    full_context = replace(context, access=rich_access)
    original_policy = case.policy
    case.policy = case.policy.model_copy(
        update={
            "sources": tuple(
                source.model_copy(update={"enrich": "deny"})
                if source.source_id == value.source_id
                else source
                for source in case.policy.sources
            )
        }
    )
    with release_case.ledger.transaction() as tx:
        with pytest.raises(ContractError, match="forbidden"):
            verify_canonical_input(revision_ref, case.data.report_ref, tx=tx, context=full_context)
    case.policy = original_policy
    with release_case.ledger.transaction() as tx:
        assert (
            verify_canonical_input(
                revision_ref, case.data.report_ref, tx=tx, context=full_context
            ).text
            == b"Synthetic text"
        )
    case.access = old_access
    withdraw(
        release_case,
        str(uuid4()),
        Reason(code="forbidden", message="Source withdrawn"),
        asset_id=ASSET,
    )
    case.access = rich_access
    with release_case.ledger.transaction() as tx:
        with pytest.raises(ContractError, match="forbidden"):
            verify_canonical_input(revision_ref, case.data.report_ref, tx=tx, context=full_context)


def test_register_operation_production_authority_and_replay(release_case) -> None:  # noqa: F811
    import io
    import json
    from uuid import uuid4

    from test_ledger_db import ACTOR, ASSET, PROJECT, RUN, TIME, encoded, reference
    from test_release_build import selected_source

    from conscience_foundry.contracts.enrichment import (
        EnrichmentAllocationPolicy,
        EnrichmentOperation,
        EnrichmentPayload,
        EnrichmentPlan,
        enrichment_operation_key,
    )
    from conscience_foundry.contracts.execution import RunAuthorization
    from conscience_foundry.contracts.extensions import EnrichmentSpec
    from conscience_foundry.enrichment.context import EnrichmentContext
    from conscience_foundry.enrichment.registration import register_operation
    from conscience_foundry.enrichment.task_schemas import install_task_schemas
    from conscience_foundry.execution.evidence import budget_context
    from conscience_foundry.ledger.budget import install_run_authorization
    from conscience_foundry.ledger.enrichment import install_enrichment_schema
    from conscience_foundry.policy.access import AccessContext

    case = release_case.case
    selected = selected_source(release_case)
    install_enrichment_schema(release_case.ledger)
    schema_raw = json.dumps(
        {
            "type": "object",
            "properties": {"x": {"type": "string", "maxLength": 8}},
            "required": ["x"],
            "additionalProperties": False,
        },
        separators=(",", ":"),
    ).encode()
    schema_ref = reference(schema_raw, "json-schema.2020-12")
    case.store.put_verified(io.BytesIO(schema_raw), schema_ref, case.access)
    other = case.limits_ref
    spec = EnrichmentSpec(
        schema_version="cf.enrichment-spec.v1",
        spec_id="test",
        task_id="test",
        profile_id="technical_minimal",
        profile_version="synthetic.v1",
        input_schema_ref=schema_ref,
        output_schema_ref=schema_ref,
        prompt_ref=other,
        context_policy_ref=other,
        model_route_ref=other,
        generation_settings_ref=other,
        validation_policy_ref=other,
        review_policy_ref=other,
        execution_limits_ref=other,
        runtime_ref=other,
    )
    spec_ref = case.put(spec)
    policy_ref = case.put(case.policy)
    old_access = case.access
    access = AccessContext(PROJECT, ACTOR, old_access.scopes | {"enrich"})
    case.access = access

    class Authority:
        allow = True
        hook = None

        def approve(self, proof):
            if self.hook:
                self.hook()
            return self.allow

    now_box = [TIME]
    authority = Authority()
    context = EnrichmentContext(
        access=access,
        store=case.store,
        clock=lambda: now_box[0],
        limits_by_schema=case.schemas,
        output_store_id="synthetic",
        current_policy=lambda: case.policy,
        authority=authority,
    )
    installation_ref = install_task_schemas(
        spec_ref,
        policy_ref=policy_ref,
        evidence_ref=other,
        ledger=release_case.ledger,
        context=context,
    )
    payload_ref = case.put(
        EnrichmentPayload(
            schema_version="cf.enrichment-payload.v1",
            project_id=PROJECT,
            schema_ref=schema_ref,
            value={"x": "hello"},
        )
    )
    operation = EnrichmentOperation(
        schema_version="cf.enrichment-operation.v1",
        project_id=PROJECT,
        asset_id=ASSET,
        canonical_revision_ref=selected.revision_ref,
        spec_ref=spec_ref,
        policy_ref=policy_ref,
        input_ref=payload_ref,
        context_spans=(),
        omitted_context_refs=(),
    )
    op_ref = case.put(operation)
    key = enrichment_operation_key(operation, limits=case.bound)
    tariff_ref = other
    allocation_ref = case.put(
        EnrichmentAllocationPolicy(
            schema_version="cf.enrichment-allocation-policy.v1",
            project_id=PROJECT,
            tariff_ref=tariff_ref,
            fixed_charge_usd="1",
            funded_from=TIME,
            funded_until="2026-10-26T00:00:00.000Z",
        )
    )
    auth_id = str(uuid4())
    plan = EnrichmentPlan(
        schema_version="cf.enrichment-plan.v1",
        project_id=PROJECT,
        run_id=RUN,
        plan_id=str(uuid4()),
        operation_ref=op_ref,
        operation_key=key,
        admission_report_ref=case.data.report_ref,
        contract_set_ref=case.plan.contract_set_ref,
        limits_refs=(case.limits_ref,),
        allocation_policy_ref=allocation_ref,
        task_schema_installation_ref=installation_ref,
        resources=case.plan.resources,
        budget=case.plan.budget.model_copy(
            update={"tariff_ref": tariff_ref, "authorization_id": auth_id}
        ),
        expires_at=case.plan.expires_at,
    )
    plan_ref = case.put(plan)
    authorization = RunAuthorization(
        schema_version="cf.run-authorization.v1",
        authorization_id=auth_id,
        project_id=PROJECT,
        run_id=RUN,
        admission_report_digest=case.data.report_ref.digest,
        allowed_plan_digests=(plan_ref.digest,),
        max_run_cost=plan.budget.max_run_cost,
        max_concurrent_attempts=case.auth.max_concurrent_attempts,
        actor_id=ACTOR,
        authorized_at=TIME,
        expires_at=case.auth.expires_at,
    )
    auth_ref = case.put(authorization)
    with pytest.raises(ContractError):
        register_operation(op_ref, plan_ref, auth_ref, ledger=release_case.ledger, context=context)
    case.access = old_access
    case.authority.grants[auth_ref.digest] = (auth_ref.digest, case.auth.authorization_id)
    with release_case.ledger.transaction() as tx:
        install_run_authorization(
            authorization,
            auth_ref,
            encoded(authorization),
            tx,
            context=budget_context(case.control, tx=tx),
            expected_previous_authorization_id=case.auth.authorization_id,
        )
    case.access = access
    assert (
        register_operation(op_ref, plan_ref, auth_ref, ledger=release_case.ledger, context=context)
        == key
    )
    assert (
        register_operation(op_ref, plan_ref, auth_ref, ledger=release_case.ledger, context=context)
        == key
    )
    authority.hook = lambda: now_box.__setitem__(0, "2026-10-24T00:00:00.000Z")
    with pytest.raises(ContractError):
        register_operation(op_ref, plan_ref, auth_ref, ledger=release_case.ledger, context=context)
    authority.hook = None
    now_box[0] = TIME
    authority.allow = False
    with pytest.raises(ContractError):
        register_operation(op_ref, plan_ref, auth_ref, ledger=release_case.ledger, context=context)
    authority.allow = True

    # A historical bundle remains valid for F1, but never authorizes new enrichment roles.
    from pathlib import Path

    from conscience_foundry.contracts.registry import ContractSet

    legacy_data = json.loads(Path("tests/fixtures/public/schema_parity.json").read_text())[
        "preEnrichmentContractSet"
    ]["contractSet"]
    legacy_ref = case.put(ContractSet.model_validate(legacy_data))
    next_id = str(uuid4())
    legacy_plan = plan.model_copy(
        update={
            "plan_id": str(uuid4()),
            "contract_set_ref": legacy_ref,
            "budget": plan.budget.model_copy(update={"authorization_id": next_id}),
        }
    )
    legacy_plan_ref = case.put(legacy_plan)
    legacy_auth = authorization.model_copy(
        update={"authorization_id": next_id, "allowed_plan_digests": (legacy_plan_ref.digest,)}
    )
    legacy_auth_ref = case.put(legacy_auth)
    case.access = old_access
    case.authority.grants[legacy_auth_ref.digest] = (legacy_auth_ref.digest, auth_id)
    with release_case.ledger.transaction() as tx:
        install_run_authorization(
            legacy_auth,
            legacy_auth_ref,
            encoded(legacy_auth),
            tx,
            context=budget_context(case.control, tx=tx),
            expected_previous_authorization_id=auth_id,
        )
    case.access = access
    with pytest.raises(ContractError, match="unsupported_schema"):
        register_operation(
            op_ref, legacy_plan_ref, legacy_auth_ref, ledger=release_case.ledger, context=context
        )
    from conscience_foundry.contracts.canonical import DocumentRevision, DocumentSpan

    previous_id = next_id

    def grant_variant(changes, candidate=operation):
        nonlocal previous_id
        candidate_ref = case.put(candidate)
        candidate_key = enrichment_operation_key(candidate, limits=case.bound)
        new_id = str(uuid4())
        variant = plan.model_copy(
            update={
                "plan_id": str(uuid4()),
                "operation_ref": candidate_ref,
                "operation_key": candidate_key,
                "budget": plan.budget.model_copy(update={"authorization_id": new_id}),
                **changes,
            }
        )
        variant_ref = case.put(variant)
        grant = authorization.model_copy(
            update={"authorization_id": new_id, "allowed_plan_digests": (variant_ref.digest,)}
        )
        grant_ref = case.put(grant)
        case.access = old_access
        case.authority.grants[grant_ref.digest] = (grant_ref.digest, previous_id)
        with release_case.ledger.transaction() as tx:
            install_run_authorization(
                grant,
                grant_ref,
                encoded(grant),
                tx,
                context=budget_context(case.control, tx=tx),
                expected_previous_authorization_id=previous_id,
            )
        case.access = access
        previous_id = new_id
        return candidate_ref, variant_ref, grant_ref, candidate_key

    bad_policy_ref = case.put(
        EnrichmentAllocationPolicy(
            schema_version="cf.enrichment-allocation-policy.v1",
            project_id=PROJECT,
            tariff_ref=case.spec_ref,
            fixed_charge_usd="1",
            funded_from=TIME,
            funded_until="2026-10-26T00:00:00.000Z",
        )
    )
    candidate_ref, variant_ref, grant_ref, _ = grant_variant(
        {"allocation_policy_ref": bad_policy_ref}
    )
    with pytest.raises(ContractError, match="forbidden"):
        register_operation(
            candidate_ref, variant_ref, grant_ref, ledger=release_case.ledger, context=context
        )

    revision = DocumentRevision.from_wire(
        case.store.read_verified(selected.revision_ref, access, 65536).data, case.bound
    )
    span = DocumentSpan(
        schema_version="cf.document-span.v1",
        project_id=PROJECT,
        source_id=revision.source_id,
        revision_id=revision.revision_id,
        section_id=revision.sections[0].section_id,
        start=0,
        end=999,
        offset_unit="unicode_scalar",
    )
    invalid_operation = operation.model_copy(update={"context_spans": (span,)})
    candidate_ref, variant_ref, grant_ref, invalid_key = grant_variant({}, invalid_operation)
    with pytest.raises(ContractError, match="invalid_span"):
        register_operation(
            candidate_ref, variant_ref, grant_ref, ledger=release_case.ledger, context=context
        )
    with release_case.ledger.transaction() as tx:
        assert (
            tx.connection.execute(
                sql.SQL(
                    "SELECT count(*) FROM {}.enrichment_operations "
                    "WHERE project_id=%s AND operation_key=%s"
                ).format(sql.Identifier(tx.schema)),
                (PROJECT, invalid_key),
            ).fetchone()[0]
            == 0
        )

    invalid_payload_ref = case.put(
        EnrichmentPayload(
            schema_version="cf.enrichment-payload.v1",
            project_id=PROJECT,
            schema_ref=schema_ref,
            value={"x": "exceeds eight"},
        )
    )
    invalid_operation = operation.model_copy(update={"input_ref": invalid_payload_ref})
    candidate_ref, variant_ref, grant_ref, invalid_key = grant_variant({}, invalid_operation)
    with pytest.raises(ContractError, match="invalid_schema"):
        register_operation(
            candidate_ref, variant_ref, grant_ref, ledger=release_case.ledger, context=context
        )
    with release_case.ledger.transaction() as tx:
        assert (
            tx.connection.execute(
                sql.SQL(
                    "SELECT count(*) FROM {}.enrichment_operations "
                    "WHERE project_id=%s AND operation_key=%s"
                ).format(sql.Identifier(tx.schema)),
                (PROJECT, invalid_key),
            ).fetchone()[0]
            == 0
        )

    with release_case.ledger.transaction() as tx:
        count = tx.connection.execute(
            sql.SQL(
                "SELECT count(*) FROM {}.enrichment_operations "
                "WHERE project_id=%s AND operation_key=%s"
            ).format(sql.Identifier(tx.schema)),
            (PROJECT, key),
        ).fetchone()[0]
        assert count == 1
