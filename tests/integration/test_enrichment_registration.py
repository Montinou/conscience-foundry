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
