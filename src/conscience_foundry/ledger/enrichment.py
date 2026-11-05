"""Explicit installation and verification of additive enrichment sidecars."""

from __future__ import annotations

import hashlib
from importlib.resources import files

from psycopg import sql

from conscience_foundry.contracts.common import ContractError
from conscience_foundry.ledger.db import Ledger, LedgerTxn

MIGRATION_NAME = "003_enrichment.sql"
_TABLES = frozenset(
    {
        "enrichment_operations",
        "enrichment_requests",
        "enrichment_results",
        "enrichment_selections",
        "enrichment_current_selection",
        "enrichment_task_schemas",
    }
)


def migration_text() -> str:
    return (
        files("conscience_foundry.ledger")
        .joinpath("migrations/" + MIGRATION_NAME)
        .read_text(encoding="utf-8")
    )


def migration_digest() -> str:
    return hashlib.sha256(migration_text().encode("utf-8")).hexdigest()


def _table(tx: LedgerTxn, name: str) -> sql.Identifier:
    if not tx._active or name not in _TABLES:
        raise ContractError("invalid_schema")
    return sql.Identifier(tx.schema, name)


def _installed_comment(tx: LedgerTxn) -> str | None:
    rows = tx.connection.execute(
        "SELECT c.relname, pg_catalog.obj_description(c.oid,'pg_class') "
        "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=%s AND c.relname = ANY(%s) AND c.relkind='r'",
        (tx.schema, list(_TABLES)),
    ).fetchall()
    if not rows:
        return None
    names = {row[0]: row[1] for row in rows}
    if set(names) != _TABLES:
        raise ContractError("schema_incompatible")
    return str(names["enrichment_operations"]) if names["enrichment_operations"] is not None else ""


def install_enrichment_schema(ledger: Ledger) -> None:
    text, digest = migration_text(), migration_digest()
    with ledger.transaction() as tx:
        tx.connection.execute(
            "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(%s,0))",
            ("conscience-foundry:migrate-enrichment:" + tx.schema,),
        )
        present = _installed_comment(tx)
        if present is not None:
            if present != digest:
                raise ContractError("schema_incompatible")
            return
        tx.connection.execute(sql.SQL(text).format(schema=sql.Identifier(tx.schema)))
        tx.connection.execute(
            sql.SQL("COMMENT ON TABLE {} IS {}").format(
                _table(tx, "enrichment_operations"), sql.Literal(digest)
            )
        )
        shared = tx.connection.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace, "
            "LATERAL pg_catalog.aclexplode(COALESCE(c.relacl, "
            "pg_catalog.acldefault('r',c.relowner))) a "
            "WHERE n.nspname=%s AND c.relname = ANY(%s) AND a.grantee<>c.relowner)",
            (tx.schema, list(_TABLES)),
        ).fetchone()
        if shared is None or shared[0]:
            raise ContractError("forbidden")


def require_enrichment_schema(tx: LedgerTxn) -> None:
    if _installed_comment(tx) != migration_digest():
        raise ContractError("schema_incompatible")
