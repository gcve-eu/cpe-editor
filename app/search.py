"""CPE substring search and optional SQLite FTS5 trigram acceleration."""

import re

from sqlalchemy import column, event, func, or_, select, table, text, union_all

from .models import CPEEntry, Product, Vendor, db


def apply_cpe_text_search(query, value):
    """Preselect matching CPE ids without multiplying rows through product joins.

    Keep LIKE as the final test, including its existing % and _ semantics. FTS
    only narrows candidates using a literal run from the pattern, so short and
    wildcard-only searches can safely use the same fallback query.
    """
    pattern = f"%{value.lower()}%"
    scoped_ids = query.with_entities(CPEEntry.id).order_by(None)
    cpe_matches = scoped_ids.filter(
        or_(
            func.lower(CPEEntry.cpe_uri).like(pattern),
            func.lower(CPEEntry.title).like(pattern),
            func.lower(CPEEntry.version).like(pattern),
        )
    )
    literal = max(re.split(r"[%_]", value.lower()), key=len)
    if len(literal) >= 3 and "\x00" not in value and _has_trigram_index():
        fts = table("cpe_search_fts", column("rowid"))
        candidates = (
            select(fts.c.rowid)
            .where(text("cpe_search_fts MATCH :cpe_search_term"))
            .params(cpe_search_term='"' + literal.replace('"', '""') + '"')
        )
        cpe_matches = cpe_matches.filter(CPEEntry.id.in_(candidates))

    vendor_ids = select(Vendor.id).where(
        or_(
            func.lower(Vendor.name).like(pattern),
            func.lower(Vendor.title).like(pattern),
        )
    )
    product_ids = select(Product.id).where(
        or_(
            func.lower(Product.name).like(pattern),
            func.lower(Product.title).like(pattern),
        )
    )
    return query.filter(
        CPEEntry.id.in_(
            union_all(
                cpe_matches.statement,
                scoped_ids.filter(CPEEntry.vendor_id.in_(vendor_ids)).statement,
                scoped_ids.filter(CPEEntry.product_id.in_(product_ids)).statement,
            )
        )
    )


def _has_trigram_index():
    if db.engine.dialect.name != "sqlite":
        return False
    # Check per search so running the CLI enables the index in existing workers.
    return (
        db.session.execute(
            text(
                "SELECT 1 FROM sqlite_master "
                "WHERE type = 'table' AND name = 'cpe_search_fts'"
            )
        ).scalar()
        is not None
    )


def rebuild_cpe_search_index():
    """Build outside server startup; triggers maintain ORM and bulk SQL writes."""
    if db.engine.dialect.name != "sqlite":
        raise ValueError("The CPE trigram search index requires SQLite with FTS5.")
    with db.engine.begin() as connection:
        # SQLite's legacy transaction mode does not start transactions for DDL.
        # Explicitly begin so index creation, triggers and backfill are atomic.
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        connection.exec_driver_sql(
            "CREATE VIRTUAL TABLE IF NOT EXISTS cpe_search_fts USING fts5("
            "cpe_uri, title, version, content='cpe_entry', content_rowid='id', "
            "tokenize='trigram')"
        )
        connection.exec_driver_sql("""
            CREATE TRIGGER IF NOT EXISTS cpe_search_insert AFTER INSERT ON cpe_entry BEGIN
                INSERT INTO cpe_search_fts(rowid, cpe_uri, title, version)
                VALUES (new.id, new.cpe_uri, new.title, new.version);
            END
        """)
        connection.exec_driver_sql("""
            CREATE TRIGGER IF NOT EXISTS cpe_search_delete AFTER DELETE ON cpe_entry BEGIN
                INSERT INTO cpe_search_fts(cpe_search_fts, rowid, cpe_uri, title, version)
                VALUES ('delete', old.id, old.cpe_uri, old.title, old.version);
            END
        """)
        connection.exec_driver_sql("""
            CREATE TRIGGER IF NOT EXISTS cpe_search_update
            AFTER UPDATE OF id, cpe_uri, title, version ON cpe_entry BEGIN
                INSERT INTO cpe_search_fts(cpe_search_fts, rowid, cpe_uri, title, version)
                VALUES ('delete', old.id, old.cpe_uri, old.title, old.version);
                INSERT INTO cpe_search_fts(rowid, cpe_uri, title, version)
                VALUES (new.id, new.cpe_uri, new.title, new.version);
            END
        """)
        connection.exec_driver_sql(
            "INSERT INTO cpe_search_fts(cpe_search_fts) VALUES ('rebuild')"
        )


@event.listens_for(CPEEntry.__table__, "after_drop")
def _drop_cpe_search_index(_target, connection, **_kwargs):
    if connection.dialect.name == "sqlite":
        connection.exec_driver_sql("DROP TABLE IF EXISTS cpe_search_fts")
