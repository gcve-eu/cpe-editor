import pytest
from sqlalchemy import event, func, or_, text
from sqlalchemy.exc import OperationalError

from app.models import CPEEntry, Product, Vendor, db
from app.search import rebuild_cpe_search_index


def _enable_index():
    try:
        rebuild_cpe_search_index()
    except OperationalError as exc:
        if "no such module" in str(exc) or "no such tokenizer" in str(exc):
            pytest.skip("SQLite FTS5 trigram tokenizer unavailable")
        raise


@pytest.mark.parametrize("indexed", [False, True])
def test_partial_search_matches_like_semantics_and_all_fields(client, indexed):
    cpe = CPEEntry.query.filter_by(version="2021").one()
    cpe.title = 'Quoted "needle" café Straße 東京サーバー'
    cpe.product.title = "Product display marker"
    cpe.vendor.title = "Vendor display marker"
    db.session.commit()
    if indexed:
        _enable_index()

    patterns = [
        "dows", "HTTP_SERVER", "2.4.5", "202", "display marker",
        "product display", "vendor display", '"needle"', "café", "Straße",
        "東京サーバー", "d_ws", "http%server", "%", "_", "o", "23",
        "no-matches", "a%", "dows\x00ignored", "cpe:2.3:o:micro",
    ]
    for value in patterns:
        pattern = f"%{value.lower()}%"
        expected = (
            CPEEntry.query.join(CPEEntry.vendor).join(CPEEntry.product)
            .filter(or_(*[
                func.lower(field).like(pattern) for field in (
                    CPEEntry.cpe_uri, CPEEntry.title, CPEEntry.version,
                    Vendor.name, Vendor.title, Product.name, Product.title,
                )
            ]))
            .order_by(Vendor.name, Product.name, CPEEntry.cpe_uri)
            .all()
        )
        response = client.get("/api/cpes", query_string={"q": value, "per_page": 100})
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["total"] == len(expected), value
        assert [item["id"] for item in payload["items"]] == [
            row.id for row in expected
        ], value


def test_search_only_matches_a_cpes_own_product(client):
    office = Product.query.filter_by(name="office").one()
    office.title = "Exclusive product phrase"
    db.session.commit()

    payload = client.get("/api/cpes?q=Exclusive%20product%20phrase").get_json()
    assert payload["total"] == 1
    assert all(item["product_id"] == office.id for item in payload["items"])

    # Multiple products belonging to one vendor must not duplicate/shorten pages.
    first = client.get("/api/cpes?q=micro&per_page=1").get_json()
    second = client.get("/api/cpes?q=micro&per_page=1&page=2").get_json()
    assert first["total"] == second["total"] == 2
    assert len(first["items"]) == len(second["items"]) == 1
    assert first["items"][0]["id"] != second["items"][0]["id"]
    assert first["items"][0]["cpe_uri"] < second["items"][0]["cpe_uri"]
    assert client.get("/api/cpes?q=micro&per_page=1&page=3").get_json()["items"] == []


@pytest.mark.parametrize("indexed", [False, True])
def test_partial_search_combines_with_existing_filters(client, indexed):
    if indexed:
        _enable_index()
    args = {
        "q": "2.4", "vendor_q": "apa", "product_q": "http", "part": "a",
        "purl_q": "pkg:generic/apache", "per_page": 1,
    }
    payload = client.get("/api/cpes", query_string=args).get_json()
    assert payload["total"] == payload["total_pages"] == 1
    assert "apache:http_server" in payload["items"][0]["cpe_uri"]
    args["part"] = "o"
    assert client.get("/api/cpes", query_string=args).get_json()["total"] == 0
    args["vendor_q"] = "nonexistent"
    assert client.get("/api/cpes", query_string=args).get_json()["total"] == 0


def test_trigram_index_tracks_bulk_writes_and_rollback(client):
    _enable_index()
    cpe = CPEEntry.query.filter_by(version="2021").one()
    cpe_id = cpe.id
    cpe.title = "Before rollback token"
    db.session.flush()
    db.session.rollback()
    assert client.get("/api/cpes?q=rollback").get_json()["total"] == 0

    db.session.execute(
        text("UPDATE cpe_entry SET title = 'New search token' WHERE id = :id"),
        {"id": cpe_id},
    )
    db.session.commit()
    assert client.get("/api/cpes?q=search%20token").get_json()["total"] == 1
    db.session.execute(
        text(
            "UPDATE cpe_entry SET title = NULL, version = 'versiontoken', "
            "cpe_uri = cpe_uri || :suffix WHERE id = :id"
        ),
        {"id": cpe_id, "suffix": ":uritoken"},
    )
    db.session.commit()
    assert client.get("/api/cpes?q=search%20token").get_json()["total"] == 0
    assert client.get("/api/cpes?q=versiontoken").get_json()["total"] == 1
    assert client.get("/api/cpes?q=uritoken").get_json()["total"] == 1

    product = Product.query.filter_by(name="office").one()
    added = CPEEntry(
        vendor_id=product.vendor_id, product_id=product.id,
        cpe_uri="cpe:2.3:a:microsoft:office:inserttoken:*:*:*:*:*:*:*", part="a",
    )
    db.session.add(added)
    db.session.commit()
    assert client.get("/api/cpes?q=inserttoken").get_json()["total"] == 1
    CPEEntry.query.filter_by(id=added.id).delete()
    db.session.commit()
    assert client.get("/api/cpes?q=inserttoken").get_json()["total"] == 0
    db.session.execute(text(
        "INSERT INTO cpe_search_fts(cpe_search_fts, rank) VALUES ('integrity-check', 1)"
    ))
    db.session.commit()


def test_search_uses_trigram_index_and_count_avoids_joins(client):
    _enable_index()
    statements = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append((statement, parameters))

    event.listen(db.engine, "before_cursor_execute", capture)
    try:
        response = client.get("/api/cpes?q=dows")
    finally:
        event.remove(db.engine, "before_cursor_execute", capture)
    assert response.status_code == 200
    sql, parameters = next(
        (sql, params) for sql, params in statements if "count(" in sql.lower()
    )
    assert " join " not in sql.lower()
    assert "distinct" not in sql.lower()
    plan = db.session.connection().exec_driver_sql(
        "EXPLAIN QUERY PLAN " + sql, parameters
    ).all()
    assert any("VIRTUAL TABLE INDEX" in row[3] for row in plan)


def test_search_index_rebuild_and_database_reset(app, client):
    _enable_index()
    result = app.test_cli_runner().invoke(args=["rebuild-cpe-search-index"])
    assert result.exit_code == 0, result.output
    assert client.get("/api/cpes?q=dows").get_json()["total"] == 1
    db.drop_all()
    db.create_all()
    assert db.session.execute(text(
        "SELECT name FROM sqlite_master WHERE name = 'cpe_search_fts'"
    )).scalar() is None
    assert client.get("/api/cpes?q=dows").get_json()["total"] == 0
