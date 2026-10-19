import pytest
from sqlalchemy import event

from app.models import CPEEntry, Product, Vendor, db


def test_products_api_lists_paginated_detail_records(client):
    first = client.get("/api/products?per_page=2").get_json()
    assert first["page"] == 1
    assert first["per_page"] == 2
    assert first["total"] == 3
    assert first["total_pages"] == 2
    assert [item["name"] for item in first["items"]] == ["http_server", "office"]
    for item in first["items"]:
        assert item == client.get(f"/api/products/{item['uuid']}").get_json()
        assert item["vendor_uuid"]
        assert item["cpe_count"] == 1

    second = client.get("/api/products?per_page=2&page=2").get_json()
    assert second["page"] == 2
    assert [item["name"] for item in second["items"]] == ["windows_11"]
    assert client.get("/api/products?page=99").get_json()["items"] == []


@pytest.mark.parametrize("query", ["  INdOWs  ", "Windows 11"])
def test_products_api_searches_name_and_title(client, query):
    response = client.get("/api/products", query_string={"q": query})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["total"] == 1
    assert payload["items"][0]["name"] == "windows_11"


@pytest.mark.parametrize(
    ("params", "page", "per_page"),
    [
        ({}, 1, 25),
        ({"page": "invalid", "per_page": "invalid"}, 1, 25),
        ({"page": -2, "per_page": -2}, 1, 1),
        ({"page": 0, "per_page": 0}, 1, 25),
        ({"per_page": 1000}, 1, 100),
    ],
)
def test_products_api_pagination_matches_vendors(client, params, page, per_page):
    response = client.get("/api/products", query_string=params)
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["page"] == page
    assert payload["per_page"] == per_page
    assert len(payload["items"]) == min(per_page, 3)


def test_products_api_empty_search(client):
    response = client.get("/api/products?q=does-not-exist")
    assert response.status_code == 200
    assert response.get_json() == {
        "items": [], "page": 1, "per_page": 25, "total": 0, "total_pages": 1
    }


def test_products_api_keeps_same_name_products_from_different_vendors(client, app):
    with app.app_context():
        vendor = Vendor.query.filter_by(name="apache").one()
        product = Product(vendor_id=vendor.id, name="office")
        db.session.add(product)
        db.session.commit()
        duplicate_uuid = product.uuid

    first = client.get("/api/products?q=office&per_page=1").get_json()
    second = client.get("/api/products?q=office&per_page=1&page=2").get_json()
    assert first["total"] == second["total"] == 2
    assert first["items"][0]["uuid"] != second["items"][0]["uuid"]
    assert first["items"][0]["vendor_uuid"] != second["items"][0]["vendor_uuid"]
    assert second["items"][0]["uuid"] == duplicate_uuid
    assert second["items"][0]["cpe_count"] == 0


def test_products_page_navigation_details_vendor_and_export_links(client, app):
    home = client.get("/")
    assert b'href="/products"' in home.data
    assert b"Browse products" in home.data

    response = client.get("/products")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "<h1>Browse products</h1>" in html
    assert html.index(">Apache HTTP Server</a>") < html.index(">Microsoft Office</a>")
    assert html.index(">Microsoft Office</a>") < html.index(">Windows 11</a>")
    with app.app_context():
        for product in Product.query.all():
            assert f'href="/products/{product.uuid}"' in html
            assert f'href="/vendors/{product.vendor.uuid}"' in html
            assert f'data-export-url="/api/products/{product.uuid}"' in html
            assert f'data-export-filename="product-{product.uuid}.json"' in html


def test_products_page_search_and_empty_state(client):
    response = client.get("/products?q=  WINDOWS 11  ")
    assert response.status_code == 200
    assert b'value="WINDOWS 11"' in response.data
    assert b">Windows 11</a>" in response.data
    assert b">Microsoft Office</a>" not in response.data
    assert b"No products found" in client.get("/products?q=missing").data


def test_products_page_pagination_preserves_search_and_sort(client, app):
    with app.app_context():
        vendor = Vendor.query.first()
        db.session.add_all(
            Product(vendor_id=vendor.id, name=f"extra_product_{index:02d}")
            for index in range(30)
        )
        db.session.commit()

    response = client.get("/products?q=extra_product&sort=cpes")
    assert response.status_code == 200
    assert response.data.count(b'href="/products?page=2&amp;q=extra_product&amp;sort=cpes"') == 2
    assert b'name="sort" value="cpes"' in response.data
    assert b">extra_product_00</a>" in response.data
    assert b">extra_product_25</a>" not in response.data

    second = client.get("/products?q=extra_product&sort=cpes&page=2")
    assert second.status_code == 200
    assert second.data.count(b'href="/products?page=1&amp;q=extra_product&amp;sort=cpes"') == 2
    assert b">extra_product_25</a>" in second.data
    assert b">extra_product_00</a>" not in second.data
    assert b"Page 2 of 2" in client.get("/products?q=extra_product&page=999").data


def test_products_page_sorts_by_cpe_count_including_zero(client, app):
    with app.app_context():
        vendor = Vendor.query.first()
        db.session.add(Product(vendor_id=vendor.id, name="aaa_empty"))
        windows = Product.query.filter_by(name="windows_11").one()
        db.session.add(
            CPEEntry(
                vendor_id=windows.vendor_id,
                product_id=windows.id,
                cpe_uri="cpe:2.3:o:microsoft:windows_11:24h2:*:*:*:*:*:*:*",
                part="o",
                version="24h2",
            )
        )
        db.session.commit()

    response = client.get("/products?sort=cpes")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert html.index(">windows_11</code>") < html.index(">http_server</code>")
    assert html.index(">http_server</code>") < html.index(">office</code>")
    assert html.index(">office</code>") < html.index(">aaa_empty</code>")
    assert html.count("1 CPE entry</span>") == 2
    assert "2 CPE entries</span>" in html
    assert "0 CPE entries</span>" in html


@pytest.mark.parametrize("page", ["0", "-1", "invalid"])
def test_products_page_handles_invalid_page_and_sort(client, page):
    response = client.get(f"/products?page={page}&sort=invalid")
    assert response.status_code == 200
    assert b"Page 1 of 1" in response.data
    assert b'name="sort" value="name"' in response.data


@pytest.mark.parametrize("path", ["/products", "/api/products"])
def test_product_name_listing_uses_existing_index(client, path):
    statements = []

    def capture_sql(conn, cursor, statement, parameters, context, executemany):
        if "FROM product ORDER BY product.name ASC, product.id ASC" in statement:
            statements.append((statement, parameters))

    event.listen(db.engine, "before_cursor_execute", capture_sql)
    try:
        response = client.get(path)
    finally:
        event.remove(db.engine, "before_cursor_execute", capture_sql)

    assert response.status_code == 200
    assert len(statements) == 1
    statement, parameters = statements[0]
    plan = db.session.connection().exec_driver_sql(
        "EXPLAIN QUERY PLAN " + statement, parameters
    ).all()
    details = " ".join(row[3] for row in plan)
    assert "USING INDEX ix_product_name" in details
    assert "TEMP B-TREE" not in details


def test_product_cpe_sort_uses_index_and_counts_products_without_cpe_join(client):
    statements = []

    def capture_sql(conn, cursor, statement, parameters, context, executemany):
        statements.append((statement, parameters))

    event.listen(db.engine, "before_cursor_execute", capture_sql)
    try:
        response = client.get("/products?q=windows&sort=cpes")
    finally:
        event.remove(db.engine, "before_cursor_execute", capture_sql)

    assert response.status_code == 200
    counts = [sql.lower() for sql, _ in statements if "count(*)" in sql.lower()]
    assert len(counts) == 1
    assert "from product" in counts[0]
    assert "cpe_entry" not in counts[0]
    assert "order by" not in counts[0]
    statement, parameters = next(
        (sql, params) for sql, params in statements if "LEFT OUTER JOIN cpe_entry" in sql
    )
    plan = db.session.connection().exec_driver_sql(
        "EXPLAIN QUERY PLAN " + statement, parameters
    ).all()
    assert any(
        "SEARCH cpe_entry USING COVERING INDEX ix_cpe_entry_product_id" in row[3]
        for row in plan
    )
