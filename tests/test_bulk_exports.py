from html import unescape
from types import SimpleNamespace

import pytest
from sqlalchemy import event

from app import cache
from app.models import (
    CPEEntry, CPEPurlMapping, EntityMetadata, EntityNote, EntityRelationship,
    Product, ProductAlias, ProductAliasMember, Vendor, db,
)


class ExpiringValkey:
    def __init__(self):
        self.now = 0
        self.values = {}
        self.ttls = {}

    def ping(self):
        return True

    def get(self, key):
        value, expires = self.values.get(key, (None, 0))
        return value if expires > self.now else None

    def setex(self, key, ttl, value):
        self.ttls[key] = ttl
        self.values[key] = (value, self.now + ttl)


@pytest.fixture(autouse=True)
def export_cache(app, monkeypatch):
    client = ExpiringValkey()
    module = SimpleNamespace(Valkey=SimpleNamespace(from_url=lambda *a, **kw: client))
    monkeypatch.setattr(cache.importlib, "import_module", lambda name: module)
    app.config.update(VALKEY_URL="redis://test:6379/0", EXPORT_CACHE_TTL_SECONDS=3600)
    return client


@pytest.mark.parametrize("entity,total", [("vendors", 2), ("products", 3), ("cpes", 3)])
def test_export_returns_all_public_records_and_matches_detail(client, entity, total):
    response = client.get(f"/api/{entity}/export?page=99&per_page=1")
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    assert response.headers["Content-Disposition"] == f'attachment; filename="{entity}-export.json"'
    payload = response.get_json()
    assert payload["entity"] == entity
    assert payload["total"] == len(payload["items"]) == total
    assert payload["filters"] == {}
    assert payload["generated_at"]
    for item in payload["items"]:
        identifier = item["id"] if entity == "cpes" else item["uuid"]
        assert item == client.get(f"/api/{entity}/{identifier}").get_json()
        assert "submitter_ip" not in item
        assert "proposals" not in item


def test_exports_are_not_limited_to_api_page_size(client):
    product = Product.query.first()
    db.session.add_all([
        CPEEntry(
            vendor_id=product.vendor_id, product_id=product.id,
            cpe_uri=f"cpe:2.3:a:test:bulk:{index}:*:*:*:*:*:*:*", part="a",
        )
        for index in range(505)
    ])
    db.session.commit()
    payload = client.get("/api/cpes/export?q=test:bulk&per_page=1").get_json()
    assert payload["total"] == len(payload["items"]) == 505
    assert len({item["id"] for item in payload["items"]}) == 505


def test_exports_preserve_curated_entity_data_without_lazy_queries(client):
    products = Product.query.order_by(Product.id).all()
    product = products[0]
    alias = ProductAlias(name="Export alias")
    alias.members = [
        ProductAliasMember(vendor_id=p.vendor_id, product_id=p.id)
        for p in products[:2]
    ]
    db.session.add(alias)
    for field, identifier in (("product_id", product.id), ("vendor_id", product.vendor_id)):
        db.session.add(EntityNote(**{field: identifier}, note_text="Export note"))
        db.session.add(EntityMetadata(**{field: identifier}, metadata_key="gcve:description", metadata_value="Export metadata"))
    db.session.add_all([
        EntityRelationship(source_product_id=product.id, target_product_id=products[-1].id, relationship_type="equivalent-to"),
        EntityRelationship(source_vendor_id=product.vendor_id, target_product_id=products[-1].id, relationship_type="synonym-of"),
    ])
    db.session.commit()
    scopes = [("products", product.uuid), ("vendors", product.vendor.uuid)]
    db.session.remove()
    for entity, uuid in scopes:
        exported = client.get(f"/api/{entity}/export").get_json()
        item = next(item for item in exported["items"] if item["uuid"] == uuid)
        assert item["approved_notes"][0]["note_text"] == "Export note"
        assert item["approved_metadata"][0]["metadata_value"] == "Export metadata"
        assert item["approved_relationships"][0]["target"]["vendor_uuid"]
        if entity == "products":
            assert item["aliases"][0]["member_count"] == 2
        db.session.remove()
        assert item == client.get(f"/api/{entity}/{uuid}").get_json()
        db.session.remove()


@pytest.mark.parametrize("entity,query", [
    ("vendors", "q=MICRO"),
    ("products", "q=windows"),
    ("cpes", "vendor_q=micro&product_q=windows&part=o"),
    ("cpes", "q=apache"),
    ("cpes", "purl_q=pkg:generic/apache"),
    ("cpes", "q=no-such-entry"),
])
def test_exports_use_existing_listing_filter_semantics(client, entity, query):
    exported = client.get(f"/api/{entity}/export?{query}").get_json()
    listed = client.get(f"/api/{entity}?{query}").get_json()
    assert exported["total"] == listed["total"]
    assert {item["id"] for item in exported["items"]} == {
        item["id"] for item in listed["items"]
    }


def test_vendor_and_product_scopes_and_duplicate_purl_matches(client):
    product = Product.query.filter_by(name="http_server").one()
    cpe = CPEEntry.query.filter_by(product_id=product.id).one()
    db.session.add(CPEPurlMapping(cpe_name_id=cpe.cpe_name_id, purl="pkg:generic/apache/other", source="test"))
    db.session.commit()
    for scope in (f"vendor_uuid={product.vendor.uuid}", f"product_uuid={product.uuid}"):
        payload = client.get(f"/api/cpes/export?{scope}&purl_q=pkg:generic/apache").get_json()
        assert payload["total"] == 1
        assert payload["items"][0]["id"] == cpe.id
        assert len(payload["items"][0]["purl_mappings"]) == 2
        assert payload["items"][0]["vulnerability_references"]
    payload = client.get(f"/api/products/export?vendor_uuid={product.vendor.uuid}").get_json()
    assert [item["uuid"] for item in payload["items"]] == [product.uuid]
    assert client.get("/api/cpes/export?vendor_uuid=00000000-0000-0000-0000-000000000000").get_json()["total"] == 0


@pytest.mark.parametrize("query", ["part=bad", "vendor_uuid=bad", "product_uuid=bad"])
def test_invalid_export_filters_return_400(client, query):
    assert client.get(f"/api/cpes/export?{query}").status_code == 400


@pytest.mark.parametrize("entity", ["vendors", "products", "cpes"])
def test_hourly_cache_reuses_snapshot_without_queries_and_expires(client, export_cache, entity):
    first = client.get(f"/api/{entity}/export?q=%20MICRO%20")
    assert first.headers["X-Export-Cache"] == "MISS"
    assert list(export_cache.ttls.values()) == [3600]

    def unexpected_query(*args):
        raise AssertionError("Warm exports must not query the database")

    event.listen(db.engine, "before_cursor_execute", unexpected_query)
    try:
        export_cache.now = 3599
        repeated = client.get(f"/api/{entity}/export?per_page=1&q=micro&page=2")
        assert repeated.headers["X-Export-Cache"] == "HIT"
        assert repeated.data == first.data
    finally:
        event.remove(db.engine, "before_cursor_execute", unexpected_query)

    export_cache.now = 3600
    refreshed = client.get(f"/api/{entity}/export?q=micro")
    assert refreshed.headers["X-Export-Cache"] == "MISS"
    assert refreshed.get_json()["generated_at"] != first.get_json()["generated_at"]


def test_cache_separates_entities_filters_and_scopes(client):
    product = Product.query.filter_by(name="http_server").one()
    paths = [
        "/api/vendors/export", "/api/products/export", "/api/cpes/export",
        "/api/cpes/export?part=a", "/api/cpes/export?part=o",
        f"/api/cpes/export?product_uuid={product.uuid}",
    ]
    for path in paths:
        assert client.get(path).headers["X-Export-Cache"] == "MISS"
    for path in paths:
        assert client.get(path).headers["X-Export-Cache"] == "HIT"


def test_export_cache_independent_of_statistics_ttl(app, client, export_cache):
    app.config["STATISTICS_CACHE_TTL_SECONDS"] = 0
    assert client.get("/api/vendors/export").headers["X-Export-Cache"] == "MISS"
    assert client.get("/api/vendors/export").headers["X-Export-Cache"] == "HIT"
    assert not cache.cache_set_json("statistics:disabled", {})
    assert cache.cache_get_json("statistics:disabled") is None


@pytest.mark.parametrize("failure", ["connect", "get", "setex", "disabled", "ttl"])
def test_export_stays_available_without_cache(app, client, monkeypatch, export_cache, failure):
    def unavailable(*args, **kwargs):
        raise ConnectionError("Valkey unavailable")

    if failure == "connect":
        monkeypatch.setattr(cache.importlib, "import_module", unavailable)
    elif failure == "disabled":
        app.config["VALKEY_URL"] = ""
    elif failure == "ttl":
        app.config["EXPORT_CACHE_TTL_SECONDS"] = 0
    else:
        monkeypatch.setattr(export_cache, failure, unavailable)
    response = client.get("/api/cpes/export")
    assert response.status_code == 200
    assert response.get_json()["total"] == 3
    if failure != "get":
        assert response.headers["X-Export-Cache"] == "BYPASS"


def test_ui_download_links_preserve_filters_and_scope(client):
    pages_and_links = [
        ("/vendors?q=micro&page=2", "/api/vendors/export?q=micro"),
        ("/products?q=windows", "/api/products/export?q=windows"),
        ("/?vendor_q=micro&product_q=windows&part=o", "/api/cpes/export?vendor_q=micro&product_q=windows&part=o"),
        ("/", "/api/cpes/export"),
    ]
    vendor = Vendor.query.filter_by(name="microsoft").one()
    product = Product.query.filter_by(name="windows_11").one()
    pages_and_links.extend([
        (f"/vendors/{vendor.uuid}", f"/api/products/export?vendor_uuid={vendor.uuid}"),
        (f"/vendors/{vendor.uuid}", f"/api/cpes/export?vendor_uuid={vendor.uuid}"),
        (f"/products/{product.uuid}", f"/api/cpes/export?product_uuid={product.uuid}"),
    ])
    for page, link in pages_and_links:
        # The fixture holds an app context across requests; emulate request teardown.
        db.session.remove()
        response = client.get(page)
        assert response.status_code == 200
        assert f'href="{link}"' in unescape(response.get_data(as_text=True))
        db.session.remove()
        assert client.get(link).status_code == 200
