import pytest
from uuid import uuid4

from app.models import (
    CPEEntry, CPEPurlMapping, CPEVulnerabilityReference, EntityRelationship,
    Product, Proposal, Vendor, db,
)


@pytest.fixture
def catalog(app):
    root = Vendor.query.filter_by(name="microsoft").one()
    unrelated = Vendor.query.filter_by(name="apache").one()
    unrelated_product = unrelated.products[0]
    neighbors = [Vendor(name=f"catalog_neighbor_{index}") for index in range(2)]
    db.session.add_all(neighbors)
    db.session.flush()
    products = [
        Product(vendor=neighbors[0], name="windows_11"),
        Product(vendor=neighbors[1], name="combined_only"),
        Product(vendor=neighbors[1], name="empty_product"),
    ]
    db.session.add_all(products)
    db.session.flush()
    cpes = [
        CPEEntry(
            vendor=product.vendor, product=product, part="a", deprecated=True,
            cpe_name_id=str(uuid4()),
            cpe_uri=f"cpe:2.3:a:{product.vendor.name}:{product.name}:1:*:*:*:*:*:*:*",
        )
        for product in products[:2]
    ]
    db.session.add_all(cpes)
    db.session.flush()
    db.session.add_all([
        CPEPurlMapping(cpe_name_id=cpes[1].cpe_name_id, purl=f"pkg:generic/catalog/{suffix}", source="test")
        for suffix in ("one", "two")
    ] + [
        CPEVulnerabilityReference(cpe_entry=cpes[1], vulnerability_source="CVE",
                                  vulnerability_id="CVE-2026-1234", cpe_applicability="vulnerable"),
        EntityRelationship(source_vendor=root, target_vendor=unrelated, relationship_type="derived-from"),
        EntityRelationship(source_vendor=unrelated, target_vendor=neighbors[0], relationship_type="related-to"),
        EntityRelationship(source_product=products[0], target_product=unrelated_product, relationship_type="equivalent-to"),
        Proposal(proposal_type="new_record_relationship", vendor=root,
                 target_vendor_id=unrelated.id, proposed_relationship_type="synonym-of", status="pending"),
    ])
    db.session.commit()
    return {
        "vendors": [root.id, *[vendor.id for vendor in neighbors]],
        "uuids": [root.uuid, *[vendor.uuid for vendor in neighbors]],
        "product_uuid": products[1].uuid,
        "unrelated_product_uuid": unrelated_product.uuid,
        "cpe_id": cpes[1].id,
    }


def get_json(client, path, **params):
    # The app fixture spans requests; emulate production session teardown.
    db.session.remove()
    response = client.get(path, query_string=params)
    assert response.status_code == 200
    return response.get_json()


@pytest.mark.parametrize("entity", ["products", "cpes"])
@pytest.mark.parametrize("relationship", [
    "synonym-of", "canonical-of", "equivalent-to", "renamed-to",
    "vendor-merge-into", "superseded-by",
])
def test_combined_lists_match_exports_with_pagination(client, catalog, entity, relationship):
    root, middle, last = catalog["vendors"]
    db.session.add_all([
        EntityRelationship(source_vendor_id=root, target_vendor_id=middle, relationship_type=relationship),
        EntityRelationship(source_vendor_id=last, target_vendor_id=middle, relationship_type=relationship),
        EntityRelationship(source_vendor_id=middle, target_vendor_id=root, relationship_type=relationship),
    ])
    db.session.commit()
    model = Product if entity == "products" else CPEEntry
    expected_ids = {record.id for record in model.query.filter(model.vendor_id.in_(catalog["vendors"]))}
    for vendor_uuid in (catalog["uuids"][0], catalog["uuids"][-1]):
        scope = {"vendor_uuid": vendor_uuid, "combined": "true"}
        exported = get_json(client, f"/api/{entity}/export", **scope)
        items = []
        for page in range(1, len(expected_ids) + 1):
            payload = get_json(client, f"/api/{entity}", **scope, page=page, per_page=1)
            assert payload["total"] == payload["total_pages"] == len(expected_ids)
            assert payload["page"] == page
            assert payload["per_page"] == 1
            assert len(payload["items"]) == 1
            items.extend(payload["items"])
        assert {item["id"] for item in items} == expected_ids
        assert len(items) == len(expected_ids)
        assert items == exported["items"]
        assert get_json(client, f"/api/{entity}", **scope, page=999)["items"] == []


@pytest.mark.parametrize("entity", ["products", "cpes"])
def test_exact_scopes_and_boolean_normalization(client, catalog, entity):
    model = Product if entity == "products" else CPEEntry
    root_id = catalog["vendors"][0]
    uuid = catalog["uuids"][0]
    expected_ids = {record.id for record in model.query.filter_by(vendor_id=root_id)}
    for combined in ("", "false", " FALSE ", "true"):
        # No combining relationship has been added, so even true stays exact.
        payload = get_json(client, f"/api/{entity}", vendor_uuid=f" {uuid.upper()} ", combined=combined)
        assert {item["id"] for item in payload["items"]} == expected_ids
    for combined in ("false", "true"):
        missing = get_json(client, f"/api/{entity}", vendor_uuid="00000000-0000-0000-0000-000000000000", combined=combined)
        assert missing == {"items": [], "page": 1, "per_page": 25, "total": 0, "total_pages": 1}


@pytest.mark.parametrize("entity", ["products", "cpes"])
def test_combined_list_search_filters_intersect_scope(client, catalog, entity):
    root, _, last = catalog["vendors"]
    db.session.add(EntityRelationship(source_vendor_id=root, target_vendor_id=last, relationship_type="synonym-of"))
    db.session.commit()
    scope = {"vendor_uuid": catalog["uuids"][0], "combined": " TRUE "}
    searched = get_json(client, f"/api/{entity}", **scope, q="COMBINED_ONLY")
    assert searched["total"] == 1
    assert get_json(client, f"/api/{entity}", **scope, q="apache")["total"] == 0
    if entity == "cpes":
        for filters in (
            {"product_uuid": catalog["product_uuid"]},
            {"part": "a", "vendor_q": "catalog_neighbor", "product_q": "combined", "purl_q": "pkg:generic/catalog/"},
        ):
            result = get_json(client, "/api/cpes", **scope, **filters)
            assert result["total"] == 1
            cpe = result["items"][0]
            assert cpe["id"] == catalog["cpe_id"]
            assert cpe["deprecated"] is True
            assert len(cpe["purl_mappings"]) == 2
            assert cpe["vulnerability_references"][0]["vulnerability_id"] == "CVE-2026-1234"
        assert get_json(client, "/api/cpes", **scope, product_uuid=catalog["unrelated_product_uuid"])["total"] == 0
        assert get_json(client, "/api/cpes", vendor_uuid=scope["vendor_uuid"], product_uuid=catalog["product_uuid"])["total"] == 0
        assert get_json(client, "/api/cpes", product_uuid=catalog["product_uuid"])["total"] == 1


@pytest.mark.parametrize("entity", ["products", "cpes"])
@pytest.mark.parametrize("params", [
    {"vendor_uuid": "bad"}, {"combined": "yes"}, {"combined": "true"},
    {"combined": "true", "vendor_uuid": " "},
])
def test_list_scope_validation(client, entity, params):
    assert client.get(f"/api/{entity}", query_string=params).status_code == 400


def test_cpe_product_scope_validation(client):
    assert client.get("/api/cpes?product_uuid=bad").status_code == 400
    assert get_json(client, "/api/cpes", product_uuid="00000000-0000-0000-0000-000000000000")["total"] == 0


def test_swagger_exposes_list_and_export_scopes(client):
    spec = client.get("/api/openapi.yaml").get_data(as_text=True)
    for path in ("/api/products", "/api/products/export", "/api/cpes", "/api/cpes/export"):
        operation = spec.split(f"  {path}:\n", 1)[1].split("\n  /api/", 1)[0]
        assert "#/components/parameters/Export_vendor_uuid" in operation
        assert "#/components/parameters/Export_combined" in operation
        assert "'400':" in operation
        if "/cpes" in path:
            assert "#/components/parameters/Export_product_uuid" in operation
    docs = client.get("/api/docs").get_data(as_text=True)
    assert "combined=true" in docs
    assert "SwaggerUIBundle" in docs
    assert 'url: "/api/openapi.yaml"' in docs
