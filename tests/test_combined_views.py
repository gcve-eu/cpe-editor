import pytest

from app.models import CPEEntry, EntityRelationship, Product, Vendor, db
from app.views import (
    _collect_related_products_for_combined_view,
    _collect_related_vendors_for_combined_view,
)


@pytest.mark.parametrize("entity_type", ["vendor", "product"])
@pytest.mark.parametrize("relationship_type", ["renamed-to", "vendor-merge-into"])
def test_identity_chains_are_combined_from_either_end(
    client, app, entity_type, relationship_type
):
    vendors = [Vendor(name=f"rename_vendor_{index}") for index in range(3)]
    db.session.add_all(vendors)
    db.session.flush()
    products = [
        Product(
            vendor=vendor,
            name="same_token" if entity_type == "vendor" else f"rename_product_{index}",
        )
        for index, vendor in enumerate(vendors)
    ]
    db.session.add_all(products)
    db.session.flush()
    cpes = [
        CPEEntry(
            vendor=product.vendor,
            product=product,
            cpe_uri=f"cpe:2.3:a:{product.vendor.name}:{product.name}:1:*:*:*:*:*:*:*",
            part="a",
            version="1",
        )
        for product in products
    ]
    records = vendors if entity_type == "vendor" else products
    for source, target in zip(records, records[1:]):
        db.session.add(EntityRelationship(
            **{f"source_{entity_type}": source, f"target_{entity_type}": target},
            relationship_type=relationship_type,
        ))
    # Other products under related vendors belong only in the vendor combined view.
    other_product = Product(vendor=vendors[1], name="unrelated_token")
    db.session.add_all(cpes + [other_product])
    db.session.commit()

    for index in (0, 2):
        if entity_type == "vendor":
            response = client.get(f"/vendors/{vendors[index].uuid}")
            assert response.status_code == 200
            combined = response.get_data(as_text=True).split(
                "<h2>Combined products view</h2>", 1
            )[1]
            for product in [*products, other_product]:
                assert product.name in combined
                if product.vendor_id != vendors[index].id:
                    assert f'href="/products/{product.uuid}"' in combined
            assert relationship_type in combined

        response = client.get(f"/products/{products[index].uuid}")
        assert response.status_code == 200
        combined = response.get_data(as_text=True).split(
            "<h2>Combined product view</h2>", 1
        )[1].split("<h2>PURL mappings</h2>", 1)[0]
        assert relationship_type in combined
        for cpe in cpes:
            assert cpe.cpe_uri in combined
        assert other_product.name not in combined

        graph = client.get(f"/products/{products[index].uuid}/graph")
        assert graph.status_code == 200
        combined_product_ids = {
            node["id"] for node in graph.get_json()["nodes"]
            if node["data"]["kind"] == "product" and node["data"]["combined"]
        }
        assert combined_product_ids == {f"product:{product.uuid}" for product in products}


@pytest.mark.parametrize("entity_type", ["vendor", "product"])
@pytest.mark.parametrize("relationship_type", ["superseded-by", "derived-from"])
def test_replacement_and_provenance_links_do_not_combine_records(
    client, app, entity_type, relationship_type
):
    vendors = [Vendor(name=f"distinct_vendor_{index}") for index in range(2)]
    db.session.add_all(vendors)
    db.session.flush()
    products = [
        Product(vendor=vendor, name="same_token") for vendor in vendors
    ]
    db.session.add_all(products)
    db.session.flush()
    records = vendors if entity_type == "vendor" else products
    relationship = EntityRelationship(
        **{f"source_{entity_type}": records[0], f"target_{entity_type}": records[1]},
        relationship_type=relationship_type,
    )
    db.session.add(relationship)
    db.session.commit()

    for index in (0, 1):
        assert _collect_related_vendors_for_combined_view(vendors[index]) == [vendors[index]]
        assert _collect_related_products_for_combined_view(products[index]) == [products[index]]
        response = client.get(f"/{entity_type}s/{records[index].uuid}/graph")
        assert response.status_code == 200
        payload = response.get_json()
        neighbor = next(
            node for node in payload["nodes"]
            if node["id"] == f"{entity_type}:{records[1 - index].uuid}"
        )
        assert neighbor["data"]["combined"] is False
        assert any(
            edge["id"] == f"relationship:{relationship.id}"
            for edge in payload["edges"]
        )
