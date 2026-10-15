import pytest

from app.models import CPEEntry, EntityRelationship, Product, Vendor, db


@pytest.mark.parametrize("entity_type", ["vendor", "product"])
def test_rename_chains_are_combined_from_either_end(client, app, entity_type):
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
            relationship_type="renamed-to",
        ))
    # Other products under renamed vendors belong only in the vendor combined view.
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
            assert "renamed-to" in combined

        response = client.get(f"/products/{products[index].uuid}")
        assert response.status_code == 200
        combined = response.get_data(as_text=True).split(
            "<h2>Combined product view</h2>", 1
        )[1].split("<h2>PURL mappings</h2>", 1)[0]
        assert "renamed-to" in combined
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
