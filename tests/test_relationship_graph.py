import pytest

from app.graphs import GRAPH_EDGE_LIMIT, GRAPH_NODE_LIMIT
from app.models import CPEEntry, EntityRelationship, Product, ProductAlias, ProductAliasMember, Proposal, Vendor, db


def _node_id(record):
    kind = "vendor" if isinstance(record, Vendor) else "product"
    return f"{kind}:{record.uuid}"


def _assert_integrity(payload):
    node_ids = {node["id"] for node in payload["nodes"]}
    assert len(node_ids) == len(payload["nodes"]) <= GRAPH_NODE_LIMIT
    assert len({edge["id"] for edge in payload["edges"]}) == len(payload["edges"]) <= GRAPH_EDGE_LIMIT
    assert payload["root"] in node_ids
    assert [node["id"] for node in payload["nodes"] if node["data"]["current"]] == [payload["root"]]
    for edge in payload["edges"]:
        assert edge["from"] in node_ids
        assert edge["to"] in node_ids


def test_graph_preserves_relationship_direction_and_transitive_combined_members(client, app):
    root = Product.query.order_by(Product.id).first()
    original_vendor = root.vendor
    # The intermediate vendor has no same-token product; it still explains the path.
    intermediate = Vendor(name="graph_intermediate")
    final_vendor = Vendor(name="graph_final")
    other_vendor = Vendor(name="graph_other")
    disconnected = Vendor(name="graph_disconnected")
    db.session.add_all([intermediate, final_vendor, other_vendor, disconnected])
    db.session.flush()
    same_token = Product(vendor=final_vendor, name=root.name, title=root.title)
    equivalent = Product(vendor=other_vendor, name="graph_equivalent")
    db.session.add_all([same_token, equivalent])
    db.session.flush()
    relationships = [
        EntityRelationship(source_vendor=original_vendor, target_vendor=intermediate, relationship_type="synonym-of"),
        EntityRelationship(source_vendor=final_vendor, target_vendor=intermediate, relationship_type="canonical-of"),
        EntityRelationship(source_product=same_token, target_product=equivalent, relationship_type="equivalent-to"),
        EntityRelationship(source_product=equivalent, target_vendor=original_vendor, relationship_type="derived-from"),
    ]
    related_cpe = CPEEntry(vendor=final_vendor, product=same_token, cpe_uri="cpe:2.3:a:graph_final:example:1:*:*:*:*:*:*:*", part="a", version="1")
    db.session.add_all(relationships + [related_cpe])
    db.session.add(Proposal(proposal_type="new_record_relationship", vendor=original_vendor, target_vendor_id=disconnected.id, proposed_relationship_type="synonym-of", status="pending"))
    db.session.commit()

    response = client.get(f"/products/{root.uuid}/graph")
    assert response.status_code == 200
    payload = response.get_json()
    _assert_integrity(payload)
    assert payload["truncated"] is False
    nodes = {node["id"]: node["data"] for node in payload["nodes"]}
    assert nodes[_node_id(same_token)]["combined"] is True
    assert nodes[_node_id(equivalent)]["combined"] is True
    assert _node_id(intermediate) in nodes
    assert _node_id(disconnected) not in nodes
    assert nodes[_node_id(root)]["label"] == nodes[_node_id(same_token)]["label"]
    assert f"cpe:{related_cpe.id}" in nodes
    edges = {edge["id"]: edge for edge in payload["edges"]}
    for relationship in relationships:
        edge = edges[f"relationship:{relationship.id}"]
        assert edge["from"] == _node_id(relationship.source_vendor or relationship.source_product)
        assert edge["to"] == _node_id(relationship.target_vendor or relationship.target_product)
        assert edge["data"]["label"] == relationship.relationship_type
    assert edges[f"product-cpe:{related_cpe.id}"]["from"] == _node_id(same_token)
    assert edges[f"product-cpe:{related_cpe.id}"]["data"]["kind"] == "contains"
    assert nodes[_node_id(root)]["url"] == f"/products/{root.uuid}"

    vendor_payload = client.get(f"/vendors/{original_vendor.uuid}/graph").get_json()
    _assert_integrity(vendor_payload)
    assert _node_id(same_token) in {node["id"] for node in vendor_payload["nodes"]}
    assert not any(node["data"]["kind"] == "cpe" for node in vendor_payload["nodes"])


def test_graph_includes_non_combining_incoming_relationships(client, app):
    root = Product.query.first()
    neighbor = Product(vendor=root.vendor, name="graph_neighbor")
    db.session.add(neighbor)
    db.session.flush()
    relationship = EntityRelationship(source_product=neighbor, target_product=root, relationship_type="superseded-by")
    db.session.add(relationship)
    db.session.commit()
    payload = client.get(f"/products/{root.uuid}/graph").get_json()
    _assert_integrity(payload)
    node = next(node for node in payload["nodes"] if node["id"] == _node_id(neighbor))
    assert node["data"]["combined"] is False
    assert any(edge["from"] == _node_id(neighbor) and edge["to"] == _node_id(root) for edge in payload["edges"])


@pytest.mark.parametrize("entity_type", ["vendors", "products"])
def test_graph_panel_is_additional_and_missing_entities_return_404(client, app, entity_type):
    record = (Vendor if entity_type == "vendors" else Product).query.first()
    html = client.get(f"/{entity_type}/{record.uuid}").get_data(as_text=True)
    assert "Relationship graph" in html
    assert "Approved relationships" in html
    assert "Combined product" in html
    assert f'data-graph-url="/{entity_type}/{record.uuid}/graph"' in html
    assert "<noscript>" in html
    assert client.get(f"/{entity_type}/missing/graph").status_code == 404
    _assert_integrity(client.get(f"/{entity_type}/{record.uuid}/graph").get_json())


def test_product_graph_is_bounded_and_keeps_current_product(client, app):
    root = Product.query.first()
    for index in range(GRAPH_NODE_LIMIT + 20):
        db.session.add(CPEEntry(vendor=root.vendor, product=root, cpe_uri=f"cpe:2.3:a:graph:bulk:{index}:*:*:*:*:*:*:*", part="a", version=str(index)))
    db.session.commit()
    payload = client.get(f"/products/{root.uuid}/graph").get_json()
    _assert_integrity(payload)
    assert payload["truncated"] is True
    assert len(payload["nodes"]) == GRAPH_NODE_LIMIT
    assert payload == client.get(f"/products/{root.uuid}/graph").get_json()
    assert payload["limits"] == {"nodes": GRAPH_NODE_LIMIT, "edges": GRAPH_EDGE_LIMIT}


def test_vendor_graph_bounds_products_and_relationship_edges(client, app):
    root = Vendor.query.first()
    for index in range(GRAPH_NODE_LIMIT + 20):
        db.session.add(Product(vendor=root, name=f"graph_bulk_{index:03d}"))
    db.session.commit()
    payload = client.get(f"/vendors/{root.uuid}/graph").get_json()
    _assert_integrity(payload)
    assert payload["truncated"] is True
    neighbor = Vendor(name="graph_edge_neighbor")
    db.session.add(neighbor)
    db.session.flush()
    for _ in range(GRAPH_EDGE_LIMIT + 20):
        db.session.add(EntityRelationship(source_vendor=root, target_vendor=neighbor, relationship_type="derived-from"))
    db.session.commit()
    payload = client.get(f"/vendors/{root.uuid}/graph").get_json()
    _assert_integrity(payload)
    assert payload["truncated"] is True
    assert len(payload["edges"]) == GRAPH_EDGE_LIMIT


def test_contributed_labels_are_returned_as_data_and_html_is_escaped(client, app):
    root = Product.query.first()
    root.title = '</script><img src=x onerror="window.graphXss=true">'
    db.session.commit()
    payload = client.get(f"/products/{root.uuid}/graph").get_json()
    current = next(node for node in payload["nodes"] if node["data"]["current"])
    assert current["data"]["label"] == root.title
    html = client.get(f"/products/{root.uuid}").get_data(as_text=True)
    assert root.title not in html
    assert "&lt;/script&gt;&lt;img" in html


def _create_alias(products, name="Graph alias"):
    alias = ProductAlias(name=name, description="An approved product group")
    db.session.add(alias)
    for product in products:
        alias.members.append(ProductAliasMember(vendor=product.vendor, product=product))
    db.session.commit()
    return alias


def test_alias_graph_links_members_owners_cpes_and_approved_relationships(client, app):
    products = Product.query.order_by(Product.id).limit(2).all()
    alias = _create_alias(products)
    neighbor = Product(vendor=products[0].vendor, name="alias_graph_neighbor")
    relationship = EntityRelationship(
        source_product=neighbor, target_product=products[0], relationship_type="derived-from",
    )
    db.session.add(relationship)
    db.session.add(Proposal(
        proposal_type="new_product_alias", status="pending",
        proposed_alias_name="Pending graph alias",
        proposed_alias_members=[{"vendor_id": neighbor.vendor_id, "product_id": neighbor.id}],
    ))
    db.session.commit()

    response = client.get(f"/aliases/{alias.uuid}/graph")
    assert response.status_code == 200
    payload = response.get_json()
    _assert_integrity(payload)
    assert payload["truncated"] is False
    assert payload["root"] == f"alias:{alias.uuid}"
    nodes = {node["id"]: node["data"] for node in payload["nodes"]}
    assert nodes[payload["root"]]["url"] == f"/aliases/{alias.uuid}"
    assert nodes[payload["root"]]["kind"] == "alias"
    assert len([node for node in nodes.values() if node["kind"] == "alias"]) == 1
    edges = {edge["id"]: edge for edge in payload["edges"]}
    for product in products:
        member_edge = edges[f"alias-product:{alias.uuid}:{product.uuid}"]
        assert member_edge["from"] == payload["root"]
        assert member_edge["to"] == _node_id(product)
        assert member_edge["data"]["kind"] == "membership"
        assert nodes[_node_id(product)]["url"] == f"/products/{product.uuid}"
        assert edges[f"vendor-product:{product.uuid}"]["from"] == _node_id(product.vendor)
        for cpe in product.cpes:
            assert edges[f"product-cpe:{cpe.id}"]["to"] == f"cpe:{cpe.id}"
    assert not any(edge["from"] == payload["root"] and edge["to"] == _node_id(neighbor) for edge in payload["edges"])
    assert edges[f"relationship:{relationship.id}"]["from"] == _node_id(neighbor)
    assert edges[f"relationship:{relationship.id}"]["to"] == _node_id(products[0])

    html = client.get(f"/aliases/{alias.uuid}").get_data(as_text=True)
    assert f'data-graph-url="/aliases/{alias.uuid}/graph"' in html
    assert "Relationship graph" in html
    assert "graph-alias-key" in html
    assert "Vendor/product tuples" in html
    assert "<noscript>" in html


def test_empty_alias_graph_and_missing_alias(client, app):
    alias = _create_alias([])
    payload = client.get(f"/aliases/{alias.uuid}/graph").get_json()
    _assert_integrity(payload)
    assert len(payload["nodes"]) == 1
    assert payload["edges"] == []
    assert payload["truncated"] is False
    assert client.get("/aliases/missing/graph").status_code == 404


@pytest.mark.parametrize("overflow", ["members", "cpes", "relationships"])
def test_alias_graph_is_bounded_and_preserves_membership(client, app, overflow):
    product = Product.query.first()
    alias = _create_alias([product])
    if overflow == "members":
        for index in range(GRAPH_NODE_LIMIT + 20):
            member_product = Product(vendor=product.vendor, name=f"alias_bulk_{index:03d}")
            alias.members.append(ProductAliasMember(vendor=product.vendor, product=member_product))
    elif overflow == "cpes":
        for index in range(GRAPH_NODE_LIMIT + 20):
            db.session.add(CPEEntry(
                vendor=product.vendor, product=product,
                cpe_uri=f"cpe:2.3:a:alias:bulk:{index}:*:*:*:*:*:*:*", part="a", version=str(index),
            ))
    else:
        for _ in range(GRAPH_EDGE_LIMIT + 20):
            db.session.add(EntityRelationship(
                source_product=product, target_vendor=product.vendor, relationship_type="derived-from",
            ))
    db.session.commit()
    payload = client.get(f"/aliases/{alias.uuid}/graph").get_json()
    _assert_integrity(payload)
    assert payload["truncated"] is True
    assert payload == client.get(f"/aliases/{alias.uuid}/graph").get_json()
    assert any(edge["from"] == payload["root"] and edge["to"] == _node_id(product) for edge in payload["edges"])
    assert any(edge["from"] == _node_id(product.vendor) and edge["to"] == _node_id(product) for edge in payload["edges"])


def test_alias_graph_contributed_labels_are_data_and_html_is_escaped(client, app):
    alias = _create_alias([], name='</script><img src=x onerror="window.graphXss=true">')
    payload = client.get(f"/aliases/{alias.uuid}/graph").get_json()
    assert payload["nodes"][0]["data"]["label"] == alias.name
    html = client.get(f"/aliases/{alias.uuid}").get_data(as_text=True)
    assert alias.name not in html
    assert "&lt;/script&gt;&lt;img" in html
