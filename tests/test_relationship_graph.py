import pytest

from app.graphs import GRAPH_EDGE_LIMIT, GRAPH_NODE_LIMIT
from app.models import CPEEntry, EntityRelationship, Product, Proposal, Vendor, db


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
