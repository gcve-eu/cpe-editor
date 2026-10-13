"""Bounded, read-only graph data for the public entity detail pages."""

from flask import url_for
from sqlalchemy import case, or_
from sqlalchemy.orm import selectinload

from .models import CPEEntry, EntityRelationship, Product, Vendor


GRAPH_NODE_LIMIT = 200
GRAPH_EDGE_LIMIT = 400


def build_entity_graph(root, vendors, products, *, include_cpes=False):
    nodes = {}
    edges = {}
    records = {}
    truncated = False
    vendor_ids = {vendor.id for vendor in vendors}
    product_ids = {product.id for product in products}

    def add_node(record):
        nonlocal truncated
        if record is None:
            return None
        if isinstance(record, Vendor):
            kind, identity = "vendor", record.uuid
            label = record.title or record.name
            detail = record.name
            href = url_for("main.vendor_detail", vendor_uuid=record.uuid)
            combined = record.id in vendor_ids
        elif isinstance(record, Product):
            kind, identity = "product", record.uuid
            label = record.title or record.name
            detail = f"{record.vendor.title or record.vendor.name} / {record.name}"
            href = url_for("main.product_detail", product_uuid=record.uuid)
            combined = record.id in product_ids
        else:
            kind, identity = "cpe", record.id
            label = record.title or f"{record.product.name} · {record.part} · {record.version}"
            detail = record.cpe_uri
            href = url_for("main.cpe_detail", cpe_id=record.id)
            combined = record.product_id in product_ids
        node_id = f"{kind}:{identity}"
        if node_id not in nodes:
            if len(nodes) >= GRAPH_NODE_LIMIT:
                truncated = True
                return None
            nodes[node_id] = {
                "id": node_id,
                "data": {
                    "kind": kind,
                    "label": label,
                    "detail": detail,
                    "url": href,
                    "current": record is root,
                    "combined": combined,
                },
            }
            records[node_id] = record
        return node_id

    def add_edge(edge_id, source, target, label, kind, rationale=None):
        nonlocal truncated
        if not source or not target or edge_id in edges:
            return
        if len(edges) >= GRAPH_EDGE_LIMIT:
            truncated = True
            return
        edges[edge_id] = {
            "id": edge_id,
            "from": source,
            "to": target,
            "data": {"label": label, "kind": kind, "rationale": rationale},
        }

    root_id = add_node(root)
    root_filter = (
        or_(
            EntityRelationship.source_vendor_id == root.id,
            EntityRelationship.target_vendor_id == root.id,
        )
        if isinstance(root, Vendor)
        else or_(
            EntityRelationship.source_product_id == root.id,
            EntityRelationship.target_product_id == root.id,
        )
    )
    relationships = (
        EntityRelationship.query.filter(
            or_(
                EntityRelationship.source_vendor_id.in_(vendor_ids),
                EntityRelationship.target_vendor_id.in_(vendor_ids),
                EntityRelationship.source_product_id.in_(product_ids),
                EntityRelationship.target_product_id.in_(product_ids),
            )
        )
        .options(
            selectinload(EntityRelationship.source_vendor),
            selectinload(EntityRelationship.target_vendor),
            selectinload(EntityRelationship.source_product).selectinload(Product.vendor),
            selectinload(EntityRelationship.target_product).selectinload(Product.vendor),
        )
        .order_by(case((root_filter, 0), else_=1), EntityRelationship.id.asc())
        .limit(GRAPH_EDGE_LIMIT + 1)
        .all()
    )
    if len(relationships) > GRAPH_EDGE_LIMIT:
        truncated = True
    # Prioritize the current record's relationships before catalog containment.
    for relationship in relationships[:GRAPH_EDGE_LIMIT]:
        source = add_node(relationship.source_vendor or relationship.source_product)
        target = add_node(relationship.target_vendor or relationship.target_product)
        add_edge(
            f"relationship:{relationship.id}", source, target,
            relationship.relationship_type, "relationship", relationship.rationale,
        )

    for vendor in vendors:
        add_node(vendor)
    for product in products:
        add_node(product)
    # Include ownership for relationship neighbors as well as combined members.
    for node_id, record in list(records.items()):
        if isinstance(record, Product):
            owner_id = add_node(record.vendor)
            add_edge(f"vendor-product:{record.uuid}", owner_id, node_id, "has product", "contains")

    if include_cpes:
        # Only query CPEs for products that made it onto the canvas.
        visible_product_ids = [
            record.id for record in records.values()
            if isinstance(record, Product) and record.id in product_ids
        ]
        cpes = (
            CPEEntry.query.filter(CPEEntry.product_id.in_(visible_product_ids))
            .options(selectinload(CPEEntry.product).selectinload(Product.vendor))
            .order_by(
                case((CPEEntry.product_id == root.id, 0), else_=1),
                CPEEntry.cpe_uri.asc(), CPEEntry.id.asc(),
            )
            .limit(GRAPH_NODE_LIMIT + 1)
            .all()
        )
        if len(cpes) > GRAPH_NODE_LIMIT:
            truncated = True
        for cpe in cpes:
            cpe_id = add_node(cpe)
            add_edge(
                f"product-cpe:{cpe.id}", f"product:{cpe.product.uuid}", cpe_id,
                "has CPE", "contains",
            )

    return {
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "root": root_id,
        "truncated": truncated,
        "limits": {"nodes": GRAPH_NODE_LIMIT, "edges": GRAPH_EDGE_LIMIT},
    }
