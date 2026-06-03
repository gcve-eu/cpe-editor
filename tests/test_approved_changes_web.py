from datetime import datetime

from app.models import CPEEntry, Product, Proposal, Vendor, db
from app.views import apply_proposal


def test_new_vendor_product_approved_change_links_to_created_records(app, client):
    with app.app_context():
        proposal = Proposal(
            proposal_type="new_vendor_product",
            status="pending",
            proposed_vendor_name="example_vendor",
            proposed_vendor_title="Example Vendor",
            proposed_product_name="example_product",
            proposed_product_title="Example Product",
            proposed_part="a",
            proposed_version="1.0",
            proposed_update="*",
            proposed_edition="*",
            proposed_language="*",
            proposed_sw_edition="*",
            proposed_target_sw="*",
            proposed_target_hw="*",
            proposed_other="*",
            proposed_title="Example Product 1.0",
            proposed_cpe_uri="cpe:2.3:a:example_vendor:example_product:1.0:*:*:*:*:*:*:*",
            reviewed_at=datetime(2024, 2, 3, 4, 5, 6),
        )
        db.session.add(proposal)
        db.session.flush()
        apply_proposal(proposal)
        proposal.status = "accepted"
        db.session.commit()

        vendor_uuid = proposal.vendor.uuid
        product_uuid = proposal.product.uuid
        cpe_id = proposal.cpe_entry.id
        proposal_id = proposal.id

    list_response = client.get("/changes")
    assert list_response.status_code == 200
    assert f'href="/vendors/{vendor_uuid}"'.encode() in list_response.data
    assert b"Vendor: Example Vendor" in list_response.data
    assert f'href="/products/{product_uuid}"'.encode() in list_response.data
    assert b"Product: Example Product" in list_response.data

    detail_response = client.get(f"/changes/{proposal_id}")
    assert detail_response.status_code == 200
    assert f'href="/vendors/{vendor_uuid}"'.encode() in detail_response.data
    assert f'href="/products/{product_uuid}"'.encode() in detail_response.data
    assert f'href="/cpes/{cpe_id}"'.encode() in detail_response.data


def test_new_vendor_product_links_can_resolve_legacy_accepted_proposal(app, client):
    with app.app_context():
        vendor = Vendor(name="legacy_vendor", title="Legacy Vendor")
        db.session.add(vendor)
        db.session.flush()
        product = Product(vendor_id=vendor.id, name="legacy_product", title="Legacy Product")
        db.session.add(product)
        db.session.flush()
        cpe = CPEEntry(
            vendor_id=vendor.id,
            product_id=product.id,
            cpe_uri="cpe:2.3:a:legacy_vendor:legacy_product:2.0:*:*:*:*:*:*:*",
            part="a",
            version="2.0",
            update="*",
            edition="*",
            language="*",
            sw_edition="*",
            target_sw="*",
            target_hw="*",
            other="*",
            title="Legacy Product 2.0",
            from_proposal=True,
        )
        db.session.add(cpe)
        db.session.flush()
        proposal = Proposal(
            proposal_type="new_vendor_product",
            status="accepted",
            proposed_vendor_name="legacy_vendor",
            proposed_vendor_title="Legacy Vendor",
            proposed_product_name="legacy_product",
            proposed_product_title="Legacy Product",
            proposed_cpe_uri=cpe.cpe_uri,
            reviewed_at=datetime(2024, 2, 4, 4, 5, 6),
        )
        db.session.add(proposal)
        db.session.commit()

        vendor_uuid = vendor.uuid
        product_uuid = product.uuid

    response = client.get("/changes")

    assert response.status_code == 200
    assert f'href="/vendors/{vendor_uuid}"'.encode() in response.data
    assert f'href="/products/{product_uuid}"'.encode() in response.data
