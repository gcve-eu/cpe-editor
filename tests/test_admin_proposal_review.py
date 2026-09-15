from app.models import CPEEntry, Product, Proposal, Vendor, db


def test_accept_new_vendor_product_reuses_existing_vendor(app, client):
    with app.app_context():
        existing_vendor = Vendor.query.first()
        proposal = Proposal(
            proposal_type="new_vendor_product",
            status="pending",
            proposed_vendor_name=existing_vendor.name,
            proposed_vendor_title="Duplicate vendor",
            proposed_product_name="new_product",
            proposed_product_title="New product",
            proposed_cpe_uri=(
                f"cpe:2.3:a:{existing_vendor.name}:new_product:*:*:*:*:*:*:*:*"
            ),
        )
        db.session.add(proposal)
        db.session.commit()
        proposal_id = proposal.id
        vendor_name = existing_vendor.name

    with client.session_transaction() as session:
        session["is_admin"] = True
        session["_csrf_token"] = "test-token"

    response = client.post(
        f"/admin/proposals/{proposal_id}",
        data={"action": "accept", "csrf_token": "test-token"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Proposal accepted and applied." in response.data

    with app.app_context():
        proposal = db.session.get(Proposal, proposal_id)
        assert proposal.status == "accepted"
        assert Vendor.query.filter_by(name=vendor_name).count() == 1
        product = Product.query.filter_by(
            vendor_id=proposal.vendor_id, name="new_product"
        ).one()
        assert proposal.product_id == product.id
        cpe = db.session.get(CPEEntry, proposal.cpe_entry_id)
        assert cpe.vendor_id == proposal.vendor_id
        assert cpe.product_id == product.id
