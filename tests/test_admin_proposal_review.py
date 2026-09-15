from app.models import Proposal, Vendor, db


def test_accept_duplicate_vendor_shows_clear_error_and_keeps_proposal_pending(
    app, client
):
    with app.app_context():
        existing_vendor = Vendor.query.first()
        proposal = Proposal(
            proposal_type="new_vendor_product",
            status="pending",
            proposed_vendor_name=existing_vendor.name,
            proposed_vendor_title="Duplicate vendor",
            proposed_product_name="new_product",
            proposed_product_title="New product",
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
    assert (
        f"vendor &#39;{vendor_name}&#39; already exists".encode() in response.data
    )
    assert b"use the existing vendor instead of creating a new one" in response.data

    with app.app_context():
        proposal = db.session.get(Proposal, proposal_id)
        assert proposal.status == "pending"
        assert Vendor.query.filter_by(name=vendor_name).count() == 1
