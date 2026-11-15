import pytest

from app.models import CPEEntry, Product, Proposal, Vendor, db


@pytest.mark.parametrize(
    "proposal_type", ["new_vendor_product", "new_product", "new_cpe", "edit_cpe"]
)
def test_review_hides_duplicate_warning_without_matches(app, client, proposal_type):
    with app.app_context():
        proposal = Proposal(
            proposal_type=proposal_type,
            status="pending",
            proposed_vendor_name="unique_vendor",
            proposed_product_name="unique_product",
            proposed_cpe_uri="cpe:2.3:a:unique_vendor:unique_product:*:*:*:*:*:*:*:*",
        )
        db.session.add(proposal)
        db.session.commit()
        proposal_id = proposal.id

    with client.session_transaction() as session:
        session["is_admin"] = True

    response = client.get(f"/admin/proposals/{proposal_id}")

    assert response.status_code == 200
    assert f"Review proposal #{proposal_id}".encode() in response.data
    assert b"Potential Duplicates Detected" not in response.data
    assert b"The following records may be similar" not in response.data
    assert b'class="card duplicate-alert"' not in response.data


@pytest.mark.parametrize(
    ("duplicate_type", "field", "model", "attribute", "section"),
    [
        ("vendor", "proposed_vendor_name", Vendor, "name", b"Similar Vendors (1)"),
        ("product", "proposed_product_name", Product, "name", b"Similar Products (1)"),
        ("cpe", "proposed_cpe_uri", CPEEntry, "cpe_uri", b"Similar CPEs (1)"),
    ],
)
def test_review_duplicate_warning_disappears_after_dismissal(
    app, client, duplicate_type, field, model, attribute, section
):
    with app.app_context():
        record = model.query.first()
        duplicate_id = record.id
        proposal = Proposal(
            proposal_type="new_vendor_product",
            status="pending",
            **{field: getattr(record, attribute)},
        )
        db.session.add(proposal)
        db.session.commit()
        proposal_id = proposal.id

    with client.session_transaction() as session:
        session["is_admin"] = True
        session["_csrf_token"] = "test-token"

    review_url = f"/admin/proposals/{proposal_id}"
    response = client.get(review_url)

    assert response.status_code == 200
    assert b"Potential Duplicates Detected" in response.data
    assert section in response.data

    response = client.post(
        "/admin/dismiss-duplicate",
        data={
            "csrf_token": "test-token",
            "source_type": "proposal",
            "source_id": proposal_id,
            "duplicate_type": duplicate_type,
            "duplicate_id": duplicate_id,
            "redirect_target": review_url,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Duplicate dismissed." in response.data
    assert section not in response.data
    assert b"Potential Duplicates Detected" not in response.data
    assert b"The following records may be similar" not in response.data
    assert b'class="card duplicate-alert"' not in response.data


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
