import json

import pytest

from app.models import CPEEntry, Proposal, db
from app.previews import proposal_comparison
from app.utils import build_cpe_uri


def test_pending_cpe_comparison_matches_effective_values(app, client):
    cpe = CPEEntry.query.first()
    proposal = Proposal(proposal_type="edit_cpe", status="pending", cpe_entry=cpe,
                        proposed_title="Updated title", proposed_version="2.0",
                        proposed_notes="</script><img src=x onerror=alert(1)>")
    db.session.add(proposal)
    db.session.commit()
    before_count = CPEEntry.query.count()
    comparison = proposal_comparison(proposal)
    original = json.loads(comparison["original"])
    proposed = json.loads(comparison["modified"])
    assert original["cpe_uri"] == cpe.cpe_uri
    assert proposed["title"] == "Updated title"
    assert proposed["version"] == "2.0"
    assert proposed["language"] == cpe.language
    assert proposed["cpe_uri"] == build_cpe_uri(cpe.part, cpe.vendor.name, cpe.product.name,
                                               "2.0", cpe.update, cpe.edition, cpe.language,
                                               cpe.sw_edition, cpe.target_sw, cpe.target_hw, cpe.other)
    with client.session_transaction() as session:
        session["is_admin"] = True
    response = client.get(f"/admin/proposals/{proposal.id}")
    assert response.status_code == 200
    assert b'"original"' in response.data
    assert b"<img src=x onerror=alert(1)>" not in response.data
    assert b"\\u003c/script\\u003e" in response.data
    assert CPEEntry.query.count() == before_count
    assert cpe.title != "Updated title"


@pytest.mark.parametrize("status", ["accepted", "rejected"])
def test_completed_proposals_do_not_claim_a_historical_comparison(app, status):
    assert proposal_comparison(Proposal(status=status, proposal_type="edit_cpe")) is None


def test_new_comparison_omits_submitter_details(app):
    proposal = Proposal(status="pending", proposal_type="new_product", proposed_product_name="example",
                        submitter_email="private@example.test", submitter_ip="192.0.2.1")
    comparison = proposal_comparison(proposal)
    assert json.loads(comparison["original"]) == {}
    assert json.loads(comparison["modified"]) == {"product_name": "example"}


def test_note_comparison_keeps_empty_proposed_value(app):
    cpe = CPEEntry.query.first()
    proposal = Proposal(status="pending", proposal_type="edit_vendor_note", vendor=cpe.vendor, proposed_notes="")
    assert json.loads(proposal_comparison(proposal)["modified"])["notes"] == ""
