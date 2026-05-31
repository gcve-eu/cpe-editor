import json
import os
from datetime import datetime
from pathlib import Path

import pytest

from app import create_app
from app.models import CPEEntry, CPEPurlMapping, CPEVulnerabilityReference, Product, Proposal, Vendor, db


@pytest.fixture()
def app():
    previous_database_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = "sqlite:///:memory:"
    app = create_app()
    app.config.update(
        TESTING=True,
        PROPOSAL_RATE_LIMIT_PER_HOUR=0,
    )

    try:
        with app.app_context():
            db.drop_all()
            db.create_all()
            _load_fixture_data()
            yield app
            db.session.remove()
            db.drop_all()
    finally:
        if previous_database_url is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous_database_url


@pytest.fixture()
def client(app):
    return app.test_client()


def _load_fixture_data():
    fixture_path = Path(__file__).parent / "fixtures" / "cpe_subset.json"
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))

    cpes_by_uri = {}

    for vendor_item in payload["vendors"]:
        vendor = Vendor(
            name=vendor_item["name"],
            title=vendor_item.get("title"),
            notes=vendor_item.get("notes"),
        )
        db.session.add(vendor)
        db.session.flush()

        for product_item in vendor_item["products"]:
            product = Product(
                vendor_id=vendor.id,
                name=product_item["name"],
                title=product_item.get("title"),
            )
            db.session.add(product)
            db.session.flush()

            for cpe_item in product_item["cpes"]:
                cpe = CPEEntry(
                    vendor_id=vendor.id,
                    product_id=product.id,
                    cpe_uri=cpe_item["cpe_uri"],
                    cpe_name_id=cpe_item.get("cpe_name_id"),
                    part=cpe_item["part"],
                    version=cpe_item.get("version", "*"),
                    update=cpe_item.get("update", "*"),
                    edition=cpe_item.get("edition", "*"),
                    language=cpe_item.get("language", "*"),
                    sw_edition=cpe_item.get("sw_edition", "*"),
                    target_sw=cpe_item.get("target_sw", "*"),
                    target_hw=cpe_item.get("target_hw", "*"),
                    other=cpe_item.get("other", "*"),
                    title=cpe_item.get("title"),
                    notes=cpe_item.get("notes"),
                )
                db.session.add(cpe)
                db.session.flush()
                cpes_by_uri[cpe.cpe_uri] = cpe

    for ref_item in payload.get("vulnerability_references", []):
        cpe = cpes_by_uri[ref_item["cpe_uri"]]
        reference = CPEVulnerabilityReference(
            cpe_entry_id=cpe.id,
            vulnerability_source=ref_item["vulnerability_source"],
            vulnerability_id=ref_item["vulnerability_id"],
            cpe_applicability=ref_item["cpe_applicability"],
            rationale=ref_item.get("rationale"),
        )
        db.session.add(reference)

    for mapping_item in payload.get("purl_mappings", []):
        cpe = cpes_by_uri[mapping_item["cpe_uri"]]
        mapping = CPEPurlMapping(
            cpe_name_id=cpe.cpe_name_id,
            purl=mapping_item["purl"],
            source=mapping_item.get("source") or "purl2cpe",
        )
        db.session.add(mapping)

    microsoft_windows = cpes_by_uri[
        "cpe:2.3:o:microsoft:windows_11:23h2:*:*:*:*:*:*:*"
    ]
    accepted_proposal = Proposal(
        proposal_type="edit_cpe",
        status="accepted",
        submitter_name="Fixture Contributor",
        submitter_email="fixture@example.test",
        rationale="Correct the display title.",
        vendor_id=microsoft_windows.vendor_id,
        product_id=microsoft_windows.product_id,
        cpe_entry_id=microsoft_windows.id,
        proposed_title="Microsoft Windows 11 Version 23H2",
        proposed_cpe_uri=microsoft_windows.cpe_uri,
        review_comment="Approved for API fixture coverage.",
        reviewed_at=datetime(2024, 1, 2, 3, 4, 5),
    )
    db.session.add(accepted_proposal)

    pending_proposal = Proposal(
        proposal_type="edit_cpe",
        status="pending",
        cpe_entry_id=microsoft_windows.id,
        proposed_title="Pending title that should not be public",
    )
    db.session.add(pending_proposal)

    db.session.commit()
