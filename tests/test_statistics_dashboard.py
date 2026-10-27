from datetime import datetime

from app.models import CPEEntry, CPEPurlMapping, CPEVulnerabilityReference, Product, Vendor, db


def test_coverage_counts_records_once_and_includes_catalog_gaps(app, client):
    app.config["VALKEY_URL"] = ""
    cpe = CPEEntry.query.filter(CPEEntry.purl_mappings.any()).first()
    reference = CPEVulnerabilityReference.query.filter_by(cpe_entry_id=cpe.id).first()
    assert reference is not None
    cpe.deprecated = True
    cpe.from_proposal = True
    db.session.add_all([
        CPEPurlMapping(cpe_name_id=cpe.cpe_name_id, purl="pkg:generic/another-mapping@1"),
        CPEVulnerabilityReference(
            cpe_entry_id=cpe.id,
            vulnerability_source="CVE",
            vulnerability_id="CVE-2026-12345",
            cpe_applicability=reference.cpe_applicability,
        ),
        Product(vendor_id=cpe.vendor_id, name="no_cpe_yet"),
        Vendor(name="no_products_yet"),
    ])
    db.session.commit()

    payload = client.get("/api/statistics").get_json()
    assert payload["counts"]["purl_mappings"] == 3
    assert payload["counts"]["vulnerability_references"] == 3
    assert payload["counts"]["cpes_with_purl_mappings"] == 2
    assert payload["counts"]["cpes_with_vulnerability_references"] == 2
    assert payload["counts"]["products_with_cpes"] == 3
    assert payload["counts"]["products_without_cpes"] == 1
    assert payload["counts"]["vendors_without_products"] == 1
    assert payload["counts"]["active_cpes"] == 2
    assert payload["counts"]["deprecated_cpes"] == 1
    assert payload["coverage"] == {
        "cpes_with_purl_mappings_percent": 66.67,
        "cpes_with_vulnerability_references_percent": 66.67,
        "products_with_cpes_percent": 75.0,
        "active_cpes_percent": 66.67,
    }
    assert payload["averages"]["cpes_per_product"] == 0.75
    assert datetime.fromisoformat(payload["generated_at"]).utcoffset().total_seconds() == 0


def test_empty_statistics_has_finite_metrics_and_explains_missing_data(app, client):
    app.config["VALKEY_URL"] = ""
    db.session.remove()
    db.drop_all()
    db.create_all()
    payload = client.get("/api/statistics").get_json()
    assert all(value == 0 for value in payload["counts"].values())
    assert all(value == 0 for value in payload["averages"].values())
    assert all(value == 0 for value in payload["coverage"].values())
    assert payload["top_vendor"] is None
    response = client.get("/statistics")
    assert response.status_code == 200
    assert b"No records yet" in response.data
    assert b"No CPE records available yet" in response.data
    assert b"No vendors available yet" in response.data
    assert b"No proposals submitted yet" in response.data


def test_vendor_rankings_preserve_global_rank_and_previous_next_links(app, client):
    app.config["VALKEY_URL"] = ""
    db.session.add_all(Vendor(name=f"extra_vendor_{i:02d}") for i in range(30))
    db.session.commit()
    response = client.get("/statistics?vendor_page=2")
    assert response.status_code == 200
    assert b"Page 2 of 2" in response.data
    assert b"<td>26</td>" in response.data
    assert b'vendor_page=1#vendor-ranking' in response.data
    assert b'rel="next"' not in response.data
    # Oversized requests clamp to the final page; invalid/negative requests to page 1.
    assert b"Page 2 of 2" in client.get("/statistics?vendor_page=999").data
    assert b"Page 1 of 2" in client.get("/statistics?vendor_page=-2").data
    assert b"Page 1 of 2" in client.get("/statistics?vendor_page=invalid").data
