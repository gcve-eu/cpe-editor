import io
import json
import tarfile
import warnings

from sqlalchemy.exc import SAWarning

from app.models import (
    CPEEntry,
    CPEPurlMapping,
    CPEVulnerabilityReference,
    EntityMetadata,
    EntityNote,
    EntityRelationship,
    Product,
    Proposal,
    ProductAlias,
    ProductAliasMember,
    Vendor,
    db,
)
from app import views


def test_index_cpe_search_uses_cpe_product_join_without_eager_load_warning(client):
    with warnings.catch_warnings():
        warnings.simplefilter("error", SAWarning)
        response = client.get("/?vendor_q=micro")

    assert response.status_code == 200
    assert b"cpe:2.3:o:microsoft:windows_11" in response.data


def test_list_vendors_with_pagination(client):
    response = client.get("/api/vendors?per_page=1&page=1")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["page"] == 1
    assert payload["per_page"] == 1
    assert payload["total"] == 2
    assert payload["total_pages"] == 2
    assert len(payload["items"]) == 1


def test_vendor_search_and_detail(client):
    response = client.get("/api/vendors?q=micro")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["total"] == 1
    vendor = payload["items"][0]
    assert vendor["name"] == "microsoft"

    detail_response = client.get(f"/api/vendors/{vendor['uuid']}")
    assert detail_response.status_code == 200
    detail_payload = detail_response.get_json()
    assert detail_payload["name"] == "microsoft"
    assert detail_payload["product_count"] == 2


def test_vendor_suggestions_prefix_matching(client):
    response = client.get("/api/vendors/suggest?q=apa")

    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload["items"]) == 1
    assert payload["items"][0]["name"] == "apache"


def test_product_detail_and_suggestions(client):
    vendor_response = client.get("/api/vendors?q=microsoft")
    vendor_payload = vendor_response.get_json()
    vendor_uuid = vendor_payload["items"][0]["uuid"]

    assert vendor_uuid

    suggestion_response = client.get("/api/products/suggest?q=windows")
    assert suggestion_response.status_code == 200
    suggestion_payload = suggestion_response.get_json()
    assert len(suggestion_payload["items"]) == 1
    product = suggestion_payload["items"][0]
    assert product["name"] == "windows_11"

    detail_response = client.get(f"/api/products/{product['uuid']}")
    assert detail_response.status_code == 200
    detail_payload = detail_response.get_json()
    assert detail_payload["name"] == "windows_11"
    assert detail_payload["vendor_uuid"] == vendor_uuid


def test_cpe_listing_filters_and_detail(client):
    response = client.get("/api/cpes?vendor_q=micro&part=o&per_page=5")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["total"] >= 1
    matching_items = [
        item
        for item in payload["items"]
        if item["part"] == "o" and "windows_11" in item["cpe_uri"]
    ]
    assert matching_items
    cpe = matching_items[0]

    detail_response = client.get(f"/api/cpes/{cpe['id']}")
    assert detail_response.status_code == 200
    detail_payload = detail_response.get_json()
    assert detail_payload["id"] == cpe["id"]
    assert detail_payload["cpe_uri"] == cpe["cpe_uri"]
    assert "purl_mappings" in detail_payload
    assert isinstance(detail_payload["purl_mappings"], list)
    assert len(detail_payload["purl_mappings"]) >= 1


def test_cpe_listing_supports_purl_prefix_filter(client):
    response = client.get("/api/cpes?purl_q=pkg:generic/apache")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["total"] == 1
    assert len(payload["items"]) == 1
    assert "apache:http_server" in payload["items"][0]["cpe_uri"]


def test_cpe_listing_counts_distinct_cpes_when_filter_matches_multiple_related_rows(client):
    cpe = CPEEntry.query.filter(
        CPEEntry.cpe_uri.contains("apache:http_server")
    ).one()
    db.session.add(
        CPEPurlMapping(
            cpe_name_id=cpe.cpe_name_id,
            purl="pkg:generic/apache/httpd-alias",
            source="test",
        )
    )
    db.session.commit()

    response = client.get("/api/cpes?purl_q=pkg:generic/apache&per_page=1")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["total"] == 1
    assert payload["total_pages"] == 1
    assert len(payload["items"]) == 1
    assert "apache:http_server" in payload["items"][0]["cpe_uri"]


def test_vulnerability_reference_endpoints(client):
    cpe_listing = client.get("/api/cpes?q=http_server")
    cpe_payload = cpe_listing.get_json()
    cpe_id = cpe_payload["items"][0]["id"]

    by_cpe_response = client.get(f"/api/cpes/{cpe_id}/vulnerability-references")
    assert by_cpe_response.status_code == 200
    by_cpe_payload = by_cpe_response.get_json()
    assert by_cpe_payload["total"] == 1
    assert by_cpe_payload["items"][0]["vulnerability_source"] == "CVE"

    listing_response = client.get(
        "/api/vulnerability-references?vulnerability_source=CVE"
    )
    assert listing_response.status_code == 200
    listing_payload = listing_response.get_json()
    assert listing_payload["total"] == 1
    assert listing_payload["items"][0]["vulnerability_id"] == "CVE-2024-12345"


def test_approved_changes_api_list_and_detail(client):
    response = client.get("/api/changes?per_page=1")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["page"] == 1
    assert payload["per_page"] == 1
    assert payload["total"] == 1
    assert payload["total_pages"] == 1
    assert len(payload["items"]) == 1

    change = payload["items"][0]
    assert change["status"] == "accepted"
    assert change["proposal_type"] == "edit_cpe"
    assert change["approved_at"] == "2024-01-02T03:04:05"
    assert change["submitter_name"] == "Fixture Contributor"
    assert change["proposed"]["title"] == "Microsoft Windows 11 Version 23H2"
    assert change["cpe"]["cpe_uri"].startswith("cpe:2.3:o:microsoft:windows_11")
    assert "submitter_ip" not in change

    detail_response = client.get(f"/api/changes/{change['id']}")
    assert detail_response.status_code == 200
    detail_payload = detail_response.get_json()
    assert detail_payload["id"] == change["id"]
    assert detail_payload["summary"] == change["summary"]


def test_scoped_approved_change_feeds_and_discovery_links(client):
    change_payload = client.get("/api/changes?per_page=1").get_json()
    change = change_payload["items"][0]
    vendor_uuid = change["vendor"]["uuid"]
    product_uuid = change["product"]["uuid"]
    cpe_id = change["cpe"]["id"]

    feed_paths = [
        "/changes.rss",
        "/changes.atom",
        f"/vendors/{vendor_uuid}/changes.rss",
        f"/vendors/{vendor_uuid}/changes.atom",
        f"/products/{product_uuid}/changes.rss",
        f"/products/{product_uuid}/changes.atom",
        f"/cpes/{cpe_id}/changes.rss",
        f"/cpes/{cpe_id}/changes.atom",
    ]

    for feed_path in feed_paths:
        response = client.get(feed_path)
        assert response.status_code == 200
        assert b"Approved change #" in response.data
        assert b"cpe:2.3:o:microsoft:windows_11" in response.data

    vendor_page = client.get(f"/vendors/{vendor_uuid}")
    assert vendor_page.status_code == 200
    assert f'href="/vendors/{vendor_uuid}/changes.rss"'.encode() in vendor_page.data
    assert f'href="/vendors/{vendor_uuid}/changes.atom"'.encode() in vendor_page.data

    product_page = client.get(f"/products/{product_uuid}")
    assert product_page.status_code == 200
    assert f'href="/products/{product_uuid}/changes.rss"'.encode() in product_page.data
    assert f'href="/products/{product_uuid}/changes.atom"'.encode() in product_page.data

    cpe_page = client.get(f"/cpes/{cpe_id}")
    assert cpe_page.status_code == 200
    assert f'href="/cpes/{cpe_id}/changes.rss"'.encode() in cpe_page.data
    assert f'href="/cpes/{cpe_id}/changes.atom"'.encode() in cpe_page.data


def test_approved_changes_api_filters_proposal_type(client):
    response = client.get("/api/changes?proposal_type=new_cpe")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["total"] == 0
    assert payload["items"] == []


def test_approved_changes_api_can_include_bcp10_change_bundle(client):
    response = client.get("/api/changes?per_page=1&include=bcp10")

    assert response.status_code == 200
    payload = response.get_json()
    dataset = payload["bcp10_dataset"]
    assert dataset["format"] == "cpe-editor-dataset"
    assert dataset["profile"] == "gcve-bcp-10-change-bundle"
    assert dataset["counts"] == {
        "vendors": 1,
        "products": 1,
        "cpes": 1,
        "metadata": 0,
        "relationships": 0,
        "proposals": 1,
    }
    assert dataset["vendors"][0]["uuid"] == payload["items"][0]["vendor"]["uuid"]
    assert dataset["products"][0]["vendor_uuid"] == dataset["vendors"][0]["uuid"]
    assert dataset["cpes"][0]["cpe_uri"].startswith("cpe:2.3:o:microsoft:windows_11")
    assert dataset["cpes"][0]["vendor_uuid"] == dataset["vendors"][0]["uuid"]
    assert dataset["cpes"][0]["product_uuid"] == dataset["products"][0]["uuid"]
    assert dataset["proposals"][0]["status"] == "accepted"
    assert "submitter_ip" not in dataset["proposals"][0]

    detail_response = client.get(
        f"/api/changes/{payload['items'][0]['id']}?include=bcp10"
    )
    assert detail_response.status_code == 200
    detail_payload = detail_response.get_json()
    assert detail_payload["bcp10_dataset"]["counts"]["cpes"] == 1


def test_vendor_page_bottom_pagination_and_search(client, app):
    with app.app_context():
        for index in range(30):
            db.session.add(
                Vendor(
                    name=f"extra_vendor_{index:02d}",
                    title=f"Extra Vendor {index:02d}",
                )
            )
        db.session.commit()

    response = client.get("/vendors")

    assert response.status_code == 200
    assert response.data.count(b'page=2') == 2
    assert b'class="vendor-search-form"' in response.data
    assert b'name="q" type="search"' in response.data
    assert b'data-show-more-label="Show more"' not in response.data
    assert b'data-show-less-label="Show less"' not in response.data

    search_response = client.get("/vendors?q=extra_vendor_00")

    assert search_response.status_code == 200
    assert b'value="extra_vendor_00"' in search_response.data
    assert b"Extra Vendor 00" in search_response.data
    assert b"Extra Vendor 01" not in search_response.data


def test_statistics_page_renders_cpe_part_distribution_counts(client):
    response = client.get("/statistics")

    assert response.status_code == 200
    assert b"<code>a</code>: 2" in response.data
    assert b"<code>o</code>: 1" in response.data
    assert b"built-in method count" not in response.data


def test_statistics_api_returns_clean_dataset_summary(client):
    response = client.get("/api/statistics")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["counts"] == {
        "vendors": 2,
        "products": 3,
        "cpes": 3,
        "purl_mappings": 2,
        "cpes_with_purl_mappings": 2,
        "vendors_with_products": 2,
        "vendors_without_products": 0,
        "contributed_inputs": 2,
        "contributed_cpes": 0,
        "metadata_entries": 0,
        "relationships": 0,
        "product_aliases": 0,
        "product_alias_members": 0,
        "notes": 0,
        "vulnerability_references": 2,
    }
    assert payload["averages"] == {
        "purls_per_cpe": 0.67,
        "products_per_vendor": 1.5,
    }
    assert payload["top_vendor"]["name"] == "microsoft"
    assert payload["top_vendor"]["product_count"] == 2
    assert payload["top_vendor"]["rank"] == 1
    assert payload["cpe_part_counts"] == [
        {"part": "a", "count": 2},
        {"part": "o", "count": 1},
    ]
    assert payload["metadata_key_counts"] == []
    assert payload["relationship_type_counts"] == []
    assert payload["proposal_status_counts"] == {"accepted": 1, "pending": 1}


def test_statistics_includes_contributed_metadata_relationships_and_aliases(client, app):
    with app.app_context():
        vendor = Vendor.query.filter_by(name="microsoft").one()
        source_product = Product.query.filter_by(name="windows_11").one()
        target_product = Product.query.filter_by(name="office").one()
        contributed_cpe = CPEEntry.query.filter_by(product_id=source_product.id).first()
        contributed_cpe.from_proposal = True

        db.session.add(
            EntityMetadata(
                vendor_id=vendor.id,
                metadata_key="gcve:url",
                metadata_value="https://example.test/microsoft",
            )
        )
        db.session.add(
            EntityNote(
                product_id=source_product.id,
                note_text="Fixture note for statistics.",
            )
        )
        db.session.add(
            EntityRelationship(
                source_product_id=source_product.id,
                target_product_id=target_product.id,
                relationship_type="equivalent-to",
            )
        )
        alias = ProductAlias(name="Statistics alias")
        db.session.add(alias)
        db.session.flush()
        alias.members.append(
            ProductAliasMember(
                vendor_id=source_product.vendor_id,
                product_id=source_product.id,
            )
        )
        db.session.commit()

    response = client.get("/api/statistics")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["counts"]["contributed_inputs"] == 7
    assert payload["counts"]["contributed_cpes"] == 1
    assert payload["counts"]["metadata_entries"] == 1
    assert payload["counts"]["relationships"] == 1
    assert payload["counts"]["product_aliases"] == 1
    assert payload["counts"]["product_alias_members"] == 1
    assert payload["counts"]["notes"] == 1
    assert payload["counts"]["vulnerability_references"] == 2
    assert payload["metadata_key_counts"] == [
        {"metadata_key": "gcve:url", "count": 1}
    ]
    assert payload["relationship_type_counts"] == [
        {"relationship_type": "equivalent-to", "count": 1}
    ]

    page_response = client.get("/statistics")
    assert page_response.status_code == 200
    assert b"Contributed inputs" in page_response.data
    assert b"Metadata by key" in page_response.data
    assert b"Relationships by type" in page_response.data
    assert b"Product aliases" in page_response.data


def test_statistics_top_list_api_paginates_vendors_and_products(client):
    vendors_response = client.get("/api/statistics/top-list?entity=vendors&per_page=1")

    assert vendors_response.status_code == 200
    vendors_payload = vendors_response.get_json()
    assert vendors_payload["entity"] == "vendors"
    assert vendors_payload["page"] == 1
    assert vendors_payload["per_page"] == 1
    assert vendors_payload["total"] == 2
    assert vendors_payload["total_pages"] == 2
    assert vendors_payload["items"] == [
        {
            "entity_type": "vendor",
            "id": vendors_payload["items"][0]["id"],
            "uuid": vendors_payload["items"][0]["uuid"],
            "name": "microsoft",
            "title": "Microsoft",
            "product_count": 2,
            "rank": 1,
        }
    ]

    products_response = client.get(
        "/api/statistics/top-list?entity=products&page=2&per_page=2"
    )

    assert products_response.status_code == 200
    products_payload = products_response.get_json()
    assert products_payload["entity"] == "products"
    assert products_payload["page"] == 2
    assert products_payload["per_page"] == 2
    assert products_payload["total"] == 3
    assert products_payload["total_pages"] == 2
    assert products_payload["items"][0]["rank"] == 3
    assert products_payload["items"][0]["name"] == "windows_11"
    assert products_payload["items"][0]["vendor_name"] == "microsoft"
    assert products_payload["items"][0]["cpe_count"] == 1


def test_statistics_top_list_api_rejects_unknown_entity(client):
    response = client.get("/api/statistics/top-list?entity=projects")

    assert response.status_code == 400


def test_openapi_and_docs_endpoints(client):
    openapi_response = client.get("/api/openapi.yaml")
    docs_response = client.get("/api/docs")

    assert openapi_response.status_code == 200
    assert b"openapi:" in openapi_response.data
    assert docs_response.status_code == 200
    assert b"SwaggerUIBundle" in docs_response.data


def test_fixture_contains_expected_subset_records(app):
    with app.app_context():
        assert Vendor.query.count() == 2
        assert Product.query.count() == 3
        assert CPEEntry.query.count() == 3


def test_gcve_cpe_search_accepts_cvelistv5_payload(client, monkeypatch):
    payload = {
        "cvelistv5": [
            {
                "cveMetadata": {
                    "cveId": "CVE-2018-1083",
                    "dateUpdated": "2024-09-16T18:13:29.080Z",
                },
                "containers": {
                    "cna": {
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Example vulnerability description.",
                            }
                        ]
                    }
                },
            }
        ]
    }

    def fake_urlopen(_request_obj, timeout=8):
        return io.StringIO(json.dumps(payload))

    monkeypatch.setattr(views, "urlopen", fake_urlopen)

    response = client.get("/api/gcve/cpesearch?cpe=cpe:2.3:a:zsh:zsh:*:*:*:*:*:*:*:*")
    assert response.status_code == 200
    result = response.get_json()
    assert result["ok"] is True
    assert result["count"] == 1
    assert result["items"][0]["id"] == "CVE-2018-1083"
    assert result["items"][0]["source"] == "CVE"
    assert result["items"][0]["summary"] == "Example vulnerability description."


def test_write_app_dataset_archive_streams_valid_dataset(app, tmp_path):
    from app.cli import read_dataset_archive, write_app_dataset_archive

    output_path = tmp_path / "cpe-editor-dataset.tar.gz"

    with app.app_context():
        counts = write_app_dataset_archive(output_path, include_proposals=True)

    assert output_path.exists()
    with tarfile.open(output_path, mode="r:gz") as archive:
        assert "dataset.json" in archive.getnames()

    dataset = read_dataset_archive(str(output_path))
    assert dataset["format"] == "cpe-editor-dataset"
    assert dataset["counts"] == counts
    assert dataset["counts"]["vendors"] == len(dataset["vendors"])
    assert dataset["counts"]["products"] == len(dataset["products"])
    assert dataset["counts"]["cpes"] == len(dataset["cpes"])
    assert dataset["counts"]["purl_mappings"] == len(dataset["purl_mappings"])
    assert dataset["counts"]["proposals"] == len(dataset["proposals"])


def test_build_app_dataset_skips_orphaned_purl_mappings(app):
    from app.cli import build_app_dataset
    from app.models import CPEPurlMapping, db

    with app.app_context():
        db.session.add(
            CPEPurlMapping(
                cpe_name_id="00000000-0000-0000-0000-000000000000",
                purl="pkg:generic/orphaned-mapping",
                source="test",
            )
        )
        db.session.commit()

        dataset = build_app_dataset()

    assert all(
        mapping["purl"] != "pkg:generic/orphaned-mapping"
        for mapping in dataset["purl_mappings"]
    )
    assert dataset["counts"]["purl_mappings"] == len(dataset["purl_mappings"])


def _csrf_token(client):
    client.get("/proposals/new")
    with client.session_transaction() as sess:
        return sess["_csrf_token"]


def test_relationship_form_does_not_statically_require_product_token(client):
    response = client.get("/proposals/new?proposal_type=new_record_relationship")

    assert response.status_code == 200
    product_input = response.data.split(b'id="proposed_product_name"', 1)[1].split(
        b">", 1
    )[0]
    assert b"required" not in product_input


def test_vendor_relationship_submission_does_not_need_product_token(client, app):
    with app.app_context():
        vendors = Vendor.query.order_by(Vendor.id).limit(2).all()
        source_vendor_id = vendors[0].id
        target_vendor_id = vendors[1].id

    response = client.post(
        "/proposals/new",
        data={
            "csrf_token": _csrf_token(client),
            "proposal_type": "new_record_relationship",
            "proposed_relationship_type": "equivalent-to",
            "source_entity_kind": "vendor",
            "source_vendor_id": str(source_vendor_id),
            "target_entity_kind": "vendor",
            "target_vendor_id": str(target_vendor_id),
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Proposal submitted" in response.data
    with app.app_context():
        proposal = Proposal.query.filter_by(
            proposal_type="new_record_relationship",
            source_vendor_id=source_vendor_id,
            target_vendor_id=target_vendor_id,
        ).one()
        assert proposal.proposed_product_name is None


def test_cpe_detail_limits_gcve_detail_fetches(client, app, monkeypatch):
    with app.app_context():
        cpe = CPEEntry.query.filter_by(
            cpe_uri="cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"
        ).one()
        for index in range(6):
            db.session.add(
                CPEVulnerabilityReference(
                    cpe_entry_id=cpe.id,
                    vulnerability_source="CVE",
                    vulnerability_id=f"CVE-2024-99{index:03d}",
                    cpe_applicability="vulnerable",
                )
            )
        db.session.commit()
        cpe_id = cpe.id

    calls = []

    def fake_fetch(reference, timeout=None):
        calls.append((reference.vulnerability_id, timeout))
        return {"ok": True, "lookup_url": "https://db.gcve.eu/vuln/example"}

    app.config["GCVE_DETAIL_MAX_REFERENCES"] = 2
    app.config["GCVE_DETAIL_TOTAL_BUDGET_SECONDS"] = 30
    monkeypatch.setattr(views, "_fetch_gcve_vulnerability", fake_fetch)

    response = client.get(f"/cpes/{cpe_id}")

    assert response.status_code == 200
    assert len(calls) == 2
    assert b"db.gcve.eu details were skipped to keep the page responsive." in response.data


def test_fetch_gcve_vulnerability_handles_os_errors(app, monkeypatch):
    with app.app_context():
        reference = CPEVulnerabilityReference(
            vulnerability_source="CVE",
            vulnerability_id="CVE-2024-12345",
        )

        def fake_urlopen(_request_obj, timeout=1):
            raise OSError("network is unreachable")

        monkeypatch.setattr(views, "urlopen", fake_urlopen)

        result = views._fetch_gcve_vulnerability(reference)

    assert result["ok"] is False
    assert result["error"] == "db.gcve.eu details are currently unavailable."
