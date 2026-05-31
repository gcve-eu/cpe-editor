import io
import json

from app.models import CPEEntry, Product, Vendor
from app import views


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
    matching_items = [item for item in payload["items"] if item["part"] == "o" and "windows_11" in item["cpe_uri"]]
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


def test_vulnerability_reference_endpoints(client):
    cpe_listing = client.get("/api/cpes?q=http_server")
    cpe_payload = cpe_listing.get_json()
    cpe_id = cpe_payload["items"][0]["id"]

    by_cpe_response = client.get(f"/api/cpes/{cpe_id}/vulnerability-references")
    assert by_cpe_response.status_code == 200
    by_cpe_payload = by_cpe_response.get_json()
    assert by_cpe_payload["total"] == 1
    assert by_cpe_payload["items"][0]["vulnerability_source"] == "CVE"

    listing_response = client.get("/api/vulnerability-references?vulnerability_source=CVE")
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

    detail_response = client.get(f"/api/changes/{payload['items'][0]['id']}?include=bcp10")
    assert detail_response.status_code == 200
    detail_payload = detail_response.get_json()
    assert detail_payload["bcp10_dataset"]["counts"]["cpes"] == 1

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
                            {"lang": "en", "value": "Example vulnerability description."}
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
