import io
import json
from html import unescape
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

import pytest

from app import gcve
from app.models import EntityRelationship, Product, Vendor, db


def upstream(monkeypatch, payload):
    requests = []

    def open_response(request, timeout):
        requests.append((request, timeout))
        return io.StringIO(json.dumps(payload))

    monkeypatch.setattr(gcve, "urlopen", open_response)
    return requests


def test_gcve_tuple_lookup_queries_exact_tokens_and_normalizes_records(client, monkeypatch):
    requests = upstream(monkeypatch, {
        "results": {
            "cvelistv5": [["CVE-2026-1234", {
                "cveMetadata": {"cveId": "CVE-2026-1234", "dateUpdated": "2026-11-04T10:00:00Z"},
                "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Example vulnerability"}]}},
            }]],
            "nvd": [["cve-2026-1234", {"id": "cve-2026-1234"}]],
            "ghsa": [["GHSA-aaaa-bbbb-cccc", {"summary": "GHSA summary"}]],
        },
        "total_count": 51, "page": 2, "page_size": 25,
    })
    response = client.get("/api/gcve/search", query_string={"vendor": " Apache ", "product": "HTTP_Server", "page": 2})
    assert response.status_code == 200
    payload = response.get_json()
    request, timeout = requests[0]
    assert request.full_url == "https://db.gcve.eu/api/vulnerability/search/apache/http_server?page=2&per_page=25"
    assert timeout == 8
    assert request.get_header("Accept") == "application/json"
    assert request.get_header("User-agent") == "cpe-editor/1.0"
    assert payload["vendor"] == "apache"
    assert payload["product"] == "http_server"
    assert payload["total"] == 51
    assert payload["has_next"] is True
    assert payload["page"] == 2
    assert payload["count"] == len(payload["items"]) == 2
    assert payload["items"][0] == {
        "id": "CVE-2026-1234", "source": "cvelistv5", "summary": "Example vulnerability",
        "updated_at": "2026-11-04T10:00:00Z", "url": "https://db.gcve.eu/vuln/CVE-2026-1234",
    }
    assert payload["items"][1]["summary"] == "GHSA summary"
    assert payload["search_url"] == "https://db.gcve.eu/search?vendor=apache&product=http_server"


def test_tuple_lookup_encodes_tokens_and_uses_configured_gcve(client, app, monkeypatch):
    app.config.update(GCVE_API_BASE_URL="https://gcve.example/api/", GCVE_WEB_BASE_URL="https://gcve.example/")
    requests = upstream(monkeypatch, {"results": {}, "total_count": 0})
    vendor, product = "vendor/a &b", "product?#é"
    result = client.get("/api/gcve/search", query_string={"vendor": vendor, "product": product, "per_page": 100}).get_json()
    assert requests[0][0].full_url == "https://gcve.example/api/vulnerability/search/vendor%2Fa%20%26b/product%3F%23%C3%A9?page=1&per_page=100"
    assert parse_qs(urlsplit(result["search_url"]).query) == {"vendor": [vendor], "product": [product]}
    assert result["count"] == result["total"] == 0
    assert result["has_next"] is False


@pytest.mark.parametrize("payload", [
    {"cvelistv5": [["CVE-2026-1234", {"summary": "Legacy pair"}]]},
    {"cvelistv5": [{"cveMetadata": {"cveId": "CVE-2026-1234"}}]},
])
def test_legacy_gcve_responses(client, monkeypatch, payload):
    upstream(monkeypatch, payload)
    result = client.get("/api/gcve/search?vendor=apache&product=http_server&per_page=1").get_json()
    assert result["ok"] is True
    assert result["count"] == 1
    assert result["items"][0]["id"] == "CVE-2026-1234"
    assert result["total"] is None
    assert result["has_next"] is True


@pytest.mark.parametrize("query", [
    "", "vendor=apache", "product=http_server", "vendor=%20&product=p",
    "vendor=v&product=p&page=0", "vendor=v&product=p&page=no",
    "vendor=v&product=p&per_page=0", "vendor=v&product=p&per_page=101",
    "vendor=v&product=p&per_page=no", "vendor=" + "v" * 256 + "&product=p",
])
def test_invalid_tuple_lookup_never_calls_gcve(client, monkeypatch, query):
    def unexpected(*args, **kwargs):
        raise AssertionError("Invalid requests must not call GCVE")

    monkeypatch.setattr(gcve, "urlopen", unexpected)
    response = client.get("/api/gcve/search?" + query)
    assert response.status_code == 400
    assert response.get_json()["ok"] is False


@pytest.mark.parametrize("error", [
    HTTPError("https://db.gcve.eu", 429, "rate limited", None, None),
    URLError("unavailable"), TimeoutError(), OSError("network unreachable"), ValueError("invalid JSON"),
])
def test_gcve_lookup_errors_are_recoverable(client, monkeypatch, error):
    def unavailable(*args, **kwargs):
        raise error

    monkeypatch.setattr(gcve, "urlopen", unavailable)
    response = client.get("/api/gcve/search?vendor=apache&product=http_server")
    assert response.status_code == 502
    assert response.get_json()["ok"] is False
    assert response.get_json()["error"]


@pytest.mark.parametrize("payload", [[], None, {"error": "service unavailable"}, {"results": []}])
def test_malformed_gcve_payload_is_not_reported_as_no_matches(client, monkeypatch, payload):
    upstream(monkeypatch, payload)
    response = client.get("/api/gcve/search?vendor=apache&product=http_server")
    assert response.status_code == 502
    assert response.get_json()["ok"] is False


def test_vendor_and_product_panels_include_combined_tuples_without_cpes(client, monkeypatch):
    root = Product.query.filter_by(name="windows_11").one()
    neighbor_vendor = Vendor(name="lookup_neighbor")
    db.session.add(neighbor_vendor)
    db.session.flush()
    neighbor_product = Product(vendor=neighbor_vendor, name="windows_11", title="Display title is not the token")
    db.session.add(neighbor_product)
    db.session.add(EntityRelationship(source_vendor=root.vendor, target_vendor=neighbor_vendor, relationship_type="superseded-by"))
    db.session.commit()
    paths = [f"/vendors/{root.vendor.uuid}", f"/products/{root.uuid}", f"/products/{neighbor_product.uuid}"]

    def unexpected(*args, **kwargs):
        raise AssertionError("Page rendering must not perform GCVE lookups")

    monkeypatch.setattr(gcve, "urlopen", unexpected)
    for path in paths:
        db.session.remove()
        response = client.get(path)
        assert response.status_code == 200
        html = unescape(response.get_data(as_text=True))
        assert 'data-lookup-url="/api/gcve/search"' in html
        assert 'data-vendor="microsoft" data-product="windows_11"' in html
        assert 'data-vendor="lookup_neighbor" data-product="windows_11"' in html
        assert "Find vulnerabilities on GCVE" in html
        assert "/static/js/gcve-tuple-lookup.js" in html


def test_empty_vendor_lookup_panel(client):
    vendor = Vendor(name="lookup_empty")
    db.session.add(vendor)
    db.session.commit()
    html = client.get(f"/vendors/{vendor.uuid}").get_data(as_text=True)
    assert "No products are available for a vendor/product lookup yet." in html


def test_gcve_lookup_openapi_documentation(client):
    spec = client.get("/api/openapi.yaml").get_data(as_text=True)
    operation = spec.split("  /api/gcve/search:\n", 1)[1].split("\n  /api/", 1)[0]
    for expected in ("name: vendor", "name: product", "name: page", "name: per_page", "'400':", "'502':", "#/components/schemas/GCVETupleMatches"):
        assert expected in operation
