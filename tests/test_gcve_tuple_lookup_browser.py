"""Optional Chromium checks for on-demand tuple search and safe rendering."""

import io
import json
import os
from pathlib import Path
import shutil
from urllib.error import URLError
from urllib.parse import parse_qs, urlsplit

import pytest

from app import gcve
from app.models import Product, db

playwright = pytest.importorskip("playwright.sync_api")


@pytest.mark.parametrize("view", ["vendors", "products"])
def test_tuple_lookup_in_browser(app, client, monkeypatch, view):
    product = Product.query.filter_by(name="windows_11").one()
    identifier = product.uuid if view == "products" else product.vendor.uuid
    requests = []
    fail = [False]

    def upstream(request, timeout):
        requests.append(request.full_url)
        if fail[0]:
            raise URLError("unavailable")
        page_number = int(parse_qs(urlsplit(request.full_url).query)["page"][0])
        data = {
            "results": {"cvelistv5": [[f"CVE-2026-{page_number:04d}", {
                "summary": '<img src=x onerror="window.lookupXss=true">',
            }]]},
            "total_count": 26,
        }
        return io.StringIO(json.dumps(data))

    monkeypatch.setattr(gcve, "urlopen", upstream)
    executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH") or shutil.which("chromium")
    with playwright.sync_playwright() as runtime:
        if not executable and not Path(runtime.chromium.executable_path).exists():
            pytest.skip("Chromium is not installed")
        browser = runtime.chromium.launch(executable_path=executable, headless=True)
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))

        def serve(route):
            parsed = urlsplit(route.request.url)
            with app.app_context():
                response = client.get(parsed.path + ("?" + parsed.query if parsed.query else ""))
            route.fulfill(status=response.status_code, body=response.get_data(), content_type=response.content_type)

        page.route("http://lookup.test/**", serve)
        page.route("https://**", lambda route: route.abort())
        try:
            page.goto(f"http://lookup.test/{view}/{identifier}")
            panel = page.locator(".gcve-tuple-lookup")
            pagination = panel.locator(".gcve-tuple-pagination")
            assert not pagination.is_visible()
            assert requests == []
            if view == "vendors":
                panel.locator("select").select_option(label="microsoft / windows_11")
            assert panel.locator("select option:checked").text_content().strip() == "microsoft / windows_11"
            panel.get_by_role("button", name="Find vulnerabilities on GCVE").click()
            panel.get_by_role("link", name="CVE-2026-0001", exact=True).wait_for()
            assert "<img src=x" in panel.locator("tbody").text_content()
            assert panel.locator("tbody img").count() == 0
            assert page.evaluate("window.lookupXss === undefined")
            assert panel.locator(".gcve-tuple-prev").is_disabled()
            assert "search/microsoft/windows_11" in requests[0]
            panel.get_by_role("button", name="Next", exact=True).click()
            panel.get_by_role("link", name="CVE-2026-0002", exact=True).wait_for()
            assert "page=2" in requests[-1]
            assert panel.locator(".gcve-tuple-next").is_disabled()
            panel.get_by_role("button", name="Previous", exact=True).click()
            panel.get_by_role("link", name="CVE-2026-0001", exact=True).wait_for()
            fail[0] = True
            panel.get_by_role("button", name="Find vulnerabilities on GCVE").click()
            page.wait_for_function("document.querySelector('.gcve-tuple-status').textContent.includes('Unable to complete lookup')")
            assert panel.locator("table").count() == 0
            assert panel.get_by_role("button", name="Find vulnerabilities on GCVE").is_enabled()
            fail[0] = False
            panel.get_by_role("button", name="Find vulnerabilities on GCVE").click()
            panel.get_by_role("link", name="CVE-2026-0001", exact=True).wait_for()
            if view == "vendors":
                panel.locator("select").select_option(label="microsoft / office")
                assert panel.locator("table").count() == 0
                assert not pagination.is_visible()
            assert not errors
        finally:
            browser.close()
