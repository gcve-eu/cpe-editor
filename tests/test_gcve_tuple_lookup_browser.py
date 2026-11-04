"""Optional Chromium checks for on-demand tuple search and safe rendering."""

import csv
import io
import json
import os
from pathlib import Path
import shutil
from urllib.error import URLError
from urllib.parse import parse_qs, urlsplit

import pytest

from app import gcve
from app.models import Product

playwright = pytest.importorskip("playwright.sync_api")


@pytest.mark.parametrize("view", ["vendors", "products"])
@pytest.mark.parametrize("width", [1440, 390])
def test_tuple_lookup_in_browser(app, client, monkeypatch, view, width):
    product = Product.query.filter_by(name="windows_11").one()
    identifier = product.uuid if view == "products" else product.vendor.uuid
    requests = []
    fail = [False]
    long_summary = ('<img src=x onerror="window.lookupXss=true"> ' + "A long vulnerability description, with quoted \"text\". " * 30).strip()

    def upstream(request, timeout):
        requests.append(request.full_url)
        if fail[0]:
            raise URLError("unavailable")
        page_number = int(parse_qs(urlsplit(request.full_url).query)["page"][0])
        data = {
            "results": {"cvelistv5": [
                [f"cve-2026-{page_number:04d}", {"summary": long_summary, "modified": "2026-07-10T14:40:55.735Z"}],
                ["CVE-2026-8888", {"summary": "An older advisory.\nWith a second paragraph.", "modified": "2025-08-01T10:30:00"}],
                ["CVE-2026-9999", {"summary": "An advisory without a valid date.", "modified": "unknown"}],
            ]},
            "total_count": 26,
        }
        return io.StringIO(json.dumps(data))

    monkeypatch.setattr(gcve, "urlopen", upstream)
    executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH") or shutil.which("chromium")
    with playwright.sync_playwright() as runtime:
        if not executable and not Path(runtime.chromium.executable_path).exists():
            pytest.skip("Chromium is not installed")
        browser = runtime.chromium.launch(executable_path=executable, headless=True)
        page = browser.new_page(viewport={"width": width, "height": 1000}, locale="en-GB", timezone_id="America/New_York", accept_downloads=True)
        errors = []
        assets = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("request", lambda request: assets.append(request.url) if "/vt-csv.js" in request.url else None)

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
            table = panel.locator(".gcve-results-table")
            assert "<img src=x" in table.text_content()
            assert long_summary in table.text_content()
            assert table.locator("img").count() == 0
            assert page.evaluate("window.lookupXss === undefined")
            assert assets == []  # Vitrine loads only when its optional tools are opened.
            assert table.get_by_role("columnheader", name="Vulnerability", exact=True).evaluate("cell => getComputedStyle(cell).whiteSpace") == "nowrap"
            assert table.locator(".gcve-result-id").first.evaluate("cell => getComputedStyle(cell).whiteSpace") == "nowrap"
            assert table.locator("time").first.get_attribute("title") == "2026-07-10T14:40:55.735Z"
            assert table.locator("time").first.text_content() == "10 Jul 202614:40 UTC"
            assert table.locator("time").nth(1).text_content() == "01 Aug 202510:30 UTC"
            assert "Not available" in table.locator(".gcve-result-updated").nth(2).text_content()
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
            region = panel.get_by_role("region", name="GCVE vulnerability results", exact=True)
            if width == 390:
                assert region.evaluate("element => element.scrollWidth <= element.clientWidth + 1")
                assert table.locator("tbody tr").first.evaluate("element => getComputedStyle(element).display") == "grid"
                region.focus()
                page.keyboard.press("ArrowDown")
                page.wait_for_function("document.querySelector('.gcve-results-scroll').scrollTop > 0")

            panel.get_by_text("Search, sort or export this page", exact=True).click()
            explorer = panel.locator("vt-csv")
            explorer.locator("tbody tr").first.wait_for()
            assert len(assets) == 1
            assert explorer.evaluate("element => element.rows[1][3]") == long_summary
            assert explorer.locator("img").count() == 0
            explorer.get_by_role("button", name="Updated (UTC)", exact=True).click()
            assert explorer.locator("thead th[aria-sort=ascending]").text_content() == "Updated (UTC)"
            assert "CVE-2026-8888" in explorer.locator("tbody tr").first.text_content()
            explorer.get_by_role("button", name="Updated (UTC)", exact=True).click()
            assert "CVE-2026-0001" in explorer.locator("tbody tr").first.text_content()
            explorer.get_by_role("button", name="Search", exact=True).click()
            explorer.get_by_role("searchbox", name="Search", exact=True).fill("older advisory")
            page.wait_for_function("document.querySelector('vt-csv').shadowRoot.querySelectorAll('tbody tr').length === 1")
            assert "CVE-2026-8888" in explorer.locator("tbody").text_content()
            explorer.get_by_role("searchbox", name="Search", exact=True).fill("")
            page.wait_for_function("document.querySelector('vt-csv').shadowRoot.querySelectorAll('tbody tr').length === 3")
            with page.expect_download() as download_info:
                explorer.get_by_role("button", name="Download", exact=True).click()
            download = download_info.value
            assert download.suggested_filename == "gcve-page-1.csv"
            exported = list(csv.reader(io.StringIO(Path(download.path()).read_text())))
            assert exported[1][3] == long_summary
            assert exported[2][2] == "2025-08-01T10:30:00.000Z"
            assert exported[2][3] == "An older advisory.\nWith a second paragraph."
            explorer.get_by_role("button", name="Full screen", exact=True).click()
            page.wait_for_function("document.querySelector('vt-csv').shadowRoot.querySelector('.vt').dataset.fullscreen")
            explorer.get_by_role("button", name="Exit full screen", exact=True).click()
            page.evaluate("document.documentElement.dataset.theme = 'dark'")
            page.wait_for_function("document.querySelector('vt-csv').getAttribute('theme') === 'dark'")
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
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

            # An unavailable optional module must leave the main lookup usable.
            page.route("**/vt-csv.js", lambda route: route.abort())
            page.reload()
            panel.get_by_role("button", name="Find vulnerabilities on GCVE").click()
            panel.get_by_role("link", name="CVE-2026-0001", exact=True).wait_for()
            panel.get_by_text("Search, sort or export this page", exact=True).click()
            page.wait_for_function("document.querySelector('.gcve-data-tools').textContent.includes('Data tools could not load')")
            assert panel.get_by_role("link", name="CVE-2026-0001", exact=True).is_visible()
            assert not errors
        finally:
            browser.close()
