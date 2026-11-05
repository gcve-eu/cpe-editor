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
    large_page = [False]
    long_summary = '<img src=x onerror="window.lookupXss=true"> ' + "A long vulnerability description, with quoted \"text\". " * 30 + "unique-summary-ending"
    oversized_summary = "A" * 2_097_152 + " oversized-summary-ending"
    formula_values = [
        "=1+1", "+SUM(1,1)", "-1+1", "@SUM(1,1)",
        " \t=1+1", "\r\n+SUM(1,1)", "\x1f@SUM(1,1)", "\ufeff-1+1",
    ]
    expected_rows = 4 + len(formula_values)

    def upstream(request, timeout):
        requests.append(request.full_url)
        if fail[0]:
            raise URLError("unavailable")
        page_number = int(parse_qs(urlsplit(request.full_url).query)["page"][0])
        data = {
            "results": {"cvelistv5": [
                [f"cve-2026-{page_number:04d}", {"summary": oversized_summary if large_page[0] else long_summary, "modified": "2026-07-10T14:40:55.735Z"}],
                ["CVE-2026-8888", {"summary": "An older advisory.\nWith a second paragraph.", "modified": "2025-08-01T10:30:00"}],
                ["CVE-2026-9999", {"summary": "An advisory without a valid date.", "modified": "unknown"}],
                ["CVE-2026-9998", {"summary": "'=1+1"}],
            ]},
            "total_count": 26,
        }
        for index, formula in enumerate(formula_values):
            # Both the source group and summary are controlled by upstream data.
            vuln_id = "=1+1" if index == 0 else f"CVE-2026-{7000 + index}"
            data["results"][formula] = [[vuln_id, {"summary": formula}]]
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
        page.on("request", lambda request: assets.append(request.url) if "/gcve-results-table.js" in request.url else None)

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
            assert assets == []  # The table component loads only after a lookup.
            if view == "vendors":
                panel.locator(".gcve-tuple-select").select_option(label="microsoft / windows_11")
            assert panel.locator(".gcve-tuple-select option:checked").text_content().strip() == "microsoft / windows_11"
            panel.get_by_role("button", name="Find vulnerabilities on GCVE").click()
            explorer = panel.locator("gcve-results-table")
            table = explorer.locator('.tb-grid, .tb-cards')
            table.wait_for()
            assert panel.locator("table").count() == (1 if width == 1440 else 0)
            assert panel.locator(".gcve-data-tools").count() == 0
            assert panel.locator("vt-csv").count() == 0
            panel.get_by_role("link", name="CVE-2026-0001", exact=True).wait_for()
            assert "<img src=x" in table.text_content()
            assert long_summary in table.text_content()
            assert table.locator(".gcve-result-summary").nth(4).text_content() == "=1+1"
            assert table.locator("img").count() == 0
            assert page.evaluate("window.lookupXss === undefined")
            assert len(assets) == 1
            if width == 1440:
                assert table.locator('th[data-key="id"]').evaluate("cell => getComputedStyle(cell).whiteSpace") == "nowrap"
            assert table.locator(".gcve-result-id").first.evaluate("cell => getComputedStyle(cell).whiteSpace") == "nowrap"
            assert table.locator("time").first.get_attribute("title") == "2026-07-10T14:40:55.735Z"
            assert table.locator("time").first.text_content() == "10 Jul 202614:40 UTC"
            assert table.locator("time").nth(1).text_content() == "01 Aug 202510:30 UTC"
            assert "Not available" in table.locator(".gcve-result-updated").nth(2).text_content()
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
            region = explorer.locator(".tb-body")
            assert region.evaluate("element => element.scrollHeight <= element.clientHeight + 1")
            if width == 390:
                assert region.evaluate("element => element.scrollWidth <= element.clientWidth + 1")
                assert explorer.locator('[part="card"]').count() == expected_rows
            assert explorer.evaluate("element => element.data[0].summary") == long_summary
            assert explorer.locator("img").count() == 0
            if width == 390:
                explorer.get_by_role("combobox", name="Sort by", exact=True).select_option("updated_at")
            else:
                explorer.locator('th[data-key="updated_at"]').click()
            if width == 1440:
                assert explorer.locator('th[data-key="updated_at"]').get_attribute("aria-sort") == "ascending"
            assert "CVE-2026-8888" in explorer.locator('[part="row"], [part="card"]').first.text_content()
            assert explorer.locator('[part="row"], [part="card"]').first.get_by_role("link").get_attribute("href").endswith("CVE-2026-8888")
            if width == 390:
                explorer.get_by_role("button", name="Sort ascending", exact=True).click()
            else:
                explorer.locator('th[data-key="updated_at"]').click()
            assert "CVE-2026-0001" in explorer.locator('[part="row"], [part="card"]').first.text_content()
            explorer.get_by_role("button", name="Search", exact=True).click()
            explorer.get_by_role("searchbox", name="Search", exact=True).fill("older advisory")
            page.wait_for_function("document.querySelector('gcve-results-table').shadowRoot.querySelectorAll('[part=row], [part=card]').length === 1")
            assert "CVE-2026-8888" in explorer.locator('[part="row"], [part="card"]').text_content()
            assert explorer.get_by_role("link", name="CVE-2026-8888", exact=True).is_visible()
            explorer.get_by_role("searchbox", name="Search", exact=True).fill("unique-summary-ending")
            explorer.get_by_text("unique-summary-ending", exact=True).wait_for()
            assert explorer.locator("mark").last.text_content() == "unique-summary-ending"
            assert explorer.get_by_role("link", name="CVE-2026-0001", exact=True).is_visible()
            explorer.get_by_role("searchbox", name="Search", exact=True).fill("10 Jul 2026")
            page.wait_for_function("document.querySelector('gcve-results-table').shadowRoot.querySelectorAll('[part=row], [part=card]').length === 1")
            assert explorer.get_by_role("link", name="CVE-2026-0001", exact=True).is_visible()
            explorer.get_by_role("searchbox", name="Search", exact=True).fill("")
            page.wait_for_function("count => document.querySelector('gcve-results-table').shadowRoot.querySelectorAll('[part=row], [part=card]').length === count", arg=expected_rows)
            explorer.get_by_role("tab", name="Raw", exact=True).click()
            assert "'=1+1" in explorer.locator("pre.code").text_content()
            raw_rows = list(csv.reader(io.StringIO(explorer.locator("pre.code").text_content())))
            assert raw_rows[1][3] == long_summary
            assert explorer.locator("img").count() == 0
            explorer.get_by_role("tab", name="Table", exact=True).click()
            assert panel.locator("table").count() == (1 if width == 1440 else 0)
            assert explorer.get_by_role("button", name="Download", exact=True).count() == 0
            exported = list(csv.reader(io.StringIO(explorer.evaluate("element => element.exportData('csv')"))))
            assert exported[1][3] == long_summary
            assert exported[2][2] == "2025-08-01T10:30:00.000Z"
            assert exported[2][3] == "An older advisory.\nWith a second paragraph."
            assert exported[3][2] == ""  # Empty dates stay empty.
            assert exported[4][3] == "'=1+1"  # Already literal; do not add another guard.
            for row, formula in zip(exported[5:], formula_values, strict=True):
                # Vitrine normalizes line endings while preserving the guard.
                assert row[1] == "'" + formula
                assert row[3] == "'" + formula.strip()
            assert exported[5][0] == "'=1+1"
            assert exported[5][4] == "https://db.gcve.eu/vuln/%3D1%2B1"
            # Capture the text handed to the browser's clipboard fallback.
            page.evaluate("""() => {
                document.execCommand = command => {
                    if (command !== 'copy') return false;
                    const root = document.querySelector('gcve-results-table').shadowRoot;
                    window.copiedCSV = root.querySelector('textarea[readonly]').value;
                    return true;
                };
            }""")
            explorer.get_by_role("button", name="Copy rows", exact=True).click()
            page.wait_for_function("typeof window.copiedCSV === 'string'")
            copied = list(csv.reader(io.StringIO(page.evaluate("window.copiedCSV")), delimiter="\t"))
            assert len(copied) == len(exported)
            assert copied[0] == exported[0]
            assert copied[5][0] == "'=1+1"
            assert copied[5][4] == exported[5][4]
            explorer.get_by_role("button", name="Full screen", exact=True).click()
            page.wait_for_function("document.querySelector('gcve-results-table').shadowRoot.querySelector('.vt').dataset.fullscreen")
            explorer.get_by_role("button", name="Exit full screen", exact=True).click()
            page.evaluate("document.documentElement.dataset.theme = 'dark'")
            page.wait_for_function("document.querySelector('gcve-results-table').getAttribute('theme') === 'dark'")
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
                panel.locator(".gcve-tuple-select").select_option(label="microsoft / office")
                assert panel.locator("table").count() == 0
                assert not pagination.is_visible()

            # Vitrine rejects oversized CSV by event, without throwing. Keep
            # every readable result and link, then allow a normal-page retry.
            large_page[0] = True
            page.evaluate("""() => {
                document.querySelector('.gcve-tuple-lookup').addEventListener('vt-error', event => {
                    window.tableError = event.detail.cause.code;
                }, {once: true});
            }""")
            panel.get_by_role("button", name="Find vulnerabilities on GCVE").click()
            page.wait_for_function("document.querySelector('.gcve-tuple-results').textContent.includes('Table controls could not load')")
            assert page.evaluate("window.tableError") == "tooLarge"
            assert panel.locator("gcve-results-table").count() == 0
            assert panel.locator("table").count() == 1
            assert panel.locator("tbody tr").count() == expected_rows
            assert panel.locator(".gcve-results-scroll").evaluate("element => element.scrollHeight <= element.clientHeight + 1")
            summary = panel.locator(".gcve-result-summary").first
            assert summary.evaluate("cell => cell.textContent.length") == len(oversized_summary)
            assert summary.evaluate("cell => cell.textContent.endsWith('oversized-summary-ending')")
            assert panel.get_by_role("link", name="CVE-2026-0001", exact=True).get_attribute("href").endswith("cve-2026-0001")
            large_page[0] = False
            panel.get_by_role("button", name="Find vulnerabilities on GCVE").click()
            panel.locator("gcve-results-table").get_by_role("tab", name="Raw", exact=True).wait_for()
            assert panel.locator("table").count() == (1 if width == 1440 else 0)
            assert panel.get_by_text("Table controls could not load", exact=False).count() == 0

            # An unavailable module must leave exactly one readable fallback.
            page.route("**/gcve-results-table.js", lambda route: route.abort())
            page.reload()
            panel.get_by_role("button", name="Find vulnerabilities on GCVE").click()
            panel.get_by_role("link", name="CVE-2026-0001", exact=True).wait_for()
            page.wait_for_function("document.querySelector('.gcve-tuple-results').textContent.includes('Table controls could not load')")
            assert panel.get_by_role("link", name="CVE-2026-0001", exact=True).is_visible()
            assert panel.locator("table").count() == 1
            assert not errors
        finally:
            browser.close()
