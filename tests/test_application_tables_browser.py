"""Browser regressions for Vitrine controls on native application tables."""
import csv
import io
import json
import os
from pathlib import Path
import shutil
from urllib.parse import urlsplit

from flask import render_template_string
import pytest

from app.models import CPEEntry, Product, ProductAlias, ProductAliasMember, Proposal, db

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture()
def browser_page(app, client):
    executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH") or shutil.which("chromium")
    with playwright.sync_playwright() as runtime:
        if not executable and not Path(runtime.chromium.executable_path).exists():
            pytest.skip("Chromium is not installed")
        browser = runtime.chromium.launch(executable_path=executable, headless=True)
        page = browser.new_page(locale="en-GB", timezone_id="America/New_York", accept_downloads=True)
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))

        def serve(route):
            request = route.request
            parsed = urlsplit(request.url)
            with app.app_context():
                response = client.open(parsed.path + ("?" + parsed.query if parsed.query else ""),
                                       method=request.method, data=request.post_data_buffer,
                                       content_type=request.headers.get("content-type"), follow_redirects=True)
            route.fulfill(status=response.status_code, body=response.data, content_type=response.content_type)

        page.route("http://tables.test/**", serve)
        page.route("https://**", lambda route: route.abort())
        yield page, errors
        browser.close()


@pytest.mark.parametrize("width", [1440, 390])
def test_table_controls_preserve_rows_and_forms(app, client, browser_page, width):
    page, errors = browser_page
    page.set_viewport_size({"width": width, "height": 1000})
    summary = '<img src=x onerror="window.tableXss=true"> ' + "Complete summary. " * 90 + "summary-tail"
    vectors = ["=1+1", "+SUM(1,1)", "-1+1", "@SUM(1,1)", " \t=1+1", "\r\n+SUM(1,1)", "\x1f@SUM(1,1)", "\ufeff-1+1"]
    rows = [(f"Row {index:02}", str(1000 - index), vectors[index] if index < len(vectors) else summary) for index in range(30)]

    @app.route("/table-fixture")
    def table_fixture():
        return render_template_string('''{% extends 'base.html' %}{% block content %}
        <section class="card"><h1>Regression records</h1><form id="records-form">
        <table><thead><tr><th>Name</th><th>Count</th><th>Updated</th><th>Summary</th><th>Include</th><th></th></tr></thead>
        <tbody>{% for name, count, summary in rows %}<tr>
        <td><a href="/record/{{ loop.index }}">{{ name }}</a></td><td>{{ count }}</td>
        <td>2026-07-10 14:40:55.735123</td><td>{{ summary }}</td>
        <td><input type="checkbox" name="selected" value="{{ loop.index }}"><input type="hidden" name="csrf_token" value="SECRET-TOKEN"></td>
        <td><button type="button" class="record-action">Open</button></td></tr>{% endfor %}</tbody></table></form></section>
        <script>document.addEventListener('DOMContentLoaded', () => document.querySelectorAll('.record-action').forEach(button => button.addEventListener('click', () => window.actionClicked = true)));</script>
        {% endblock %}''', rows=rows)

    page.goto("http://tables.test/table-fixture")
    host = page.locator("application-table")
    host.get_by_role("tab", name="Raw", exact=True).wait_for()
    assert host.locator("table").count() == (1 if width == 1440 else 0)
    assert host.locator('[part="row"], [part="card"]').count() == 25
    region = host.locator(".tb-body")
    assert region.evaluate("element => element.scrollHeight <= element.clientHeight + 1")
    assert region.evaluate("element => element.clientHeight > innerHeight")
    host.get_by_role("button", name="Next page", exact=True).click()
    assert host.locator('[part="row"], [part="card"]').count() == 5
    host.get_by_role("button", name="Previous page", exact=True).click()
    assert page.locator("img[src=x]").count() == 0
    assert page.evaluate("window.tableXss === undefined")
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    checkbox = host.locator('input[name=selected][value="1"]')
    checkbox.check()
    assert checkbox.evaluate("input => input.form.id") == "records-form"
    if width == 390:
        host.get_by_role("combobox", name="Sort by", exact=True).select_option("count")
    else:
        host.locator('th[data-key="count"]').click()
    assert host.evaluate("table => table.getRows()[0].name") == "Row 29"
    if width == 390:
        host.get_by_role("button", name="Sort ascending", exact=True).click()
    else:
        host.locator('th[data-key="count"]').click()
    assert host.evaluate("table => table.getRows()[0].name") == "Row 00"
    host.locator(".record-action:visible").first.click()
    assert page.evaluate("window.actionClicked")
    host.get_by_role("button", name="Search", exact=True).click()
    host.get_by_role("searchbox", name="Search", exact=True).fill("Row 29")
    page.wait_for_function("document.querySelector('application-table').shadowRoot.querySelectorAll('[part=row], [part=card]').length === 1")
    assert host.get_by_role("link", name="Row 29", exact=True).is_visible()
    assert host.locator("mark").count() > 0
    host.get_by_role("searchbox", name="Search", exact=True).press("Enter")
    assert host.locator("mark").count() > 0
    assert page.evaluate("new FormData(document.querySelector('#records-form')).getAll('selected')") == ["1"]
    with page.expect_download() as info:
        host.get_by_role("button", name="Download", exact=True).click()
    downloaded = Path(info.value.path()).read_text()
    exported = list(csv.reader(io.StringIO(downloaded)))
    assert len(exported) == 31  # all loaded rows, including filtered/other pages
    assert "SECRET-TOKEN" not in downloaded
    for index, value in enumerate(vectors):
        assert exported[index + 1][3] == "'" + value.replace("\r\n", "\n")
    assert exported[1][4] == "Yes"
    assert exported[1][2] == "2026-07-10T14:40:55.735123Z"
    assert exported[-1][3] == summary
    page.evaluate("""() => {
        document.execCommand = () => {
            window.copiedCSV = document.querySelector('application-table').shadowRoot.querySelector('textarea[readonly]').value;
            return true;
        };
    }""")
    host.get_by_role("button", name="Copy rows", exact=True).click()
    page.wait_for_function("window.copiedCSV !== undefined")
    copied = list(csv.reader(io.StringIO(page.evaluate("window.copiedCSV")), delimiter="\t"))
    assert len(copied) == len(exported)
    assert copied[0] == exported[0]
    assert copied[1][3] == exported[1][3]
    assert "SECRET-TOKEN" not in page.evaluate("window.copiedCSV")
    host.get_by_role("tab", name="Raw", exact=True).click()
    assert "SECRET-TOKEN" not in host.locator("pre.code").text_content()
    assert host.locator(".editor-raw").evaluate("element => element.scrollHeight <= element.clientHeight + 1")
    host.get_by_role("tab", name="Table", exact=True).click()
    host.get_by_role("searchbox", name="Search", exact=True).fill("summary-tail")
    page.wait_for_function("document.querySelector('application-table').shadowRoot.querySelectorAll('[part=row], [part=card]').length === 22")
    assert host.locator("mark").last.text_content() == "summary-tail"
    host.get_by_role("searchbox", name="Search", exact=True).fill("10 Jul 2026")
    page.wait_for_function("document.querySelector('application-table').shadowRoot.querySelectorAll('[part=row], [part=card]').length === 25")
    assert host.locator("time").first.text_content() == "10 Jul 2026 14:40 UTC"
    host.get_by_role("button", name="Full screen", exact=True).click()
    page.wait_for_function("document.querySelector('application-table').shadowRoot.querySelector('.vt').dataset.fullscreen")
    assert host.locator(".tb-body").evaluate("element => element.scrollHeight > element.clientHeight + 1")
    host.get_by_role("button", name="Exit full screen", exact=True).click()
    page.wait_for_function("!document.querySelector('application-table').shadowRoot.querySelector('.vt').dataset.fullscreen")
    assert host.locator(".tb-body").evaluate("element => element.scrollHeight <= element.clientHeight + 1")
    page.evaluate("document.documentElement.dataset.theme = 'dark'")
    page.wait_for_function("document.querySelector('application-table').getAttribute('theme') === 'dark'")
    host.get_by_role("searchbox", name="Search", exact=True).fill("")
    page.wait_for_function("document.querySelector('application-table').getRows().length === 30")
    # New upstream query chips combine column comparisons with AND / OR.
    query = host.get_by_role("combobox", name="Filter rows", exact=True)
    query.fill("Count:>=990")
    query.press("Enter")
    page.wait_for_function("document.querySelector('application-table').getRows().length === 11")
    query.fill("Name:Row 29")
    query.press("Enter")
    page.wait_for_function("document.querySelector('application-table').getRows().length === 0")
    host.get_by_role("button", name="Match all", exact=True).click()
    page.wait_for_function("document.querySelector('application-table').getRows().length === 12")
    host.get_by_role("button", name="Clear the conditions", exact=True).click()
    query.press("Escape")
    page.wait_for_function("document.querySelector('application-table').getRows().length === 30")
    if width == 1440:
        page.evaluate("window.copiedCSV = ''")
        host.locator('[role="gridcell"][data-r="0"][data-c="3"]').focus()
        page.keyboard.press("Control+c")
        page.wait_for_function("window.copiedCSV === \"'=1+1\"")
        host.locator('th[data-key="name"]').click()
        host.locator('th[data-key="count"]').click(modifiers=["Shift"])
        assert len(host.evaluate("table => table.state.sort")) == 2
        host.get_by_role("button", name="Show filters", exact=True).click()
        host.locator('[aria-label="Filter Count"]').fill(">=990")
        page.wait_for_function("document.querySelector('application-table').getRows().length === 11")
        host.locator('[aria-label="Filter Count"]').fill("")
        page.wait_for_function("document.querySelector('application-table').getRows().length === 30")
        host.get_by_role("button", name="Include column options", exact=True).click()
        host.get_by_role("menuitem", name="Group by this column", exact=True).click()
        assert host.locator('[part="group-row"]').count() == 2
        host.get_by_role("button", name="Collapse all", exact=True).click()
        assert host.locator('[part="row"]').count() == 0
        assert page.evaluate("new FormData(document.querySelector('#records-form')).getAll('selected')") == ["1"]
        host.get_by_role("button", name="Expand all", exact=True).click()
        host.get_by_role("button", name="Include column options", exact=True).click()
        host.get_by_role("menuitem", name="Ungroup", exact=True).click()
    # Selection exports contain just the selected records, with hidden form
    # fields omitted. Page-level exports above still include all loaded rows.
    host.get_by_role("checkbox", name="Select row 1", exact=True).check()
    with page.expect_download() as selected_info:
        host.get_by_role("button", name="JSON", exact=True).click()
    selected = json.loads(Path(selected_info.value.path()).read_text())
    assert len(selected) == 1
    assert selected[0]["name"] == "Row 00"
    assert "SECRET-TOKEN" not in json.dumps(selected)
    host.get_by_role("button", name="Clear the selection", exact=True).click()
    host.get_by_role("button", name="Columns", exact=True).click()
    host.get_by_role("checkbox", name="Summary", exact=True).uncheck()
    assert host.evaluate("table => table.state.columns.find(c => c.key === 'summary').hidden")
    host.get_by_role("button", name="Move Summary up", exact=True).click()
    assert host.evaluate("table => table.state.columns[2].key") == "summary"
    host.get_by_role("button", name="Reset layout", exact=True).click()
    host.get_by_role("button", name="Columns", exact=True).click()
    host.get_by_role("button", name="Density: comfortable", exact=True).click()
    assert host.evaluate("table => table.state.density") == "compact"
    # Content may change after enhancement. Vitrine's size rejection restores
    # the original scrollable table, including controls and hidden rows.
    host.locator(".application-cell[data-column='3']").first.evaluate("cell => cell.textContent = 'A'.repeat(2097153)")
    page.wait_for_function("document.querySelector('application-table') === null")
    assert page.locator(".table-scroll table tbody tr:visible").count() == 30
    assert page.locator('input[name=selected][value="1"]').is_checked()
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    page.route("**/application-table.js", lambda route: route.abort())
    page.reload()
    page.wait_for_load_state("networkidle")
    assert page.locator("application-table").count() == 0
    assert page.locator("tbody tr:visible").count() == 30
    assert not errors


@pytest.mark.parametrize("width", [1440, 390])
def test_application_pages_and_alias_submission(app, client, browser_page, width):
    page, errors = browser_page
    page.set_viewport_size({"width": width, "height": 1000})
    product = Product.query.filter_by(name="windows_11").one()
    alias = ProductAlias(name="Regression alias", description="Test alias")
    alias.members.append(ProductAliasMember(vendor_id=product.vendor_id, product_id=product.id))
    db.session.add(alias)
    db.session.commit()
    with client.session_transaction() as session:
        session["is_admin"] = True
    paths = ["/vendors", "/vendors?sort=products", "/products", "/products?sort=cpes", "/?vendor_q=micro", f"/vendors/{product.vendor.uuid}", f"/products/{product.uuid}",
             f"/cpes/{product.cpes[0].id}", "/aliases", f"/aliases/{alias.uuid}", "/changes", "/statistics",
             "/admin", f"/admin/proposals/{Proposal.query.filter_by(status='pending').first().id}",
             "/admin/aliases/new", f"/admin/aliases/{alias.id}/edit"]
    for path in paths:
        response = client.get(path)
        assert response.status_code == 200, path
        page.goto("http://tables.test" + path)
        # Every ordinary table, including empty/property/admin tables, upgrades.
        page.wait_for_function("""() => {
            const tables = [...document.querySelectorAll('main table')].filter(table => !table.closest('.gcve-tuple-lookup'));
            return tables.length === 0 && [...document.querySelectorAll("application-table")].every(host => host.shadowRoot.querySelector("[role=tab]"));
        }""")
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), path
        assert page.locator(".collapse-toggle").filter(has=page.locator("table")).count() == 0
    # Product CPE lookups create tables after page load. They receive the same
    # controls, preserve complete summaries/links and treat remote text safely.
    page.goto("http://tables.test/products/" + product.uuid)
    page.route("**/api/gcve/cpesearch?*", lambda route: route.fulfill(json={"ok": True, "count": 1, "items": [{
        "id": "CVE-2026-1234", "source": "nvd", "updated_at": "2026-07-10T14:40:00Z",
        "summary": '<img src=x onerror="window.tableXss=true"> ' + "Full summary. " * 100 + "ending-marker",
    }]}))
    page.locator(".js-gcve-cpe-search").first.click()
    dynamic = page.locator("#gcve-cpe-search-results application-table")
    dynamic.get_by_role("tab", name="Raw", exact=True).wait_for()
    assert dynamic.get_by_role("link").get_attribute("href").endswith("CVE-2026-1234")
    assert dynamic.locator('[part="row"], [part="card"]').text_content().endswith("ending-marker")
    assert dynamic.locator("img").count() == 0
    assert page.evaluate("window.tableXss === undefined")
    assert dynamic.locator("time").first.text_content() == "10 Jul 2026 14:40 UTC"
    page.goto("http://tables.test/aliases/proposals/new")
    host = page.locator("application-table")
    host.get_by_role("tab", name="Raw", exact=True).wait_for()
    checkbox = host.locator(f'input[name=product_ids][value="{product.id}"]')
    checkbox.check()
    if width == 390:
        host.get_by_role("combobox", name="Sort by", exact=True).select_option("product")
    else:
        host.locator('th[data-key="product"]').click()
    host.get_by_role("button", name="Search", exact=True).click()
    host.get_by_role("searchbox", name="Search", exact=True).fill("no-such-product")
    page.wait_for_function("document.querySelector('application-table').getRows().length === 0")
    page.locator("#proposed_alias_name").fill("Browser submitted alias")
    page.get_by_role("button", name="Submit alias proposal", exact=True).click()
    page.wait_for_load_state()
    proposal = Proposal.query.filter_by(proposed_alias_name="Browser submitted alias").one()
    assert [member["product_id"] for member in proposal.proposed_alias_members] == [product.id]
    assert not errors
