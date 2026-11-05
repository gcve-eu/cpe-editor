"""Read-only Vitrine content views, lazy loading, form and fallback regressions."""
import csv
import io
import json
import os
from pathlib import Path
import shutil
from urllib.parse import urlsplit

import pytest
from app.models import CPEEntry, EntityMetadata, EntityNote, Product, Proposal, db

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture()
def content_page(app, client):
    executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH") or shutil.which("chromium")
    with playwright.sync_playwright() as runtime:
        if not executable and not Path(runtime.chromium.executable_path).exists():
            pytest.skip("Chromium is not installed")
        browser = runtime.chromium.launch(executable_path=executable, headless=True)
        page = browser.new_page(locale="en-GB", accept_downloads=True)
        errors, requests = [], []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("request", lambda request: requests.append(request.url))
        def serve(route):
            parsed = urlsplit(route.request.url)
            with app.app_context():
                response = client.open(parsed.path + ("?" + parsed.query if parsed.query else ""),
                    method=route.request.method, data=route.request.post_data_buffer,
                    content_type=route.request.headers.get("content-type"), follow_redirects=True)
            route.fulfill(status=response.status_code, body=response.data, content_type=response.content_type)
        page.route("http://content.test/**", serve)
        page.route("https://**", lambda route: route.abort())
        yield page, errors, requests
        browser.close()


@pytest.mark.parametrize("width", [1440, 390])
def test_json_code_markdown_and_live_form_preview(app, client, content_page, width):
    page, errors, requests = content_page
    page.set_viewport_size({"width": width, "height": 1000})
    product = Product.query.filter_by(name="windows_11").one()
    note = '# Readable note\n\n**Important** context.\n\n<img src=x onerror="window.contentXss=true">\n\n![tracking](https://example.test/pixel.png)\n\n```ruby\nputs "safe"\n```'
    db.session.add(EntityNote(vendor_id=product.vendor_id, product_id=product.id, note_text=note))
    db.session.add(EntityMetadata(product_id=product.id, metadata_key="gcve:description", metadata_value="**Description** text"))
    db.session.commit()
    page.goto(f"http://content.test/products/{product.uuid}")
    assert not any(f"/api/products/{product.uuid}" in url for url in requests)
    inspector = page.locator('details[data-vitrine-url]')
    inspector.locator("summary").click()
    viewer = inspector.locator("vt-json")
    viewer.get_by_role("tab", name="Raw", exact=True).click()
    assert json.loads(viewer.locator("pre.code").text_content())["uuid"] == product.uuid
    with page.expect_download() as info:
        viewer.get_by_role("button", name="Download", exact=True).click()
    assert json.loads(Path(info.value.path()).read_text())["uuid"] == product.uuid
    notes = page.locator('[data-vitrine-label="Approved note"]')
    notes.scroll_into_view_if_needed()
    notes.locator('vt-markdown [part="markdown"]').wait_for()
    assert notes.locator("vt-markdown strong").first.text_content() == "Important"
    notes.locator("vt-markdown .hljs-string").wait_for()
    assert any("/content/languages/ruby.js" in url for url in requests)
    assert notes.locator("vt-markdown img").count() == 0
    assert not any("example.test/pixel" in url for url in requests)
    assert page.evaluate("window.contentXss === undefined")
    description = page.locator('[data-vitrine-label="Description"]')
    description.scroll_into_view_if_needed()
    description.locator("vt-markdown strong").wait_for()
    assert description.locator("vt-markdown strong").text_content() == "Description"
    page.goto(f"http://content.test/cpes/{product.cpes[0].id}")
    code = page.locator('vt-code')
    code.get_by_role("button", name="Copy code", exact=True).wait_for()
    assert product.cpes[0].cpe_uri in code.locator("pre.code").text_content()
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    page.evaluate("document.documentElement.dataset.theme = 'dark'")
    page.wait_for_function("document.querySelector('vt-code').getAttribute('theme') === 'dark'")
    page.goto(f"http://content.test/proposals/note/new?product_id={product.id}")
    field = page.locator("#proposed_notes")
    field.fill("**Previewed** note")
    preview = page.locator('[data-vitrine-input="proposed_notes"]')
    preview.locator("summary").click()
    preview.locator("vt-markdown strong").wait_for()
    assert preview.locator("vt-markdown strong").text_content() == "Previewed"
    field.fill("**Updated** note")
    page.wait_for_function("document.querySelector('vt-markdown')?.content === '**Updated** note'")
    assert field.input_value() == "**Updated** note"
    page.get_by_role("button", name="Submit note", exact=True).click()
    page.wait_for_load_state()
    assert Proposal.query.filter_by(proposed_notes="**Updated** note").one().status == "pending"
    # A missing component leaves the original CPE and direct JSON link usable.
    page.route("**/vt-code.js", lambda route: route.abort())
    page.goto(f"http://content.test/cpes/{product.cpes[0].id}")
    page.locator('[data-vitrine-kind="code"] .vitrine-status').get_by_text("The enhanced view could not load", exact=False).wait_for()
    assert page.locator('[data-vitrine-kind="code"] [data-vitrine-fallback]').is_visible()
    page.locator('details[data-vitrine-url] summary').click()
    assert page.get_by_role("link", name="Open JSON directly").get_attribute("href").startswith("/api/cpes/")
    assert not errors


@pytest.mark.parametrize("width", [1440, 390])
def test_statistics_diff_and_json_input(app, client, content_page, width):
    page, errors, requests = content_page
    page.set_viewport_size({"width": width, "height": 1000})
    cpe = CPEEntry.query.first()
    proposal = Proposal(proposal_type="edit_cpe", status="pending", cpe_entry=cpe,
                        proposed_title="Reviewed title", proposed_notes="**Text** </script><img src=x>")
    db.session.add(proposal)
    db.session.add(EntityMetadata(vendor_id=cpe.vendor_id, metadata_key="=1+1", metadata_value="value"))
    db.session.commit()
    page.goto("http://content.test/statistics")
    chart = page.locator('editor-chart').first
    chart.get_by_role("tab", name="Table", exact=True).click()
    assert chart.locator("tbody tr").count() == 4
    assert chart.get_attribute("label") == "Record coverage"
    with page.expect_download() as info:
        chart.get_by_role("button", name="Download", exact=True).click()
    rows = list(csv.reader(io.StringIO(Path(info.value.path()).read_text())))
    assert rows[0] == ["Label", "Value"]
    assert rows[1][0].startswith("CPEs with PURL mappings (")
    chart.get_by_role("tab", name="Chart", exact=True).click()
    chart.locator("canvas").wait_for()
    assert any("/content/vendor/echarts.js" in url for url in requests)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    metadata = page.locator('[aria-labelledby="metadata-heading"]')
    metadata.scroll_into_view_if_needed()
    metadata.locator('editor-chart').get_by_role("tab", name="Table", exact=True).wait_for()
    with page.expect_download() as info:
        metadata.locator('editor-chart').get_by_role("button", name="Download", exact=True).click()
    assert "'=1+1" in Path(info.value.path()).read_text()
    page.evaluate("""() => {
        document.execCommand = () => {
            const host = document.querySelector('[aria-labelledby="metadata-heading"] editor-chart');
            window.chartCSV = host.shadowRoot.querySelector('textarea[readonly]').value;
            return true;
        };
    }""")
    metadata.locator('editor-chart').get_by_role("button", name="Copy data", exact=True).click()
    page.wait_for_function("window.chartCSV !== undefined")
    assert "'=1+1" in page.evaluate("window.chartCSV")
    with client.session_transaction() as session:
        session["is_admin"] = True
    page.goto(f"http://content.test/admin/proposals/{proposal.id}")
    assert not any("/vt-diff.js" in url for url in requests)
    page.locator('[data-vitrine-kind="diff"]').scroll_into_view_if_needed()
    diff = page.locator('vt-diff')
    diff.get_by_role("tab", name="Unified", exact=True).wait_for()
    assert "Reviewed title" in diff.locator(".vt").text_content()
    assert diff.locator("img").count() == 0
    assert page.locator('#review-form input[name="csrf_token"]').count() == 1
    assert proposal.status == "pending"
    page.goto("http://content.test/admin")
    field = page.locator('#json_payload')
    editor = page.locator('#json_ingest_form vt-json textarea')
    editor.wait_for()
    assert field.is_hidden()
    editor.fill('{"broken":')
    page.locator('#json_ingest_form button[type="submit"]').click()
    page.locator('#json_payload_error').get_by_text("Invalid JSON", exact=False).wait_for()
    assert field.input_value() == '{"broken":'
    editor.fill('{"repaired":true}')
    page.wait_for_function("document.querySelector('#json_ingest_form vt-json')?.data?.repaired === true")
    assert field.input_value() == '{"repaired":true}'
    assert not any("/admin/ingest-json" in url for url in requests)
    assert not errors
    # ECharts is optional: if it fails, the original statistics stay readable.
    page.route("**/content/vendor/echarts.js", lambda route: route.abort())
    page.goto("http://content.test/statistics")
    page.locator('[aria-labelledby="coverage-heading"] .vitrine-status').get_by_text("The enhanced view could not load", exact=False).wait_for()
    assert page.locator('[aria-labelledby="coverage-heading"] [data-vitrine-fallback]').is_visible()
