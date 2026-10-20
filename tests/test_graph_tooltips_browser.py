"""Optional browser regression: install Playwright and Chromium to run this test."""

import os
from pathlib import Path
import shutil
from urllib.parse import urlsplit

import pytest

from app.models import Product

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture()
def graph_page(client, app):
    executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH") or shutil.which("chromium")
    with playwright.sync_playwright() as runtime:
        if not executable and not Path(runtime.chromium.executable_path).exists():
            pytest.skip("Chromium is not installed")
        browser = runtime.chromium.launch(executable_path=executable, headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))

        def serve(route):
            response = client.get(urlsplit(route.request.url).path)
            body = response.get_data()
            if route.request.url.endswith("/pivotick.iife.js"):
                # Expose the real instance to open tooltips without hover timing races.
                body += b"""
window.Pivotick = new Proxy(Pivotick, {
  construct(Type, args) {
    window.testGraph = new Type(...args);
    return window.testGraph;
  }
});
"""
            route.fulfill(status=response.status_code, body=body, content_type=response.content_type)

        page.route("http://graph.test/**", serve)
        page.route("https://**", lambda route: route.abort())
        product = Product.query.first()
        payload = client.get(f"/products/{product.uuid}/graph").get_json()
        page.goto(f"http://graph.test/products/{product.uuid}")
        page.locator(".entity-graph summary").click()
        page.wait_for_function("window.testGraph && document.querySelector('.graph-status').textContent.includes('links.')")
        try:
            yield page, payload
            assert not errors
        finally:
            browser.close()


def _pin(page, node_id):
    page.locator(".graph-canvas").scroll_into_view_if_needed()
    page.evaluate("""id => {
      const node = testGraph.getMutableNode(id);
      const box = node.getGraphElement().getBoundingClientRect();
      testGraph.UIManager.tooltip.openForNodeOnElement({
        pageX: box.x + window.scrollX, pageY: box.y + window.scrollY,
      }, node);
    }""", node_id)
    page.locator("body > .pvt-tooltip:not(.pvt-tooltip-floating) .pin-button").click()
    _assert_contained(page)


def _assert_contained(page):
    page.wait_for_function("""() => {
      const canvas = document.querySelector('.graph-canvas');
      const box = canvas.getBoundingClientRect();
      const pins = [...canvas.querySelectorAll(':scope > .pvt-tooltip-floating')];
      return pins.length && pins.every(pin => {
        const rect = pin.getBoundingClientRect();
        return rect.left >= box.left + canvas.clientLeft - 1 &&
          rect.top >= box.top + canvas.clientTop - 1 &&
          rect.right <= box.left + canvas.clientLeft + canvas.clientWidth + 1 &&
          rect.bottom <= box.top + canvas.clientTop + canvas.clientHeight + 1;
      });
    }""")


def _assert_connectors(page):
    page.wait_for_function("""() => {
      const pins = [...testGraph.UIManager.tooltip.tooltipDataMap];
      const paths = [...document.querySelectorAll('.pivotick-shadowlink')];
      return pins.length === paths.length && pins.every(([pin, record], index) => {
        const box = pin.getBoundingClientRect();
        const target = testGraph.UIManager.tooltip.linkTarget(record);
        const path = paths[index];
        const start = path.getPointAtLength(0);
        const end = path.getPointAtLength(path.getTotalLength());
        return Math.abs(start.x - (box.left + window.scrollX + box.width / 2)) < 1 &&
          Math.abs(start.y - (box.top + window.scrollY + box.height / 2)) < 1 &&
          Math.abs(end.x - (target.x + window.scrollX + target.width / 2)) < 1 &&
          Math.abs(end.y - (target.y + window.scrollY + target.height / 2)) < 1;
      });
    }""")


def test_pinned_tooltips_stay_inside_graph(graph_page):
    page, payload = graph_page
    _pin(page, payload["root"])
    for x, y in [(0, 0), (1270, 0), (1270, 890), (0, 890)]:
        handle = page.locator(".pvt-tooltip-floating .pvt-tooltip-topbar").bounding_box()
        page.mouse.move(handle["x"] + handle["width"] / 2, handle["y"] + handle["height"] / 2)
        page.mouse.down()
        page.mouse.move(x, y, steps=5)
        page.mouse.up()
        _assert_contained(page)
        _assert_connectors(page)

    before = page.locator(".pvt-tooltip-floating").bounding_box()
    scroll_before = page.evaluate("window.scrollY")
    page.evaluate("window.scrollBy(0, 150)")
    after = page.locator(".pvt-tooltip-floating").bounding_box()
    scroll_delta = page.evaluate("window.scrollY") - scroll_before
    assert abs(after["y"] - before["y"] + scroll_delta) < 1
    _assert_contained(page)
    _assert_connectors(page)

    _pin(page, payload["nodes"][0]["id"])
    assert page.locator(".pvt-tooltip-floating").count() == 2
    for width, height in [(500, 650), (320, 500), (1280, 900)]:
        page.set_viewport_size({"width": width, "height": height})
        _assert_contained(page)

    page.evaluate("""() => {
      const content = document.querySelector('.pvt-tooltip-floating .pvt-tooltip-container');
      content.style.width = '1400px';
      content.style.height = '1200px';
    }""")
    _assert_contained(page)
    _assert_connectors(page)
    page.locator(".pvt-tooltip-floating .select-element").last.click()
    assert page.locator(".graph-record-picker").input_value()
    page.locator(".pvt-tooltip-floating .focus-element").last.click()
    _assert_contained(page)
    _assert_connectors(page)

    page.locator(".entity-graph summary").click()
    assert not page.locator(".pvt-tooltip-floating").first.is_visible()
    page.locator(".entity-graph summary").click()
    _assert_contained(page)
    page.locator(".pvt-tooltip-floating .close-button").last.click()
    assert page.locator(".pvt-tooltip-floating").count() == 1

    page.evaluate("window.dispatchEvent(new PageTransitionEvent('pagehide'))")
    assert page.locator(".pvt-tooltip-floating").count() == 0
    assert page.locator(".pivotick-shadowlink-container").count() == 0
    page.evaluate("window.dispatchEvent(new PageTransitionEvent('pageshow'))")
    page.wait_for_selector(".graph-canvas .pvt-node")
    _pin(page, payload["root"])
    _assert_connectors(page)
