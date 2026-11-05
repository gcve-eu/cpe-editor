(() => {
  "use strict";
  const script = document.currentScript;
  const moduleUrl = new URL("application-table.js", script.src).href;
  let component;
  const pending = new WeakSet();
  const excluded = "application-table, .gcve-tuple-lookup, vt-openapi, #swagger-ui, [data-table-native]";

  function label(table) {
    return table.getAttribute("aria-label") || table.caption?.textContent.trim()
      || table.closest(".card, section")?.querySelector("h2, h3, h1")?.textContent.trim()
      || document.querySelector("h1")?.textContent.trim() || "Table";
  }

  async function enhance(table) {
    if (pending.has(table) || table.closest(excluded)) return;
    pending.add(table);
    try {
      component ||= import(moduleUrl);
      await component;
      if (!table.isConnected || table.closest(excluded)) return;
      const host = document.createElement("application-table");
      host.setAttribute("variant", "full");
      host.setAttribute("label", label(table));
      host.setAttribute("theme", document.documentElement.dataset.theme || "auto");
      host.setAttribute("download", `${label(table).toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 80) || "table"}.csv`);
      host.setAttribute("page-size", table.dataset.serverPageSize || "25");
      if (table.dataset.serverPageSize) {
        host.dataset.serverPaging = "";
        host.setAttribute("search", "false");
        host.setAttribute("page-sizes", "false"); // The page's own list bar has it.
        host.dataset.serverTotal = table.dataset.serverTotal;
        host.dataset.serverTotalLabel = table.dataset.serverTotalLabel;
        host.dataset.exportUrl = table.dataset.exportUrl || "";
        host.dataset.serverFilters = table.dataset.serverFilters || "[]";
        host.dataset.resetAnchor = table.dataset.resetAnchor || "";
        host.dataset.serverSort = table.dataset.serverSort || "[]";
        if (table.dataset.serverColumns) {
          host.dataset.serverColumns = table.dataset.serverColumns;
          host.dataset.serverCurrent = table.dataset.serverCurrent;
          host.dataset.sortAnchor = table.dataset.sortAnchor || "results";
        }
      }
      host.setAttribute("selectable", table.dataset.selectable || "multiple");
      // Rows have nothing more to reveal: no expand arrow on application tables.
      host.setAttribute("expandable", "false");
      if (table.dataset.sortable === "false") host.setAttribute("sortable", "false");
      if (table.dataset.bulkBar === "false") host.setAttribute("bulk-bar", "false");
      if (table.dataset.hiddenColumns) host.dataset.hiddenColumns = table.dataset.hiddenColumns;
      if (table.dataset.queryBar === "false") host.setAttribute("query-bar", "false");
      host.setAttribute("density", "comfortable");
      host.setAttribute("wrap", "true");
      host.setAttribute("filters", "false");
      host.setAttribute("footer", "true");
      host.setAttribute("persist", `cpe-editor:${location.pathname}:${label(table)}`);
      host.setAttribute("sticky-header", "false");
      const wrapper = table.parentElement.classList.contains("table-scroll") ? table.parentElement : table;
      // Attach the error listener before content is connected: size rejection
      // is an event, not a thrown exception. Keep the original table available.
      host.addEventListener("vt-error", () => queueMicrotask(() => {
        if (!host.isConnected) return;
        host.restore();
        const region = document.createElement("div");
        region.className = "table-scroll";
        region.tabIndex = 0;
        region.setAttribute("role", "region");
        region.setAttribute("aria-label", host.getAttribute("label"));
        host.before(region);
        region.append(table);
        host.remove();
      }), {once: true});
      host.initialize(table);
      wrapper.before(host);
      wrapper.remove();
    } catch (_) {
      // Network/CSP failures leave the server-rendered table usable.
    }
  }

  function discover(root = document) {
    root.querySelectorAll("main table").forEach(enhance);
  }
  document.addEventListener("DOMContentLoaded", () => {
    discover();
    new MutationObserver(records => {
      if (records.some(record => [...record.addedNodes].some(node => node.nodeType === 1 && (node.matches("table") || node.querySelector("table"))))) discover();
    }).observe(document.querySelector("main"), {childList: true, subtree: true});
    new MutationObserver(() => document.querySelectorAll("application-table").forEach(host =>
      host.setAttribute("theme", document.documentElement.dataset.theme || "auto")))
      .observe(document.documentElement, {attributes: true, attributeFilter: ["data-theme"]});
  });
})();
