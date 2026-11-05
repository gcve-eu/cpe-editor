import {VtTable} from "../vendor/vitrine/esm/vt-table.js";

import {csvCell, spreadsheetText as guard} from "./export-text.js";

// Application policy around upstream vt-table: keep full-page safe exports and
// a Raw CSV view. Sorting, filters, selection, grouping and layout are upstream.
export class EditorTable extends VtTable {
  static styles = [...VtTable.styles, `
    .header { flex-wrap: wrap; min-height: 44px; padding: .4rem .75rem; }
    .toolbar { flex-wrap: wrap; max-width: 100%; }
    .header [data-focus-key] { display: inline-flex; }
    .tb-bulk { flex-wrap: wrap; }
    .tb-bulk .text-btn > span:not(:only-child) { display: inline; }
    .header, .search, .editor-tabs { flex-shrink: 0; }
    .editor-tabs { display: flex; gap: .25rem; }
    .editor-tabs button { border: 0; background: transparent; padding: .5rem; color: var(--_fg-muted); font: inherit; cursor: pointer; }
    .editor-tabs [aria-selected=true] { color: var(--_accent-fg); box-shadow: inset 0 -2px var(--_accent); }
    .editor-raw { padding: 1rem; overflow: auto; background: var(--_surface); }
    .editor-raw pre { margin: 0; white-space: pre; font: var(--_font-size-small)/1.65 var(--_font-mono); }
    .tb-grid thead { position: relative; z-index: 3; }
    .tb-head-label { white-space: nowrap; }
    .editor-server-group { display: contents; }
    .editor-server-filter .tb-cond-label, .editor-state-label { padding: 0 .1rem 0 .4rem; }
    .editor-server-action { flex: none; padding: 0 .35rem; border: 0; background: none; color: var(--_accent-fg); cursor: pointer; font: inherit; font-size: var(--_font-size-small); font-weight: 600; line-height: 22px; }
    .editor-server-action:hover { text-decoration: underline; }
    .tb-query { align-items: center; flex-wrap: wrap; row-gap: .4rem; }
    .editor-sort { display: inline-flex; flex: none; align-items: center; gap: .3rem; margin-left: .5rem; color: var(--_fg-muted); font-size: var(--_font-size-small); }
    .editor-sort span { margin-right: .15rem; }
    .editor-sort button { padding: .15rem .6rem; border: 1px solid var(--_border-strong); border-radius: 6px; background: transparent; color: var(--_fg); cursor: pointer; font: inherit; font-weight: 600; }
    .editor-sort button:hover { border-color: var(--_accent); }
    .editor-sort button[aria-pressed="true"] { border-color: var(--_accent); background: var(--_accent); color: var(--_bg, #fff); cursor: default; }
    .tb-query-field { flex: 1 1 16rem; min-width: 0; }
    .editor-clear-all { flex: none; margin-left: .5rem; padding: .15rem .6rem; border: 1px solid var(--_border-strong); border-radius: 6px; background: transparent; color: var(--_accent-fg); cursor: pointer; font: inherit; font-size: var(--_font-size-small); font-weight: 600; }
    .editor-clear-all:hover:not(:disabled) { background: var(--_accent-soft, transparent); text-decoration: underline; }
    .editor-clear-all:disabled { color: var(--_fg-muted); cursor: not-allowed; opacity: .6; }
    .tb-query-box { min-width: 8rem; }
    .tb-cell { vertical-align: top; }
    .vt[data-wrap] .tb-grid td { padding-block: .85rem; line-height: 1.7; }
    .editor-cell { white-space: normal; line-height: 1.7; overflow-wrap: anywhere; }
    .editor-cell a { color: var(--_accent-fg); text-underline-offset: .2em; }
    .editor-cell time { display: inline-flex; flex-direction: column; gap: .2rem; white-space: nowrap; font-variant-numeric: tabular-nums; }
    .editor-cell time small { color: var(--_fg-muted); }
    .editor-cell p { margin: 0; white-space: pre-line; }
    .editor-cell.gcve-result-id { white-space: nowrap; font-family: var(--_font-mono); font-weight: 600; }
    .editor-cell.gcve-result-source span { display: inline-block; padding: .15rem .45rem; border: 1px solid var(--_border); border-radius: 5px; background: var(--_accent-soft); font-size: var(--_font-size-small); }
    .vt[data-fullscreen] .tb { flex: 1; min-height: 0; }
    .vt[data-fullscreen] .tb-body, .vt[data-fullscreen] .editor-raw { flex: 1; max-height: none; }
    @media (max-width: 700px) { .title { flex: 1 0 calc(100% - 24px); } }
  `];

  // The table toolbar has no Download button; Copy and selection exports remain.
  feature(name) {
    return name === "download" ? false : super.feature(name);
  }

  // Server-paged tables load one page at a time: their page size comes from the
  // server, and changing it reloads that page size instead of re-slicing rows.
  get pageSize() {
    return "serverPaging" in this.dataset ? Number(this.getAttribute("page-size")) : super.pageSize;
  }

  render() {
    super.render();
    if (!("serverPaging" in this.dataset)) return;
    this.applyServerPaging();
    if (this.serverPagingBound) return;
    this.serverPagingBound = true;
    // With more results on the server, the header checkbox first asks what "all"
    // means: this page or every result. Unchecking still clears directly.
    this.root.addEventListener("click", event => {
      const box = event.target;
      if (!box.matches?.("thead .tb-check") || this.selected.size || !this.hasMoreOnServer) return;
      event.preventDefault();
      event.stopPropagation();
      this.root.querySelector('[data-focus-key="select-menu"]')?.click();
    }, true);
    this.root.addEventListener("change", event => {
      if (!event.target.matches?.(".tb-size")) return;
      event.stopPropagation();
      const url = new URL(location.href);
      url.searchParams.set("per_page", event.target.value);
      url.searchParams.delete("page");
      url.hash = "results";
      location.assign(url);
    }, true);
  }

  applyServerPaging() {
    if (!("serverPaging" in this.dataset)) return;
    this.root.querySelectorAll('.tb-size option[value="0"]').forEach(option => option.remove());
    this.showServerFilters();
  }

  // The server search and sort live in Vitrine's filter bar, in the same chips as
  // its column conditions and always before them. They never filter the loaded
  // rows: changing one runs a new server search.
  showServerFilters() {
    const field = this.root.querySelector(".tb-query-field");
    if (!field) return;
    const first = field.firstElementChild;
    if (first?.classList.contains("editor-server-group")) return;
    field.querySelector(".editor-server-group")?.remove();
    const group = document.createElement("span");
    group.className = "editor-server-group";
    const names = Object.fromEntries(JSON.parse(this.dataset.serverFilters || "[]"));
    const sorts = Object.fromEntries(JSON.parse(this.dataset.serverSort || "[]"));
    const params = new URLSearchParams(location.search);
    const active = Object.keys(names).filter(name => params.get(name)?.trim());
    const search = (remove, set = {}) => {
      const url = new URL(location.href);
      remove.forEach(name => url.searchParams.delete(name));
      if (remove.includes("sort")) url.searchParams.delete("dir");
      Object.entries(set).forEach(([name, value]) => url.searchParams.set(name, value));
      url.searchParams.delete("page");
      const left = Object.keys(names).some(name => url.searchParams.get(name)?.trim());
      url.hash = left ? "results" : this.dataset.resetAnchor;
      location.assign(url);
    };
    active.forEach(name => {
      const chip = document.createElement("span");
      chip.className = "tb-cond editor-server-filter";
      const text = document.createElement("span");
      text.className = "tb-cond-label";
      const value = params.get(name).trim();
      const column = this.serverColumns?.find(([, sort]) => sort === value)?.[0];
      text.textContent = `${names[name]}: ${name === "sort" ? sorts[value] || column || value : value}`;
      const close = document.createElement("button");
      close.type = "button";
      close.className = "tb-chip-x";
      close.textContent = "×";
      close.setAttribute("aria-label", `Remove ${names[name]} filter`);
      close.title = `Remove ${names[name]} filter`;
      close.addEventListener("click", () => search([name]));
      chip.append(text, close);
      group.append(chip);
    });
    if (group.childElementCount) field.prepend(group);
  }

  // Column filters, grouping and multi-sort chips join the filter field, so that
  // everything acting on the table sits at the same level.
  stateBar() {
    return "serverPaging" in this.dataset && this.feature("query-bar") ? null : super.stateBar();
  }

  queryBar() {
    const bar = super.queryBar();
    if (!bar || !("serverPaging" in this.dataset)) return bar;
    const state = super.stateBar();
    const box = bar.querySelector(".tb-query-box");
    [...(state?.children || [])].forEach(item => {
      if (!item.classList.contains("tb-chip")) return; // Replaced by the Clear below.
      item.className = "tb-cond";
      item.firstElementChild.classList.add("tb-cond-label", "editor-state-label");
      box.before(item);
    });
    // One Clear, always at the far right: it removes everything acting on the table.
    bar.querySelector(`[data-focus-key="clear-conditions"]`)?.remove();
    const names = JSON.parse(this.dataset.serverFilters || "[]").map(([name]) => name);
    const params = new URL(location.href).searchParams;
    const server = names.filter(name => params.get(name)?.trim());
    const local = Boolean(state) || this.conditions.length > 0;
    const clear = document.createElement("button");
    clear.type = "button";
    clear.className = "editor-clear-all";
    clear.textContent = "Clear";
    clear.title = "Remove all filters";
    clear.disabled = !server.length && !local;
    clear.addEventListener("click", () => {
      if (local) {
        this.setConditions([]);
        this.clearQuery();
      }
      if (!server.length) return;
      const url = new URL(location.href);
      server.forEach(name => url.searchParams.delete(name));
      url.searchParams.delete("dir");
      url.searchParams.delete("page");
      url.hash = this.dataset.resetAnchor;
      location.assign(url);
    });
    bar.append(this.serverSortControl() || "", clear);
    return bar;
  }

  // Selecting "all" on a server-paged table means every result of the search, not
  // only the loaded page. Those rows are not in the browser: the selection is a
  // flag, and its only action is the server export of the whole search.
  get hasMoreOnServer() {
    return "serverPaging" in this.dataset && Boolean(this.dataset.exportUrl)
      && Number(this.dataset.serverTotal) > this.getDataset().rows.length;
  }

  selectEveryResult() {
    this.serverAllSelected = true;
    this.selectAll();
  }

  selectionChanged() {
    if (this.serverAllSelected && this.selected.size < this.getDataset().rows.length) this.serverAllSelected = false;
    super.selectionChanged();
  }

  selectMenu(box) {
    super.selectMenu(box);
    if (!("serverPaging" in this.dataset)) return;
    // Vitrine's "matching" entry would repeat the page: only one page is loaded.
    const items = box.querySelectorAll(".tb-menu-item");
    items[1]?.remove();
    if (!this.hasMoreOnServer) return;
    const item = document.createElement("button");
    item.type = "button";
    item.className = "tb-menu-item";
    item.setAttribute("role", "menuitem");
    const label = document.createElement("span");
    label.textContent = "All results";
    const hint = document.createElement("span");
    hint.className = "tb-option-hint";
    hint.textContent = this.dataset.serverTotalLabel;
    item.append(label, hint);
    item.addEventListener("click", () => {
      this.panel = null;
      this.selectEveryResult();
      this.restoreFocus("select-all");
    });
    items[0].after(item);
  }

  bulkBar(order) {
    const bar = super.bulkBar(order);
    if (!bar || !("serverPaging" in this.dataset)) return bar;
    if (this.serverAllSelected) {
      bar.querySelector(".tb-bulk-count").textContent = `All ${this.dataset.serverTotalLabel} results selected`;
      ["bulk-copy", "bulk-csv", "bulk-json"].forEach(key => bar.querySelector(`[data-focus-key="${key}"]`)?.remove());
      const exportAll = this.textButton("Export all (JSON)", "bulk-export-all", () => {
        const link = document.createElement("a");
        link.href = this.dataset.exportUrl;
        link.download = "";
        link.click();
      }, "download");
      bar.querySelector(".spacer").after(exportAll);
    } else if (this.hasMoreOnServer && this.selected.size === this.getDataset().rows.length) {
      const more = this.textButton(`Select all ${this.dataset.serverTotalLabel} results`, "bulk-every", () => this.selectEveryResult());
      bar.querySelector(".spacer").before(more);
    }
    return bar;
  }

  // Server sort choices, visible next to Clear: they order every page.
  serverSortControl() {
    const sorts = JSON.parse(this.dataset.serverSort || "[]");
    if (!sorts.length) return null;
    const current = new URL(location.href).searchParams.get("sort") || sorts[0][0];
    const control = document.createElement("div");
    control.className = "editor-sort";
    control.setAttribute("role", "group");
    control.setAttribute("aria-label", "Sort all results");
    const label = document.createElement("span");
    label.textContent = "Sort by";
    control.append(label);
    sorts.forEach(([value, text]) => {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = text;
      button.setAttribute("aria-pressed", String(value === current));
      button.addEventListener("click", () => {
        if (value === current) return;
        const url = new URL(location.href);
        url.searchParams.set("sort", value);
        url.searchParams.delete("dir");
        url.searchParams.delete("page");
        url.hash = "results";
        location.assign(url);
      });
      control.append(button);
    });
    return control;
  }

  // Columns sorted by the server: a header click reorders every page, not just the
  // loaded rows. Columns left out of data-server-columns keep sorting locally.
  get serverColumns() {
    return this.dataset.serverColumns ? JSON.parse(this.dataset.serverColumns) : null;
  }

  allColumns() {
    const hidden = this.dataset.hiddenColumns ? JSON.parse(this.dataset.hiddenColumns) : [];
    const columns = super.allColumns().map(column => hidden.includes(column.label) ? {...column, hidden: true} : column);
    const server = this.serverColumns;
    if (!server) return columns;
    // A column the server cannot order would only sort the loaded page.
    return columns.map(column => server.some(([label]) => label === column.label) ? column : {...column, sortable: false});
  }

  get sortSpecs() {
    if (!this.serverColumns) return super.sortSpecs;
    const [label, dir] = JSON.parse(this.dataset.serverCurrent);
    const column = this.allColumns().find(item => item.label === label);
    return column ? [{key: column.key, direction: dir === "desc" ? "descending" : "ascending"}] : [];
  }

  setSort(specs) {
    if (!this.serverColumns) return super.setSort(specs);
    const url = new URL(location.href);
    const spec = specs[0];
    const label = this.allColumns().find(item => item.key === spec?.key)?.label;
    const [currentLabel, currentDir] = JSON.parse(this.dataset.serverCurrent);
    // Vitrine's third click clears the sort; the server always has an order, so flip it.
    const mapped = this.serverColumns.find(([name]) => name === (label || currentLabel));
    const dir = spec ? (spec.direction === "descending" ? "desc" : "asc") : (currentDir === "asc" ? "desc" : "asc");
    if (mapped) {
      url.searchParams.set("sort", mapped[1]);
      url.searchParams.set("dir", dir);
    }
    url.searchParams.delete("page");
    url.searchParams.delete("vendor_page");
    url.hash = this.dataset.sortAnchor || "results";
    location.assign(url);
  }

  setConditions(...args) {
    const result = super.setConditions(...args);
    if ("serverPaging" in this.dataset) this.showServerFilters();
    return result;
  }

  // Keep column headers visible under the site menu while the page scrolls. The
  // grid is a horizontal scroll container, so CSS sticky cannot follow the page.
  connectedCallback() {
    super.connectedCallback?.();
    this.followScroll = () => {
      if (this.followFrame) return;
      this.followFrame = requestAnimationFrame(() => {
        this.followFrame = 0;
        this.positionHeader();
      });
    };
    window.addEventListener("scroll", this.followScroll, {passive: true});
    window.addEventListener("resize", this.followScroll, {passive: true});
    // Vitrine rebuilds parts of its shadow DOM on sort, group, density and filter
    // changes: put the additions to the rebuilt parts back each time.
    this.followObserver = new MutationObserver(() => {
      this.applyServerPaging();
      this.followScroll();
    });
    this.followObserver.observe(this.root, {childList: true, subtree: true});
    this.followScroll();
  }

  disconnectedCallback() {
    super.disconnectedCallback?.();
    window.removeEventListener("scroll", this.followScroll);
    window.removeEventListener("resize", this.followScroll);
    this.followObserver?.disconnect();
  }

  positionHeader() {
    const head = this.root.querySelector(".tb-grid thead");
    if (!head) return;
    const fullscreen = this.root.querySelector(".vt[data-fullscreen]");
    const box = head.parentElement.getBoundingClientRect();
    const menu = document.querySelector("body > header")?.getBoundingClientRect().bottom ?? 0;
    const offset = fullscreen ? 0 : Math.min(Math.max(menu - box.top, 0), Math.max(box.height - head.offsetHeight, 0));
    const value = offset ? `translateY(${Math.round(offset)}px)` : "";
    if (head.style.transform !== value) head.style.transform = value;
  }

  setRecords(rows, columns = null) {
    if (columns) this.columns = columns;
    this.data = rows;
    // Keep the existing Vitrine content-size guard, including for property data.
    this.content = JSON.stringify(rows);
  }

  onGridKey(event) {
    // Upstream's single-cell keyboard copy uses displayText rather than the
    // row exporter. Apply the same spreadsheet guard for that path as well.
    this.copyingCell = (event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "c";
    try { return super.onGridKey(event); } finally { this.copyingCell = false; }
  }

  displayText(column, row) {
    const value = super.displayText(column, row);
    return this.copyingCell ? guard(value) : value;
  }

  exportData(format = "csv", options = {}) {
    const rows = this.getRows({filtered: false, selected: Boolean(options.selected)});
    const columns = options.raw ? this.allColumns() : this.visibleColumns();
    if (format === "json") return JSON.stringify(rows.map(row => Object.fromEntries(columns.map(column => [column.key, row[column.key] ?? null]))), null, 2);
    const values = [columns.map(column => column.label), ...rows.map(row => columns.map(column => row[column.key]))];
    return format === "tsv"
      ? values.map(row => row.map(value => guard(value).replace(/[\t\r\n]+/g, " ")).join("\t")).join("\n")
      : values.map(row => row.map(csvCell).join(",")).join("\r\n");
  }

  renderContent(frame) {
    super.renderContent(frame);
    const tabs = document.createElement("div");
    tabs.className = "editor-tabs";
    tabs.setAttribute("role", "tablist");
    tabs.setAttribute("aria-label", "Table format");
    ["Table", "Raw"].forEach((label, index) => {
      const button = document.createElement("button");
      button.type = "button";
      button.setAttribute("role", "tab");
      button.setAttribute("aria-selected", String(Boolean(this.rawView) === Boolean(index)));
      button.textContent = label;
      button.addEventListener("click", () => {
        this.rawView = Boolean(index);
        this.searchQuery = this.rawView ? this.rawQuery || "" : this.query;
        this.render();
        this.root.querySelectorAll('[role="tab"]')[index]?.focus();
      });
      tabs.append(button);
    });
    this.root.querySelector(".badge")?.remove();
    this.root.querySelector(".toolbar")?.before(tabs);
    if (this.rawView) {
      this.host.hidden = true;
      ["columns", "filters", "density", "expand-all", "collapse-all", "help"].forEach(key => {
        const button = this.root.querySelector(`.header [data-focus-key="${key}"]`);
        if (button) button.hidden = true;
      });
      const region = document.createElement("div");
      region.className = "body editor-raw";
      region.tabIndex = 0;
      region.setAttribute("role", "region");
      region.setAttribute("aria-label", "Raw CSV");
      const pre = document.createElement("pre");
      pre.className = "code";
      pre.textContent = this.exportData("csv", {raw: true});
      region.append(pre);
      frame.append(region);
    }
  }

  search(query) {
    if (!this.rawView) return super.search(query);
    this.rawQuery = query;
    const pre = this.root.querySelector(".editor-raw pre");
    pre.textContent = this.exportData("csv", {raw: true});
    this.rawMatches = [];
    if (query) {
      const value = pre.textContent;
      const fragment = document.createDocumentFragment();
      let start = 0;
      let index = value.toLowerCase().indexOf(query.toLowerCase());
      while (index >= 0) {
        fragment.append(value.slice(start, index));
        const mark = document.createElement("mark");
        mark.textContent = value.slice(index, index + query.length);
        fragment.append(mark);
        this.rawMatches.push(mark);
        start = index + query.length;
        index = value.toLowerCase().indexOf(query.toLowerCase(), start);
      }
      fragment.append(value.slice(start));
      pre.replaceChildren(fragment);
    }
    return {total: this.rawMatches.length, capped: false};
  }

  goToResult(index) {
    if (this.rawView) this.rawMatches?.[index]?.scrollIntoView({block: "nearest", inline: "nearest"});
    else super.goToResult(index);
  }
}
