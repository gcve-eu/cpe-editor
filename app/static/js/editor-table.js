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
    .header, .search, .editor-scope, .editor-tabs { flex-shrink: 0; }
    .editor-scope { margin: 0; padding: .5rem .75rem; color: var(--_fg-muted); font-size: var(--_font-size-small); border-bottom: 1px solid var(--_border); }
    .editor-tabs { display: flex; gap: .25rem; }
    .editor-tabs button { border: 0; background: transparent; padding: .5rem; color: var(--_fg-muted); font: inherit; cursor: pointer; }
    .editor-tabs [aria-selected=true] { color: var(--_accent-fg); box-shadow: inset 0 -2px var(--_accent); }
    .editor-raw { padding: 1rem; overflow: auto; background: var(--_surface); }
    .editor-raw pre { margin: 0; white-space: pre; font: var(--_font-size-small)/1.65 var(--_font-mono); }
    .tb-head-label { white-space: nowrap; }
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
    const scope = document.createElement("p");
    scope.className = "editor-scope";
    scope.textContent = "Search, filter and sort loaded rows. Copy/download include all loaded rows; selection actions export selected rows. Use page links outside the table for more results. Dates and times are UTC.";
    this.host.before(scope);
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
