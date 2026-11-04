import {VtCsv} from "../vendor/vitrine/esm/vt-csv.js";

const csvCell = value => {
  const text = String(value ?? "");
  const literal = /^[\s\u0000-\u001f\u007f]*[=+\-@]/u.test(text) ? `'${text}` : text;
  return `"${literal.replaceAll('"', '""')}"`;
};
const dateFormat = new Intl.DateTimeFormat(undefined, {year: "numeric", month: "short", day: "2-digit", timeZone: "UTC"});
const timeFormat = new Intl.DateTimeFormat(undefined, {hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone: "UTC"});

// Keep the real rows in light DOM: slotted inputs retain their form owner,
// links and action buttons keep their handlers, and no CSRF values enter CSV.
class ApplicationTable extends VtCsv {
  static styles = [...VtCsv.styles, `
    .header { flex-wrap: wrap; padding: .4rem .75rem; min-height: 44px; }
    .header, .search, .pager, .table-scope { flex-shrink: 0; }
    .toolbar { flex-wrap: wrap; max-width: 100%; }
    .table-scope { margin: 0; padding: .5rem .75rem; color: var(--_fg-muted); font-size: var(--_font-size-small); border-bottom: 1px solid var(--_border); }
    .table-body { max-height: min(42rem, 70vh); scrollbar-gutter: stable; }
    .vt[data-fullscreen] .table-host { flex: 1; min-height: 0; }
    .vt[data-fullscreen] .table-body { flex: 1; max-height: none; }
    @media (max-width: 700px) { .title { flex: 1 0 calc(100% - 24px); } .tabs { min-height: 36px; } }
  `];

  initialize(table) {
    this.nativeTable = table;
    this.originalHead = table.tHead?.cloneNode(true);
    if (!table.tHead) {
      const head = table.createTHead();
      const row = head.insertRow();
      ["Field", "Value"].forEach(name => {
        const th = document.createElement("th");
        th.textContent = name;
        row.append(th);
      });
    }
    this.names = [...table.tHead.rows[0].cells].map(cell => cell.textContent.trim() || "Actions");
    this.observer = new MutationObserver(() => this.refresh());
    this.onChange = () => this.refresh();
    table.addEventListener("change", this.onChange);
    table.slot = "table";
    table.classList.add("application-data-table");
    table.dataset.tableColumns = this.names.length;
    this.refresh();
  }

  connectedCallback() {
    super.connectedCallback();
    this.watch();
  }

  disconnectedCallback() {
    this.observer?.disconnect();
    super.disconnectedCallback();
  }

  watch() {
    if (this.isConnected) this.observer?.observe(this.nativeTable, {childList: true, subtree: true, characterData: true});
  }

  cellValue(cell) {
    const clone = cell.cloneNode(true);
    clone.querySelectorAll("script, style, input, select, textarea, button, .visually-hidden, .sr-only, [data-table-row-number]").forEach(node => node.remove());
    const time = clone.querySelector("time");
    const text = time?.dateTime || (clone.childNodes.length === 1 && clone.firstChild.nodeType === Node.TEXT_NODE
      ? clone.textContent : clone.textContent.replace(/\s+/g, " ").trim());
    const fields = [...cell.querySelectorAll("input:not([type=hidden]), select, textarea")].map(input =>
      input.type === "checkbox" || input.type === "radio" ? (input.checked ? "Yes" : "No") : input.value);
    return [text, ...fields].filter(Boolean).join(" ");
  }

  formatDate(cell) {
    if (cell.querySelector("time, code, input, button, a")) return;
    const raw = cell.textContent.trim();
    if (!/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z| UTC|[+-]\d{2}:\d{2})?$/.test(raw)) return;
    const iso = raw.replace(" UTC", "Z").replace(" ", "T");
    const date = new Date(/(?:Z|[+-]\d{2}:\d{2})$/.test(iso) ? iso : `${iso}Z`);
    if (Number.isNaN(date.getTime())) return;
    const time = document.createElement("time");
    time.dateTime = /(?:Z|[+-]\d{2}:\d{2})$/.test(iso) ? iso : `${iso}Z`;
    time.title = raw;
    const day = document.createElement("span");
    day.textContent = dateFormat.format(date);
    const hour = document.createElement("small");
    hour.textContent = `${timeFormat.format(date)} UTC`;
    time.append(day, " ", hour);
    cell.replaceChildren(time);
  }

  refresh() {
    this.observer.disconnect();
    this.clearHighlights();
    const table = this.nativeTable;
    const rows = [...table.tBodies].flatMap(body => [...body.rows]).filter(row => !row.hasAttribute("data-table-empty"));
    this.emptyRows = rows.filter(row => row.cells.length === 1 && row.cells[0].colSpan > 1);
    const records = rows.filter(row => !this.emptyRows.includes(row));
    this.records = [...(this.records || []).filter(row => records.includes(row)), ...records.filter(row => !this.records?.includes(row))];
    this.values = this.records.map((row, index) => [...row.cells].filter(cell => !cell.hasAttribute("data-table-row-number")).map((cell, column) => {
      this.formatDate(cell);
      cell.dataset.row = index;
      cell.dataset.column = column;
      if (cell.tagName === "TH" && !cell.hasAttribute("scope")) cell.scope = "row";
      cell.classList.toggle("table-long-text", this.cellValue(cell).length > 80);
      cell.querySelectorAll('input[type="checkbox"]:not([aria-label])').forEach(input => {
        if (!input.labels?.length) input.setAttribute("aria-label", `${this.names[column]}: ${row.textContent.replace(/\s+/g, " ").trim()}`);
      });
      return this.cellValue(cell);
    }));
    this.searchValues = this.records.map((row, index) => this.values[index].map((value, column) =>
      `${value} ${row.querySelector(`[data-column="${column}"]`).textContent}`));
    const state = {sort: this.sort, page: this.page, query: this.query};
    this.content = [this.names, ...this.values].map(row => row.map(csvCell).join(",")).join("\r\n");
    Object.assign(this, state);
    if (this.query) this.search(this.query);
    this.watch();
  }

  order(data, types) {
    const query = this.query;
    this.query = "";
    let order;
    try { order = super.order(data, types); } finally { this.query = query; }
    return query ? order.filter(index => this.searchValues[index].some(value => value.toLowerCase().includes(query.toLowerCase()))) : order;
  }

  search(query) {
    this.query = query;
    this.page = 0;
    this.current = -1;
    this.searchMatches = [];
    const {data, types} = this.model();
    if (query) for (const row of this.order(data, types)) {
      this.searchValues[row].forEach((value, column) => {
        if (value.toLowerCase().includes(query.toLowerCase())) this.searchMatches.push({row, column});
      });
    }
    this.renderTable();
    return {total: this.searchMatches.length, capped: false};
  }

  render() {
    super.render();
    const scope = document.createElement("p");
    scope.className = "table-scope";
    scope.textContent = "Search and sort loaded rows. Copy and download include all loaded rows, even when filtered. Use the page links outside this table for more results. Dates and times are UTC.";
    this.root.querySelector(".panel")?.prepend(scope);
  }

  renderTable() {
    if (!this.tableHost || !this.nativeTable) return;
    this.observer.disconnect();
    try {
      const {data, types} = this.model();
      const order = this.order(data, types);
      const pages = Math.max(1, Math.ceil(order.length / this.pageSize));
      this.page = Math.min(this.page, pages - 1);
      const visible = order.slice(this.page * this.pageSize, (this.page + 1) * this.pageSize);
      const head = this.nativeTable.tHead.rows[0];
      head.replaceChildren();
      const number = document.createElement("th");
      number.textContent = "#";
      number.scope = "col";
      number.setAttribute("aria-label", "Row number");
      head.append(number);
      this.names.forEach((name, column) => {
        const th = document.createElement("th");
        th.scope = "col";
        const direction = this.sort?.column === column ? this.sort.direction : "none";
        th.setAttribute("aria-sort", direction);
        const button = document.createElement("button");
        button.type = "button";
        button.className = "table-sort";
        button.dataset.sortColumn = column;
        button.textContent = name;
        const arrow = document.createElement("span");
        arrow.setAttribute("aria-hidden", "true");
        arrow.textContent = direction === "ascending" ? " ↑" : direction === "descending" ? " ↓" : " ↕";
        button.append(arrow);
        button.addEventListener("click", () => this.sortBy(column, name));
        th.append(button);
        head.append(th);
      });
      this.records.forEach((row, index) => {
        row.hidden = !visible.includes(index);
        if (!row.querySelector("[data-table-row-number]")) {
          const th = document.createElement("th");
          th.dataset.tableRowNumber = "";
          th.scope = "row";
          row.prepend(th);
        }
        row.querySelector("[data-table-row-number]").textContent = index + 1;
      });
      // Move, never clone, rows. Hidden form fields remain successful controls.
      visible.forEach(index => this.records[index].parentElement.append(this.records[index]));
      this.emptyRows.forEach(row => { row.hidden = Boolean(this.records.length) || Boolean(this.query); row.cells[0].colSpan = this.names.length + 1; });
      this.nativeTable.querySelectorAll("[data-table-empty]").forEach(row => row.remove());
      if (!visible.length && !this.emptyRows.some(row => !row.hidden)) {
        const row = this.nativeTable.tBodies[0].insertRow();
        row.dataset.tableEmpty = "";
        const td = row.insertCell();
        td.colSpan = this.names.length + 1;
        td.textContent = "No matching rows.";
      }
      const region = document.createElement("div");
      region.className = "body table-body";
      region.tabIndex = 0;
      region.setAttribute("role", "region");
      region.setAttribute("aria-label", this.heading);
      const slot = document.createElement("slot");
      slot.name = "table";
      region.append(slot);
      this.tableHost.replaceChildren(region, this.pager(order.length, pages));
      this.highlightMatches();
    } finally { this.watch(); }
  }

  sortBy(column, name) {
    super.sortBy(column, name);
    this.nativeTable.querySelector(`[data-sort-column="${column}"]`)?.focus();
  }

  clearHighlights() {
    this.nativeTable?.querySelectorAll("mark[data-table-match]").forEach(mark => {
      const parent = mark.parentNode;
      mark.replaceWith(...mark.childNodes);
      parent.normalize();
    });
  }

  highlightMatches() {
    this.clearHighlights();
    if (!this.query) return;
    const needle = this.query.toLowerCase();
    this.records.filter(row => !row.hidden).forEach(row => {
      const walker = document.createTreeWalker(row, NodeFilter.SHOW_TEXT);
      const texts = [];
      while (walker.nextNode()) {
        if (!walker.currentNode.parentElement.closest("input, textarea, select, script, style, [data-table-row-number]")) texts.push(walker.currentNode);
      }
      for (const text of texts) {
        const value = text.textContent;
        let start = 0;
        let index = value.toLowerCase().indexOf(needle);
        if (index < 0) continue;
        const fragment = document.createDocumentFragment();
        while (index >= 0) {
          fragment.append(value.slice(start, index));
          const mark = document.createElement("mark");
          mark.dataset.tableMatch = "";
          const current = this.searchMatches[this.current];
          const cell = text.parentElement.closest("[data-row][data-column]");
          if (current && Number(cell?.dataset.row) === current.row && Number(cell?.dataset.column) === current.column) mark.className = "current";
          mark.textContent = value.slice(index, index + needle.length);
          fragment.append(mark);
          start = index + needle.length;
          index = value.toLowerCase().indexOf(needle, start);
        }
        fragment.append(value.slice(start));
        text.replaceWith(fragment);
      }
    });
  }

  goToMatch(index) {
    const match = this.searchMatches[index];
    if (!match) return;
    this.current = index;
    const {data, types} = this.model();
    this.page = Math.floor(this.order(data, types).indexOf(match.row) / this.pageSize);
    this.renderTable();
    this.records[match.row].querySelector(`[data-column="${match.column}"]`)?.scrollIntoView({block: "nearest", inline: "nearest"});
  }

  restore() {
    this.observer.disconnect();
    this.nativeTable.removeEventListener("change", this.onChange);
    this.clearHighlights();
    this.nativeTable.querySelectorAll("[data-table-empty], [data-table-row-number]").forEach(node => node.remove());
    this.records.forEach(row => { row.hidden = false; row.parentElement.append(row); });
    this.emptyRows.forEach(row => { row.hidden = false; row.cells[0].colSpan = this.names.length; });
    this.nativeTable.tHead.remove();
    if (this.originalHead) this.nativeTable.prepend(this.originalHead);
    this.nativeTable.removeAttribute("slot");
    this.nativeTable.classList.remove("application-data-table");
  }
}

customElements.define("application-table", ApplicationTable);
