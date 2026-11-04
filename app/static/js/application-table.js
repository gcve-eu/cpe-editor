import {EditorTable} from "./editor-table.js";

const dates = new Intl.DateTimeFormat(undefined, {year: "numeric", month: "short", day: "2-digit", timeZone: "UTC"});
const times = new Intl.DateTimeFormat(undefined, {hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone: "UTC"});

// Slot original cell contents, keeping inputs inside their native form and
// preserving the actual action buttons. Upstream renders the grid and cards.
class ApplicationTable extends EditorTable {
  initialize(table) {
    this.nativeTable = table;
    const head = table.tHead;
    this.names = head ? [...head.rows[0].cells].map(cell => cell.textContent.trim() || "Actions") : ["Field", "Value"];
    const used = new Set();
    this.keys = this.names.map((name, i) => {
      const base = name.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "") || "field";
      const key = used.has(base) ? `${base}_${i + 1}` : base;
      used.add(key);
      return key;
    });
    this.nativeRows = [...table.tBodies].flatMap(body => [...body.rows]).filter(row => !(row.cells.length === 1 && row.cells[0].colSpan > 1));
    this.cells = this.nativeRows.map((row, index) => [...row.cells].map((cell, column) => {
      this.formatDate(cell);
      const span = document.createElement("span");
      span.slot = `cell-${index}-${column}`;
      span.className = "application-cell";
      span.dataset.row = index;
      span.dataset.column = column;
      if (cell.className) span.className += ` ${cell.className}`;
      span.append(...cell.childNodes);
      span.querySelectorAll('input[type="checkbox"]:not([aria-label])').forEach(input => {
        if (!input.labels?.length) input.setAttribute("aria-label", `${this.names[column]}: ${row.textContent.trim() || index + 1}`);
      });
      this.append(span);
      return {cell, span, rich: Boolean(span.querySelector("a, button, input, select, textarea, time, code, ul, .pill, form"))};
    }));
    this.observer = new MutationObserver(() => this.refresh());
    this.onChange = event => { if (event.target.closest?.(".application-cell")) this.refresh(); };
    this.addEventListener("change", this.onChange);
    this.refresh(true);
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
    if (this.isConnected && !this.mutating) this.observer?.observe(this, {childList: true, subtree: true, characterData: true});
  }

  cellValue(span) {
    const clone = span.cloneNode(true);
    clone.querySelectorAll("script, style, input, select, textarea, button, .visually-hidden, .sr-only").forEach(node => node.remove());
    const value = clone.querySelector("time")?.dateTime || (clone.childNodes.length === 1 && clone.firstChild.nodeType === Node.TEXT_NODE
      ? clone.textContent : clone.textContent.replace(/\s+/g, " ").trim());
    const fields = [...span.querySelectorAll("input:not([type=hidden]), select, textarea")].map(input =>
      input.type === "checkbox" || input.type === "radio" ? (input.checked ? "Yes" : "No") : input.value);
    return [value, ...fields].filter(Boolean).join(" ");
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
    day.textContent = dates.format(date);
    const hour = document.createElement("small");
    hour.textContent = `${times.format(date)} UTC`;
    time.append(day, " ", hour);
    cell.replaceChildren(time);
  }

  refresh(initial = false) {
    this.observer.disconnect();
    this.clearHighlights();
    this.records ||= this.cells.map(() => ({}));
    this.cells.forEach((row, index) => row.forEach(({span}, column) => { this.records[index][this.keys[column]] = this.cellValue(span); }));
    const columns = initial ? this.names.map((label, column) => {
      const rich = this.cells.some(row => row[column]?.rich);
      const hasActions = this.cells.some(row => row[column]?.span.querySelector("button, form"));
      const isDate = this.cells.some(row => row[column]?.span.querySelector("time"));
      return {
        key: this.keys[column], label, maxLength: 0,
        ...(hasActions ? {width: 240, sortable: false, filterable: false} : {}),
        ...(isDate ? {width: 195, format: value => {
          const date = new Date(value);
          return Number.isNaN(date.getTime()) ? value : `${dates.format(date)} ${times.format(date)} UTC`;
        }} : {}),
        ...(rich ? {render: (value, record) => {
          const index = this.records.indexOf(record);
          const slot = document.createElement("slot");
          slot.name = this.cells[index][column].span.slot;
          return slot;
        }} : {}),
      };
    }) : null;
    const selection = this.selectedKeys;
    const page = this.page;
    this.setRecords(this.records, columns);
    this.selected = new Set(selection);
    this.page = page;
    this.watch();
  }

  cellContent(column, row, inDetail = false) {
    // A slot can display its original input/button only once. Details show the
    // complete value as text while the original control stays in the grid/card.
    if (inDetail && column.render) return document.createTextNode(row[column.key] ?? "");
    return super.cellContent(column, row, inDetail);
  }

  renderGrid() {
    this.mutate(() => {
      super.renderGrid();
      this.clearHighlights();
      if (this.query) this.highlightSlots();
    });
  }

  refreshRows() {
    this.mutate(() => {
      this.clearHighlights();
      super.refreshRows();
      if (this.query) this.highlightSlots();
    });
  }

  highlight(root) {
    this.mutate(() => {
      super.highlight(root);
      this.clearHighlights();
      if (this.query) this.highlightSlots();
    });
  }

  mutate(callback) {
    this.mutating = (this.mutating || 0) + 1;
    this.observer?.disconnect();
    try {
      return callback();
    } finally {
      this.mutating -= 1;
      this.watch();
    }
  }

  clearHighlights() {
    this.querySelectorAll("mark[data-table-match]").forEach(mark => {
      const parent = mark.parentNode;
      mark.replaceWith(...mark.childNodes);
      parent.normalize();
    });
  }

  highlightSlots() {
    const needle = this.query.toLowerCase();
    for (const span of this.querySelectorAll(".application-cell")) {
      const walker = document.createTreeWalker(span, NodeFilter.SHOW_TEXT);
      const texts = [];
      while (walker.nextNode()) if (!walker.currentNode.parentElement.closest("input, textarea, select, script, style")) texts.push(walker.currentNode);
      for (const node of texts) {
        const value = node.textContent;
        let start = 0;
        let index = value.toLowerCase().indexOf(needle);
        if (index < 0) continue;
        const fragment = document.createDocumentFragment();
        while (index >= 0) {
          fragment.append(value.slice(start, index));
          const mark = document.createElement("mark");
          mark.dataset.tableMatch = "";
          mark.textContent = value.slice(index, index + needle.length);
          fragment.append(mark);
          start = index + needle.length;
          index = value.toLowerCase().indexOf(needle, start);
        }
        fragment.append(value.slice(start));
        node.replaceWith(fragment);
      }
    }
  }

  restore() {
    this.observer.disconnect();
    this.removeEventListener("change", this.onChange);
    this.clearHighlights();
    this.cells.forEach(row => row.forEach(({cell, span}) => cell.append(...span.childNodes)));
  }
}

customElements.define("application-table", ApplicationTable);
