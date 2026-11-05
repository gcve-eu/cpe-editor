# Vitrine assets

Locally hosted components from https://github.com/ecrou-exact/vitrine (MIT):

- OpenAPI: commit `e7db1ebd587b27f41988a0da9785310eaa6f2f08`.
  Included: `esm/vt-openapi.js` and `esm/chunks/` copied from upstream's
  `dist/` (`node scripts/build.js`), and `vendor/yaml.js`. Preserve the
  directory layout for lazy YAML loading.
- Tables: commit `e7db1ebd587b27f41988a0da9785310eaa6f2f08` (2026-11-04),
  including both new `<vt-table>` commits. `esm/vt-table.js` is a standalone
  bundle. It replaces the previous `vt-csv.js` integration.

Built with Node 24 using the upstream lockfile. Source maps were omitted.
LICENSE and THIRD_PARTY_NOTICES.md cover both bundles; the dependency notices
are unchanged at the table revision. No Node build is needed to run CPE Editor.

The November table component supplies multi-column sorting, typed column
filters, AND/OR condition chips, grouping, row details, selection with CSV/JSON
exports, column visibility/order/width/pinning, footer aggregates, density,
numbered pagination with page-size controls, mobile cards, keyboard navigation,
fullscreen and saved layouts. Editing stays off: record changes use proposals.
Application and GCVE tables set `sticky-header="false"` and omit `max-height`
to disable Vitrine's default bounded table viewport. Tables, mobile cards, Raw
CSV and native fallbacks grow with their content; the document handles vertical
scrolling. Horizontal scrolling and pagination remain available. Fullscreen
tables retain internal scrolling to fit the screen.

`app/static/js/editor-table.js` extends `VtTable` with application policy:
Raw CSV, full-loaded-page copy/download, and spreadsheet formula protection
(including whitespace/control prefixes) for both CSV and clipboard TSV. Selection
exports contain the selected rows. Hidden form fields never enter the dataset.
JSON content also passes through Vitrine's existing size guard, including when
using the `data` property. Raw CSV includes all fields, including hidden columns.

`app/static/js/application-table.js` slots original cell contents into Vitrine's
grid/cards. Inputs stay in light DOM under their original form, preserving form
ownership, checkbox state and button handlers. Cell render callbacks insert
slots; details show complete values without duplicating controls. Input and text
changes refresh the dataset. Exact ISO timestamps remain in exports while UTC
dates/times are displayed on separate lines. `table-tools.js` discovers static
and dynamic tables; Swagger/OpenAPI and specialized tuple results are excluded.
If loading fails the native table stays available. A `vt-error` (including content
size rejection) restores original cells and all rows in an accessible scroll box.

`app/static/js/gcve-results-table.js` uses the same base class for tuple lookups,
with safe record renderers for linked IDs, source badges and full summaries.
GCVE URLs remain in Raw CSV and exports, and the column chooser can reveal them.
Changing tuples still clears earlier results. Application and GCVE tables save
layout preferences per page in localStorage, using Vitrine's normal persistence.

To rebuild the table bundle, check out its pinned upstream revision and run
`npm ci` there (using its upstream lockfile), then from the CPE Editor root:

```sh
node tools/build_vitrine_table.mjs /path/to/vitrine
```

The standalone build leaves the OpenAPI shared chunks intact. Rerun application
and GCVE browser regressions when updating Vitrine: the adapters also hook table
render/search refreshes to preserve slotted content and highlighting.

## Content components

`content/` is built from the same `e7db1ebd587b27f41988a0da9785310eaa6f2f08`
revision. It contains `<vt-code>`, `<vt-json>`, `<vt-markdown>`, `<vt-diff>` and
`<vt-chart>` with a shared ESM chunk. ECharts and highlight.js language modules
are separate lazy assets. Their existing licenses are covered by
THIRD_PARTY_NOTICES.md. Rebuild with:

```sh
node tools/build_vitrine_content.mjs /path/to/vitrine
```

The build follows upstream's ECharts Trusted Types transformation and preserves
the relative `esm/`, `vendor/` and `languages/` layout. `content-views.js` imports
components only when visible or expanded. JSON inspectors fetch existing
same-origin API responses on demand; exact response text goes into `<vt-json>`.
Native form controls remain authoritative. The admin "Ingest single JSON object"
form edits in a `<vt-json mode="edit">` (`admin-json-editor.js`) that copies its
text into the native textarea, which is what gets submitted and stays visible if
the component cannot load. Markdown previews are read-only,
disable raw HTML and block images. Failed modules restore the native text or
statistics, and JSON validation errors remain visible while typing.

`StatisticsChart` uses the shared CSV guard from `export-text.js` for both copy
and download, including whitespace/control-prefixed formula markers. Chart data
comes from the same values as the server-rendered bars. ECharts loads only for
visible charts, and an engine import failure leaves the native values available.
Proposal diffs are built without writes and shown only for pending proposals;
they are not a stored historical before/after snapshot. The new content views
follow the page theme and expand with their content.

The editor stylesheet adopts Vitrine's light/dark palette, flat surfaces, thin
borders, and the native UI and monospace fonts shared with GCVE Patch2Vuln.
