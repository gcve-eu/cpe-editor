# Vitrine assets

Locally hosted components from https://github.com/ecrou-exact/vitrine (MIT):

- OpenAPI: commit `7c379edba7ffb89abcae01b0806f20ed43dbc627`.
  Included: `esm/vt-openapi.js`, its static import dependencies, and
  `vendor/yaml.js`. Preserve the directory layout for lazy YAML loading.
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

The editor stylesheet adopts Vitrine's light/dark palette, flat surfaces, thin
borders, and the native UI and monospace fonts shared with GCVE Patch2Vuln.
