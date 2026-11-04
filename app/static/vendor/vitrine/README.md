# Vitrine assets

Locally hosted OpenAPI component from https://github.com/ecrou-exact/vitrine,
commit `7c379edba7ffb89abcae01b0806f20ed43dbc627` (MIT).

Built with Node 24 using the upstream lockfile: `npm ci && npm run build`.
Included: `dist/esm/vt-openapi.js`, its static import dependencies, and
`dist/vendor/yaml.js`. Preserve the dist directory layout for lazy YAML loading.
Source maps were omitted. See LICENSE and THIRD_PARTY_NOTICES.md for attribution.
No Node build is needed to run CPE Editor; these assets are served by Flask.

`esm/vt-csv.js` is an additional standalone bundle from the same pinned commit.
It loads after a GCVE lookup and provides typed sorting, page-local search,
CSV copy/download, raw view and fullscreen in the same results table.

`app/static/js/gcve-results-table.js` extends its exported `VtCsv` class. The
adapter decorates cells by their original `data-row`/`data-column` indexes,
keeping links, formatted UTC dates and full summaries attached to the correct
record after sorting/filtering. It replaces the standard 1,000-character cell
preview with complete record text, while Raw/copy/download use the guarded CSV.
The URL stays in CSV/Raw and is a clickable identifier in Table view. Mobile
rows use cards with an accessible sort selector. The browser regressions must
be rerun when updating the pinned Vitrine implementation and these hooks.

To rebuild it with Node 24, check out the pinned Vitrine commit, run `npm ci`
there (using its upstream lockfile), then from the CPE Editor root run:

```sh
node tools/build_vitrine_csv.mjs /path/to/vitrine
```

The standalone build avoids replacing the existing OpenAPI component's shared
chunks. Its dependencies are already covered by THIRD_PARTY_NOTICES.md.

The editor stylesheet adopts Vitrine's light/dark palette, flat surfaces, thin
borders, and compact controls, with the native UI and monospace fonts shared
with GCVE Patch2Vuln.
