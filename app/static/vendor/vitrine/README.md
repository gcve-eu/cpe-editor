# Vitrine assets

Locally hosted OpenAPI component from https://github.com/ecrou-exact/vitrine,
commit `7c379edba7ffb89abcae01b0806f20ed43dbc627` (MIT).

Built with Node 24 using the upstream lockfile: `npm ci && npm run build`.
Included: `dist/esm/vt-openapi.js`, its static import dependencies, and
`dist/vendor/yaml.js`. Preserve the dist directory layout for lazy YAML loading.
Source maps were omitted. See LICENSE and THIRD_PARTY_NOTICES.md for attribution.
No Node build is needed to run CPE Editor; these assets are served by Flask.

`esm/vt-csv.js` is an additional standalone bundle from the same pinned commit.
It loads only when the GCVE lookup's data tools are opened. It provides typed
sorting, page-local search, CSV copy/download, raw view and fullscreen. The
linked results table keeps full summaries; Vitrine previews cells up to 1,000
characters, while its raw view and exports keep their complete contents.

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
