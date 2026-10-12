# Vitrine assets

Locally hosted OpenAPI component from https://github.com/ecrou-exact/vitrine,
commit `7c379edba7ffb89abcae01b0806f20ed43dbc627` (MIT).

Built with Node 24 using the upstream lockfile: `npm ci && npm run build`.
Included: `dist/esm/vt-openapi.js`, its static import dependencies, and
`dist/vendor/yaml.js`. Preserve the dist directory layout for lazy YAML loading.
Source maps were omitted. See LICENSE and THIRD_PARTY_NOTICES.md for attribution.
No Node build is needed to run CPE Editor; these assets are served by Flask.

The editor stylesheet adopts Vitrine's light/dark palette, flat surfaces, thin
borders, and compact controls while retaining the existing Inter font.
