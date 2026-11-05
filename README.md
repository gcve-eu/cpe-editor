# CPE Editor

A modern Flask application for browsing, curating, and publishing CPE (Common Platform Enumeration) data with a built-in moderation workflow, API access, and dataset portability.

<img width="1882" height="1349" alt="Screenshot from 2026-10-13 14-59-09" src="https://github.com/user-attachments/assets/9b278c7e-35f4-41a2-8a52-eaa0cab44d6c" />
<img width="1882" height="1349" alt="Screenshot from 2026-10-13 14-59-42" src="https://github.com/user-attachments/assets/fb6938d1-0fcb-4a82-8d9e-45b71674fc9b" />
<img width="1882" height="1349" alt="Screenshot from 2026-10-13 15-00-00" src="https://github.com/user-attachments/assets/a9e24fb2-ca54-4e03-8943-36d138fc1cd0" />

The online version is available at [https://cpe.gcve.eu](https://cpe.gcve.eu/).

## Highlights

- **Fast catalog browsing** for vendors, products, and CPE entries.
- **Powerful search** across names, titles, versions, and full CPE URIs.
- **Structured proposals** for edits, additions, and relationship changes.
- **Moderation dashboard** for reviewing and approving submitted changes.
- **Approved change feed** with dedicated pages plus RSS/Atom endpoints.
- **Read-only OpenAPI interface** with interactive Swagger docs.
- **Vitrine table controls throughout the application**: multi-column sorting,
  column filters, AND/OR conditions, grouping, selection exports, column controls,
  mobile cards, Raw CSV and fullscreen.
- **NVD feed ingestion** for both CPE and CPE Match archives.
- **PURL → CPE mapping import (`import-purl2cpe`)** with optional replace mode and auto-creation of missing vendor/product/CPE records.
- **GCVE enriched CVE dump import (`import-gcve-enriched-cves`)** for CVE→CPE references plus missing vendor/product/CPE records.
- **CPE vulnerability reference proposals** (CVE/GCVE/GHSA + `cpeApplicability`) in the public contribution workflow.
- **Entity note proposals** for adding structured context without directly editing canonical records.
- **Portable dataset export/import** to migrate curated data between instances.
- **Stable deterministic UUIDs** for vendor and product identity consistency.

## Core capabilities

### Public experience

- Browse vendors, products, and CPE records.
- Every application table, including directories, CPE search, record fields,
  aliases, statistics, moderation and API clients, uses Vitrine's full table
  controls. They also apply to dynamically loaded CPE vulnerability results.
  Tables use the November 4 Vitrine `<vt-table>` component: Shift-click adds sort
  columns; filters accept comparisons/ranges; condition chips combine with AND
  or OR. Use column menus for grouping, pinning and aggregates, and **Columns**
  to hide, show or reorder fields. Resize columns by dragging their edges.
  Row selection adds CSV/JSON export actions. Density, page size, keyboard help,
  expandable details and saved layouts are available; small screens use cards.
  Links, action buttons and form selections remain active after sorting or
  filtering; selected rows stay included when submitting a form while hidden.
  Search/sort operate on loaded rows, with 25 rows per local table page.
  Copy/download include all loaded rows, even rows hidden by a search or local
  paging; selection exports include selected records. Clipboard output is TSV
  for spreadsheets; **Raw** shows CSV. Existing server page links fetch more
  records; **Export all matching … (JSON)** downloads every match across server
  pages. CSV exports omit hidden form fields and guard spreadsheet formula
  markers. Dates use readable UTC
  date/time lines, with exact timestamps on hover and in CSV. Tables expand to
  show the full height of the current page, including mobile cards and Raw CSV;
  use the page scrollbar to read them. Wide tables can scroll horizontally.
  Fullscreen tables scroll inside the available screen. Tables remain usable if
  the component cannot load or rejects oversized content.
- Drill into vendor/product detail pages and linked relationships.
- Expand **Inspect record JSON** on vendor, product, CPE, alias and approved
  change pages to browse the API response as a tree or raw JSON, search keys and
  values, copy paths/values and download the record. Statistics have the same
  inspector. Records are fetched only when the panel is opened.
- CPE identifiers have code-view copy, search, download and fullscreen controls.
  Approved notes and descriptions use Markdown with a source view; note and
  description forms offer live previews while submitting the original text.
  Raw HTML stays literal and images are blocked. The admin JSON ingestion form
  has a read-only tree/raw preview with validation feedback.
- Statistics distributions offer interactive bar charts, keyboard value
  navigation, an accessible data table, CSV copy/download and fullscreen.
  Chart exports guard spreadsheet formula markers in labels. Components load
  when opened or brought into view, with the original content as a fallback.
- Combined views follow approved `synonym-of`, `canonical-of`, `equivalent-to`,
  `renamed-to`, and `vendor-merge-into` relationships in either direction, including
  chains. Vendor views combine products; product views combine CPE entries from
  linked products and same-token products under related vendors. Vendor
  `superseded-by` relationships also combine vendor catalogs and connect same-token
  products under those vendors, including in the graph views. Product
  `superseded-by` and all `derived-from` relationships remain visible as graph
  edges without combining their records.
- Expand the **Relationship graph** on vendor, product, and alias detail pages to explore
  approved relationships alongside the combined view. The read-only [Pivotick](https://github.com/Pivotick/Pivotick)
  graph supports pan, zoom, node inspection, and links to the original records.
  Its **Simplify graph** toolbar control opens a popover with Pivotick's rules to group repeated
  neighbours or chains and fold nodes with few links or outside the core. Rules
  start off and can be toggled or adjusted for the current view without changing
  records; double-click a group to open it. The record picker keeps every record.
  Product and alias graphs also include CPE entries. Alias graphs link the alias
  to its member products and their vendors. It loads on demand and shows a notice
  when the 200-record / 400-link limit omits data. Existing lists remain available.
- Submit anonymous proposals to:
  - edit an existing CPE
  - add a CPE to an existing vendor/product
  - add a product to an existing vendor
  - add a new vendor and product
  - propose a CPE vulnerability reference (CVE/GCVE/GHSA + cpeApplicability)
  - attach note proposals to entities
- Explore the approved change history and detail pages.
- Run **GCVE vulnerability lookup** from vendor and product detail pages. Select
  a vendor/product tuple from the record or its combined view to fetch matching
  vulnerabilities on demand from db.gcve.eu, across versions. Products without
  CPE entries can be searched too. Results link to GCVE and offer previous/next
  pages; changing the tuple clears the previous results. GCVE lookups do not
  modify local records or create vulnerability references.
  The lookup table keeps identifiers and headers intact, shows dates and UTC
  times on separate lines (with the original timestamp on hover), and expands
  to its full height within the page. On phones, rows stack into cards
  so the identifier, date and summary can be read without sideways scrolling.
  The same table includes Vitrine's multi-column sorting, filters, grouping,
  selection/column controls, raw CSV, copy/download and fullscreen. Full summaries and clickable
  vulnerability identifiers stay available after sorting and filtering.
  Search also recognizes formatted dates and readable source labels.
  On phones, a **Sort by** selector controls the card order. Use the GCVE
  Previous/Next controls to fetch more results. Copy/download keep all rows on
  the current page, including rows hidden by a local search. The table component
  loads after a lookup; a readable linked table remains if it cannot load.
  CSV values that start with a spreadsheet formula marker (`=`, `+`, `-`, or
  `@`), including after whitespace/control characters, are prefixed with an
  apostrophe before CSV quoting so copy/download treat them as text.

### Moderation and operations

- Admin login and protected review workflows.
- Pending CPE/note updates and new record proposals have unified/side-by-side
  diffs with change navigation, search and patch downloads. These compare the
  current record or empty starting point with submitted values without changing
  records; completed proposals do not claim to show a historical comparison.
- Accept/reject proposal queue with server-side application of accepted updates.
- Optional request rate limiting for anonymous submissions.
- Built-in CSRF token handling for form submissions.
- SQLite optimization defaults (WAL mode, busy timeout, reindex support).

### API and integrations

- OpenAPI spec endpoint and Swagger UI.
- Search and pagination for API list endpoints.
- Vendor/product suggestion endpoints for picker-style UIs.
- Import/export commands for offline transfer and environment bootstrapping.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m flask --app run init-db --drop
python run.py
```

Then open the local URL printed by Flask.

### Production start

Use the dedicated WSGI entry point with a production WSGI server instead of the Flask debug server:

```bash
./start.py
```

The start script runs Gunicorn against `wsgi:app` and binds to all IPv4 and IPv6 addresses on `PORT` (default `5000`). It uses production-oriented defaults for concurrency and request handling: `gthread` workers, `WEB_CONCURRENCY` defaulting to `(CPU * 2) + 1`, four threads per worker, worker recycling, access/error logs on stdout/stderr, and a larger connection backlog. You can pass additional Gunicorn options after the script name; command-line arguments are appended last so they can override the defaults:

```bash
PORT=5000 WEB_CONCURRENCY=4 GUNICORN_THREADS=8 ./start.py --timeout 90
```

Access logs include the `X-Forwarded-For` request header by default so deployments behind a proxy can see the original client IP; set `GUNICORN_ACCESS_LOGFORMAT` to override the format.

Set `HOST_IPV6=` to disable the IPv6 listener in environments without IPv6 support.

The `wsgi.py` entry point creates the Flask application without enabling debug mode.

### Configuration (environment variables)

- `DATABASE_URL`
- `SECRET_KEY`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `PROPOSAL_RATE_LIMIT_PER_HOUR` (default `10`; set `0` or negative to disable)
- `SQLITE_BUSY_TIMEOUT_SECONDS` (default `30`)
- `VALKEY_URL` (default `redis://127.0.0.1:6379/0`; set empty to disable caching)
- `STATISTICS_CACHE_TTL_SECONDS` (default `300`; set `0` or negative to disable statistics caching)
- `EXPORT_CACHE_TTL_SECONDS` (default `3600`; set `0` or negative to disable export caching)
- `EXPORT_CACHE_MAX_BYTES` (default `4194304`, 4 MiB per JSON artifact; larger exports bypass caching)
- `EXPORT_CACHE_SLOTS` (default `64`; maximum number of cached export snapshots; set `0` to disable)

The statistics page and `/api/statistics` share a cached snapshot, including
record coverage, distributions, and a UTC `generated_at` timestamp. Vendor and
product rankings are cached separately by entity, page, and page size. Changes
appear after the cache TTL expires; if Valkey is unavailable, statistics are
computed directly from the database. Coverage counts distinct records, while
mapping and reference totals count individual links. All CPE totals include
deprecated records. Charts and their numeric labels work without JavaScript.

## Web routes

- Home: `GET /`
- Vendors: `GET /vendors`
- Products: `GET /products` (search with `q`; sort by `name` or `cpes`)
- Vendor detail: `GET /vendors/{vendor_uuid}`
- Product detail: `GET /products/{product_uuid}`
- Vendor graph data: `GET /vendors/{vendor_uuid}/graph`
- Product graph data: `GET /products/{product_uuid}/graph`
- Alias graph data: `GET /aliases/{alias_uuid}/graph`
- CPE detail: `GET /cpes/{cpe_id}`
- Statistics: `GET /statistics`
- Proposal form: `GET|POST /proposals/new`
- Note proposal form: `GET|POST /proposals/note/new`
- Approved changes: `GET /changes`
- Approved change detail: `GET /changes/{proposal_id}`
- RSS feed: `GET /changes.rss`
- Atom feed: `GET /changes.atom`
- Vendor change feeds: `GET /vendors/{vendor_uuid}/changes.rss`, `GET /vendors/{vendor_uuid}/changes.atom`
- Product change feeds: `GET /products/{product_uuid}/changes.rss`, `GET /products/{product_uuid}/changes.atom`
- CPE change feeds: `GET /cpes/{cpe_id}/changes.rss`, `GET /cpes/{cpe_id}/changes.atom`

## OpenAPI interface

- Swagger UI: `GET /api/docs`
- OpenAPI spec: `GET /api/openapi.yaml`

Documented endpoints include:

- `GET /api/vendors`
- `GET /api/vendors/export`
- `GET /api/vendors/{vendor_uuid}`
- `GET /api/vendors/suggest`
- `GET /api/products`
- `GET /api/products/export`
- `GET /api/products/{product_uuid}`
- `GET /api/products/suggest`
- `GET /api/changes`
- `GET /api/changes/{proposal_id}`
- `GET /api/cpes`
- `GET /api/cpes/export`
- `GET /api/cpes/{cpe_id}`
- `GET /api/cpes/{cpe_id}/vulnerability-references`
- `GET /api/gcve/search?vendor=VENDOR&product=PRODUCT&page=1&per_page=25`
- `GET /api/vulnerability-references`

### Quick API examples

```bash
curl "http://127.0.0.1:5000/api/vendors?page=1&per_page=5"
curl "http://127.0.0.1:5000/api/products?q=windows&page=1&per_page=5"
curl "http://127.0.0.1:5000/api/cpes?vendor_q=microsoft&part=a&per_page=10"
curl "http://127.0.0.1:5000/api/changes?per_page=10"
```

Product and CPE lists support the same combined vendor scope as their exports:
pass `vendor_uuid=VENDOR_UUID&combined=true` to `/api/products` or `/api/cpes`.
This follows approved vendor relationships, including `superseded-by`, in either
direction and through chains. Each record appears once with its original vendor
and product UUIDs. Search filters intersect the scope; `page`, `per_page`, `total`,
and `total_pages` describe the combined results. CPE lists also accept an exact
`product_uuid`, which intersects any vendor scope. Without `combined=true`, UUID
filters remain exact. Unknown valid UUIDs return empty lists; malformed UUIDs,
invalid `combined` values, and `combined=true` without `vendor_uuid` return 400.
These parameters are available in the Swagger request console at `/api/docs`.

```bash
curl "http://127.0.0.1:5000/api/products?vendor_uuid=VENDOR_UUID&combined=true&per_page=25"
curl "http://127.0.0.1:5000/api/cpes?vendor_uuid=VENDOR_UUID&combined=true&part=o&page=1"
```

### Bulk JSON exports

Download all matching records with `GET /api/vendors/export`,
`GET /api/products/export`, or `GET /api/cpes/export`. These public endpoints
return a JSON attachment containing `entity`, `filters`, `generated_at`, `total`,
and `items`. Items use the same fields as the existing detail API. Exports
include all matches, including deprecated CPEs, and ignore pagination and sorting
parameters. With no filters, they export the entire entity collection.

The vendor and product directories show **Export all matching … (JSON)** only
after a search filter is applied. Empty and wildcard-only searches, sorting and
pagination do not enable this download. The link includes the active search;
individual record downloads and vendor/product-scoped exports remain available.

Vendor and product exports support the existing `q` substring search on name
and title. Product exports also accept an exact `vendor_uuid`. CPE exports
support `q`, `vendor_q`, `product_q`, `purl_q`, and `part` with the existing search
semantics, plus exact `vendor_uuid` and `product_uuid` filters. Filters combine
with AND. Invalid UUIDs or CPE parts return 400; valid filters without matches
return an empty export. CPE exports include PURL mappings and vulnerability
references. Vendor/product exports contain their own records; use a scoped CPE
export to download their CPEs.

For product and CPE exports, add `combined=true` with `vendor_uuid` to include
all products from the vendor's combined view, or all CPEs belonging to those
products. This follows the same approved vendor relationships in both
directions and through chains, without duplicates. Other filters still combine
with AND; `product_uuid` remains exact. Omitting `combined` (or setting it to
`false`) keeps exact vendor scoping. Combined exports use separate cache snapshots.

```bash
curl -OJ "http://127.0.0.1:5000/api/vendors/export?q=micro"
curl -OJ "http://127.0.0.1:5000/api/products/export?vendor_uuid=VENDOR_UUID"
curl -OJ "http://127.0.0.1:5000/api/cpes/export?vendor_uuid=VENDOR_UUID&combined=true"
curl -OJ "http://127.0.0.1:5000/api/cpes/export?product_uuid=PRODUCT_UUID"
curl -OJ "http://127.0.0.1:5000/api/cpes/export?vendor_q=microsoft&part=o"
```

The vendor/product directories and CPE search page offer **Export all matching**
downloads that preserve current filters across all pages. Vendor details also
offer all-product and all-CPE downloads that include the combined products view;
product details offer all-CPE downloads.

Exports are serialized incrementally to temporary files and downloaded in bounded
chunks, so a full-catalog download does not retain the full result in worker
memory. Temporary files are closed after the download, on cancellation, or if
generation fails.

Valkey stores eligible entity/filter snapshots for one hour by default.
Equivalent requests (including reordered parameters, surrounding whitespace,
text case, and redundant SQL `LIKE` percent wildcards in `q`) share a cache entry.
For example, `q=%`, `q=%%`, and no `q` reuse the same full-catalog snapshot.
Cache hits do not query the database and do not extend expiry.
`generated_at` identifies the snapshot, and `X-Export-Cache` reports `HIT`,
`MISS` (generated and cached), or `BYPASS` (generated without caching). Changes
appear after expiry or cache eviction. Export caching is independent of the
statistics TTL. If Valkey is unavailable or caching is disabled, exports are
generated directly.

To bound storage for these public endpoints, only artifacts up to 4 MiB are
cached by default, in 64 shared slots across all export entities (at most
256 MiB of artifact data, plus small key/fingerprint overhead). A slot collision
evicts the previous snapshot; full fingerprints prevent serving another query's
data. Larger exports still download completely from disk with `BYPASS`. Adjust
`EXPORT_CACHE_MAX_BYTES` and `EXPORT_CACHE_SLOTS` to change this budget. Existing
entries expire naturally when reducing these settings.

### Faster CPE partial searches (SQLite)

`GET /api/cpes?q=...` searches substrings in CPE URIs, titles, versions, and
vendor/product names and titles. It filters matching CPE IDs before joining the
page to its vendor and product, preserving exact totals and pagination.

To accelerate substring searches on a large SQLite catalog, build the optional
FTS5 trigram index once after upgrading, preferably outside busy import periods:

```bash
python -m flask --app run rebuild-cpe-search-index
```

This requires SQLite with FTS5 and the trigram tokenizer (SQLite 3.34 or newer).
The command indexes existing CPE URIs, titles, and versions; database triggers
keep the index current for subsequent inserts, updates, deletes, and imports.
Existing server workers detect the index without a restart. Re-running the
command rebuilds it. Building the index takes a SQLite write lock and uses
additional disk space; the index also adds work to catalog writes. No large
index build runs during server startup.

Queries with a literal run of at least three characters use the index to narrow
CPE candidates, then apply the original case-insensitive substring checks.
Vendor and product text is searched separately and mapped through foreign-key
indexes. Shorter searches, patterns without a three-character literal run, and
databases without the index use the regular search path. Existing `%` and `_`
wildcard behavior, response fields, prefix filters, and page ordering are retained.
For narrower searches, combine `q` with `vendor_q`, `product_q`, `part`, or `purl_q`.

## Running API tests

A focused API regression suite is included under `tests/` and uses a very small CPE fixture (`tests/fixtures/cpe_subset.json`) representing a tiny subset of real-world CPE-style records (vendors, products, CPE URIs, and vulnerability links).

Run locally:

```bash
pytest -q
```

CI runs this same suite via `.github/workflows/api-tests.yml`.

The optional `tests/test_graph_tooltips_browser.py` regression also checks pinned
tooltips in Chromium. Install `playwright` and run `playwright install chromium`
to enable it; an installed `chromium` or `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH`
can also supply the browser. It is skipped when Playwright or Chromium is absent.

## CLI commands

### Database lifecycle

Initialize schema:

```bash
python -m flask --app run init-db
```

Reset schema/data:

```bash
python -m flask --app run init-db --drop
```

Add missing columns without dropping existing rows:

```bash
python -m flask --app run init-db --alter
```

Rebuild indexes (and planner stats by default):

```bash
python -m flask --app run reindex-db
```

Skip `ANALYZE` during reindex:

```bash
python -m flask --app run reindex-db --no-analyze
```

### Import NVD CPE feed

```bash
python -m flask --app run import-nvd-cpes
```

From a local archive:

```bash
python -m flask --app run import-nvd-cpes --source /path/to/nvdcpe-2.0.tar.gz
```

Imports can be rerun against an existing database. UUID conflicts are skipped and
reported as `uuid-conflicts` in the final summary; other rows in the batch are
preserved. Legacy vendor/product UUIDs are retained when assigning their
deterministic UUID would collide with another row.

Replace existing vendor/product/CPE data first:

```bash
python -m flask --app run import-nvd-cpes --replace
```

### Import NVD CPE Match feed

```bash
python -m flask --app run import-nvd-cpematches
```

From a local archive:

```bash
python -m flask --app run import-nvd-cpematches --source /path/to/nvdcpematch-2.0.tar.gz
```

### Import PURL → CPE mappings (purl2cpe)

Import mappings from a local clone of [`scanoss/purl2cpe`](https://github.com/scanoss/purl2cpe).  
By default, the command expects the repository at `../purl2cpe` relative to `cpe-editor`.
If a CPE from `purl2cpe` does not exist locally yet, the importer will create the vendor, product, and CPE entry first.

```bash
python -m flask --app run import-purl2cpe
```

Use a custom clone path:

```bash
python -m flask --app run import-purl2cpe --source /path/to/purl2cpe
```

Replace existing CPE↔PURL mappings first:

```bash
python -m flask --app run import-purl2cpe --replace
```

### Import GCVE enriched CVE dumps

Import CVE→CPE vulnerability references from a local clone of [`CVEProject/gcve-enriched-dumps`](https://github.com/CVEProject/gcve-enriched-dumps).
By default, the command expects the repository at `../gcve-enriched-dumps` relative to `cpe-editor`. The source can point either at the repository root or directly at its `cves` directory.
If an imported CPE does not exist locally yet, the importer will create the vendor, product, and CPE entry first. Existing CVE→CPE references are left in place and duplicate references are skipped.

```bash
python -m flask --app run import-gcve-enriched-cves
```

Use a custom clone or `cves` directory path:

```bash
python -m flask --app run import-gcve-enriched-cves --source /path/to/gcve-enriched-dumps
```

Control how many CVE files are processed per transaction with `--batch-size`
(default: `2000`). The importer clears its in-memory caches after each batch, so
use a smaller value on memory-constrained systems. Smaller batches reduce peak
memory usage at the cost of more database commits:

```bash
python -m flask --app run import-gcve-enriched-cves --batch-size 500
```

### Export dataset

Export vendors, products, relationships, and CPE entries:

```bash
python -m flask --app run export-app-dataset
```

Custom output path:

```bash
python -m flask --app run export-app-dataset --output /path/to/cpe-editor-dataset.tar.gz
```

Include proposals:

```bash
python -m flask --app run export-app-dataset --include-proposals
```

### Export dataset for git storage

Convert a portable app export into a deterministic directory tree that can be
committed to a git repository without rewriting one large JSON blob on every
change:

```bash
python tools/export_dataset_to_git.py /path/to/cpe-editor-dataset.tar.gz /path/to/git-dataset
```

If the destination already exists, the tool updates the generated files in place
without deleting the destination directory, so repository metadata such as `.git`
is preserved. Stale generated files are removed from the managed dataset paths.

The generated layout includes `manifest.json`, one JSON file per vendor/product,
sharded CPE JSON Lines files under `cpes/<vendor>/<product>/<part>.jsonl`, and
separate JSON Lines shards for metadata, relationships, PURL mappings, and
proposals.

### Convert exported dataset to single NDJSON

Convert the same portable app export into one newline-delimited JSON file for
streaming data pipelines or tools that prefer a single append-style file:

```bash
python tools/export_dataset_to_jsonl.py /path/to/cpe-editor-dataset.tar.gz /path/to/cpe-editor-dataset.ndjson
```

The converter accepts either the `.tar.gz` export or a plain `dataset.json` file.
It parses each top-level record array incrementally and writes one NDJSON row per
record, so memory usage is bounded by the largest individual dataset record
instead of the full export size. The first row contains dataset metadata; later
rows have `type: "record"`, `collection`, and `record` fields.

### Import exported dataset

```bash
python -m flask --app run import-app-dataset --source /path/to/cpe-editor-dataset.tar.gz
```

Replace existing data first:

```bash
python -m flask --app run import-app-dataset --source /path/to/cpe-editor-dataset.tar.gz --replace
```

Skip proposal history while importing:

```bash
python -m flask --app run import-app-dataset --source /path/to/cpe-editor-dataset.tar.gz --replace --no-proposals
```

## Data model notes

- Vendor UUIDs are deterministic UUIDv5 values based on normalized vendor names.
- Product UUIDs are deterministic UUIDv5 values based on normalized vendor+product names.
- Repeated imports keep identity stable across compatible instances.

## Development notes

A `.gitignore` is included to exclude common local artifacts like:

- SQLite files under `instance/`
- virtual environments
- Python cache files
- local import/export archives and `.env` files
