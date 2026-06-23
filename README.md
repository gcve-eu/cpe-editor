# CPE Editor

A modern Flask application for browsing, curating, and publishing CPE (Common Platform Enumeration) data with a built-in moderation workflow, API access, and dataset portability.

<img width="1213" height="1047" alt="CPE Editor - Statistics" src="https://github.com/user-attachments/assets/2ff7545e-077b-4f82-96e2-43b7d7218920" />
<img width="1213" height="1047" alt="CPE Editor - A Vendor View" src="https://github.com/user-attachments/assets/95c3c102-52e2-4612-8351-c5ff1057f74c" />


## Highlights

- **Fast catalog browsing** for vendors, products, and CPE entries.
- **Powerful search** across names, titles, versions, and full CPE URIs.
- **Structured proposals** for edits, additions, and relationship changes.
- **Moderation dashboard** for reviewing and approving submitted changes.
- **Approved change feed** with dedicated pages plus RSS/Atom endpoints.
- **Read-only OpenAPI interface** with interactive Swagger docs.
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
- Drill into vendor/product detail pages and linked relationships.
- Submit anonymous proposals to:
  - edit an existing CPE
  - add a CPE to an existing vendor/product
  - add a product to an existing vendor
  - add a new vendor and product
  - propose a CPE vulnerability reference (CVE/GCVE/GHSA + cpeApplicability)
  - attach note proposals to entities
- Explore the approved change history and detail pages.

### Moderation and operations

- Admin login and protected review workflows.
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

## Web routes

- Home: `GET /`
- Vendors: `GET /vendors`
- Vendor detail: `GET /vendors/{vendor_uuid}`
- Product detail: `GET /products/{product_uuid}`
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
- `GET /api/vendors/{vendor_uuid}`
- `GET /api/vendors/suggest`
- `GET /api/products/{product_uuid}`
- `GET /api/products/suggest`
- `GET /api/changes`
- `GET /api/changes/{proposal_id}`
- `GET /api/cpes`
- `GET /api/cpes/{cpe_id}`
- `GET /api/cpes/{cpe_id}/vulnerability-references`
- `GET /api/vulnerability-references`

### Quick API examples

```bash
curl "http://127.0.0.1:5000/api/vendors?page=1&per_page=5"
curl "http://127.0.0.1:5000/api/cpes?vendor_q=microsoft&part=a&per_page=10"
curl "http://127.0.0.1:5000/api/changes?per_page=10"
```

## Running API tests

A focused API regression suite is included under `tests/` and uses a very small CPE fixture (`tests/fixtures/cpe_subset.json`) representing a tiny subset of real-world CPE-style records (vendors, products, CPE URIs, and vulnerability links).

Run locally:

```bash
pytest -q
```

CI runs this same suite via `.github/workflows/api-tests.yml`.

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

Commit progress after a custom number of CVE files:

```bash
python -m flask --app run import-gcve-enriched-cves --batch-size 1000
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
