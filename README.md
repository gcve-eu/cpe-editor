# CPE Editor

A modern Flask application for browsing, curating, and publishing CPE (Common Platform Enumeration) data with a built-in moderation workflow, API access, and dataset portability.

<img width="1359" height="1019" alt="CPE Editor Screenshot" src="https://github.com/user-attachments/assets/4ac173f1-d8ea-4480-be5c-3a13e9ca9d70" />

## Highlights

- **Fast catalog browsing** for vendors, products, and CPE entries.
- **Powerful search** across names, titles, versions, and full CPE URIs.
- **Structured proposals** for edits, additions, and relationship changes.
- **Moderation dashboard** for reviewing and approving submitted changes.
- **Approved change feed** with dedicated pages plus RSS/Atom endpoints.
- **Read-only OpenAPI interface** with interactive Swagger docs.
- **NVD feed ingestion** for both CPE and CPE Match archives.
- **PURL → CPE mapping import (`import-purl2cpe`)** with optional replace mode and auto-creation of missing vendor/product/CPE records.
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

## OpenAPI interface

- Swagger UI: `GET /api/docs`
- OpenAPI spec: `GET /api/openapi.yaml`

Documented endpoints include:

- `GET /api/vendors`
- `GET /api/vendors/{vendor_uuid}`
- `GET /api/vendors/suggest`
- `GET /api/products/{product_uuid}`
- `GET /api/products/suggest`
- `GET /api/cpes`
- `GET /api/cpes/{cpe_id}`
- `GET /api/cpes/{cpe_id}/vulnerability-references`
- `GET /api/vulnerability-references`

### Quick API examples

```bash
curl "http://127.0.0.1:5000/api/vendors?page=1&per_page=5"
curl "http://127.0.0.1:5000/api/cpes?vendor_q=microsoft&part=a&per_page=10"
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
