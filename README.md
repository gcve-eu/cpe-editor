# CPE Editor 

A small Flask for a moderated CPE editor:

- anyone can search vendors, products, and CPE entries
- anyone can submit anonymous proposals
- an admin can review, accept, or reject proposals
- accepted proposals are applied to the main data tables
- a CLI importer can populate the database from the NVD CPE 2.0 feed

## What this skeleton includes

- SQLite storage with SQLAlchemy models
- vendor / product / CPE browse pages
- simple search over vendor, product, title, version, and CPE URI
- dedicated vendor/product prefix filters optimized for faster lookup
- proposal workflow for:
  - editing an existing CPE
  - adding a CPE to an existing vendor/product
  - adding a product to an existing vendor
  - adding a new vendor and product
- minimal admin login using environment variables
- CLI command to import the official NVD CPE 2.0 feed
- UUID columns on vendors and products

## What this skeleton does **not** yet include

This is intentionally a skeleton. Before production use, you should add:

- real authentication and authorization
- CSRF protection
- rate limiting / spam protection / CAPTCHA for anonymous submissions
- CPE format validation and normalization against your own rules
- a searchable product picker instead of raw `product_id` / `cpe_entry_id` fields
- duplicate detection and merge suggestions
- audit log / moderation history
- pagination and richer filters
- unit tests and migrations

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m flask --app run init-db --drop
python run.py
```

Then open the local URL printed by Flask.

Admin defaults are read from environment variables:

- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `PROPOSAL_RATE_LIMIT_PER_HOUR` (default: `10`; set to `0` or a negative value to disable rate limiting)

## OpenAPI interface

This project now includes a read-only OpenAPI interface for browsing core records.

- Swagger UI: `GET /api/docs`
- OpenAPI spec file: `GET /api/openapi.yaml`

Currently documented API endpoints:

- `GET /api/vendors` (search and pagination)
- `GET /api/vendors/{vendor_uuid}`
- `GET /api/products/{product_uuid}`
- `GET /api/cpes` (search and pagination)
- `GET /api/cpes/{cpe_id}`

### Quick API examples

```bash
curl "http://127.0.0.1:5000/api/vendors?page=1&per_page=5"
curl "http://127.0.0.1:5000/api/cpes?vendor_q=microsoft&part=a&per_page=10"
```

## Import the NVD CPE feed

The importer accepts either a URL or a local tarball path.

```bash
python -m flask --app run import-nvd-cpes
```

Or from a file you already downloaded:

```bash
python -m flask --app run import-nvd-cpes --source /path/to/nvdcpe-2.0.tar.gz
```

To replace existing vendor/product/CPE data first:

```bash
python -m flask --app run import-nvd-cpes --replace
```

What the importer does:

- reads the NVD CPE 2.0 tar.gz feed
- creates vendors and products as needed
- assigns deterministic UUIDs to vendors and products
- imports or updates CPE entries by `cpe_uri`
- stores `cpeNameId`, `deprecated`, and `deprecatedBy` when present
- backfills missing UUIDs on already-existing vendors/products

## Import the NVD CPE Match feed

The CPE Match importer reads concrete `cpeName` values from each `matchString.matches[]`
entry and imports only records that do not already exist by `cpe_uri`.

```bash
python -m flask --app run import-nvd-cpematches
```

Or from a local archive:

```bash
python -m flask --app run import-nvd-cpematches --source /path/to/nvdcpematch-2.0.tar.gz
```

## Notes about UUIDs

- `Vendor.uuid` is generated deterministically from the normalized vendor name
- `Product.uuid` is generated deterministically from `vendor + product`
- this makes repeated imports idempotent for vendor/product identity inside this app

## Rebuild indexes / refresh query stats

Use the CLI command below after large imports or bulk edits:

```bash
python -m flask --app run reindex-db
```

By default it also refreshes planner statistics (`ANALYZE`). To skip that:

```bash
python -m flask --app run reindex-db --no-analyze
```

## Important schema note

Because this skeleton still uses `db.create_all()` and does not yet include Alembic migrations, schema updates may require either:

- additive updates in-place (keeps existing rows):

```bash
python -m flask --app run init-db --alter
```

- or a full rebuild when you intentionally want a clean database:

```bash
rm -f instance/cpe_editor.db
python -m flask --app run init-db --drop
```

## Suggested next improvements

1. Replace the admin login with Flask-Login and hashed passwords.
2. Add Alembic migrations.
3. Add WTForms or another form layer with validation.
4. Add autocomplete endpoints for vendor and product lookup.
5. Validate imported and proposed CPE names more strictly.
6. Track diffs when editing existing CPE entries.
7. Add email notifications for new pending proposals.
8. Export accepted records as JSON for downstream tooling.


## Export a dataset from this app

You can export the full curated dataset from this app and let someone else bootstrap a new instance from that archive instead of re-importing the original NVD feed.

Export vendors, products, and CPE entries:

```bash
python -m flask --app run export-app-dataset
```

Choose another output file:

```bash
python -m flask --app run export-app-dataset --output /path/to/cpe-editor-dataset.tar.gz
```

Optionally include moderation proposals too:

```bash
python -m flask --app run export-app-dataset --include-proposals
```

What gets exported:

- vendors with UUIDs
- products with UUIDs and vendor linkage
- CPE entries with all parsed CPE fields and metadata
- optional proposal records
- export metadata and counts

## Import a dataset exported by this app

To bootstrap another instance from an archive created by `export-app-dataset`:

```bash
python -m flask --app run import-app-dataset --source /path/to/cpe-editor-dataset.tar.gz
```

To replace the existing local dataset first:

```bash
python -m flask --app run import-app-dataset --source /path/to/cpe-editor-dataset.tar.gz --replace
```

To skip proposal history while importing:

```bash
python -m flask --app run import-app-dataset --source /path/to/cpe-editor-dataset.tar.gz --replace --no-proposals
```

Import behavior:

- vendors are matched by UUID first, then by name
- products are matched by UUID first, then by `(vendor, name)`
- CPE entries are matched by `cpe_uri`, then by `cpeNameId` when available
- the imported dataset keeps vendor/product UUIDs stable across instances

## Suggested git ignore behavior

A `.gitignore` is included and ignores:

- local SQLite databases under `instance/`
- virtual environments
- Python cache files
- local export/import archives and environment files
