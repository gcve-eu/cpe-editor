from __future__ import annotations

import io
import json
import tarfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import click
from sqlalchemy import inspect, schema, text

from .models import (
    CPEEntry,
    CPEVulnerabilityReference,
    EntityMetadata,
    EntityRelationship,
    Product,
    Proposal,
    Vendor,
    db,
)
from .utils import parse_cpe23_uri, product_uuid_for_names, vendor_uuid_for_name

DEFAULT_NVD_CPE_FEED = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"
DEFAULT_NVD_CPE_MATCH_FEED = (
    "https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.tar.gz"
)
APP_DATASET_VERSION = "1"


def _render_default_literal(value):
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    if value is None:
        return "NULL"
    escaped = str(value).replace("'", "''")
    return f"'{escaped}'"


def _add_missing_columns(engine):
    """Add model columns that are missing from existing tables without dropping data."""
    inspector = inspect(engine)
    added = 0
    skipped = []

    for table in db.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue

        existing_columns = {col["name"] for col in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing_columns:
                continue

            if not column.nullable and column.server_default is None:
                default = None
                if column.default is not None and getattr(column.default, "is_scalar", False):
                    default = _render_default_literal(column.default.arg)

                if default is None:
                    skipped.append(f"{table.name}.{column.name}")
                    continue

                column_sql = f"{column.name} {column.type.compile(dialect=engine.dialect)} DEFAULT {default} NOT NULL"
            else:
                column_sql = str(schema.CreateColumn(column).compile(dialect=engine.dialect)).strip()

            db.session.execute(text(f"ALTER TABLE {table.name} ADD COLUMN {column_sql}"))
            added += 1

    if added:
        db.session.commit()

    return added, skipped


def register_cli(app):
    @app.cli.command("init-db")
    @click.option("--drop", is_flag=True, help="Drop all tables before creating them again.")
    @click.option(
        "--alter",
        is_flag=True,
        help="Add missing columns to existing tables without dropping existing data.",
    )
    def init_db(drop: bool, alter: bool):
        """Initialize or evolve the database schema."""
        if drop:
            db.drop_all()

        db.create_all()

        if alter:
            engine = db.session.get_bind()
            added, skipped = _add_missing_columns(engine)
            if added:
                click.echo(f"Added {added} missing column(s) via ALTER TABLE.")
            if skipped:
                click.echo(
                    "Skipped non-null column(s) without safe default: "
                    + ", ".join(skipped)
                    + ". Use a migration tool for these changes."
                )

        click.echo("Database initialized.")

    @app.cli.command("reindex-db")
    @click.option(
        "--analyze/--no-analyze",
        default=True,
        show_default=True,
        help="Refresh planner statistics after rebuilding indexes.",
    )
    def reindex_db(analyze: bool):
        """Rebuild DB indexes (SQLite) and optionally refresh stats."""
        db.create_all()
        engine = db.session.get_bind()
        dialect = engine.dialect.name if engine else ""

        if dialect == "sqlite":
            db.session.execute(text("REINDEX"))
            click.echo("SQLite REINDEX completed.")
        else:
            click.echo("REINDEX is only executed for SQLite in this command.")

        if analyze:
            db.session.execute(text("ANALYZE"))
            click.echo("ANALYZE completed.")

        db.session.commit()

    @app.cli.command("import-nvd-cpes")
    @click.option(
        "--source",
        default=DEFAULT_NVD_CPE_FEED,
        show_default=True,
        help="Path or URL to an NVD CPE 2.0 tar.gz feed.",
    )
    @click.option(
        "--replace",
        is_flag=True,
        help="Delete existing CPE/vendor/product data before import.",
    )
    @click.option(
        "--batch-size",
        default=2000,
        show_default=True,
        type=int,
        help="Number of CPE rows between commits.",
    )
    def import_nvd_cpes(source: str, replace: bool, batch_size: int):
        """Import CPEs from the NVD CPE 2.0 feed into the local DB."""
        db.create_all()

        if replace:
            click.echo("Deleting existing CPE, product and vendor rows...")
            CPEEntry.query.delete()
            Product.query.delete()
            Vendor.query.delete()
            db.session.commit()

        vendor_cache = {v.name: v for v in Vendor.query.all()}
        product_cache = {(p.vendor_id, p.name): p for p in Product.query.all()}
        vendor_uuid_to_id = {v.uuid: v.id for v in vendor_cache.values() if v.uuid}
        product_uuid_to_id = {p.uuid: p.id for p in product_cache.values() if p.uuid}
        cpe_name_id_to_id = {
            c.cpe_name_id: c.id
            for c in CPEEntry.query.filter(CPEEntry.cpe_name_id.isnot(None)).all()
            if c.cpe_name_id
        }

        imported = 0
        skipped = 0
        skipped_uuid_conflicts = 0
        created_vendors = 0
        created_products = 0
        updated = 0

        for item in iter_nvd_products(source):
            cpe_data = item.get("cpe") or item
            cpe_uri = (
                cpe_data.get("cpeName")
                or cpe_data.get("criteria")
                or cpe_data.get("cpe23Uri")
            )
            if not cpe_uri:
                skipped += 1
                continue

            parsed = parse_cpe23_uri(cpe_uri)
            if not parsed:
                skipped += 1
                continue

            vendor_name = parsed["vendor"]
            product_name = parsed["product"]

            vendor_uuid = vendor_uuid_for_name(vendor_name)
            product_uuid = product_uuid_for_names(vendor_name, product_name)

            vendor = vendor_cache.get(vendor_name)
            if not vendor:
                existing_vendor_id = vendor_uuid_to_id.get(vendor_uuid)
                if existing_vendor_id is not None:
                    skipped += 1
                    skipped_uuid_conflicts += 1
                    continue
                vendor = Vendor(
                    uuid=vendor_uuid,
                    name=vendor_name,
                    title=titleize_token(vendor_name),
                )
                db.session.add(vendor)
                db.session.flush()
                vendor_cache[vendor_name] = vendor
                vendor_uuid_to_id[vendor.uuid] = vendor.id
                created_vendors += 1
            elif vendor.uuid != vendor_uuid:
                existing_vendor_id = vendor_uuid_to_id.get(vendor_uuid)
                if existing_vendor_id is None or existing_vendor_id == vendor.id:
                    vendor_uuid_to_id.pop(vendor.uuid, None)
                    vendor.uuid = vendor_uuid
                    vendor_uuid_to_id[vendor.uuid] = vendor.id
                else:
                    skipped += 1
                    skipped_uuid_conflicts += 1
                    continue

            product_key = (vendor.id, product_name)
            product = product_cache.get(product_key)
            if not product:
                existing_product_id = product_uuid_to_id.get(product_uuid)
                if existing_product_id is not None:
                    skipped += 1
                    skipped_uuid_conflicts += 1
                    continue
                product = Product(
                    uuid=product_uuid,
                    vendor_id=vendor.id,
                    name=product_name,
                    title=titleize_token(product_name),
                )
                db.session.add(product)
                db.session.flush()
                product_cache[product_key] = product
                product_uuid_to_id[product.uuid] = product.id
                created_products += 1
            elif product.uuid != product_uuid:
                existing_product_id = product_uuid_to_id.get(product_uuid)
                if existing_product_id is None or existing_product_id == product.id:
                    product_uuid_to_id.pop(product.uuid, None)
                    product.uuid = product_uuid
                    product_uuid_to_id[product.uuid] = product.id
                else:
                    skipped += 1
                    skipped_uuid_conflicts += 1
                    continue

            titles = cpe_data.get("titles") or []
            title = pick_english_title(titles) or titleize_token(product_name)
            deprecated_by = None
            dep = cpe_data.get("deprecatedBy")
            if isinstance(dep, list) and dep:
                deprecated_by = (
                    dep[0].get("cpeName") if isinstance(dep[0], dict) else str(dep[0])
                )
            elif dep:
                deprecated_by = str(dep)

            existing = CPEEntry.query.filter_by(cpe_uri=cpe_uri).first()
            if existing:
                incoming_cpe_name_id = cpe_data.get("cpeNameId")
                if incoming_cpe_name_id:
                    existing_cpe_row_id = cpe_name_id_to_id.get(incoming_cpe_name_id)
                    if existing_cpe_row_id is not None and existing_cpe_row_id != existing.id:
                        skipped += 1
                        skipped_uuid_conflicts += 1
                        continue
                existing.vendor_id = vendor.id
                existing.product_id = product.id
                if incoming_cpe_name_id:
                    cpe_name_id_to_id.pop(existing.cpe_name_id, None)
                    existing.cpe_name_id = incoming_cpe_name_id
                    cpe_name_id_to_id[existing.cpe_name_id] = existing.id
                existing.deprecated = bool(cpe_data.get("deprecated", False))
                existing.deprecated_by = deprecated_by
                existing.part = parsed["part"]
                existing.version = parsed["version"]
                existing.update = parsed["update"]
                existing.edition = parsed["edition"]
                existing.language = parsed["language"]
                existing.sw_edition = parsed["sw_edition"]
                existing.target_sw = parsed["target_sw"]
                existing.target_hw = parsed["target_hw"]
                existing.other = parsed["other"]
                existing.title = title
                updated += 1
            else:
                incoming_cpe_name_id = cpe_data.get("cpeNameId")
                if incoming_cpe_name_id and cpe_name_id_to_id.get(incoming_cpe_name_id) is not None:
                    skipped += 1
                    skipped_uuid_conflicts += 1
                    continue
                cpe_entry = CPEEntry(
                    vendor_id=vendor.id,
                    product_id=product.id,
                    cpe_uri=cpe_uri,
                    cpe_name_id=cpe_data.get("cpeNameId"),
                    deprecated=bool(cpe_data.get("deprecated", False)),
                    deprecated_by=deprecated_by,
                    part=parsed["part"],
                    version=parsed["version"],
                    update=parsed["update"],
                    edition=parsed["edition"],
                    language=parsed["language"],
                    sw_edition=parsed["sw_edition"],
                    target_sw=parsed["target_sw"],
                    target_hw=parsed["target_hw"],
                    other=parsed["other"],
                    title=title,
                    notes="Imported from NVD CPE 2.0 feed",
                )
                db.session.add(cpe_entry)
                if incoming_cpe_name_id:
                    db.session.flush()
                    cpe_name_id_to_id[incoming_cpe_name_id] = cpe_entry.id
                imported += 1

            total_processed = imported + updated + skipped
            if total_processed % batch_size == 0:
                db.session.commit()
                click.echo(
                    f"Processed {total_processed} items | new CPEs={imported} updated={updated} "
                    f"vendors={created_vendors} products={created_products} skipped={skipped}"
                )

        backfill_missing_uuids()
        db.session.commit()
        click.echo(
            f"Done. new CPEs={imported}, updated={updated}, vendors={created_vendors}, "
            f"products={created_products}, skipped={skipped} "
            f"(uuid-conflicts={skipped_uuid_conflicts})"
        )

    @app.cli.command("import-nvd-cpematches")
    @click.option(
        "--source",
        default=DEFAULT_NVD_CPE_MATCH_FEED,
        show_default=True,
        help="Path or URL to an NVD CPE Match 2.0 tar.gz feed.",
    )
    @click.option(
        "--batch-size",
        default=2000,
        show_default=True,
        type=int,
        help="Number of CPE rows between commits.",
    )
    def import_nvd_cpematches(source: str, batch_size: int):
        """Import concrete CPE names from the NVD CPE Match 2.0 feed."""
        db.create_all()

        vendor_cache = {v.name: v for v in Vendor.query.all()}
        product_cache = {(p.vendor_id, p.name): p for p in Product.query.all()}
        vendor_uuid_to_id = {v.uuid: v.id for v in vendor_cache.values() if v.uuid}
        product_uuid_to_id = {p.uuid: p.id for p in product_cache.values() if p.uuid}
        cpe_name_id_to_id = {
            c.cpe_name_id: c.id
            for c in CPEEntry.query.filter(CPEEntry.cpe_name_id.isnot(None)).all()
            if c.cpe_name_id
        }

        imported = 0
        skipped = 0
        skipped_uuid_conflicts = 0
        created_vendors = 0
        created_products = 0

        for match in iter_nvd_match_strings(source):
            match_data = match.get("matchString") or {}
            entries = match_data.get("matches") or []
            if not entries:
                skipped += 1
                continue

            for entry in entries:
                if not isinstance(entry, dict):
                    skipped += 1
                    continue

                cpe_uri = entry.get("cpeName")
                if not cpe_uri:
                    skipped += 1
                    continue
                cpe_name_id = entry.get("cpeNameId")
                if cpe_name_id and cpe_name_id_to_id.get(cpe_name_id) is not None:
                    skipped += 1
                    skipped_uuid_conflicts += 1
                    continue

                existing = CPEEntry.query.filter_by(cpe_uri=cpe_uri).first()
                if existing:
                    skipped += 1
                    continue

                parsed = parse_cpe23_uri(cpe_uri)
                if not parsed:
                    skipped += 1
                    continue

                vendor_name = parsed["vendor"]
                product_name = parsed["product"]

                vendor_uuid = vendor_uuid_for_name(vendor_name)
                product_uuid = product_uuid_for_names(vendor_name, product_name)

                vendor = vendor_cache.get(vendor_name)
                if not vendor:
                    existing_vendor_id = vendor_uuid_to_id.get(vendor_uuid)
                    if existing_vendor_id is not None:
                        skipped += 1
                        skipped_uuid_conflicts += 1
                        continue
                    vendor = Vendor(
                        uuid=vendor_uuid,
                        name=vendor_name,
                        title=titleize_token(vendor_name),
                    )
                    db.session.add(vendor)
                    db.session.flush()
                    vendor_cache[vendor_name] = vendor
                    vendor_uuid_to_id[vendor.uuid] = vendor.id
                    created_vendors += 1
                elif vendor.uuid != vendor_uuid:
                    existing_vendor_id = vendor_uuid_to_id.get(vendor_uuid)
                    if existing_vendor_id is None or existing_vendor_id == vendor.id:
                        vendor_uuid_to_id.pop(vendor.uuid, None)
                        vendor.uuid = vendor_uuid
                        vendor_uuid_to_id[vendor.uuid] = vendor.id
                    else:
                        skipped += 1
                        skipped_uuid_conflicts += 1
                        continue

                product_key = (vendor.id, product_name)
                product = product_cache.get(product_key)
                if not product:
                    existing_product_id = product_uuid_to_id.get(product_uuid)
                    if existing_product_id is not None:
                        skipped += 1
                        skipped_uuid_conflicts += 1
                        continue
                    product = Product(
                        uuid=product_uuid,
                        vendor_id=vendor.id,
                        name=product_name,
                        title=titleize_token(product_name),
                    )
                    db.session.add(product)
                    db.session.flush()
                    product_cache[product_key] = product
                    product_uuid_to_id[product.uuid] = product.id
                    created_products += 1
                elif product.uuid != product_uuid:
                    existing_product_id = product_uuid_to_id.get(product_uuid)
                    if existing_product_id is None or existing_product_id == product.id:
                        product_uuid_to_id.pop(product.uuid, None)
                        product.uuid = product_uuid
                        product_uuid_to_id[product.uuid] = product.id
                    else:
                        skipped += 1
                        skipped_uuid_conflicts += 1
                        continue

                cpe_entry = CPEEntry(
                    vendor_id=vendor.id,
                    product_id=product.id,
                    cpe_uri=cpe_uri,
                    cpe_name_id=cpe_name_id,
                    deprecated=False,
                    deprecated_by=None,
                    part=parsed["part"],
                    version=parsed["version"],
                    update=parsed["update"],
                    edition=parsed["edition"],
                    language=parsed["language"],
                    sw_edition=parsed["sw_edition"],
                    target_sw=parsed["target_sw"],
                    target_hw=parsed["target_hw"],
                    other=parsed["other"],
                    title=titleize_token(product_name),
                    notes="Imported from NVD CPE Match 2.0 feed",
                )
                db.session.add(cpe_entry)
                if cpe_name_id:
                    db.session.flush()
                    cpe_name_id_to_id[cpe_name_id] = cpe_entry.id
                imported += 1

                total_processed = imported + skipped
                if total_processed % batch_size == 0:
                    db.session.commit()
                    click.echo(
                        f"Processed {total_processed} items | new CPEs={imported} "
                        f"vendors={created_vendors} products={created_products} skipped={skipped}"
                    )

        backfill_missing_uuids()
        db.session.commit()
        click.echo(
            f"Done. new CPEs={imported}, vendors={created_vendors}, "
            f"products={created_products}, skipped={skipped} "
            f"(uuid-conflicts={skipped_uuid_conflicts})"
        )

    @app.cli.command("export-app-dataset")
    @click.option(
        "--output",
        default="exports/cpe-editor-dataset.tar.gz",
        show_default=True,
        help="Destination tar.gz file for the exported dataset.",
    )
    @click.option(
        "--include-proposals/--no-proposals",
        default=False,
        show_default=True,
        help="Include moderation proposals in the export.",
    )
    def export_app_dataset(output: str, include_proposals: bool):
        """Export the app dataset so other instances can bootstrap from it."""
        db.create_all()
        backfill_missing_uuids()
        db.session.commit()

        dataset = build_app_dataset(include_proposals=include_proposals)
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        write_dataset_archive(output_path, dataset)
        click.echo(
            f"Exported dataset to {output_path} "
            f"(vendors={len(dataset['vendors'])}, products={len(dataset['products'])}, "
            f"cpes={len(dataset['cpes'])}, metadata={len(dataset['metadata'])}, relationships={len(dataset['relationships'])}, "
            f"proposals={len(dataset['proposals'])})"
        )

    @app.cli.command("import-app-dataset")
    @click.option(
        "--source",
        required=True,
        help="Path or URL to a dataset archive previously exported by this app.",
    )
    @click.option(
        "--replace",
        is_flag=True,
        help="Delete existing proposals/CPE/products/vendors before import.",
    )
    @click.option(
        "--include-proposals/--no-proposals",
        default=True,
        show_default=True,
        help="Import proposal records when present in the dataset.",
    )
    @click.option(
        "--batch-size",
        default=2000,
        show_default=True,
        type=int,
        help="Number of rows between commits during dataset import.",
    )
    def import_app_dataset(
        source: str, replace: bool, include_proposals: bool, batch_size: int
    ):
        """Import a dataset archive produced by export-app-dataset."""
        db.create_all()

        if replace:
            click.echo("Deleting existing proposal, CPE, product and vendor rows...")
            CPEVulnerabilityReference.query.delete()
            EntityMetadata.query.delete()
            Proposal.query.delete()
            EntityRelationship.query.delete()
            CPEEntry.query.delete()
            Product.query.delete()
            Vendor.query.delete()
            db.session.commit()

        dataset = read_dataset_archive(source)
        validate_app_dataset(dataset)

        vendor_id_by_uuid: dict[str, int] = {}
        product_id_by_uuid: dict[str, int] = {}
        relationship_count = 0
        proposal_count = 0

        vendor_rows = dataset.get("vendors") or []
        product_rows = dataset.get("products") or []
        cpe_rows = dataset.get("cpes") or []
        relationship_rows = dataset.get("relationships") or []
        metadata_rows = dataset.get("metadata") or []
        proposal_rows = dataset.get("proposals") or []

        imported_vendors = upsert_vendors(vendor_rows, vendor_id_by_uuid)
        imported_products = upsert_products(product_rows, vendor_id_by_uuid, product_id_by_uuid)
        imported_cpes = upsert_cpes(cpe_rows, vendor_id_by_uuid, product_id_by_uuid, batch_size)
        metadata_count = upsert_metadata(
            metadata_rows,
            vendor_id_by_uuid,
            product_id_by_uuid,
            batch_size,
        )
        relationship_count = upsert_relationships(
            relationship_rows,
            vendor_id_by_uuid,
            product_id_by_uuid,
            batch_size,
        )

        if include_proposals and proposal_rows:
            proposal_count = upsert_proposals(
                proposal_rows,
                vendor_id_by_uuid,
                product_id_by_uuid,
                batch_size,
            )

        backfill_missing_uuids()
        db.session.commit()
        click.echo(
            f"Imported dataset from {source} "
            f"(vendors={imported_vendors}, products={imported_products}, cpes={imported_cpes}, metadata={metadata_count}, "
            f"relationships={relationship_count}, proposals={proposal_count})"
        )


def open_source_bytes(source: str) -> bytes:
    if source.startswith("http://") or source.startswith("https://"):
        with urllib.request.urlopen(source) as response:
            return response.read()
    return Path(source).read_bytes()


def iter_nvd_products(source: str):
    blob = open_source_bytes(source)
    imported_any = False
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        members = [m for m in archive.getmembers() if m.isfile() and m.name.endswith(".json")]
        if not members:
            raise click.ClickException(
                "Could not find a JSON file inside the NVD tar.gz feed."
            )
        for member in sorted(members, key=lambda m: m.name):
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            payload = json.load(extracted)
            products = payload.get("products")
            if isinstance(products, list):
                imported_any = True
                for item in products:
                    yield item

    if imported_any:
        return

    raise click.ClickException(
        "Unexpected NVD feed structure: missing top-level 'products' list."
    )


def iter_nvd_match_strings(source: str):
    blob = open_source_bytes(source)
    imported_any = False
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        members = [m for m in archive.getmembers() if m.isfile() and m.name.endswith(".json")]
        if not members:
            raise click.ClickException(
                "Could not find a JSON file inside the NVD CPE Match tar.gz feed."
            )
        for member in sorted(members, key=lambda m: m.name):
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            payload = json.load(extracted)
            match_strings = payload.get("matchStrings")
            if isinstance(match_strings, list):
                imported_any = True
                for item in match_strings:
                    yield item

    if imported_any:
        return

    raise click.ClickException(
        "Unexpected NVD CPE Match feed structure: missing top-level 'matchStrings' list."
    )


def pick_english_title(titles: list[dict]) -> str | None:
    for title in titles:
        if title.get("lang", "").lower() == "en":
            return title.get("title")
    if titles:
        return titles[0].get("title")
    return None


def titleize_token(value: str) -> str:
    return (value or "").replace("_", " ").replace("-", " ").strip().title()


def backfill_missing_uuids():
    for vendor in Vendor.query.all():
        expected_uuid = vendor_uuid_for_name(vendor.name)
        if vendor.uuid != expected_uuid:
            vendor.uuid = expected_uuid
    db.session.flush()

    for product in Product.query.all():
        expected_uuid = product_uuid_for_names(product.vendor.name, product.name)
        if product.uuid != expected_uuid:
            product.uuid = expected_uuid
    db.session.flush()


def isoformat_or_none(value):
    if value is None:
        return None
    return value.isoformat()


def parse_datetime_or_none(value):
    if not value:
        return None
    return datetime.fromisoformat(value)


def build_app_dataset(include_proposals: bool = False) -> dict:
    vendors = [
        {
            "uuid": vendor.uuid,
            "name": vendor.name,
            "title": vendor.title,
            "notes": vendor.notes,
            "created_at": isoformat_or_none(vendor.created_at),
            "updated_at": isoformat_or_none(vendor.updated_at),
        }
        for vendor in Vendor.query.order_by(Vendor.id.asc()).all()
    ]

    products = [
        {
            "uuid": product.uuid,
            "vendor_uuid": product.vendor.uuid,
            "name": product.name,
            "title": product.title,
            "notes": product.notes,
            "created_at": isoformat_or_none(product.created_at),
            "updated_at": isoformat_or_none(product.updated_at),
        }
        for product in Product.query.order_by(Product.id.asc()).all()
    ]

    cpes = [
        {
            "cpe_uri": cpe.cpe_uri,
            "cpe_name_id": cpe.cpe_name_id,
            "vendor_uuid": cpe.vendor.uuid,
            "product_uuid": cpe.product.uuid,
            "deprecated": cpe.deprecated,
            "deprecated_by": cpe.deprecated_by,
            "part": cpe.part,
            "version": cpe.version,
            "update": cpe.update,
            "edition": cpe.edition,
            "language": cpe.language,
            "sw_edition": cpe.sw_edition,
            "target_sw": cpe.target_sw,
            "target_hw": cpe.target_hw,
            "other": cpe.other,
            "title": cpe.title,
            "notes": cpe.notes,
            "from_proposal": cpe.from_proposal,
            "created_at": isoformat_or_none(cpe.created_at),
            "updated_at": isoformat_or_none(cpe.updated_at),
        }
        for cpe in CPEEntry.query.order_by(CPEEntry.id.asc()).all()
    ]
    relationships = [
        {
            "relationship_type": relationship.relationship_type,
            "source_vendor_uuid": relationship.source_vendor.uuid if relationship.source_vendor else None,
            "source_product_uuid": relationship.source_product.uuid if relationship.source_product else None,
            "target_vendor_uuid": relationship.target_vendor.uuid if relationship.target_vendor else None,
            "target_product_uuid": relationship.target_product.uuid if relationship.target_product else None,
            "rationale": relationship.rationale,
            "submitter_name": relationship.submitter_name,
            "submitter_email": relationship.submitter_email,
            "submitted_at": isoformat_or_none(relationship.submitted_at),
            "approved_at": isoformat_or_none(relationship.approved_at),
            "created_at": isoformat_or_none(relationship.created_at),
            "updated_at": isoformat_or_none(relationship.updated_at),
        }
        for relationship in EntityRelationship.query.order_by(EntityRelationship.id.asc()).all()
    ]
    metadata = [
        {
            "record_uuid": metadata_entry.vendor.uuid if metadata_entry.vendor else metadata_entry.product.uuid,
            "record_type": "vendor" if metadata_entry.vendor_id else "product",
            "metadata_key": metadata_entry.metadata_key,
            "metadata_value": metadata_entry.metadata_value,
            "submitter_name": metadata_entry.submitter_name,
            "submitter_email": metadata_entry.submitter_email,
            "submitted_at": isoformat_or_none(metadata_entry.submitted_at),
            "approved_at": isoformat_or_none(metadata_entry.approved_at),
            "created_at": isoformat_or_none(metadata_entry.created_at),
            "updated_at": isoformat_or_none(metadata_entry.updated_at),
        }
        for metadata_entry in EntityMetadata.query.order_by(EntityMetadata.id.asc()).all()
    ]

    proposals = []
    if include_proposals:
        proposals = [
            {
                "proposal_type": proposal.proposal_type,
                "status": proposal.status,
                "submitter_name": proposal.submitter_name,
                "submitter_email": proposal.submitter_email,
                "rationale": proposal.rationale,
                "vendor_uuid": proposal.vendor.uuid if proposal.vendor else None,
                "product_uuid": proposal.product.uuid if proposal.product else None,
                "cpe_uri": proposal.cpe_entry.cpe_uri if proposal.cpe_entry else None,
                "proposed_vendor_name": proposal.proposed_vendor_name,
                "proposed_vendor_title": proposal.proposed_vendor_title,
                "proposed_product_name": proposal.proposed_product_name,
                "proposed_product_title": proposal.proposed_product_title,
                "proposed_part": proposal.proposed_part,
                "proposed_version": proposal.proposed_version,
                "proposed_update": proposal.proposed_update,
                "proposed_edition": proposal.proposed_edition,
                "proposed_language": proposal.proposed_language,
                "proposed_sw_edition": proposal.proposed_sw_edition,
                "proposed_target_sw": proposal.proposed_target_sw,
                "proposed_target_hw": proposal.proposed_target_hw,
                "proposed_other": proposal.proposed_other,
                "proposed_title": proposal.proposed_title,
                "proposed_notes": proposal.proposed_notes,
                "proposed_cpe_uri": proposal.proposed_cpe_uri,
                "proposed_metadata_key": proposal.proposed_metadata_key,
                "proposed_metadata_value": proposal.proposed_metadata_value,
                "proposed_vulnerability_source": proposal.proposed_vulnerability_source,
                "proposed_vulnerability_id": proposal.proposed_vulnerability_id,
                "proposed_cpe_applicability": proposal.proposed_cpe_applicability,
                "review_comment": proposal.review_comment,
                "reviewed_at": isoformat_or_none(proposal.reviewed_at),
                "created_at": isoformat_or_none(proposal.created_at),
                "updated_at": isoformat_or_none(proposal.updated_at),
            }
            for proposal in Proposal.query.order_by(Proposal.id.asc()).all()
        ]

    return {
        "format": "cpe-editor-dataset",
        "version": APP_DATASET_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "counts": {
            "vendors": len(vendors),
            "products": len(products),
            "cpes": len(cpes),
            "metadata": len(metadata),
            "relationships": len(relationships),
            "proposals": len(proposals),
        },
        "vendors": vendors,
        "products": products,
        "cpes": cpes,
        "metadata": metadata,
        "relationships": relationships,
        "proposals": proposals,
    }


def write_dataset_archive(output_path: Path, dataset: dict):
    raw = json.dumps(dataset, indent=2, sort_keys=True).encode("utf-8")
    with tarfile.open(output_path, mode="w:gz") as archive:
        info = tarfile.TarInfo("dataset.json")
        info.size = len(raw)
        archive.addfile(info, io.BytesIO(raw))


def read_dataset_archive(source: str) -> dict:
    blob = open_source_bytes(source)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        member = next(
            (m for m in archive.getmembers() if m.isfile() and m.name.endswith("dataset.json")),
            None,
        )
        if not member:
            member = next(
                (m for m in archive.getmembers() if m.isfile() and m.name.endswith(".json")),
                None,
            )
        if not member:
            raise click.ClickException(
                "Could not find dataset.json inside the exported dataset archive."
            )
        extracted = archive.extractfile(member)
        if extracted is None:
            raise click.ClickException("Could not extract dataset.json from the archive.")
        return json.load(extracted)


def validate_app_dataset(dataset: dict):
    if dataset.get("format") != "cpe-editor-dataset":
        raise click.ClickException("Unsupported dataset format. Expected 'cpe-editor-dataset'.")
    if str(dataset.get("version")) != APP_DATASET_VERSION:
        raise click.ClickException(
            f"Unsupported dataset version {dataset.get('version')!r}. Expected {APP_DATASET_VERSION}."
        )


def _resolve_record_ids(
    row: dict,
    prefix: str,
    vendor_id_by_uuid: dict[str, int],
    product_id_by_uuid: dict[str, int],
) -> tuple[int | None, int | None]:
    vendor_uuid = row.get(f"{prefix}_vendor_uuid")
    product_uuid = row.get(f"{prefix}_product_uuid")
    vendor_id = vendor_id_by_uuid.get(vendor_uuid) if vendor_uuid else None
    product_id = product_id_by_uuid.get(product_uuid) if product_uuid else None
    if vendor_id is None and product_id is None:
        raise click.ClickException(
            f"Dataset relationship is missing a valid {prefix} record reference."
        )
    return vendor_id, product_id


def upsert_vendors(vendor_rows: list[dict], vendor_id_by_uuid: dict[str, int]) -> int:
    count = 0
    for row in vendor_rows:
        imported_uuid = row["uuid"]
        vendor = Vendor.query.filter_by(uuid=imported_uuid).first()
        if vendor is None:
            vendor = Vendor.query.filter_by(name=row["name"]).first()
        if vendor is None:
            vendor = Vendor(uuid=imported_uuid, name=row["name"])
            db.session.add(vendor)
        if not vendor.uuid:
            vendor.uuid = imported_uuid
        vendor.name = row["name"]
        vendor.title = row.get("title")
        vendor.notes = row.get("notes")
        vendor.created_at = parse_datetime_or_none(row.get("created_at")) or vendor.created_at
        vendor.updated_at = parse_datetime_or_none(row.get("updated_at")) or vendor.updated_at
        db.session.flush()
        vendor_id_by_uuid[imported_uuid] = vendor.id
        vendor_id_by_uuid[vendor.uuid] = vendor.id
        count += 1
    db.session.commit()
    return count


def upsert_products(
    product_rows: list[dict],
    vendor_id_by_uuid: dict[str, int],
    product_id_by_uuid: dict[str, int],
) -> int:
    count = 0
    for row in product_rows:
        imported_uuid = row["uuid"]
        vendor_uuid = row["vendor_uuid"]
        vendor_id = vendor_id_by_uuid.get(vendor_uuid)
        if vendor_id is None:
            raise click.ClickException(
                f"Dataset refers to unknown vendor_uuid {vendor_uuid!r} for product {imported_uuid!r}."
            )
        product = Product.query.filter_by(uuid=imported_uuid).first()
        if product is None:
            product = Product.query.filter_by(vendor_id=vendor_id, name=row["name"]).first()
        if product is None:
            product = Product(uuid=imported_uuid, vendor_id=vendor_id, name=row["name"])
            db.session.add(product)
        if not product.uuid:
            product.uuid = imported_uuid
        product.vendor_id = vendor_id
        product.name = row["name"]
        product.title = row.get("title")
        product.notes = row.get("notes")
        product.created_at = parse_datetime_or_none(row.get("created_at")) or product.created_at
        product.updated_at = parse_datetime_or_none(row.get("updated_at")) or product.updated_at
        db.session.flush()
        product_id_by_uuid[imported_uuid] = product.id
        product_id_by_uuid[product.uuid] = product.id
        count += 1
    db.session.commit()
    return count


def upsert_cpes(
    cpe_rows: list[dict],
    vendor_id_by_uuid: dict[str, int],
    product_id_by_uuid: dict[str, int],
    batch_size: int,
) -> int:
    count = 0
    for row in cpe_rows:
        vendor_id = vendor_id_by_uuid.get(row["vendor_uuid"])
        product_id = product_id_by_uuid.get(row["product_uuid"])
        if vendor_id is None or product_id is None:
            raise click.ClickException(
                f"Dataset refers to unknown vendor/product UUID for CPE {row['cpe_uri']!r}."
            )
        cpe = CPEEntry.query.filter_by(cpe_uri=row["cpe_uri"]).first()
        if cpe is None and row.get("cpe_name_id"):
            cpe = CPEEntry.query.filter_by(cpe_name_id=row["cpe_name_id"]).first()
        if cpe is None:
            cpe = CPEEntry(cpe_uri=row["cpe_uri"], vendor_id=vendor_id, product_id=product_id, part=row["part"])
            db.session.add(cpe)
        cpe.vendor_id = vendor_id
        cpe.product_id = product_id
        cpe.cpe_uri = row["cpe_uri"]
        cpe.cpe_name_id = row.get("cpe_name_id")
        cpe.deprecated = bool(row.get("deprecated", False))
        cpe.deprecated_by = row.get("deprecated_by")
        cpe.part = row["part"]
        cpe.version = row.get("version") or "*"
        cpe.update = row.get("update") or "*"
        cpe.edition = row.get("edition") or "*"
        cpe.language = row.get("language") or "*"
        cpe.sw_edition = row.get("sw_edition") or "*"
        cpe.target_sw = row.get("target_sw") or "*"
        cpe.target_hw = row.get("target_hw") or "*"
        cpe.other = row.get("other") or "*"
        cpe.title = row.get("title")
        cpe.notes = row.get("notes")
        cpe.from_proposal = bool(row.get("from_proposal", False))
        cpe.created_at = parse_datetime_or_none(row.get("created_at")) or cpe.created_at
        cpe.updated_at = parse_datetime_or_none(row.get("updated_at")) or cpe.updated_at
        count += 1
        if count % batch_size == 0:
            db.session.commit()
    db.session.commit()
    return count


def upsert_relationships(
    relationship_rows: list[dict],
    vendor_id_by_uuid: dict[str, int],
    product_id_by_uuid: dict[str, int],
    batch_size: int,
) -> int:
    count = 0
    for row in relationship_rows:
        source_vendor_id, source_product_id = _resolve_record_ids(
            row, "source", vendor_id_by_uuid, product_id_by_uuid
        )
        target_vendor_id, target_product_id = _resolve_record_ids(
            row, "target", vendor_id_by_uuid, product_id_by_uuid
        )

        relationship = EntityRelationship.query.filter_by(
            source_vendor_id=source_vendor_id,
            source_product_id=source_product_id,
            target_vendor_id=target_vendor_id,
            target_product_id=target_product_id,
            relationship_type=row["relationship_type"],
        ).first()
        if relationship is None:
            relationship = EntityRelationship(
                source_vendor_id=source_vendor_id,
                source_product_id=source_product_id,
                target_vendor_id=target_vendor_id,
                target_product_id=target_product_id,
                relationship_type=row["relationship_type"],
            )
            db.session.add(relationship)

        relationship.rationale = row.get("rationale")
        relationship.submitter_name = row.get("submitter_name")
        relationship.submitter_email = row.get("submitter_email")
        relationship.submitted_at = parse_datetime_or_none(row.get("submitted_at"))
        relationship.approved_at = parse_datetime_or_none(row.get("approved_at"))
        relationship.created_at = (
            parse_datetime_or_none(row.get("created_at")) or relationship.created_at
        )
        relationship.updated_at = (
            parse_datetime_or_none(row.get("updated_at")) or relationship.updated_at
        )

        count += 1
        if count % batch_size == 0:
            db.session.commit()
    db.session.commit()
    return count


def upsert_metadata(
    metadata_rows: list[dict],
    vendor_id_by_uuid: dict[str, int],
    product_id_by_uuid: dict[str, int],
    batch_size: int,
) -> int:
    count = 0
    for row in metadata_rows:
        record_uuid = row.get("record_uuid")
        record_type = row.get("record_type")
        if record_type == "vendor":
            vendor_id = vendor_id_by_uuid.get(record_uuid)
            product_id = None
        elif record_type == "product":
            vendor_id = None
            product_id = product_id_by_uuid.get(record_uuid)
        else:
            raise click.ClickException(f"Unsupported metadata record_type {record_type!r}.")

        if vendor_id is None and product_id is None:
            raise click.ClickException(
                f"Dataset metadata entry references unknown record_uuid {record_uuid!r}."
            )

        metadata_entry = EntityMetadata(
            vendor_id=vendor_id,
            product_id=product_id,
            metadata_key=row["metadata_key"],
            metadata_value=row.get("metadata_value") or "",
            submitter_name=row.get("submitter_name"),
            submitter_email=row.get("submitter_email"),
            submitted_at=parse_datetime_or_none(row.get("submitted_at")) or datetime.utcnow(),
            approved_at=parse_datetime_or_none(row.get("approved_at")),
            created_at=parse_datetime_or_none(row.get("created_at")),
            updated_at=parse_datetime_or_none(row.get("updated_at")),
        )
        db.session.add(metadata_entry)
        count += 1
        if count % batch_size == 0:
            db.session.commit()
    db.session.commit()
    return count


def upsert_proposals(
    proposal_rows: list[dict],
    vendor_id_by_uuid: dict[str, int],
    product_id_by_uuid: dict[str, int],
    batch_size: int,
) -> int:
    cpe_id_by_uri = {c.cpe_uri: c.id for c in CPEEntry.query.with_entities(CPEEntry.cpe_uri, CPEEntry.id).all()}
    count = 0
    for row in proposal_rows:
        proposal = Proposal(
            proposal_type=row["proposal_type"],
            status=row.get("status") or "pending",
            submitter_name=row.get("submitter_name"),
            submitter_email=row.get("submitter_email"),
            rationale=row.get("rationale"),
            vendor_id=vendor_id_by_uuid.get(row.get("vendor_uuid")) if row.get("vendor_uuid") else None,
            product_id=product_id_by_uuid.get(row.get("product_uuid")) if row.get("product_uuid") else None,
            cpe_entry_id=cpe_id_by_uri.get(row.get("cpe_uri")) if row.get("cpe_uri") else None,
            proposed_vendor_name=row.get("proposed_vendor_name"),
            proposed_vendor_title=row.get("proposed_vendor_title"),
            proposed_product_name=row.get("proposed_product_name"),
            proposed_product_title=row.get("proposed_product_title"),
            proposed_part=row.get("proposed_part"),
            proposed_version=row.get("proposed_version"),
            proposed_update=row.get("proposed_update"),
            proposed_edition=row.get("proposed_edition"),
            proposed_language=row.get("proposed_language"),
            proposed_sw_edition=row.get("proposed_sw_edition"),
            proposed_target_sw=row.get("proposed_target_sw"),
            proposed_target_hw=row.get("proposed_target_hw"),
            proposed_other=row.get("proposed_other"),
            proposed_title=row.get("proposed_title"),
            proposed_notes=row.get("proposed_notes"),
            proposed_cpe_uri=row.get("proposed_cpe_uri"),
            proposed_metadata_key=row.get("proposed_metadata_key"),
            proposed_metadata_value=row.get("proposed_metadata_value"),
            proposed_vulnerability_source=row.get("proposed_vulnerability_source"),
            proposed_vulnerability_id=row.get("proposed_vulnerability_id"),
            proposed_cpe_applicability=row.get("proposed_cpe_applicability"),
            review_comment=row.get("review_comment"),
            reviewed_at=parse_datetime_or_none(row.get("reviewed_at")),
            created_at=parse_datetime_or_none(row.get("created_at")),
            updated_at=parse_datetime_or_none(row.get("updated_at")),
        )
        db.session.add(proposal)
        count += 1
        if count % batch_size == 0:
            db.session.commit()
    db.session.commit()
    return count
