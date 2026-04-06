from __future__ import annotations

import io
import json
import tarfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import click
from sqlalchemy import text

from .models import CPEEntry, Product, Proposal, Vendor, db
from .utils import parse_cpe23_uri, product_uuid_for_names, vendor_uuid_for_name

DEFAULT_NVD_CPE_FEED = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"
APP_DATASET_VERSION = "1"


def register_cli(app):
    @app.cli.command("init-db")
    @click.option("--drop", is_flag=True, help="Drop all tables before creating them again.")
    def init_db(drop: bool):
        """Initialize the database schema."""
        if drop:
            db.drop_all()
        db.create_all()
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

        imported = 0
        skipped = 0
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

            vendor = vendor_cache.get(vendor_name)
            if not vendor:
                vendor = Vendor(
                    uuid=vendor_uuid_for_name(vendor_name),
                    name=vendor_name,
                    title=titleize_token(vendor_name),
                )
                db.session.add(vendor)
                db.session.flush()
                vendor_cache[vendor_name] = vendor
                created_vendors += 1
            elif not vendor.uuid:
                vendor.uuid = vendor_uuid_for_name(vendor_name)

            product_key = (vendor.id, product_name)
            product = product_cache.get(product_key)
            if not product:
                product = Product(
                    uuid=product_uuid_for_names(vendor_name, product_name),
                    vendor_id=vendor.id,
                    name=product_name,
                    title=titleize_token(product_name),
                )
                db.session.add(product)
                db.session.flush()
                product_cache[product_key] = product
                created_products += 1
            elif not product.uuid:
                product.uuid = product_uuid_for_names(vendor_name, product_name)
            else:
                skipped += 1
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
                existing.vendor_id = vendor.id
                existing.product_id = product.id
                existing.cpe_name_id = cpe_data.get("cpeNameId") or existing.cpe_name_id
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
                db.session.add(
                    CPEEntry(
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
                )
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
            f"products={created_products}, skipped={skipped}"
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
            f"cpes={len(dataset['cpes'])}, proposals={len(dataset['proposals'])})"
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
            Proposal.query.delete()
            CPEEntry.query.delete()
            Product.query.delete()
            Vendor.query.delete()
            db.session.commit()

        dataset = read_dataset_archive(source)
        validate_app_dataset(dataset)

        vendor_id_by_uuid: dict[str, int] = {}
        product_id_by_uuid: dict[str, int] = {}
        proposal_count = 0

        vendor_rows = dataset.get("vendors") or []
        product_rows = dataset.get("products") or []
        cpe_rows = dataset.get("cpes") or []
        proposal_rows = dataset.get("proposals") or []

        imported_vendors = upsert_vendors(vendor_rows, vendor_id_by_uuid)
        imported_products = upsert_products(product_rows, vendor_id_by_uuid, product_id_by_uuid)
        imported_cpes = upsert_cpes(cpe_rows, vendor_id_by_uuid, product_id_by_uuid, batch_size)

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
            f"(vendors={imported_vendors}, products={imported_products}, cpes={imported_cpes}, "
            f"proposals={proposal_count})"
        )


def open_source_bytes(source: str) -> bytes:
    if source.startswith("http://") or source.startswith("https://"):
        with urllib.request.urlopen(source) as response:
            return response.read()
    return Path(source).read_bytes()


def iter_nvd_products(source: str):
    blob = open_source_bytes(source)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        member = next(
            (m for m in archive.getmembers() if m.isfile() and m.name.endswith(".json")),
            None,
        )
        if not member:
            raise click.ClickException(
                "Could not find a JSON file inside the NVD tar.gz feed."
            )
        extracted = archive.extractfile(member)
        if extracted is None:
            raise click.ClickException(
                "Could not extract the JSON file from the NVD tar.gz feed."
            )
        payload = json.load(extracted)

    products = payload.get("products")
    if isinstance(products, list):
        for item in products:
            yield item
        return

    raise click.ClickException(
        "Unexpected NVD feed structure: missing top-level 'products' list."
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
    for vendor in Vendor.query.filter((Vendor.uuid.is_(None)) | (Vendor.uuid == "")).all():
        vendor.uuid = vendor_uuid_for_name(vendor.name)
    db.session.flush()

    for product in Product.query.filter((Product.uuid.is_(None)) | (Product.uuid == "")).all():
        product.uuid = product_uuid_for_names(product.vendor.name, product.name)
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
            "proposals": len(proposals),
        },
        "vendors": vendors,
        "products": products,
        "cpes": cpes,
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
