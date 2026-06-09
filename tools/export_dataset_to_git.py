#!/usr/bin/env python3
"""Convert a CPE Editor dataset export into a git-friendly directory tree.

The Flask ``export-app-dataset`` command produces a portable tar.gz archive with a
single ``dataset.json`` member. That shape is easy to move between instances, but
it is not ideal for long-lived git history because every dataset change rewrites a
large JSON file. This tool fans the export out into deterministic, sharded JSON
and JSON Lines files so normal git diffs stay small and reviewable.
"""

from __future__ import annotations

import argparse
import hashlib
import filecmp
import json
import re
import shutil
import tarfile
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

DATASET_FORMAT = "cpe-editor-dataset"
DATASET_VERSION = "1"

_RECORD_ARRAYS = (
    "vendors",
    "products",
    "cpes",
    "metadata",
    "relationships",
    "purl_mappings",
    "aliases",
    "proposals",
)

_SAFE_NAME_RE = re.compile(r"[^a-z0-9._-]+")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Read a CPE Editor dataset export and write a deterministic, "
            "git-friendly directory structure."
        )
    )
    parser.add_argument(
        "source",
        help="Path to cpe-editor-dataset.tar.gz or a plain dataset JSON file.",
    )
    parser.add_argument(
        "output_dir",
        help="Destination directory that can be committed to a git repository.",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help=(
            "Deprecated compatibility flag; existing output directories are "
            "updated in place without deleting the directory."
        ),
    )
    args = parser.parse_args(argv)

    counts = export_dataset_to_git_tree(
        Path(args.source), Path(args.output_dir), replace=args.replace
    )
    print(
        "Wrote git dataset tree to "
        f"{args.output_dir} "
        f"(vendors={counts['vendors']}, products={counts['products']}, "
        f"cpes={counts['cpes']}, metadata={counts['metadata']}, "
        f"relationships={counts['relationships']}, "
        f"purl_mappings={counts['purl_mappings']}, proposals={counts['proposals']})"
    )
    return 0


def export_dataset_to_git_tree(
    source: Path, output_dir: Path, *, replace: bool = False
) -> dict[str, int]:
    """Write ``source`` into ``output_dir`` as deterministic shard files.

    Returns the row counts written for each top-level dataset collection.
    """
    dataset = read_dataset(source)
    validate_dataset(dataset)

    if output_dir.exists() and not output_dir.is_dir():
        if not replace:
            raise SystemExit(
                f"Output path already exists and is not a directory: {output_dir}"
            )
        output_dir.unlink()

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=str(output_dir.parent))
    )
    try:
        counts = write_git_tree(dataset, temp_dir)
        sync_git_tree(temp_dir, output_dir)
        return counts
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def sync_git_tree(source_dir: Path, output_dir: Path) -> None:
    """Update ``output_dir`` from ``source_dir`` without replacing the root.

    This preserves repository metadata such as ``.git`` while keeping generated
    paths in sync with the latest export, including deleting stale generated
    files when records disappear from the dataset.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    sync_paths = [
        "manifest.json",
        "README.md",
        "vendors",
        "products",
        "cpes",
        "metadata",
        "relationships",
        "purl-mappings",
        "aliases",
        "proposals",
    ]
    for relative_path in sync_paths:
        sync_path(source_dir / relative_path, output_dir / relative_path)


def sync_path(source: Path, destination: Path) -> None:
    if source.is_dir():
        if destination.exists() and not destination.is_dir():
            destination.unlink()
        destination.mkdir(parents=True, exist_ok=True)

        source_entries = {item.name for item in source.iterdir()}
        for destination_item in destination.iterdir():
            if destination_item.name not in source_entries:
                if destination_item.is_dir():
                    shutil.rmtree(destination_item)
                else:
                    destination_item.unlink()

        for source_item in source.iterdir():
            sync_path(source_item, destination / source_item.name)
        return

    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.is_dir():
            shutil.rmtree(destination)
        elif filecmp.cmp(source, destination, shallow=False):
            return
    shutil.copy2(source, destination)


def read_dataset(source: Path) -> dict[str, Any]:
    if source.suffix == ".json":
        return json.loads(source.read_text(encoding="utf-8"))

    with tarfile.open(source, mode="r:gz") as archive:
        member = next(
            (
                item
                for item in archive.getmembers()
                if item.isfile() and item.name.endswith("dataset.json")
            ),
            None,
        )
        if member is None:
            member = next(
                (
                    item
                    for item in archive.getmembers()
                    if item.isfile() and item.name.endswith(".json")
                ),
                None,
            )
        if member is None:
            raise SystemExit("Could not find dataset.json in the export archive.")
        extracted = archive.extractfile(member)
        if extracted is None:
            raise SystemExit("Could not extract dataset.json from the export archive.")
        return json.load(extracted)


def validate_dataset(dataset: dict[str, Any]) -> None:
    if dataset.get("format") != DATASET_FORMAT:
        raise SystemExit(
            f"Unsupported dataset format {dataset.get('format')!r}; expected {DATASET_FORMAT!r}."
        )
    if str(dataset.get("version")) != DATASET_VERSION:
        raise SystemExit(
            f"Unsupported dataset version {dataset.get('version')!r}; expected {DATASET_VERSION!r}."
        )


def write_git_tree(dataset: dict[str, Any], output_dir: Path) -> dict[str, int]:
    output_dir.mkdir(parents=True, exist_ok=True)
    for directory in (
        "vendors",
        "products",
        "cpes",
        "metadata/vendors",
        "metadata/products",
        "relationships",
        "purl-mappings",
        "aliases",
        "proposals",
    ):
        (output_dir / directory).mkdir(parents=True, exist_ok=True)

    vendors = sorted(
        dataset.get("vendors") or [], key=lambda item: item.get("uuid") or ""
    )
    products = sorted(
        dataset.get("products") or [], key=lambda item: item.get("uuid") or ""
    )
    cpes = sorted(dataset.get("cpes") or [], key=lambda item: item.get("cpe_uri") or "")
    metadata_rows = sorted(
        dataset.get("metadata") or [],
        key=lambda item: (
            item.get("record_type") or "",
            item.get("record_uuid") or "",
            item.get("metadata_key") or "",
            item.get("metadata_value") or "",
        ),
    )
    relationships = sorted(
        dataset.get("relationships") or [], key=lambda item: json_sort_key(item)
    )
    purl_mappings = sorted(
        dataset.get("purl_mappings") or [],
        key=lambda item: (item.get("cpe_uri") or "", item.get("purl") or ""),
    )
    aliases = sorted(
        dataset.get("aliases") or [], key=lambda item: item.get("uuid") or ""
    )
    proposals = sorted(
        dataset.get("proposals") or [], key=lambda item: json_sort_key(item)
    )

    vendor_path_by_uuid = {}
    product_path_by_uuid = {}
    vendor_slug_by_uuid = {}
    product_slug_by_uuid = {}

    for vendor in vendors:
        vendor_slug = entity_slug(vendor.get("name"), vendor.get("uuid"))
        vendor_slug_by_uuid[vendor.get("uuid")] = vendor_slug
        path = output_dir / "vendors" / f"{vendor_slug}.json"
        write_json(path, vendor)
        vendor_path_by_uuid[vendor.get("uuid")] = path.relative_to(
            output_dir
        ).as_posix()

    for product in products:
        vendor_slug = vendor_slug_by_uuid.get(
            product.get("vendor_uuid")
        ) or entity_slug(product.get("vendor_uuid"), product.get("vendor_uuid"))
        product_slug = entity_slug(product.get("name"), product.get("uuid"))
        product_slug_by_uuid[product.get("uuid")] = product_slug
        path = output_dir / "products" / vendor_slug / f"{product_slug}.json"
        write_json(path, product)
        product_path_by_uuid[product.get("uuid")] = path.relative_to(
            output_dir
        ).as_posix()

    cpes_by_product_part: dict[tuple[str, str, str], list[dict[str, Any]]] = (
        defaultdict(list)
    )
    for cpe in cpes:
        vendor_slug = vendor_slug_by_uuid.get(cpe.get("vendor_uuid")) or entity_slug(
            cpe.get("vendor_uuid"), cpe.get("vendor_uuid")
        )
        product_slug = product_slug_by_uuid.get(cpe.get("product_uuid")) or entity_slug(
            cpe.get("product_uuid"), cpe.get("product_uuid")
        )
        part = slugify(cpe.get("part") or "unknown")
        cpes_by_product_part[(vendor_slug, product_slug, part)].append(cpe)

    for (vendor_slug, product_slug, part), rows in sorted(cpes_by_product_part.items()):
        write_jsonl(
            output_dir / "cpes" / vendor_slug / product_slug / f"{part}.jsonl",
            rows,
        )

    metadata_by_record: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in metadata_rows:
        metadata_by_record[
            (row.get("record_type") or "unknown", row.get("record_uuid") or "unknown")
        ].append(row)
    for (record_type, record_uuid), rows in sorted(metadata_by_record.items()):
        directory = "vendors" if record_type == "vendor" else "products"
        write_jsonl(
            output_dir
            / "metadata"
            / directory
            / f"{entity_slug(record_uuid, record_uuid)}.jsonl",
            rows,
        )

    write_jsonl(output_dir / "relationships" / "relationships.jsonl", relationships)

    mappings_by_cpe: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in purl_mappings:
        mappings_by_cpe[row.get("cpe_uri") or "unknown"].append(row)
    for cpe_uri, rows in sorted(mappings_by_cpe.items()):
        write_jsonl(
            output_dir / "purl-mappings" / f"{cpe_uri_slug(cpe_uri)}.jsonl",
            rows,
        )

    write_jsonl(output_dir / "aliases" / "aliases.jsonl", aliases)
    write_jsonl(output_dir / "proposals" / "proposals.jsonl", proposals)

    counts = {name: len(dataset.get(name) or []) for name in _RECORD_ARRAYS}
    manifest = {
        "format": DATASET_FORMAT,
        "version": str(dataset.get("version")),
        "source_exported_at": dataset.get("exported_at"),
        "layout": "git-sharded-v1",
        "counts": counts,
        "paths": {
            "vendors": "vendors/<vendor-slug>--<vendor-uuid>.json",
            "products": "products/<vendor-slug>/<product-slug>--<product-uuid>.json",
            "cpes": "cpes/<vendor-slug>/<product-slug>/<part>.jsonl",
            "metadata": "metadata/{vendors,products}/<record-uuid>.jsonl",
            "relationships": "relationships/relationships.jsonl",
            "purl_mappings": "purl-mappings/<cpe-uri-hash>.jsonl",
            "proposals": "proposals/proposals.jsonl",
        },
        "indexes": {
            "vendors_by_uuid": vendor_path_by_uuid,
            "products_by_uuid": product_path_by_uuid,
        },
    }
    write_json(output_dir / "manifest.json", manifest)
    write_text(output_dir / "README.md", build_output_readme(counts))
    return counts


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output_file:
        for row in rows:
            output_file.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
            output_file.write("\n")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def entity_slug(name: Any, uuid: Any) -> str:
    safe_name = slugify(str(name or "record"))[:80].strip("-.") or "record"
    safe_uuid = slugify(str(uuid or "no-uuid")) or "no-uuid"
    return f"{safe_name}--{safe_uuid}"


def slugify(value: str) -> str:
    value = value.strip().lower().replace(" ", "-")
    value = _SAFE_NAME_RE.sub("-", value)
    value = re.sub(r"-+", "-", value).strip("-.")
    return value or "unknown"


def cpe_uri_slug(cpe_uri: str) -> str:
    readable = slugify(cpe_uri.replace("cpe:2.3:", ""))[:80].strip("-.") or "cpe"
    digest = hashlib.sha256(cpe_uri.encode("utf-8")).hexdigest()[:16]
    return f"{readable}--{digest}"


def json_sort_key(item: dict[str, Any]) -> str:
    return json.dumps(item, sort_keys=True, separators=(",", ":"))


def build_output_readme(counts: dict[str, int]) -> str:
    return f"""# CPE Editor git dataset tree

This directory was generated by `tools/export_dataset_to_git.py` from a CPE
Editor portable dataset export. It is optimized for git review and history:
entity records are deterministic JSON files, while potentially large collections
are sharded into sorted JSON Lines files.

## Counts

- Vendors: {counts['vendors']}
- Products: {counts['products']}
- CPEs: {counts['cpes']}
- Metadata rows: {counts['metadata']}
- Relationships: {counts['relationships']}
- PURL mappings: {counts['purl_mappings']}
- Proposals: {counts['proposals']}

See `manifest.json` for the layout contract and UUID indexes.
"""


if __name__ == "__main__":
    raise SystemExit(main())
