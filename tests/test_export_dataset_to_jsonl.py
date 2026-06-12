import json
import tarfile

from tools.export_dataset_to_jsonl import export_dataset_to_jsonl


def _dataset():
    return {
        "format": "cpe-editor-dataset",
        "version": "1",
        "exported_at": "2024-01-01T00:00:00+00:00",
        "counts": {
            "vendors": 1,
            "products": 1,
            "cpes": 2,
            "metadata": 0,
            "relationships": 0,
            "purl_mappings": 0,
            "aliases": 0,
            "proposals": 0,
        },
        "vendors": [
            {
                "uuid": "vendor-uuid",
                "name": "Example Vendor",
                "title": "Example Vendor",
            }
        ],
        "products": [
            {
                "uuid": "product-uuid",
                "vendor_uuid": "vendor-uuid",
                "name": "Example Product",
                "title": "Example Product",
            }
        ],
        "cpes": [
            {
                "cpe_uri": "cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*",
                "vendor_uuid": "vendor-uuid",
                "product_uuid": "product-uuid",
                "part": "a",
                "version": "1.0",
            },
            {
                "cpe_uri": "cpe:2.3:a:example:product:2.0:*:*:*:*:*:*:*",
                "vendor_uuid": "vendor-uuid",
                "product_uuid": "product-uuid",
                "part": "a",
                "version": "2.0",
            },
        ],
        "metadata": [],
        "relationships": [],
        "purl_mappings": [],
        "aliases": [],
        "proposals": [],
    }


def test_export_dataset_to_jsonl_streams_plain_dataset_json(tmp_path):
    source = tmp_path / "dataset.json"
    source.write_text(json.dumps(_dataset()), encoding="utf-8")
    output = tmp_path / "dataset.ndjson"

    counts = export_dataset_to_jsonl(source, output)

    assert counts["vendors"] == 1
    assert counts["cpes"] == 2
    rows = [
        json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()
    ]
    assert rows[0]["type"] == "dataset"
    assert rows[0]["format"] == "cpe-editor-dataset"
    assert rows[1] == {
        "type": "record",
        "collection": "vendors",
        "record": {
            "uuid": "vendor-uuid",
            "name": "Example Vendor",
            "title": "Example Vendor",
        },
    }
    assert [
        row["record"]["version"] for row in rows if row.get("collection") == "cpes"
    ] == [
        "1.0",
        "2.0",
    ]


def test_export_dataset_to_jsonl_reads_tar_gz_export(tmp_path):
    dataset_json = tmp_path / "dataset.json"
    dataset_json.write_text(json.dumps(_dataset()), encoding="utf-8")
    source = tmp_path / "cpe-editor-dataset.tar.gz"
    with tarfile.open(source, "w:gz") as archive:
        archive.add(dataset_json, arcname="dataset.json")

    output = tmp_path / "dataset.jsonl"

    counts = export_dataset_to_jsonl(source, output)

    assert counts["products"] == 1
    rows = [
        json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()
    ]
    assert rows[-1]["collection"] == "cpes"
    assert rows[-1]["record"]["version"] == "2.0"
