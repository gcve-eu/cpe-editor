import json
import tarfile

from tools.export_dataset_to_git import export_dataset_to_git_tree


def test_export_dataset_to_git_tree_writes_deterministic_shards(tmp_path):
    dataset = {
        "format": "cpe-editor-dataset",
        "version": "1",
        "exported_at": "2024-01-01T00:00:00+00:00",
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
                "cpe_uri": "cpe:2.3:a:example:product:2.0:*:*:*:*:*:*:*",
                "vendor_uuid": "vendor-uuid",
                "product_uuid": "product-uuid",
                "part": "a",
                "version": "2.0",
            },
            {
                "cpe_uri": "cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*",
                "vendor_uuid": "vendor-uuid",
                "product_uuid": "product-uuid",
                "part": "a",
                "version": "1.0",
            },
        ],
        "metadata": [
            {
                "record_type": "vendor",
                "record_uuid": "vendor-uuid",
                "metadata_key": "homepage",
                "metadata_value": "https://example.test",
            }
        ],
        "relationships": [
            {
                "relationship_type": "successor",
                "source_product_uuid": "product-uuid",
                "target_product_uuid": "next-product-uuid",
            }
        ],
        "purl_mappings": [
            {
                "cpe_uri": "cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*",
                "purl": "pkg:generic/example-product@1.0",
            }
        ],
        "proposals": [],
    }
    source = tmp_path / "dataset.tar.gz"
    dataset_json = tmp_path / "dataset.json"
    dataset_json.write_text(json.dumps(dataset), encoding="utf-8")
    with tarfile.open(source, "w:gz") as archive:
        archive.add(dataset_json, arcname="dataset.json")

    output_dir = tmp_path / "git-dataset"
    counts = export_dataset_to_git_tree(source, output_dir)

    assert counts["cpes"] == 2
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["layout"] == "git-sharded-v1"
    assert manifest["counts"]["purl_mappings"] == 1
    assert manifest["indexes"]["vendors_by_uuid"] == {
        "vendor-uuid": "vendors/example-vendor--vendor-uuid.json"
    }

    cpe_shard = (
        output_dir
        / "cpes"
        / "example-vendor--vendor-uuid"
        / "example-product--product-uuid"
        / "a.jsonl"
    )
    cpe_rows = [
        json.loads(line) for line in cpe_shard.read_text(encoding="utf-8").splitlines()
    ]
    assert [row["version"] for row in cpe_rows] == ["1.0", "2.0"]

    assert (
        output_dir / "metadata" / "vendors" / "vendor-uuid--vendor-uuid.jsonl"
    ).exists()
    assert (output_dir / "relationships" / "relationships.jsonl").exists()
    assert list((output_dir / "purl-mappings").glob("*.jsonl"))


def test_export_dataset_to_git_tree_updates_existing_output_directory(tmp_path):
    source = tmp_path / "dataset.json"
    source.write_text(
        json.dumps(
            {
                "format": "cpe-editor-dataset",
                "version": "1",
                "vendors": [],
                "products": [],
                "cpes": [],
                "metadata": [],
                "relationships": [],
                "purl_mappings": [],
                "proposals": [],
            }
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "git-dataset"
    output_dir.mkdir()
    (output_dir / ".git").mkdir()
    (output_dir / ".git" / "HEAD").write_text(
        "ref: refs/heads/main\n", encoding="utf-8"
    )
    stale_vendor_dir = output_dir / "vendors"
    stale_vendor_dir.mkdir()
    stale_vendor = stale_vendor_dir / "stale.json"
    stale_vendor.write_text("{}\n", encoding="utf-8")
    unrelated_file = output_dir / "notes.txt"
    unrelated_file.write_text("keep me\n", encoding="utf-8")

    counts = export_dataset_to_git_tree(source, output_dir)

    assert counts["vendors"] == 0
    assert (output_dir / "manifest.json").exists()
    assert not stale_vendor.exists()
    assert (output_dir / ".git" / "HEAD").read_text(
        encoding="utf-8"
    ) == "ref: refs/heads/main\n"
    assert unrelated_file.read_text(encoding="utf-8") == "keep me\n"
