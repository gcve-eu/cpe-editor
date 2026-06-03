import json

from app.models import CPEEntry, CPEVulnerabilityReference, Product, Vendor
from app.utils import product_uuid_for_names, vendor_uuid_for_name


def test_import_gcve_enriched_cves_creates_cpes_and_references(app, tmp_path):
    cves_dir = tmp_path / "gcve-enriched-dumps" / "cves" / "2024" / "0xxx"
    cves_dir.mkdir(parents=True)
    nvd_payload = {
        "cve": {"id": "CVE-2024-9999"},
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:example:nvd_product:*:*:*:*:*:*:*:*",
                            }
                        ]
                    }
                ]
            }
        ],
    }
    payload = {
        "cveMetadata": {"cveId": "CVE-2024-9999"},
        "containers": {
            "adp": [
                {
                    "affected": [
                        {
                            "vendor": "example",
                            "product": "adp_product",
                            "cpes": ["cpe:2.3:a:example:adp_product:1.0:*:*:*:*:*:*:*"],
                            "versions": [{"version": "1.0", "status": "affected"}],
                        }
                    ]
                }
            ],
            "cna": {
                "affected": [
                    {
                        "vendor": "Example Vendor",
                        "product": "CNA Product",
                        "versions": [{"version": "1.0", "status": "affected"}],
                    }
                ]
            },
        },
        "vulnerability-lookup:meta": {"nvd": json.dumps(nvd_payload)},
    }
    cve_file = cves_dir / "CVE-2024-9999.json"
    cve_file.write_text(json.dumps(payload), encoding="utf-8")

    result = app.test_cli_runner().invoke(
        args=[
            "import-gcve-enriched-cves",
            "--source",
            str(tmp_path / "gcve-enriched-dumps"),
        ]
    )

    assert result.exit_code == 0, result.output
    assert "Imported 3 CVE→CPE references" in result.output

    cpe_uri = "cpe:2.3:a:example:adp_product:1.0:*:*:*:*:*:*:*"
    cpe = CPEEntry.query.filter_by(cpe_uri=cpe_uri).one()
    assert cpe.cpe_name_id
    assert cpe.vendor.uuid == vendor_uuid_for_name("example")
    assert cpe.product.uuid == product_uuid_for_names("example", "adp_product")

    built_cpe = CPEEntry.query.filter_by(
        cpe_uri="cpe:2.3:a:example_vendor:cna_product:*:*:*:*:*:*:*:*"
    ).one()
    assert built_cpe.vendor.name == "example_vendor"
    assert built_cpe.product.name == "cna_product"

    nvd_cpe = CPEEntry.query.filter_by(
        cpe_uri="cpe:2.3:a:example:nvd_product:*:*:*:*:*:*:*:*"
    ).one()
    references = CPEVulnerabilityReference.query.filter_by(
        vulnerability_source="CVE", vulnerability_id="CVE-2024-9999"
    ).all()
    assert {ref.cpe_entry_id for ref in references} == {
        cpe.id,
        built_cpe.id,
        nvd_cpe.id,
    }
    assert {ref.cpe_applicability for ref in references} == {"vulnerable"}

    duplicate = app.test_cli_runner().invoke(
        args=[
            "import-gcve-enriched-cves",
            "--source",
            str(tmp_path / "gcve-enriched-dumps"),
        ]
    )
    assert duplicate.exit_code == 0, duplicate.output
    assert "Imported 0 CVE→CPE references" in duplicate.output
    assert (
        CPEVulnerabilityReference.query.filter_by(
            vulnerability_id="CVE-2024-9999"
        ).count()
        == 3
    )
    assert Vendor.query.filter_by(name="example").count() == 1
    assert Product.query.filter_by(name="adp_product").count() == 1
