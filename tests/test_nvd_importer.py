import io
import json
import tarfile

import pytest
from sqlalchemy.exc import IntegrityError

from app import cli
from app.models import CPEEntry, Product, Vendor, db
from app.utils import product_uuid_for_names, vendor_uuid_for_name


COMMANDS = ["import-nvd-cpes", "import-nvd-cpematches"]
PRODUCT_NAME = "collabora_online_-_built-in_code_server"


def write_feed(tmp_path, command, names, *, vendors=None):
    if vendors is None:
        vendors = ["collabora"] * len(names)
    entries = [
        {
            "cpeName": f"cpe:2.3:a:{vendor}:{name}:1.0:*:*:*:*:*:*:*",
            "cpeNameId": f"00000000-0000-4000-8000-{index:012d}",
        }
        for index, (vendor, name) in enumerate(zip(vendors, names, strict=True), start=1)
    ]
    if command == "import-nvd-cpes":
        payload = {"products": [{"cpe": entry} for entry in entries]}
    else:
        payload = {"matchStrings": [{"matchString": {"matches": entries}}]}
    data = json.dumps(payload).encode("utf-8")
    source = tmp_path / "nvd.tar.gz"
    with tarfile.open(source, "w:gz") as archive:
        member = tarfile.TarInfo("nvd.json")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    return source, entries


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("entity_kind", ["vendor", "product"])
def test_import_handles_uuid_created_after_cache_snapshot(
    app, tmp_path, monkeypatch, command, entity_kind
):
    source, entries = write_feed(
        tmp_path, command, ["before_conflict", PRODUCT_NAME, "after_conflict"]
    )
    vendor = Vendor(name="collabora", uuid=vendor_uuid_for_name("collabora"))
    db.session.add(vendor)
    db.session.commit()
    vendor_id = vendor.id
    if entity_kind == "vendor":
        db.session.delete(vendor)
        db.session.commit()

    iterator_name = (
        "iter_nvd_products" if command == "import-nvd-cpes" else "iter_nvd_match_strings"
    )
    original_iterator = getattr(cli, iterator_name)

    def insert_after_snapshot(source):
        # Another writer populates a UUID after the importer's caches are built.
        with db.engine.begin() as connection:
            if entity_kind == "vendor":
                connection.execute(
                    Vendor.__table__.insert(),
                    {"name": "collabora", "uuid": vendor_uuid_for_name("collabora")},
                )
            else:
                connection.execute(
                    Product.__table__.insert(),
                    {
                        "vendor_id": vendor_id,
                        "name": PRODUCT_NAME,
                        "uuid": product_uuid_for_names("collabora", PRODUCT_NAME),
                    },
                )
        yield from original_iterator(source)

    monkeypatch.setattr(cli, iterator_name, insert_after_snapshot)
    result = app.test_cli_runner().invoke(
        args=[command, "--source", str(source)]
    )

    assert result.exit_code == 0, (result.output, result.exception)
    assert Vendor.query.filter_by(name="collabora").count() == 1
    if entity_kind == "product":
        assert "uuid-conflicts=1" in result.output
        assert Product.query.filter_by(name=PRODUCT_NAME).count() == 1
        assert CPEEntry.query.filter_by(cpe_uri=entries[0]["cpeName"]).one()
        assert CPEEntry.query.filter_by(cpe_uri=entries[1]["cpeName"]).first() is None
        assert CPEEntry.query.filter_by(cpe_uri=entries[2]["cpeName"]).one()
    else:
        assert "uuid-conflicts=3" in result.output


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("entity_kind", ["vendor", "product"])
def test_import_handles_legacy_uuid_update_after_cache_snapshot(
    app, tmp_path, monkeypatch, command, entity_kind
):
    source, entries = write_feed(
        tmp_path,
        command,
        ["before_conflict", PRODUCT_NAME, "after_conflict"],
        vendors=["unrelated", "collabora", "unrelated"],
    )
    vendor = Vendor(name="collabora")
    if entity_kind == "product":
        vendor.uuid = vendor_uuid_for_name("collabora")
    db.session.add(vendor)
    db.session.flush()
    product = Product(vendor_id=vendor.id, name=PRODUCT_NAME)
    db.session.add(product)
    db.session.commit()
    vendor_id = vendor.id
    legacy = vendor if entity_kind == "vendor" else product
    legacy_uuid = legacy.uuid

    iterator_name = (
        "iter_nvd_products" if command == "import-nvd-cpes" else "iter_nvd_match_strings"
    )
    original_iterator = getattr(cli, iterator_name)

    def claim_uuid_after_snapshot(source):
        with db.engine.begin() as connection:
            if entity_kind == "vendor":
                connection.execute(
                    Vendor.__table__.insert(),
                    {"name": "COLLABORA", "uuid": vendor_uuid_for_name("collabora")},
                )
            else:
                connection.execute(
                    Product.__table__.insert(),
                    {
                        "vendor_id": vendor_id,
                        "name": PRODUCT_NAME.upper(),
                        "uuid": product_uuid_for_names("collabora", PRODUCT_NAME),
                    },
                )
        yield from original_iterator(source)

    monkeypatch.setattr(cli, iterator_name, claim_uuid_after_snapshot)
    result = app.test_cli_runner().invoke(args=[command, "--source", str(source)])

    assert result.exit_code == 0, (result.output, result.exception)
    assert "uuid-conflicts=1" in result.output
    db.session.refresh(legacy)
    assert legacy.uuid == legacy_uuid
    assert CPEEntry.query.filter_by(cpe_uri=entries[0]["cpeName"]).one()
    assert CPEEntry.query.filter_by(cpe_uri=entries[1]["cpeName"]).first() is None
    assert CPEEntry.query.filter_by(cpe_uri=entries[2]["cpeName"]).one()


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("entity_kind", ["vendor", "product"])
def test_import_preserves_legacy_rows_with_colliding_normalized_names(
    app, tmp_path, command, entity_kind
):
    source, _ = write_feed(tmp_path, command, [PRODUCT_NAME])
    vendor = Vendor(name="collabora", uuid=vendor_uuid_for_name("collabora"))
    db.session.add(vendor)
    db.session.flush()
    canonical = Product(
        vendor_id=vendor.id,
        name=PRODUCT_NAME,
        uuid=product_uuid_for_names("collabora", PRODUCT_NAME),
    )
    if entity_kind == "vendor":
        legacy = Vendor(name="Collabora")
    else:
        legacy = Product(vendor_id=vendor.id, name=PRODUCT_NAME.upper())
    db.session.add_all([canonical, legacy])
    db.session.commit()
    legacy_uuid = legacy.uuid
    canonical_uuid = canonical.uuid

    result = app.test_cli_runner().invoke(args=[command, "--source", str(source)])

    assert result.exit_code == 0, (result.output, result.exception)
    db.session.refresh(legacy)
    db.session.refresh(canonical)
    assert legacy.uuid == legacy_uuid
    assert canonical.uuid == canonical_uuid
    assert CPEEntry.query.filter_by(product_id=canonical.id).count() == 1


@pytest.mark.parametrize("command", COMMANDS)
def test_import_is_repeatable_across_batches(app, tmp_path, command):
    source, entries = write_feed(tmp_path, command, [PRODUCT_NAME, "another_product"])
    args = [command, "--source", str(source), "--batch-size", "1"]
    for _ in range(2):
        result = app.test_cli_runner().invoke(args=args)
        assert result.exit_code == 0, (result.output, result.exception)

    vendor = Vendor.query.filter_by(name="collabora").one()
    assert vendor.uuid == vendor_uuid_for_name("collabora")
    assert Product.query.filter_by(vendor_id=vendor.id).count() == 2
    for entry in entries:
        cpe = CPEEntry.query.filter_by(cpe_uri=entry["cpeName"]).one()
        assert cpe.cpe_name_id == entry["cpeNameId"]
        assert cpe.product.uuid == product_uuid_for_names("collabora", cpe.product.name)


def test_save_entity_with_uuid_surfaces_unrelated_integrity_errors(app):
    with pytest.raises(IntegrityError):
        cli._save_entity_with_uuid(Vendor(name=None, uuid=vendor_uuid_for_name("invalid")))

    # The failed INSERT only rolled back its savepoint.
    assert Vendor.query.filter_by(name="microsoft").one()


@pytest.mark.parametrize("existing", [False, True])
def test_save_entity_with_uuid_keeps_writes_in_outer_transaction(app, existing):
    if existing:
        vendor = Vendor.query.filter_by(name="microsoft").one()
        old_uuid = vendor.uuid
    else:
        vendor = Vendor(name="rolled_back")
    assert cli._save_entity_with_uuid(
        vendor, expected_uuid=vendor_uuid_for_name(vendor.name)
    )

    db.session.rollback()

    if existing:
        db.session.refresh(vendor)
        assert vendor.uuid == old_uuid
    else:
        assert Vendor.query.filter_by(name="rolled_back").first() is None


@pytest.mark.parametrize("entity_kind", ["vendor", "product"])
def test_backfill_reserves_uuid_for_rows_updated_in_the_same_pass(app, entity_kind):
    vendor = Vendor(name="collabora")
    db.session.add(vendor)
    db.session.flush()
    if entity_kind == "vendor":
        rows = [vendor, Vendor(name="Collabora")]
        expected_uuid = vendor_uuid_for_name("collabora")
    else:
        rows = [
            Product(vendor_id=vendor.id, name=PRODUCT_NAME),
            Product(vendor_id=vendor.id, name=PRODUCT_NAME.upper()),
        ]
        expected_uuid = product_uuid_for_names("collabora", PRODUCT_NAME)
    db.session.add_all(rows)
    db.session.commit()

    cli.backfill_missing_uuids()
    db.session.commit()

    uuids = {row.uuid for row in rows}
    assert len(uuids) == 2
    assert expected_uuid in uuids
