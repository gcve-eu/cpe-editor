from app.models import Product, ProductAlias, ProductAliasMember, Proposal, db
from app.views import apply_proposal


def test_alias_proposal_acceptance_creates_alias(app):
    with app.app_context():
        products = Product.query.order_by(Product.id.asc()).limit(2).all()
        proposal = Proposal(
            proposal_type="new_product_alias",
            submitter_name="Alias Contributor",
            proposed_alias_name="Windows family",
            proposed_alias_description="Products commonly handled as Windows.",
            proposed_alias_members=[
                {"vendor_id": product.vendor_id, "product_id": product.id}
                for product in products
            ],
        )
        db.session.add(proposal)
        db.session.flush()

        apply_proposal(proposal)
        proposal.status = "accepted"
        db.session.commit()

        alias = ProductAlias.query.filter_by(name="Windows family").one()
        assert alias.proposal_id == proposal.id
        assert proposal.product_alias_id == alias.id
        assert {member.product_id for member in alias.members} == {
            product.id for product in products
        }


def test_alias_pages_and_proposal_form(client):
    aliases_response = client.get("/aliases")
    assert aliases_response.status_code == 200
    assert b"Product aliases" in aliases_response.data

    form_response = client.get("/aliases/proposals/new?q=windows")
    assert form_response.status_code == 200
    assert b"Propose new product alias" in form_response.data
    assert b"Microsoft" in form_response.data


def test_alias_proposal_product_search_is_paginated(client, app):
    with app.app_context():
        vendor = Product.query.first().vendor
        for index in range(105):
            db.session.add(
                Product(
                    vendor_id=vendor.id,
                    name=f"alias_pagination_product_{index:03d}",
                    title=f"Alias Pagination Product {index:03d}",
                )
            )
        db.session.commit()

    first_page = client.get("/aliases/proposals/new?q=alias_pagination")
    assert first_page.status_code == 200
    assert b"Showing page 1 of 2" in first_page.data
    assert b"Alias Pagination Product 000" in first_page.data
    assert b"Alias Pagination Product 104" not in first_page.data
    assert b"page=2" in first_page.data

    second_page = client.get("/aliases/proposals/new?q=alias_pagination&page=2")
    assert second_page.status_code == 200
    assert b"Showing page 2 of 2" in second_page.data
    assert b"Alias Pagination Product 104" in second_page.data
    assert b"page=1" in second_page.data

def test_alias_proposal_submission_requires_member(client):
    client.get("/aliases/proposals/new")
    with client.session_transaction() as sess:
        csrf_token = sess["_csrf_token"]
    response = client.post(
        "/aliases/proposals/new",
        data={
            "proposed_alias_name": "Empty alias",
            "proposed_alias_description": "No products selected.",
            "csrf_token": csrf_token,
        },
        follow_redirects=True,
    )
    assert b"Please select at least one vendor/product tuple" in response.data


def test_alias_api_list_and_detail(client, app):
    with app.app_context():
        product = Product.query.first()
        product_name = product.name
        alias = ProductAlias(name="Fixture alias", description="Fixture description")
        db.session.add(alias)
        db.session.flush()
        alias.members.append(
            ProductAliasMember(vendor_id=product.vendor_id, product_id=product.id)
        )
        db.session.commit()
        alias_uuid = alias.uuid

    list_response = client.get("/api/aliases?q=fixture&per_page=1")
    assert list_response.status_code == 200
    list_payload = list_response.get_json()
    assert list_payload["total"] == 1
    assert list_payload["items"][0]["uuid"] == alias_uuid
    assert list_payload["items"][0]["member_count"] == 1

    response = client.get(f"/api/aliases/{alias_uuid}")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["name"] == "Fixture alias"
    assert payload["member_count"] == 1
    assert payload["members"][0]["product_name"] == product_name


def test_product_api_detail_includes_aliases(client, app):
    with app.app_context():
        product = Product.query.first()
        alias = ProductAlias(name="Product detail alias")
        db.session.add(alias)
        db.session.flush()
        alias.members.append(
            ProductAliasMember(vendor_id=product.vendor_id, product_id=product.id)
        )
        db.session.commit()
        product_uuid = product.uuid
        alias_id = alias.id
        alias_uuid = alias.uuid
        alias_submitted_at = alias.submitted_at.isoformat()
        alias_created_at = alias.created_at.isoformat()
        alias_updated_at = alias.updated_at.isoformat()

    response = client.get(f"/api/products/{product_uuid}")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["aliases"] == [
        {
            "id": alias_id,
            "uuid": alias_uuid,
            "name": "Product detail alias",
            "description": None,
            "proposal_id": None,
            "member_count": 1,
            "submitted_at": alias_submitted_at,
            "approved_at": None,
            "created_at": alias_created_at,
            "updated_at": alias_updated_at,
        }
    ]


def test_app_dataset_export_import_preserves_product_aliases(app, tmp_path):
    from app.cli import write_app_dataset_archive

    output_path = tmp_path / "cpe-editor-dataset.tar.gz"

    with app.app_context():
        products = Product.query.order_by(Product.id.asc()).limit(2).all()
        alias = ProductAlias(
            name="Backup alias",
            description="Alias should survive export/import.",
            submitter_name="Dataset Tester",
            submitter_email="dataset@example.test",
        )
        db.session.add(alias)
        db.session.flush()
        for product in products:
            alias.members.append(
                ProductAliasMember(vendor_id=product.vendor_id, product_id=product.id)
            )
        db.session.commit()

        alias_uuid = alias.uuid
        member_product_names = {product.name for product in products}
        counts = write_app_dataset_archive(output_path)

    assert counts["aliases"] == 1

    runner = app.test_cli_runner()
    result = runner.invoke(
        args=["import-app-dataset", "--source", str(output_path), "--replace"]
    )

    assert result.exit_code == 0, result.output
    assert "aliases=1" in result.output
    with app.app_context():
        imported_alias = ProductAlias.query.filter_by(uuid=alias_uuid).one()
        assert imported_alias.name == "Backup alias"
        assert imported_alias.description == "Alias should survive export/import."
        assert imported_alias.submitter_name == "Dataset Tester"
        assert {
            member.product.name for member in imported_alias.members
        } == member_product_names
