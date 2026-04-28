from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from functools import wraps
from hmac import compare_digest
import secrets
from xml.sax.saxutils import escape

from flask import (
    Response,
    abort,
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from sqlalchemy import func, or_, text

from .models import (
    CPEEntry,
    EntityMetadata,
    EntityNote,
    EntityRelationship,
    Product,
    Proposal,
    Vendor,
    db,
)
from .utils import build_cpe_uri, normalize_token

bp = Blueprint("main", __name__)
RELATIONSHIP_TYPE_DESCRIPTIONS = {
    "synonym-of": "the source record is a synonym of the target record.",
    "canonical-of": "the source record is an alias whose canonical record is the target.",
    "renamed-to": "the source record has been renamed to the target.",
    "superseded-by": "the source record is obsolete and replaced operationally by the target.",
    "equivalent-to": "both records are considered operationally equivalent for identification purposes.",
    "vendor-merge-into": "vendor/product normalization relationship, when applicable.",
    "derived-from": "the record was derived from another source record.",
}
PRODUCT_COMBINED_VIEW_RELATIONSHIP_TYPES = {
    "synonym-of",
    "canonical-of",
    "equivalent-to",
}
ALLOWED_METADATA_KEYS = {"gcve:description", "gcve:url"}


# --- Helpers -----------------------------------------------------------------
def _get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@bp.app_context_processor
def inject_csrf_token():
    return {"csrf_token": _get_csrf_token}


@bp.before_app_request
def validate_csrf_token():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    session_token = session.get("_csrf_token")
    form_token = request.form.get("csrf_token")
    if not session_token or not form_token or not compare_digest(session_token, form_token):
        abort(400, description="Invalid or missing CSRF token.")
    return None



def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Please log in as admin.", "warning")
            return redirect(url_for("main.admin_login", next=request.path))
        return view_func(*args, **kwargs)

    return wrapped


def _serialize_vendor(vendor):
    return {
        "id": vendor.id,
        "uuid": vendor.uuid,
        "name": vendor.name,
        "title": vendor.title,
        "notes": vendor.notes,
        "created_at": vendor.created_at.isoformat() if vendor.created_at else None,
        "updated_at": vendor.updated_at.isoformat() if vendor.updated_at else None,
        "product_count": len(vendor.products),
        "approved_notes": [
            _serialize_entity_note(note)
            for note in sorted(
                vendor.note_entries,
                key=lambda entry: (entry.approved_at or datetime.min, entry.submitted_at),
                reverse=True,
            )
        ],
        "approved_metadata": [
            _serialize_entity_metadata(metadata)
            for metadata in sorted(
                vendor.metadata_entries,
                key=lambda entry: (entry.approved_at or datetime.min, entry.submitted_at),
                reverse=True,
            )
        ],
        "approved_relationships": [
            _serialize_entity_relationship(relationship)
            for relationship in sorted(
                vendor.outgoing_relationships,
                key=lambda entry: (entry.approved_at or datetime.min, entry.submitted_at),
                reverse=True,
            )
        ],
    }


def _serialize_product(product):
    return {
        "id": product.id,
        "uuid": product.uuid,
        "vendor_id": product.vendor_id,
        "vendor_uuid": product.vendor.uuid if product.vendor else None,
        "name": product.name,
        "title": product.title,
        "notes": product.notes,
        "created_at": product.created_at.isoformat() if product.created_at else None,
        "updated_at": product.updated_at.isoformat() if product.updated_at else None,
        "cpe_count": len(product.cpes),
        "approved_notes": [
            _serialize_entity_note(note)
            for note in sorted(
                product.note_entries,
                key=lambda entry: (entry.approved_at or datetime.min, entry.submitted_at),
                reverse=True,
            )
        ],
        "approved_metadata": [
            _serialize_entity_metadata(metadata)
            for metadata in sorted(
                product.metadata_entries,
                key=lambda entry: (entry.approved_at or datetime.min, entry.submitted_at),
                reverse=True,
            )
        ],
        "approved_relationships": [
            _serialize_entity_relationship(relationship)
            for relationship in sorted(
                product.outgoing_relationships,
                key=lambda entry: (entry.approved_at or datetime.min, entry.submitted_at),
                reverse=True,
            )
        ],
    }


def _serialize_vendor_option(vendor):
    return {
        "id": vendor.id,
        "uuid": vendor.uuid,
        "name": vendor.name,
        "title": vendor.title or vendor.name,
    }


def _serialize_product_option(product):
    vendor = product.vendor
    return {
        "id": product.id,
        "uuid": product.uuid,
        "vendor_id": product.vendor_id,
        "vendor_uuid": vendor.uuid if vendor else None,
        "name": product.name,
        "title": product.title or product.name,
        "vendor_name": vendor.name if vendor else None,
        "vendor_title": (vendor.title or vendor.name) if vendor else None,
    }


def _serialize_entity_note(note):
    return {
        "id": note.id,
        "vendor_id": note.vendor_id,
        "product_id": note.product_id,
        "proposal_id": note.proposal_id,
        "note_text": note.note_text,
        "submitter_name": note.submitter_name,
        "submitter_email": note.submitter_email,
        "submitted_at": note.submitted_at.isoformat() if note.submitted_at else None,
        "approved_at": note.approved_at.isoformat() if note.approved_at else None,
    }


def _serialize_entity_metadata(metadata):
    return {
        "id": metadata.id,
        "vendor_id": metadata.vendor_id,
        "product_id": metadata.product_id,
        "proposal_id": metadata.proposal_id,
        "metadata_key": metadata.metadata_key,
        "metadata_value": metadata.metadata_value,
        "submitter_name": metadata.submitter_name,
        "submitter_email": metadata.submitter_email,
        "submitted_at": metadata.submitted_at.isoformat() if metadata.submitted_at else None,
        "approved_at": metadata.approved_at.isoformat() if metadata.approved_at else None,
    }


def _record_label(vendor: Vendor | None, product: Product | None):
    if vendor:
        return {
            "entity_type": "vendor",
            "id": vendor.id,
            "uuid": vendor.uuid,
            "name": vendor.name,
            "title": vendor.title,
        }
    if product:
        return {
            "entity_type": "product",
            "id": product.id,
            "uuid": product.uuid,
            "name": product.name,
            "title": product.title,
            "vendor_id": product.vendor_id,
            "vendor_uuid": product.vendor.uuid if product.vendor else None,
        }
    return None


def _serialize_entity_relationship(relationship):
    return {
        "id": relationship.id,
        "relationship_type": relationship.relationship_type,
        "relationship_type_description": RELATIONSHIP_TYPE_DESCRIPTIONS.get(
            relationship.relationship_type
        ),
        "proposal_id": relationship.proposal_id,
        "rationale": relationship.rationale,
        "submitter_name": relationship.submitter_name,
        "submitter_email": relationship.submitter_email,
        "submitted_at": relationship.submitted_at.isoformat() if relationship.submitted_at else None,
        "approved_at": relationship.approved_at.isoformat() if relationship.approved_at else None,
        "source": _record_label(relationship.source_vendor, relationship.source_product),
        "target": _record_label(relationship.target_vendor, relationship.target_product),
    }


def _get_request_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _is_rate_limited_for_ip(ip_address: str):
    limit = current_app.config.get("PROPOSAL_RATE_LIMIT_PER_HOUR", 10)
    if limit is None or limit <= 0:
        return False

    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    recent_count = Proposal.query.filter(
        Proposal.submitter_ip == ip_address,
        Proposal.created_at >= one_hour_ago,
    ).count()
    return recent_count >= limit


def _serialize_cpe(cpe):
    return {
        "id": cpe.id,
        "vendor_id": cpe.vendor_id,
        "vendor_uuid": cpe.vendor.uuid if cpe.vendor else None,
        "product_id": cpe.product_id,
        "product_uuid": cpe.product.uuid if cpe.product else None,
        "cpe_uri": cpe.cpe_uri,
        "cpe_name_id": cpe.cpe_name_id,
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
        "created_at": cpe.created_at.isoformat() if cpe.created_at else None,
        "updated_at": cpe.updated_at.isoformat() if cpe.updated_at else None,
    }


def _proposal_focus_links(proposal: Proposal):
    links = []
    seen = set()

    def add_entity_link(label: str, endpoint: str, **kwargs):
        key = (endpoint, tuple(sorted(kwargs.items())))
        if key in seen:
            return
        seen.add(key)
        links.append({"label": label, "endpoint": endpoint, "kwargs": kwargs})

    vendor_refs = [proposal.vendor, proposal.source_vendor, proposal.target_vendor]
    for vendor in vendor_refs:
        if vendor:
            add_entity_link(
                f"Vendor: {vendor.title or vendor.name}",
                "main.vendor_detail",
                vendor_uuid=vendor.uuid,
            )

    product_refs = [proposal.product, proposal.source_product, proposal.target_product]
    for product in product_refs:
        if product:
            add_entity_link(
                f"Product: {product.title or product.name}",
                "main.product_detail",
                product_uuid=product.uuid,
            )

    if proposal.cpe_entry:
        add_entity_link(
            f"CPE #{proposal.cpe_entry.id}",
            "main.cpe_detail",
            cpe_id=proposal.cpe_entry.id,
        )

    return links


def _proposal_summary(proposal: Proposal):
    if proposal.proposal_type == "new_vendor_product":
        return (
            f"Added vendor '{proposal.proposed_vendor_title or proposal.proposed_vendor_name}' "
            f"and product '{proposal.proposed_product_title or proposal.proposed_product_name}'."
        )
    if proposal.proposal_type == "new_product":
        return f"Added product '{proposal.proposed_product_title or proposal.proposed_product_name}'."
    if proposal.proposal_type == "new_cpe":
        return f"Added CPE candidate {proposal.proposed_cpe_uri or 'for an existing record'}."
    if proposal.proposal_type == "edit_cpe":
        return f"Approved CPE edit to {proposal.proposed_cpe_uri or 'an existing CPE entry'}."
    if proposal.proposal_type == "edit_vendor_note":
        return "Approved a vendor note update."
    if proposal.proposal_type == "edit_product_note":
        return "Approved a product note update."
    if proposal.proposal_type == "edit_vendor_metadata":
        return "Approved a vendor metadata update."
    if proposal.proposal_type == "edit_product_metadata":
        return "Approved a product metadata update."
    if proposal.proposal_type == "new_record_relationship":
        relationship_label = proposal.proposed_relationship_type or "relationship"
        return f"Approved a {relationship_label} relationship."
    return "Approved proposal."


def _proposal_feed_timestamp(proposal: Proposal):
    timestamp = proposal.reviewed_at or proposal.created_at or datetime.utcnow()
    return timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=timezone.utc)


def _build_change_feed_entries(changes: list[Proposal]):
    entries = []
    for proposal in changes:
        change_url = url_for("main.approved_change_detail", proposal_id=proposal.id, _external=True)
        published = _proposal_feed_timestamp(proposal)
        entries.append(
            {
                "id": proposal.id,
                "title": f"Approved change #{proposal.id}",
                "summary": _proposal_summary(proposal),
                "url": change_url,
                "published": published,
                "published_rfc822": format_datetime(published),
                "published_rfc3339": published.isoformat().replace("+00:00", "Z"),
            }
        )
    return entries


def _collect_related_products_for_combined_view(product: Product):
    related_vendor_ids = {product.vendor_id}
    vendor_queue = [product.vendor_id]
    while vendor_queue:
        current_vendor_id = vendor_queue.pop(0)
        vendor_relationships = (
            EntityRelationship.query.filter(
                EntityRelationship.relationship_type.in_(
                    PRODUCT_COMBINED_VIEW_RELATIONSHIP_TYPES
                ),
                or_(
                    EntityRelationship.source_vendor_id == current_vendor_id,
                    EntityRelationship.target_vendor_id == current_vendor_id,
                ),
            ).all()
        )
        for relationship in vendor_relationships:
            vendor_neighbor_ids = [
                relationship.source_vendor_id,
                relationship.target_vendor_id,
            ]
            for vendor_neighbor_id in vendor_neighbor_ids:
                if not vendor_neighbor_id or vendor_neighbor_id in related_vendor_ids:
                    continue
                related_vendor_ids.add(vendor_neighbor_id)
                vendor_queue.append(vendor_neighbor_id)

    related_product_ids = {product.id}
    queue = [product.id]

    if related_vendor_ids:
        vendor_related_products = (
            Product.query.filter(
                Product.vendor_id.in_(related_vendor_ids),
                func.lower(Product.name) == product.name.lower(),
            ).all()
        )
        for vendor_related_product in vendor_related_products:
            if vendor_related_product.id in related_product_ids:
                continue
            related_product_ids.add(vendor_related_product.id)
            queue.append(vendor_related_product.id)

    while queue:
        current_product_id = queue.pop(0)
        relationships = (
            EntityRelationship.query.filter(
                EntityRelationship.relationship_type.in_(
                    PRODUCT_COMBINED_VIEW_RELATIONSHIP_TYPES
                ),
                or_(
                    EntityRelationship.source_product_id == current_product_id,
                    EntityRelationship.target_product_id == current_product_id,
                ),
            ).all()
        )
        for relationship in relationships:
            neighbor_ids = [
                relationship.source_product_id,
                relationship.target_product_id,
            ]
            for neighbor_id in neighbor_ids:
                if not neighbor_id or neighbor_id in related_product_ids:
                    continue
                related_product_ids.add(neighbor_id)
                queue.append(neighbor_id)

    return (
        Product.query.filter(Product.id.in_(related_product_ids))
        .order_by(Product.name.asc(), Product.id.asc())
        .all()
    )


def _collect_related_vendors_for_combined_view(vendor: Vendor):
    related_vendor_ids = {vendor.id}
    vendor_queue = [vendor.id]
    while vendor_queue:
        current_vendor_id = vendor_queue.pop(0)
        vendor_relationships = (
            EntityRelationship.query.filter(
                EntityRelationship.relationship_type.in_(
                    PRODUCT_COMBINED_VIEW_RELATIONSHIP_TYPES
                ),
                or_(
                    EntityRelationship.source_vendor_id == current_vendor_id,
                    EntityRelationship.target_vendor_id == current_vendor_id,
                ),
            ).all()
        )
        for relationship in vendor_relationships:
            vendor_neighbor_ids = [
                relationship.source_vendor_id,
                relationship.target_vendor_id,
            ]
            for vendor_neighbor_id in vendor_neighbor_ids:
                if not vendor_neighbor_id or vendor_neighbor_id in related_vendor_ids:
                    continue
                related_vendor_ids.add(vendor_neighbor_id)
                vendor_queue.append(vendor_neighbor_id)

    return (
        Vendor.query.filter(Vendor.id.in_(related_vendor_ids))
        .order_by(Vendor.name.asc(), Vendor.id.asc())
        .all()
    )


# --- Public views -------------------------------------------------------------
@bp.route("/")
def index():
    vendor_q = (request.args.get("vendor_q") or "").strip()
    product_q = (request.args.get("product_q") or "").strip()
    part = (request.args.get("part") or "").strip()
    page = max(request.args.get("page", default=1, type=int) or 1, 1)
    per_page = 25
    has_search_filters = any([vendor_q, product_q, part])

    if not has_search_filters:
        return render_template(
            "index.html",
            results=[],
            vendor_q=vendor_q,
            product_q=product_q,
            part=part,
            page=1,
            total_pages=1,
            has_prev=False,
            has_next=False,
            total_results=0,
            has_search_filters=has_search_filters,
        )

    query = CPEEntry.query.join(Vendor).join(Product)
    if vendor_q:
        vendor_like = f"{vendor_q.lower()}%"
        query = query.filter(
            or_(
                func.lower(Vendor.name).like(vendor_like),
                func.lower(Vendor.title).like(vendor_like),
            )
        )
    if product_q:
        product_like = f"{product_q.lower()}%"
        query = query.filter(
            or_(
                func.lower(Product.name).like(product_like),
                func.lower(Product.title).like(product_like),
            )
        )
    if part:
        query = query.filter(CPEEntry.part == part)

    ordered_query = query.order_by(Vendor.name.asc(), Product.name.asc(), CPEEntry.cpe_uri.asc())
    total_results = ordered_query.count()
    total_pages = max((total_results + per_page - 1) // per_page, 1)
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * per_page
    results = ordered_query.offset(offset).limit(per_page).all()

    return render_template(
        "index.html",
        results=results,
        vendor_q=vendor_q,
        product_q=product_q,
        part=part,
        page=page,
        total_pages=total_pages,
        has_prev=page > 1,
        has_next=page < total_pages,
        total_results=total_results,
        has_search_filters=has_search_filters,
    )


@bp.route("/vendors")
def vendors():
    vendor_page = max(request.args.get("page", default=1, type=int) or 1, 1)
    vendors_per_page = 25

    vendor_query = Vendor.query.order_by(Vendor.name.asc())
    vendor_total = vendor_query.count()
    vendor_total_pages = max((vendor_total + vendors_per_page - 1) // vendors_per_page, 1)
    if vendor_page > vendor_total_pages:
        vendor_page = vendor_total_pages
    vendor_offset = (vendor_page - 1) * vendors_per_page
    vendors = vendor_query.offset(vendor_offset).limit(vendors_per_page).all()

    return render_template(
        "vendors.html",
        vendors=vendors,
        vendor_page=vendor_page,
        vendor_total_pages=vendor_total_pages,
        vendor_has_prev=vendor_page > 1,
        vendor_has_next=vendor_page < vendor_total_pages,
    )


@bp.route("/statistics")
def statistics():
    vendor_page = max(request.args.get("vendor_page", default=1, type=int) or 1, 1)
    vendors_per_page = 25

    total_vendors = db.session.query(func.count(Vendor.id)).scalar() or 0
    total_products = db.session.query(func.count(Product.id)).scalar() or 0
    total_cpes = db.session.query(func.count(CPEEntry.id)).scalar() or 0

    vendor_product_counts_query = (
        db.session.query(
            Vendor.id.label("vendor_id"),
            Vendor.uuid.label("vendor_uuid"),
            Vendor.name.label("vendor_name"),
            Vendor.title.label("vendor_title"),
            func.count(Product.id).label("product_count"),
        )
        .outerjoin(Product, Product.vendor_id == Vendor.id)
        .group_by(Vendor.id, Vendor.uuid, Vendor.name, Vendor.title)
        .order_by(func.count(Product.id).desc(), Vendor.name.asc())
    )

    vendor_product_total = vendor_product_counts_query.count()
    vendor_product_total_pages = max((vendor_product_total + vendors_per_page - 1) // vendors_per_page, 1)
    if vendor_page > vendor_product_total_pages:
        vendor_page = vendor_product_total_pages
    vendor_offset = (vendor_page - 1) * vendors_per_page
    vendor_product_counts = (
        vendor_product_counts_query
        .offset(vendor_offset)
        .limit(vendors_per_page)
        .all()
    )

    top_vendor = vendor_product_counts_query.first()
    vendors_with_products = (
        db.session.query(func.count(func.distinct(Vendor.id)))
        .join(Product, Product.vendor_id == Vendor.id)
        .scalar()
        or 0
    )
    average_products_per_vendor = (
        round(total_products / total_vendors, 2) if total_vendors else 0
    )
    vendors_without_products = max(total_vendors - vendors_with_products, 0)

    cpe_part_counts = (
        db.session.query(CPEEntry.part, func.count(CPEEntry.id).label("count"))
        .group_by(CPEEntry.part)
        .order_by(func.count(CPEEntry.id).desc())
        .all()
    )

    return render_template(
        "statistics.html",
        total_vendors=total_vendors,
        total_products=total_products,
        total_cpes=total_cpes,
        average_products_per_vendor=average_products_per_vendor,
        top_vendor=top_vendor,
        vendors_without_products=vendors_without_products,
        vendor_product_counts=vendor_product_counts,
        vendor_page=vendor_page,
        vendor_total_pages=vendor_product_total_pages,
        vendor_has_prev=vendor_page > 1,
        vendor_has_next=vendor_page < vendor_product_total_pages,
        vendor_rank_start=vendor_offset + 1,
        cpe_part_counts=cpe_part_counts,
    )


@bp.route("/vendors/<string:vendor_uuid>")
def vendor_detail(vendor_uuid):
    vendor = Vendor.query.filter_by(uuid=vendor_uuid).first_or_404()
    vendor_notes = (
        EntityNote.query.filter_by(vendor_id=vendor.id)
        .order_by(EntityNote.approved_at.desc(), EntityNote.submitted_at.desc())
        .all()
    )
    vendor_metadata = (
        EntityMetadata.query.filter_by(vendor_id=vendor.id)
        .order_by(EntityMetadata.approved_at.desc(), EntityMetadata.submitted_at.desc())
        .all()
    )
    vendor_relationships = (
        EntityRelationship.query.filter(
            or_(
                EntityRelationship.source_vendor_id == vendor.id,
                EntityRelationship.target_vendor_id == vendor.id,
            )
        )
        .order_by(EntityRelationship.approved_at.desc(), EntityRelationship.submitted_at.desc())
        .all()
    )
    combined_view_vendors = _collect_related_vendors_for_combined_view(vendor)
    combined_view_products = (
        Product.query.filter(Product.vendor_id.in_([related_vendor.id for related_vendor in combined_view_vendors]))
        .order_by(Product.name.asc(), Product.id.asc())
        .all()
    )
    return render_template(
        "vendor_detail.html",
        vendor=vendor,
        vendor_notes=vendor_notes,
        vendor_metadata=vendor_metadata,
        vendor_relationships=vendor_relationships,
        combined_view_vendors=combined_view_vendors,
        combined_view_products=combined_view_products,
        combined_view_relationship_types=sorted(PRODUCT_COMBINED_VIEW_RELATIONSHIP_TYPES),
        relationship_type_descriptions=RELATIONSHIP_TYPE_DESCRIPTIONS,
    )


@bp.route("/products/<string:product_uuid>")
def product_detail(product_uuid):
    product = Product.query.filter_by(uuid=product_uuid).first_or_404()
    product_notes = (
        EntityNote.query.filter_by(product_id=product.id)
        .order_by(EntityNote.approved_at.desc(), EntityNote.submitted_at.desc())
        .all()
    )
    product_metadata = (
        EntityMetadata.query.filter_by(product_id=product.id)
        .order_by(EntityMetadata.approved_at.desc(), EntityMetadata.submitted_at.desc())
        .all()
    )
    product_relationships = (
        EntityRelationship.query.filter(
            or_(
                EntityRelationship.source_product_id == product.id,
                EntityRelationship.target_product_id == product.id,
            )
        )
        .order_by(EntityRelationship.approved_at.desc(), EntityRelationship.submitted_at.desc())
        .all()
    )
    combined_view_products = _collect_related_products_for_combined_view(product)
    combined_view_cpes = (
        CPEEntry.query.filter(
            CPEEntry.product_id.in_([related_product.id for related_product in combined_view_products])
        )
        .order_by(CPEEntry.cpe_uri.asc())
        .all()
    )
    return render_template(
        "product_detail.html",
        product=product,
        product_notes=product_notes,
        product_metadata=product_metadata,
        product_relationships=product_relationships,
        combined_view_products=combined_view_products,
        combined_view_cpes=combined_view_cpes,
        combined_view_relationship_types=sorted(PRODUCT_COMBINED_VIEW_RELATIONSHIP_TYPES),
        relationship_type_descriptions=RELATIONSHIP_TYPE_DESCRIPTIONS,
    )


@bp.route("/cpes/<int:cpe_id>")
def cpe_detail(cpe_id):
    cpe = CPEEntry.query.get_or_404(cpe_id)
    return render_template("cpe_detail.html", cpe=cpe)


@bp.route("/api/openapi.yaml")
def api_openapi_spec():
    return send_from_directory(current_app.static_folder, "openapi.yaml")


@bp.route("/api/docs")
def api_docs():
    return render_template("api_docs.html")


@bp.route("/api/vendors")
def api_vendors():
    q = (request.args.get("q") or "").strip()
    page = max(request.args.get("page", default=1, type=int) or 1, 1)
    per_page = min(max(request.args.get("per_page", default=25, type=int) or 25, 1), 100)

    query = Vendor.query
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(
            or_(
                func.lower(Vendor.name).like(like),
                func.lower(Vendor.title).like(like),
            )
        )

    total = query.count()
    results = (
        query.order_by(Vendor.name.asc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return jsonify(
        {
            "items": [_serialize_vendor(vendor) for vendor in results],
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": max((total + per_page - 1) // per_page, 1),
        }
    )


@bp.route("/api/vendors/suggest")
def api_vendor_suggestions():
    q = (request.args.get("q") or "").strip()
    if len(q) < 1:
        return jsonify({"items": []})
    limit = min(max(request.args.get("limit", default=20, type=int) or 20, 1), 50)
    vendor_like = f"{q.lower()}%"
    results = (
        Vendor.query.filter(
            or_(
                func.lower(Vendor.name).like(vendor_like),
                func.lower(Vendor.title).like(vendor_like),
            )
        )
        .order_by(Vendor.name.asc())
        .limit(limit)
        .all()
    )
    return jsonify({"items": [_serialize_vendor_option(vendor) for vendor in results]})


@bp.route("/api/vendors/<string:vendor_uuid>")
def api_vendor_detail(vendor_uuid):
    vendor = Vendor.query.filter_by(uuid=vendor_uuid).first_or_404()
    return jsonify(_serialize_vendor(vendor))


@bp.route("/api/products/<string:product_uuid>")
def api_product_detail(product_uuid):
    product = Product.query.filter_by(uuid=product_uuid).first_or_404()
    return jsonify(_serialize_product(product))


@bp.route("/api/products/suggest")
def api_product_suggestions():
    q = (request.args.get("q") or "").strip()
    if len(q) < 1:
        return jsonify({"items": []})
    limit = min(max(request.args.get("limit", default=20, type=int) or 20, 1), 50)
    product_like = f"{q.lower()}%"
    results = (
        Product.query.join(Vendor)
        .filter(
            or_(
                func.lower(Product.name).like(product_like),
                func.lower(Product.title).like(product_like),
            )
        )
        .order_by(Product.name.asc())
        .limit(limit)
        .all()
    )
    return jsonify({"items": [_serialize_product_option(product) for product in results]})


@bp.route("/api/cpes/<int:cpe_id>")
def api_cpe_detail(cpe_id):
    cpe = CPEEntry.query.get_or_404(cpe_id)
    return jsonify(_serialize_cpe(cpe))


@bp.route("/api/cpes")
def api_cpes():
    q = (request.args.get("q") or "").strip()
    vendor_q = (request.args.get("vendor_q") or "").strip()
    product_q = (request.args.get("product_q") or "").strip()
    part = (request.args.get("part") or "").strip()
    page = max(request.args.get("page", default=1, type=int) or 1, 1)
    per_page = min(max(request.args.get("per_page", default=25, type=int) or 25, 1), 100)

    query = CPEEntry.query.join(Vendor).join(Product)
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(
            or_(
                func.lower(CPEEntry.cpe_uri).like(like),
                func.lower(CPEEntry.title).like(like),
                func.lower(Vendor.name).like(like),
                func.lower(Vendor.title).like(like),
                func.lower(Product.name).like(like),
                func.lower(Product.title).like(like),
                func.lower(CPEEntry.version).like(like),
            )
        )
    if vendor_q:
        vendor_like = f"{vendor_q.lower()}%"
        query = query.filter(
            or_(
                func.lower(Vendor.name).like(vendor_like),
                func.lower(Vendor.title).like(vendor_like),
            )
        )
    if product_q:
        product_like = f"{product_q.lower()}%"
        query = query.filter(
            or_(
                func.lower(Product.name).like(product_like),
                func.lower(Product.title).like(product_like),
            )
        )
    if part:
        query = query.filter(CPEEntry.part == part)

    total = query.count()
    results = (
        query.order_by(Vendor.name.asc(), Product.name.asc(), CPEEntry.cpe_uri.asc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return jsonify(
        {
            "items": [_serialize_cpe(cpe) for cpe in results],
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": max((total + per_page - 1) // per_page, 1),
        }
    )


@bp.route("/proposals/new", methods=["GET", "POST"])
def proposal_new():
    preselected_vendor_id = request.args.get("vendor_id", type=int)
    preselected_product_id = request.args.get("product_id", type=int)
    preselected_proposal_type = request.args.get("proposal_type", "edit_cpe")
    allowed_types = {
        "edit_cpe",
        "new_cpe",
        "new_product",
        "new_vendor_product",
        "new_record_relationship",
    }
    if preselected_proposal_type not in allowed_types:
        preselected_proposal_type = "edit_cpe"

    preselected_vendor = None
    if preselected_vendor_id:
        preselected_vendor = Vendor.query.get(preselected_vendor_id)
        if not preselected_vendor:
            preselected_vendor_id = None

    preselected_product = None
    if preselected_product_id:
        preselected_product = Product.query.get(preselected_product_id)
        if not preselected_product:
            preselected_product_id = None

    if request.method == "POST":
        proposal_type = request.form.get("proposal_type", "edit_cpe")
        if proposal_type not in allowed_types:
            flash("Please choose a valid proposal type.", "danger")
            return redirect(url_for("main.proposal_new"))
        vendor_id = request.form.get("vendor_id") or None
        product_id = request.form.get("product_id") or None
        cpe_entry_id = request.form.get("cpe_entry_id") or None
        submitter_ip = _get_request_ip()

        if _is_rate_limited_for_ip(submitter_ip):
            limit = current_app.config.get("PROPOSAL_RATE_LIMIT_PER_HOUR", 10)
            flash(
                f"Rate limit reached for your IP address. Please wait before submitting more proposals (limit: {limit} per hour).",
                "danger",
            )
            return redirect(url_for("main.proposal_new", proposal_type=proposal_type))

        proposal = Proposal(
            proposal_type=proposal_type,
            submitter_name=request.form.get("submitter_name"),
            submitter_email=request.form.get("submitter_email"),
            submitter_ip=submitter_ip,
            rationale=request.form.get("rationale"),
            vendor_id=int(vendor_id) if vendor_id else None,
            product_id=int(product_id) if product_id else None,
            cpe_entry_id=int(cpe_entry_id) if cpe_entry_id else None,
            proposed_vendor_name=request.form.get("proposed_vendor_name"),
            proposed_vendor_title=request.form.get("proposed_vendor_title"),
            proposed_product_name=request.form.get("proposed_product_name"),
            proposed_product_title=request.form.get("proposed_product_title"),
            proposed_part=request.form.get("proposed_part"),
            proposed_version=request.form.get("proposed_version") or "*",
            proposed_update=request.form.get("proposed_update") or "*",
            proposed_edition=request.form.get("proposed_edition") or "*",
            proposed_language=request.form.get("proposed_language") or "*",
            proposed_sw_edition=request.form.get("proposed_sw_edition") or "*",
            proposed_target_sw=request.form.get("proposed_target_sw") or "*",
            proposed_target_hw=request.form.get("proposed_target_hw") or "*",
            proposed_other=request.form.get("proposed_other") or "*",
            proposed_title=request.form.get("proposed_title"),
            proposed_notes=request.form.get("proposed_notes"),
            proposed_relationship_type=request.form.get("proposed_relationship_type"),
            source_vendor_id=int(request.form.get("source_vendor_id"))
            if request.form.get("source_vendor_id")
            else None,
            source_product_id=int(request.form.get("source_product_id"))
            if request.form.get("source_product_id")
            else None,
            target_vendor_id=int(request.form.get("target_vendor_id"))
            if request.form.get("target_vendor_id")
            else None,
            target_product_id=int(request.form.get("target_product_id"))
            if request.form.get("target_product_id")
            else None,
        )

        vendor_name = (request.form.get("proposed_vendor_name") or "").strip()
        product_name = (request.form.get("proposed_product_name") or "").strip()
        part_value = request.form.get("proposed_part") or "a"
        if proposal_type in {"new_cpe", "edit_cpe", "new_vendor_product", "new_product"}:
            if vendor_id and not vendor_name:
                existing_vendor = Vendor.query.get(int(vendor_id))
                vendor_name = existing_vendor.name if existing_vendor else vendor_name
            if product_id and not product_name:
                existing_product = Product.query.get(int(product_id))
                product_name = existing_product.name if existing_product else product_name
            proposal.proposed_cpe_uri = build_cpe_uri(
                part_value,
                vendor_name,
                product_name,
                proposal.proposed_version,
                proposal.proposed_update,
                proposal.proposed_edition,
                proposal.proposed_language,
                proposal.proposed_sw_edition,
                proposal.proposed_target_sw,
                proposal.proposed_target_hw,
                proposal.proposed_other,
            )

        if proposal_type == "new_record_relationship":
            if proposal.proposed_relationship_type not in RELATIONSHIP_TYPE_DESCRIPTIONS:
                flash("Please choose a valid relationship type.", "danger")
                return redirect(url_for("main.proposal_new", proposal_type=proposal_type))
            source_count = int(bool(proposal.source_vendor_id)) + int(bool(proposal.source_product_id))
            target_count = int(bool(proposal.target_vendor_id)) + int(bool(proposal.target_product_id))
            if source_count != 1 or target_count != 1:
                flash("Please choose exactly one source record and one target record.", "danger")
                return redirect(url_for("main.proposal_new", proposal_type=proposal_type))
            source_id = proposal.source_vendor_id or proposal.source_product_id
            target_id = proposal.target_vendor_id or proposal.target_product_id
            if source_id == target_id:
                flash("Source and target records must be different.", "danger")
                return redirect(url_for("main.proposal_new", proposal_type=proposal_type))

        db.session.add(proposal)
        db.session.commit()
        flash("Proposal submitted. An admin will review it.", "success")
        return redirect(url_for("main.index"))

    return render_template(
        "proposal_form.html",
        preselected_vendor_id=preselected_vendor_id,
        preselected_product_id=preselected_product_id,
        preselected_proposal_type=preselected_proposal_type,
        preselected_vendor=preselected_vendor,
        preselected_product=preselected_product,
        relationship_type_descriptions=RELATIONSHIP_TYPE_DESCRIPTIONS,
    )


@bp.route("/proposals/note/new", methods=["GET", "POST"])
def note_proposal_new():
    preselected_vendor_id = request.args.get("vendor_id", type=int)
    preselected_product_id = request.args.get("product_id", type=int)

    preselected_vendor = Vendor.query.get(preselected_vendor_id) if preselected_vendor_id else None
    preselected_product = Product.query.get(preselected_product_id) if preselected_product_id else None
    if preselected_vendor_id and not preselected_vendor:
        preselected_vendor_id = None
    if preselected_product_id and not preselected_product:
        preselected_product_id = None

    if preselected_vendor_id and preselected_product_id:
        preselected_vendor_id = None
        preselected_product_id = None
        preselected_vendor = None
        preselected_product = None

    if request.method == "POST":
        submitter_ip = _get_request_ip()
        if _is_rate_limited_for_ip(submitter_ip):
            limit = current_app.config.get("PROPOSAL_RATE_LIMIT_PER_HOUR", 10)
            flash(
                f"Rate limit reached for your IP address. Please wait before submitting more proposals (limit: {limit} per hour).",
                "danger",
            )
            return redirect(
                url_for(
                    "main.note_proposal_new",
                    vendor_id=request.form.get("vendor_id", type=int),
                    product_id=request.form.get("product_id", type=int),
                )
            )

        vendor_id = request.form.get("vendor_id", type=int)
        product_id = request.form.get("product_id", type=int)
        note_text = (request.form.get("proposed_notes") or "").strip()

        if bool(vendor_id) == bool(product_id):
            flash("Please submit a note for exactly one record (vendor or product).", "danger")
            return redirect(url_for("main.note_proposal_new"))

        if not note_text:
            flash("Please provide the proposed note text.", "danger")
            return redirect(
                url_for("main.note_proposal_new", vendor_id=vendor_id, product_id=product_id)
            )

        proposal = Proposal(
            proposal_type="edit_vendor_note" if vendor_id else "edit_product_note",
            submitter_name=request.form.get("submitter_name"),
            submitter_email=request.form.get("submitter_email"),
            submitter_ip=submitter_ip,
            rationale=request.form.get("rationale"),
            vendor_id=vendor_id,
            product_id=product_id,
            proposed_notes=note_text,
        )

        db.session.add(proposal)
        db.session.commit()
        flash("Note proposal submitted. An admin will review it.", "success")
        return redirect(url_for("main.index"))

    return render_template(
        "note_proposal_form.html",
        preselected_vendor=preselected_vendor,
        preselected_product=preselected_product,
    )


@bp.route("/proposals/metadata/new", methods=["GET", "POST"])
def metadata_proposal_new():
    preselected_vendor_id = request.args.get("vendor_id", type=int)
    preselected_product_id = request.args.get("product_id", type=int)

    preselected_vendor = Vendor.query.get(preselected_vendor_id) if preselected_vendor_id else None
    preselected_product = Product.query.get(preselected_product_id) if preselected_product_id else None
    if preselected_vendor_id and not preselected_vendor:
        preselected_vendor_id = None
    if preselected_product_id and not preselected_product:
        preselected_product_id = None

    if preselected_vendor_id and preselected_product_id:
        preselected_vendor_id = None
        preselected_product_id = None
        preselected_vendor = None
        preselected_product = None

    if request.method == "POST":
        submitter_ip = _get_request_ip()
        if _is_rate_limited_for_ip(submitter_ip):
            limit = current_app.config.get("PROPOSAL_RATE_LIMIT_PER_HOUR", 10)
            flash(
                f"Rate limit reached for your IP address. Please wait before submitting more proposals (limit: {limit} per hour).",
                "danger",
            )
            return redirect(
                url_for(
                    "main.metadata_proposal_new",
                    vendor_id=request.form.get("vendor_id", type=int),
                    product_id=request.form.get("product_id", type=int),
                )
            )

        vendor_id = request.form.get("vendor_id", type=int)
        product_id = request.form.get("product_id", type=int)
        metadata_key = (request.form.get("metadata_key") or "").strip()
        metadata_value = (request.form.get("metadata_value") or "").strip()

        if bool(vendor_id) == bool(product_id):
            flash("Please submit metadata for exactly one record (vendor or product).", "danger")
            return redirect(url_for("main.metadata_proposal_new"))

        if metadata_key not in ALLOWED_METADATA_KEYS:
            flash("Please choose a valid metadata key.", "danger")
            return redirect(
                url_for("main.metadata_proposal_new", vendor_id=vendor_id, product_id=product_id)
            )

        if not metadata_value:
            flash("Please provide a metadata value.", "danger")
            return redirect(
                url_for("main.metadata_proposal_new", vendor_id=vendor_id, product_id=product_id)
            )

        proposal = Proposal(
            proposal_type="edit_vendor_metadata" if vendor_id else "edit_product_metadata",
            submitter_name=request.form.get("submitter_name"),
            submitter_email=request.form.get("submitter_email"),
            submitter_ip=submitter_ip,
            rationale=request.form.get("rationale"),
            vendor_id=vendor_id,
            product_id=product_id,
            proposed_metadata_key=metadata_key,
            proposed_metadata_value=metadata_value,
        )

        db.session.add(proposal)
        db.session.commit()
        flash("Metadata proposal submitted. An admin will review it.", "success")
        return redirect(url_for("main.index"))

    return render_template(
        "metadata_proposal_form.html",
        preselected_vendor=preselected_vendor,
        preselected_product=preselected_product,
        allowed_metadata_keys=sorted(ALLOWED_METADATA_KEYS),
    )


@bp.route("/changes")
def approved_changes():
    page = max(request.args.get("page", default=1, type=int) or 1, 1)
    per_page = 20

    ordered_query = Proposal.query.filter_by(status="accepted").order_by(
        Proposal.reviewed_at.desc(),
        Proposal.created_at.desc(),
        Proposal.id.desc(),
    )
    total_changes = ordered_query.count()
    total_pages = max((total_changes + per_page - 1) // per_page, 1)
    if page > total_pages:
        page = total_pages
    changes = ordered_query.offset((page - 1) * per_page).limit(per_page).all()

    return render_template(
        "approved_changes.html",
        changes=changes,
        page=page,
        total_pages=total_pages,
        has_prev=page > 1,
        has_next=page < total_pages,
        total_changes=total_changes,
        proposal_summary=_proposal_summary,
        proposal_focus_links=_proposal_focus_links,
    )


@bp.route("/changes.rss")
def approved_changes_rss():
    changes = (
        Proposal.query.filter_by(status="accepted")
        .order_by(Proposal.reviewed_at.desc(), Proposal.created_at.desc(), Proposal.id.desc())
        .limit(20)
        .all()
    )
    entries = _build_change_feed_entries(changes)
    feed_url = url_for("main.approved_changes_rss", _external=True)
    site_url = url_for("main.approved_changes", _external=True)
    updated_at = entries[0]["published_rfc822"] if entries else format_datetime(datetime.now(timezone.utc))

    items = "".join(
        (
            "<item>"
            f"<title>{escape(entry['title'])}</title>"
            f"<description>{escape(entry['summary'])}</description>"
            f"<link>{escape(entry['url'])}</link>"
            f"<guid>{escape(entry['url'])}</guid>"
            f"<pubDate>{entry['published_rfc822']}</pubDate>"
            "</item>"
        )
        for entry in entries
    )
    rss = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<rss version=\"2.0\">"
        "<channel>"
        "<title>CPE Editor Approved Changes</title>"
        "<description>Recent approved changes in the CPE Editor catalog.</description>"
        f"<link>{escape(site_url)}</link>"
        f"<lastBuildDate>{updated_at}</lastBuildDate>"
        f"<atom:link href=\"{escape(feed_url)}\" rel=\"self\" type=\"application/rss+xml\" xmlns:atom=\"http://www.w3.org/2005/Atom\" />"
        f"{items}"
        "</channel>"
        "</rss>"
    )
    return Response(rss, mimetype="application/rss+xml")


@bp.route("/changes.atom")
def approved_changes_atom():
    changes = (
        Proposal.query.filter_by(status="accepted")
        .order_by(Proposal.reviewed_at.desc(), Proposal.created_at.desc(), Proposal.id.desc())
        .limit(20)
        .all()
    )
    entries = _build_change_feed_entries(changes)
    feed_url = url_for("main.approved_changes_atom", _external=True)
    site_url = url_for("main.approved_changes", _external=True)
    updated_at = (
        entries[0]["published_rfc3339"]
        if entries
        else datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )

    items = "".join(
        (
            "<entry>"
            f"<id>{escape(entry['url'])}</id>"
            f"<title>{escape(entry['title'])}</title>"
            f"<link href=\"{escape(entry['url'])}\" />"
            f"<updated>{entry['published_rfc3339']}</updated>"
            f"<summary>{escape(entry['summary'])}</summary>"
            "</entry>"
        )
        for entry in entries
    )
    atom = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<feed xmlns=\"http://www.w3.org/2005/Atom\">"
        "<title>CPE Editor Approved Changes</title>"
        f"<id>{escape(site_url)}</id>"
        f"<link href=\"{escape(site_url)}\" />"
        f"<link href=\"{escape(feed_url)}\" rel=\"self\" />"
        f"<updated>{updated_at}</updated>"
        f"{items}"
        "</feed>"
    )
    return Response(atom, mimetype="application/atom+xml")


@bp.route("/changes/<int:proposal_id>")
def approved_change_detail(proposal_id):
    proposal = Proposal.query.filter_by(id=proposal_id, status="accepted").first_or_404()
    ordered_ids = [
        row.id
        for row in Proposal.query.filter_by(status="accepted")
        .order_by(Proposal.reviewed_at.desc(), Proposal.created_at.desc(), Proposal.id.desc())
        .all()
    ]
    current_index = ordered_ids.index(proposal.id)
    previous_change_id = ordered_ids[current_index - 1] if current_index > 0 else None
    next_change_id = ordered_ids[current_index + 1] if current_index < len(ordered_ids) - 1 else None

    return render_template(
        "approved_change_detail.html",
        proposal=proposal,
        previous_change_id=previous_change_id,
        next_change_id=next_change_id,
        proposal_summary=_proposal_summary,
        proposal_focus_links=_proposal_focus_links,
    )


# --- Admin -------------------------------------------------------------------
@bp.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if (
            username == current_app.config["ADMIN_USERNAME"]
            and password == current_app.config["ADMIN_PASSWORD"]
        ):
            session["is_admin"] = True
            flash("Logged in successfully.", "success")
            return redirect(request.args.get("next") or url_for("main.admin_dashboard"))
        flash("Invalid credentials.", "danger")

    return render_template("admin/login.html")


@bp.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("main.index"))


@bp.route("/admin")
@admin_required
def admin_dashboard():
    pending = Proposal.query.filter_by(status="pending").order_by(Proposal.created_at.asc()).all()
    recent = Proposal.query.order_by(Proposal.created_at.desc()).limit(20).all()
    return render_template("admin/dashboard.html", pending=pending, recent=recent)


@bp.route("/admin/reindex", methods=["POST"])
@admin_required
def admin_reindex():
    engine = db.session.get_bind()
    dialect = engine.dialect.name if engine else ""
    db.create_all()

    if dialect == "sqlite":
        db.session.execute(text("REINDEX"))
        db.session.execute(text("ANALYZE"))
        db.session.commit()
        flash("SQLite indexes rebuilt and statistics refreshed.", "success")
    else:
        db.session.execute(text("ANALYZE"))
        db.session.commit()
        flash("Index statistics refreshed using ANALYZE.", "info")
    return redirect(url_for("main.admin_dashboard"))


@bp.route("/admin/proposals/<int:proposal_id>", methods=["GET", "POST"])
@admin_required
def admin_proposal_review(proposal_id):
    proposal = Proposal.query.get_or_404(proposal_id)

    if request.method == "POST":
        action = request.form.get("action")
        review_comment = request.form.get("review_comment")
        proposal.review_comment = review_comment
        proposal.reviewed_at = datetime.utcnow()

        if action == "reject":
            proposal.status = "rejected"
            db.session.commit()
            flash("Proposal rejected.", "warning")
            return redirect(url_for("main.admin_dashboard"))

        if action == "accept":
            apply_proposal(proposal)
            proposal.status = "accepted"
            db.session.commit()
            flash("Proposal accepted and applied.", "success")
            return redirect(url_for("main.admin_dashboard"))

    return render_template("admin/review_proposal.html", proposal=proposal)


# --- Moderation logic ---------------------------------------------------------
def apply_proposal(proposal: Proposal):
    vendor = proposal.vendor
    product = proposal.product
    cpe = proposal.cpe_entry

    def create_proposal_cpe(vendor_id: int, product_id: int, cpe_uri: str | None):
        cpe = CPEEntry(
            vendor_id=vendor_id,
            product_id=product_id,
            cpe_uri=cpe_uri,
            part=proposal.proposed_part or "a",
            version=proposal.proposed_version or "*",
            update=proposal.proposed_update or "*",
            edition=proposal.proposed_edition or "*",
            language=proposal.proposed_language or "*",
            sw_edition=proposal.proposed_sw_edition or "*",
            target_sw=proposal.proposed_target_sw or "*",
            target_hw=proposal.proposed_target_hw or "*",
            other=proposal.proposed_other or "*",
            title=proposal.proposed_title,
            notes=proposal.proposed_notes,
            from_proposal=True,
        )
        db.session.add(cpe)
        return cpe

    if proposal.proposal_type == "new_vendor_product":
        vendor = Vendor(
            name=normalize_token(proposal.proposed_vendor_name),
            title=proposal.proposed_vendor_title or proposal.proposed_vendor_name,
        )
        db.session.add(vendor)
        db.session.flush()

        product = Product(
            vendor_id=vendor.id,
            name=normalize_token(proposal.proposed_product_name),
            title=proposal.proposed_product_title or proposal.proposed_product_name,
        )
        db.session.add(product)
        db.session.flush()

        create_proposal_cpe(vendor.id, product.id, proposal.proposed_cpe_uri)
        return

    if proposal.proposal_type == "new_product":
        if not vendor:
            raise ValueError("Vendor is required for a new product proposal.")
        product = Product(
            vendor_id=vendor.id,
            name=normalize_token(proposal.proposed_product_name),
            title=proposal.proposed_product_title or proposal.proposed_product_name,
        )
        db.session.add(product)
        db.session.flush()

        create_proposal_cpe(vendor.id, product.id, proposal.proposed_cpe_uri)
        return

    if proposal.proposal_type == "new_cpe":
        if not vendor or not product:
            raise ValueError("Vendor and product are required for a new CPE proposal.")
        create_proposal_cpe(vendor.id, product.id, proposal.proposed_cpe_uri)
        return

    if proposal.proposal_type == "edit_cpe":
        if not cpe:
            raise ValueError("A target CPE entry is required for an edit proposal.")
        vendor_name = proposal.proposed_vendor_name or cpe.vendor.name
        product_name = proposal.proposed_product_name or cpe.product.name
        cpe_uri = proposal.proposed_cpe_uri or build_cpe_uri(
            proposal.proposed_part or cpe.part,
            vendor_name,
            product_name,
            proposal.proposed_version or cpe.version,
            proposal.proposed_update or cpe.update,
            proposal.proposed_edition or cpe.edition,
            proposal.proposed_language or cpe.language,
            proposal.proposed_sw_edition or cpe.sw_edition,
            proposal.proposed_target_sw or cpe.target_sw,
            proposal.proposed_target_hw or cpe.target_hw,
            proposal.proposed_other or cpe.other,
        )
        new_cpe = create_proposal_cpe(cpe.vendor_id, cpe.product_id, cpe_uri)
        new_cpe.part = proposal.proposed_part or cpe.part
        new_cpe.version = proposal.proposed_version or cpe.version
        new_cpe.update = proposal.proposed_update or cpe.update
        new_cpe.edition = proposal.proposed_edition or cpe.edition
        new_cpe.language = proposal.proposed_language or cpe.language
        new_cpe.sw_edition = proposal.proposed_sw_edition or cpe.sw_edition
        new_cpe.target_sw = proposal.proposed_target_sw or cpe.target_sw
        new_cpe.target_hw = proposal.proposed_target_hw or cpe.target_hw
        new_cpe.other = proposal.proposed_other or cpe.other
        new_cpe.title = proposal.proposed_title or cpe.title
        new_cpe.notes = proposal.proposed_notes or cpe.notes
        return

    if proposal.proposal_type == "edit_vendor_note":
        if not vendor:
            raise ValueError("A target vendor is required for a vendor note proposal.")
        vendor.notes = proposal.proposed_notes
        note = EntityNote(
            vendor_id=vendor.id,
            proposal_id=proposal.id,
            note_text=proposal.proposed_notes,
            submitter_name=proposal.submitter_name,
            submitter_email=proposal.submitter_email,
            submitted_at=proposal.created_at or datetime.utcnow(),
            approved_at=proposal.reviewed_at or datetime.utcnow(),
        )
        db.session.add(note)
        return

    if proposal.proposal_type == "edit_product_note":
        if not product:
            raise ValueError("A target product is required for a product note proposal.")
        product.notes = proposal.proposed_notes
        note = EntityNote(
            product_id=product.id,
            proposal_id=proposal.id,
            note_text=proposal.proposed_notes,
            submitter_name=proposal.submitter_name,
            submitter_email=proposal.submitter_email,
            submitted_at=proposal.created_at or datetime.utcnow(),
            approved_at=proposal.reviewed_at or datetime.utcnow(),
        )
        db.session.add(note)
        return

    if proposal.proposal_type == "edit_vendor_metadata":
        if not vendor:
            raise ValueError("A target vendor is required for a vendor metadata proposal.")
        if proposal.proposed_metadata_key not in ALLOWED_METADATA_KEYS:
            raise ValueError("Unsupported metadata key for vendor metadata proposal.")
        metadata_entry = EntityMetadata(
            vendor_id=vendor.id,
            proposal_id=proposal.id,
            metadata_key=proposal.proposed_metadata_key,
            metadata_value=proposal.proposed_metadata_value,
            submitter_name=proposal.submitter_name,
            submitter_email=proposal.submitter_email,
            submitted_at=proposal.created_at or datetime.utcnow(),
            approved_at=proposal.reviewed_at or datetime.utcnow(),
        )
        db.session.add(metadata_entry)
        return

    if proposal.proposal_type == "edit_product_metadata":
        if not product:
            raise ValueError("A target product is required for a product metadata proposal.")
        if proposal.proposed_metadata_key not in ALLOWED_METADATA_KEYS:
            raise ValueError("Unsupported metadata key for product metadata proposal.")
        metadata_entry = EntityMetadata(
            product_id=product.id,
            proposal_id=proposal.id,
            metadata_key=proposal.proposed_metadata_key,
            metadata_value=proposal.proposed_metadata_value,
            submitter_name=proposal.submitter_name,
            submitter_email=proposal.submitter_email,
            submitted_at=proposal.created_at or datetime.utcnow(),
            approved_at=proposal.reviewed_at or datetime.utcnow(),
        )
        db.session.add(metadata_entry)
        return

    if proposal.proposal_type == "new_record_relationship":
        source_count = int(bool(proposal.source_vendor_id)) + int(bool(proposal.source_product_id))
        target_count = int(bool(proposal.target_vendor_id)) + int(bool(proposal.target_product_id))
        if source_count != 1 or target_count != 1:
            raise ValueError("Relationship proposals require exactly one source and one target record.")
        relationship = EntityRelationship(
            source_vendor_id=proposal.source_vendor_id,
            source_product_id=proposal.source_product_id,
            target_vendor_id=proposal.target_vendor_id,
            target_product_id=proposal.target_product_id,
            relationship_type=proposal.proposed_relationship_type,
            proposal_id=proposal.id,
            rationale=proposal.rationale,
            submitter_name=proposal.submitter_name,
            submitter_email=proposal.submitter_email,
            submitted_at=proposal.created_at or datetime.utcnow(),
            approved_at=proposal.reviewed_at or datetime.utcnow(),
        )
        db.session.add(relationship)
        return

    raise ValueError(f"Unsupported proposal type: {proposal.proposal_type}")


# --- Sample data --------------------------------------------------------------
@bp.route("/admin/bootstrap-sample-data", methods=["POST"])
@admin_required
def bootstrap_sample_data():
    if Vendor.query.count() > 0:
        flash("Sample data skipped because the database is not empty.", "info")
        return redirect(url_for("main.admin_dashboard"))

    vendor = Vendor(name="microsoft", title="Microsoft")
    product = Product(vendor=vendor, name="exchange_server", title="Exchange Server")
    cpe = CPEEntry(
        vendor=vendor,
        product=product,
        part="a",
        version="2019",
        cpe_uri="cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*",
        title="Microsoft Exchange Server 2019",
        notes="Bootstrap sample entry",
    )
    db.session.add_all([vendor, product, cpe])
    db.session.commit()

    flash("Sample data created.", "success")
    return redirect(url_for("main.admin_dashboard"))
