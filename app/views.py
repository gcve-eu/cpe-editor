from datetime import datetime
from functools import wraps

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import func, or_, text

from .models import CPEEntry, Product, Proposal, Vendor, db
from .utils import build_cpe_uri, normalize_token

bp = Blueprint("main", __name__)


# --- Helpers -----------------------------------------------------------------

def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Please log in as admin.", "warning")
            return redirect(url_for("main.admin_login", next=request.path))
        return view_func(*args, **kwargs)

    return wrapped


# --- Public views -------------------------------------------------------------
@bp.route("/")
def index():
    q = (request.args.get("q") or "").strip()
    vendor_q = (request.args.get("vendor_q") or "").strip()
    product_q = (request.args.get("product_q") or "").strip()
    part = (request.args.get("part") or "").strip()

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

    results = query.order_by(Vendor.name.asc(), Product.name.asc(), CPEEntry.cpe_uri.asc()).limit(100).all()
    vendors = Vendor.query.order_by(Vendor.name.asc()).limit(50).all()
    return render_template(
        "index.html",
        results=results,
        vendors=vendors,
        q=q,
        vendor_q=vendor_q,
        product_q=product_q,
        part=part,
    )


@bp.route("/vendors/<int:vendor_id>")
def vendor_detail(vendor_id):
    vendor = Vendor.query.get_or_404(vendor_id)
    return render_template("vendor_detail.html", vendor=vendor)


@bp.route("/products/<int:product_id>")
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template("product_detail.html", product=product)


@bp.route("/cpes/<int:cpe_id>")
def cpe_detail(cpe_id):
    cpe = CPEEntry.query.get_or_404(cpe_id)
    return render_template("cpe_detail.html", cpe=cpe)


@bp.route("/proposals/new", methods=["GET", "POST"])
def proposal_new():
    vendors = Vendor.query.order_by(Vendor.name.asc()).all()

    if request.method == "POST":
        proposal_type = request.form.get("proposal_type", "edit_cpe")
        vendor_id = request.form.get("vendor_id") or None
        product_id = request.form.get("product_id") or None
        cpe_entry_id = request.form.get("cpe_entry_id") or None

        proposal = Proposal(
            proposal_type=proposal_type,
            submitter_name=request.form.get("submitter_name"),
            submitter_email=request.form.get("submitter_email"),
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
        )

        vendor_name = request.form.get("proposed_vendor_name") or ""
        product_name = request.form.get("proposed_product_name") or ""
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

        db.session.add(proposal)
        db.session.commit()
        flash("Proposal submitted. An admin will review it.", "success")
        return redirect(url_for("main.index"))

    return render_template("proposal_form.html", vendors=vendors)


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


@bp.route("/admin/logout")
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

        cpe = CPEEntry(
            vendor_id=vendor.id,
            product_id=product.id,
            cpe_uri=proposal.proposed_cpe_uri,
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
        )
        db.session.add(cpe)
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

        cpe = CPEEntry(
            vendor_id=vendor.id,
            product_id=product.id,
            cpe_uri=proposal.proposed_cpe_uri,
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
        )
        db.session.add(cpe)
        return

    if proposal.proposal_type == "new_cpe":
        if not vendor or not product:
            raise ValueError("Vendor and product are required for a new CPE proposal.")
        cpe = CPEEntry(
            vendor_id=vendor.id,
            product_id=product.id,
            cpe_uri=proposal.proposed_cpe_uri,
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
        )
        db.session.add(cpe)
        return

    if proposal.proposal_type == "edit_cpe":
        if not cpe:
            raise ValueError("A target CPE entry is required for an edit proposal.")
        cpe.part = proposal.proposed_part or cpe.part
        cpe.version = proposal.proposed_version or cpe.version
        cpe.update = proposal.proposed_update or cpe.update
        cpe.edition = proposal.proposed_edition or cpe.edition
        cpe.language = proposal.proposed_language or cpe.language
        cpe.sw_edition = proposal.proposed_sw_edition or cpe.sw_edition
        cpe.target_sw = proposal.proposed_target_sw or cpe.target_sw
        cpe.target_hw = proposal.proposed_target_hw or cpe.target_hw
        cpe.other = proposal.proposed_other or cpe.other
        cpe.title = proposal.proposed_title or cpe.title
        cpe.notes = proposal.proposed_notes or cpe.notes

        vendor_name = proposal.proposed_vendor_name or cpe.vendor.name
        product_name = proposal.proposed_product_name or cpe.product.name
        cpe.cpe_uri = build_cpe_uri(
            proposal.proposed_part or cpe.part,
            vendor_name,
            product_name,
            cpe.version,
            cpe.update,
            cpe.edition,
            cpe.language,
            cpe.sw_edition,
            cpe.target_sw,
            cpe.target_hw,
            cpe.other,
        )
        return

    raise ValueError(f"Unsupported proposal type: {proposal.proposal_type}")


# --- Sample data --------------------------------------------------------------
@bp.route("/admin/bootstrap-sample-data")
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
