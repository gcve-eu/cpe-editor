from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

from .utils import new_uuid


db = SQLAlchemy()


class TimestampMixin:
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class Vendor(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=new_uuid, index=True)
    name = db.Column(db.String(255), unique=True, nullable=False, index=True)
    title = db.Column(db.String(255), nullable=True)
    notes = db.Column(db.Text, nullable=True)

    products = db.relationship("Product", back_populates="vendor", cascade="all, delete-orphan")


class Product(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=new_uuid, index=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey("vendor.id"), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=True)
    notes = db.Column(db.Text, nullable=True)

    vendor = db.relationship("Vendor", back_populates="products")
    cpes = db.relationship("CPEEntry", back_populates="product", cascade="all, delete-orphan")

    __table_args__ = (db.UniqueConstraint("vendor_id", "name", name="uq_product_vendor_name"),)


class CPEEntry(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey("vendor.id"), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False, index=True)

    cpe_uri = db.Column(db.String(1024), unique=True, nullable=False, index=True)
    cpe_name_id = db.Column(db.String(36), unique=True, nullable=True, index=True)
    deprecated = db.Column(db.Boolean, nullable=False, default=False, index=True)
    deprecated_by = db.Column(db.String(1024), nullable=True)
    part = db.Column(db.String(16), nullable=False, index=True)  # a, o, h
    version = db.Column(db.String(255), nullable=True, default="*")
    update = db.Column(db.String(255), nullable=True, default="*")
    edition = db.Column(db.String(255), nullable=True, default="*")
    language = db.Column(db.String(255), nullable=True, default="*")
    sw_edition = db.Column(db.String(255), nullable=True, default="*")
    target_sw = db.Column(db.String(255), nullable=True, default="*")
    target_hw = db.Column(db.String(255), nullable=True, default="*")
    other = db.Column(db.String(255), nullable=True, default="*")
    title = db.Column(db.String(255), nullable=True)
    notes = db.Column(db.Text, nullable=True)

    product = db.relationship("Product", back_populates="cpes")
    vendor = db.relationship("Vendor")


class Proposal(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    proposal_type = db.Column(db.String(32), nullable=False, index=True)
    status = db.Column(db.String(32), nullable=False, default="pending", index=True)

    submitter_name = db.Column(db.String(255), nullable=True)
    submitter_email = db.Column(db.String(255), nullable=True)
    rationale = db.Column(db.Text, nullable=True)

    vendor_id = db.Column(db.Integer, db.ForeignKey("vendor.id"), nullable=True)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=True)
    cpe_entry_id = db.Column(db.Integer, db.ForeignKey("cpe_entry.id"), nullable=True)

    proposed_vendor_name = db.Column(db.String(255), nullable=True)
    proposed_vendor_title = db.Column(db.String(255), nullable=True)
    proposed_product_name = db.Column(db.String(255), nullable=True)
    proposed_product_title = db.Column(db.String(255), nullable=True)

    proposed_part = db.Column(db.String(16), nullable=True)
    proposed_version = db.Column(db.String(255), nullable=True)
    proposed_update = db.Column(db.String(255), nullable=True)
    proposed_edition = db.Column(db.String(255), nullable=True)
    proposed_language = db.Column(db.String(255), nullable=True)
    proposed_sw_edition = db.Column(db.String(255), nullable=True)
    proposed_target_sw = db.Column(db.String(255), nullable=True)
    proposed_target_hw = db.Column(db.String(255), nullable=True)
    proposed_other = db.Column(db.String(255), nullable=True)
    proposed_title = db.Column(db.String(255), nullable=True)
    proposed_notes = db.Column(db.Text, nullable=True)
    proposed_cpe_uri = db.Column(db.String(1024), nullable=True)

    review_comment = db.Column(db.Text, nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)

    vendor = db.relationship("Vendor")
    product = db.relationship("Product")
    cpe_entry = db.relationship("CPEEntry")
