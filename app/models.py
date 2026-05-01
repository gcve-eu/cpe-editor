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
    note_entries = db.relationship(
        "EntityNote",
        back_populates="vendor",
        cascade="all, delete-orphan",
        order_by="desc(EntityNote.approved_at), desc(EntityNote.submitted_at)",
    )
    metadata_entries = db.relationship(
        "EntityMetadata",
        back_populates="vendor",
        cascade="all, delete-orphan",
        order_by="desc(EntityMetadata.approved_at), desc(EntityMetadata.submitted_at)",
    )
    outgoing_relationships = db.relationship(
        "EntityRelationship",
        foreign_keys="EntityRelationship.source_vendor_id",
        back_populates="source_vendor",
        cascade="all, delete-orphan",
        order_by="desc(EntityRelationship.approved_at), desc(EntityRelationship.submitted_at)",
    )
    incoming_relationships = db.relationship(
        "EntityRelationship",
        foreign_keys="EntityRelationship.target_vendor_id",
        back_populates="target_vendor",
        cascade="all, delete-orphan",
        order_by="desc(EntityRelationship.approved_at), desc(EntityRelationship.submitted_at)",
    )

    __table_args__ = (
        db.Index("ix_vendor_name_lower", db.func.lower(name)),
        db.Index("ix_vendor_title_lower", db.func.lower(title)),
    )


class Product(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=new_uuid, index=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey("vendor.id"), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=True)
    notes = db.Column(db.Text, nullable=True)

    vendor = db.relationship("Vendor", back_populates="products")
    cpes = db.relationship("CPEEntry", back_populates="product", cascade="all, delete-orphan")
    note_entries = db.relationship(
        "EntityNote",
        back_populates="product",
        cascade="all, delete-orphan",
        order_by="desc(EntityNote.approved_at), desc(EntityNote.submitted_at)",
    )
    metadata_entries = db.relationship(
        "EntityMetadata",
        back_populates="product",
        cascade="all, delete-orphan",
        order_by="desc(EntityMetadata.approved_at), desc(EntityMetadata.submitted_at)",
    )
    outgoing_relationships = db.relationship(
        "EntityRelationship",
        foreign_keys="EntityRelationship.source_product_id",
        back_populates="source_product",
        cascade="all, delete-orphan",
        order_by="desc(EntityRelationship.approved_at), desc(EntityRelationship.submitted_at)",
    )
    incoming_relationships = db.relationship(
        "EntityRelationship",
        foreign_keys="EntityRelationship.target_product_id",
        back_populates="target_product",
        cascade="all, delete-orphan",
        order_by="desc(EntityRelationship.approved_at), desc(EntityRelationship.submitted_at)",
    )

    __table_args__ = (
        db.UniqueConstraint("vendor_id", "name", name="uq_product_vendor_name"),
        db.Index("ix_product_vendor_name_lower", "vendor_id", db.func.lower(name)),
        db.Index("ix_product_name_lower", db.func.lower(name)),
        db.Index("ix_product_title_lower", db.func.lower(title)),
    )


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
    from_proposal = db.Column(db.Boolean, nullable=False, default=False, index=True)

    product = db.relationship("Product", back_populates="cpes")
    vendor = db.relationship("Vendor")
    vulnerability_links = db.relationship(
        "CPEVulnerabilityReference",
        back_populates="cpe_entry",
        cascade="all, delete-orphan",
        order_by="desc(CPEVulnerabilityReference.approved_at), desc(CPEVulnerabilityReference.submitted_at)",
    )
    purl_mappings = db.relationship(
        "CPEPurlMapping",
        back_populates="cpe_entry",
        cascade="all, delete-orphan",
        order_by="CPEPurlMapping.purl.asc()",
    )

    __table_args__ = (
        db.Index("ix_cpe_vendor_product_part", "vendor_id", "product_id", "part"),
        db.Index("ix_cpe_product_version", "product_id", "version"),
    )


class Proposal(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    proposal_type = db.Column(db.String(32), nullable=False, index=True)
    status = db.Column(db.String(32), nullable=False, default="pending", index=True)

    submitter_name = db.Column(db.String(255), nullable=True)
    submitter_email = db.Column(db.String(255), nullable=True)
    submitter_ip = db.Column(db.String(64), nullable=True, index=True)
    submitter_user_agent = db.Column(db.String(512), nullable=True, index=True)
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
    proposed_relationship_type = db.Column(db.String(64), nullable=True)
    proposed_metadata_key = db.Column(db.String(128), nullable=True)
    proposed_metadata_value = db.Column(db.Text, nullable=True)
    proposed_vulnerability_id = db.Column(db.String(64), nullable=True, index=True)
    proposed_vulnerability_source = db.Column(db.String(16), nullable=True, index=True)
    proposed_cpe_applicability = db.Column(db.String(64), nullable=True)
    source_vendor_id = db.Column(db.Integer, db.ForeignKey("vendor.id"), nullable=True, index=True)
    source_product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=True, index=True)
    target_vendor_id = db.Column(db.Integer, db.ForeignKey("vendor.id"), nullable=True, index=True)
    target_product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=True, index=True)

    review_comment = db.Column(db.Text, nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)

    vendor = db.relationship("Vendor", foreign_keys=[vendor_id])
    product = db.relationship("Product", foreign_keys=[product_id])
    cpe_entry = db.relationship("CPEEntry", foreign_keys=[cpe_entry_id])
    note_entry = db.relationship("EntityNote", back_populates="proposal", uselist=False)
    source_vendor = db.relationship("Vendor", foreign_keys=[source_vendor_id])
    source_product = db.relationship("Product", foreign_keys=[source_product_id])
    target_vendor = db.relationship("Vendor", foreign_keys=[target_vendor_id])
    target_product = db.relationship("Product", foreign_keys=[target_product_id])
    relationship_entry = db.relationship(
        "EntityRelationship", back_populates="proposal", uselist=False
    )
    metadata_entry = db.relationship("EntityMetadata", back_populates="proposal", uselist=False)
    vulnerability_reference_entry = db.relationship(
        "CPEVulnerabilityReference", back_populates="proposal", uselist=False
    )


class EntityNote(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey("vendor.id"), nullable=True, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=True, index=True)
    proposal_id = db.Column(
        db.Integer, db.ForeignKey("proposal.id"), nullable=True, unique=True, index=True
    )
    note_text = db.Column(db.Text, nullable=False)
    submitter_name = db.Column(db.String(255), nullable=True)
    submitter_email = db.Column(db.String(255), nullable=True)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    approved_at = db.Column(db.DateTime, nullable=True, index=True)

    vendor = db.relationship("Vendor", back_populates="note_entries")
    product = db.relationship("Product", back_populates="note_entries")
    proposal = db.relationship("Proposal", back_populates="note_entry")


class EntityRelationship(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source_vendor_id = db.Column(db.Integer, db.ForeignKey("vendor.id"), nullable=True, index=True)
    source_product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=True, index=True)
    target_vendor_id = db.Column(db.Integer, db.ForeignKey("vendor.id"), nullable=True, index=True)
    target_product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=True, index=True)
    relationship_type = db.Column(db.String(64), nullable=False, index=True)
    proposal_id = db.Column(
        db.Integer, db.ForeignKey("proposal.id"), nullable=True, unique=True, index=True
    )
    rationale = db.Column(db.Text, nullable=True)
    submitter_name = db.Column(db.String(255), nullable=True)
    submitter_email = db.Column(db.String(255), nullable=True)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    approved_at = db.Column(db.DateTime, nullable=True, index=True)

    source_vendor = db.relationship(
        "Vendor", foreign_keys=[source_vendor_id], back_populates="outgoing_relationships"
    )
    source_product = db.relationship(
        "Product", foreign_keys=[source_product_id], back_populates="outgoing_relationships"
    )
    target_vendor = db.relationship(
        "Vendor", foreign_keys=[target_vendor_id], back_populates="incoming_relationships"
    )
    target_product = db.relationship(
        "Product", foreign_keys=[target_product_id], back_populates="incoming_relationships"
    )
    proposal = db.relationship("Proposal", back_populates="relationship_entry")

    __table_args__ = (
        db.Index(
            "ix_relationship_source_record",
            "source_vendor_id",
            "source_product_id",
            "relationship_type",
        ),
        db.Index(
            "ix_relationship_target_record",
            "target_vendor_id",
            "target_product_id",
            "relationship_type",
        ),
    )


class EntityMetadata(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey("vendor.id"), nullable=True, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=True, index=True)
    proposal_id = db.Column(
        db.Integer, db.ForeignKey("proposal.id"), nullable=True, unique=True, index=True
    )
    metadata_key = db.Column(db.String(128), nullable=False, index=True)
    metadata_value = db.Column(db.Text, nullable=False)
    submitter_name = db.Column(db.String(255), nullable=True)
    submitter_email = db.Column(db.String(255), nullable=True)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    approved_at = db.Column(db.DateTime, nullable=True, index=True)

    vendor = db.relationship("Vendor", back_populates="metadata_entries")
    product = db.relationship("Product", back_populates="metadata_entries")
    proposal = db.relationship("Proposal", back_populates="metadata_entry")

    __table_args__ = (
        db.Index("ix_metadata_vendor_key", "vendor_id", "metadata_key"),
        db.Index("ix_metadata_product_key", "product_id", "metadata_key"),
    )


class CPEVulnerabilityReference(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cpe_entry_id = db.Column(db.Integer, db.ForeignKey("cpe_entry.id"), nullable=False, index=True)
    proposal_id = db.Column(
        db.Integer, db.ForeignKey("proposal.id"), nullable=True, unique=True, index=True
    )
    vulnerability_source = db.Column(db.String(16), nullable=False, index=True)
    vulnerability_id = db.Column(db.String(64), nullable=False, index=True)
    cpe_applicability = db.Column(db.String(64), nullable=False)
    rationale = db.Column(db.Text, nullable=True)
    submitter_name = db.Column(db.String(255), nullable=True)
    submitter_email = db.Column(db.String(255), nullable=True)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    approved_at = db.Column(db.DateTime, nullable=True, index=True)

    cpe_entry = db.relationship("CPEEntry", back_populates="vulnerability_links")
    proposal = db.relationship("Proposal", back_populates="vulnerability_reference_entry")

    __table_args__ = (
        db.UniqueConstraint(
            "cpe_entry_id",
            "vulnerability_source",
            "vulnerability_id",
            "cpe_applicability",
            name="uq_cpe_vuln_applicability",
        ),
    )


class CPEPurlMapping(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cpe_name_id = db.Column(
        db.String(36),
        db.ForeignKey("cpe_entry.cpe_name_id"),
        nullable=False,
        index=True,
    )
    purl = db.Column(db.String(2048), nullable=False, index=True)
    source = db.Column(db.String(255), nullable=False, default="purl2cpe")

    cpe_entry = db.relationship("CPEEntry", back_populates="purl_mappings")

    __table_args__ = (
        db.UniqueConstraint("cpe_name_id", "purl", name="uq_cpe_purl_mapping"),
        db.Index("ix_cpe_purl_mapping_purl_lower", db.func.lower(purl)),
    )
