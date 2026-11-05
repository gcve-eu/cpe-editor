"""Read-only proposal comparisons for the moderation page."""
import json

from .utils import build_cpe_uri


def proposal_comparison(proposal):
    if proposal.status != "pending":
        return None
    kind = proposal.proposal_type
    if kind == "edit_cpe" and proposal.cpe_entry:
        cpe = proposal.cpe_entry
        fields = ["part", "version", "update", "edition", "language", "sw_edition",
                  "target_sw", "target_hw", "other", "title", "notes"]
        current = {field: getattr(cpe, field) for field in fields}
        modified = {field: getattr(proposal, f"proposed_{field}") or current[field]
                    for field in fields}
        current["cpe_uri"] = cpe.cpe_uri
        modified["cpe_uri"] = proposal.proposed_cpe_uri or build_cpe_uri(
            modified["part"], proposal.proposed_vendor_name or cpe.vendor.name,
            proposal.proposed_product_name or cpe.product.name,
            *(modified[field] for field in fields[1:9]),
        )
    elif kind in {"edit_vendor_note", "edit_product_note"}:
        record = proposal.vendor if kind == "edit_vendor_note" else proposal.product
        if record is None:
            return None
        current, modified = {"notes": record.notes}, {"notes": proposal.proposed_notes}
    elif kind.startswith("new_"):
        current = {}
        modified = {column.name.removeprefix("proposed_"): getattr(proposal, column.name)
                    for column in proposal.__table__.columns
                    if column.name.startswith("proposed_") and getattr(proposal, column.name) is not None}
    else:
        return None
    return {"original": json.dumps(current, indent=2, ensure_ascii=False),
            "modified": json.dumps(modified, indent=2, ensure_ascii=False)}
