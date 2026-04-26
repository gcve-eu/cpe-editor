from __future__ import annotations

from uuid import NAMESPACE_URL, uuid4, uuid5


GCVE_ROOT_NAMESPACE_URL = "GCVE-BCP-10"
GCVE_ROOT_NAMESPACE = uuid5(NAMESPACE_URL, GCVE_ROOT_NAMESPACE_URL)
VENDOR_UUID_NAMESPACE = uuid5(GCVE_ROOT_NAMESPACE, "vendor")
PRODUCT_UUID_NAMESPACE = uuid5(GCVE_ROOT_NAMESPACE, "product")


def normalize_token(value: str) -> str:
    return (value or "").strip().lower().replace(" ", "_")


def split_escaped(value: str, sep: str = ":") -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for ch in value:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == sep:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    if escaped:
        current.append("\\")
    parts.append("".join(current))
    return parts


def parse_cpe23_uri(cpe_uri: str) -> dict[str, str] | None:
    parts = split_escaped(cpe_uri or "")
    if len(parts) < 13 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    names = [
        "part",
        "vendor",
        "product",
        "version",
        "update",
        "edition",
        "language",
        "sw_edition",
        "target_sw",
        "target_hw",
        "other",
    ]
    values = parts[2:13]
    return dict(zip(names, values, strict=False))


def build_cpe_uri(
    part,
    vendor_name,
    product_name,
    version="*",
    update="*",
    edition="*",
    language="*",
    sw_edition="*",
    target_sw="*",
    target_hw="*",
    other="*",
):
    values = [
        "cpe",
        "2.3",
        part or "a",
        normalize_token(vendor_name),
        normalize_token(product_name),
        version or "*",
        update or "*",
        edition or "*",
        language or "*",
        sw_edition or "*",
        target_sw or "*",
        target_hw or "*",
        other or "*",
    ]
    return ":".join(values)


def new_uuid() -> str:
    return str(uuid4())


def vendor_uuid_for_name(name: str) -> str:
    return str(uuid5(VENDOR_UUID_NAMESPACE, normalize_token(name)))



def product_uuid_for_names(vendor_name: str, product_name: str) -> str:
    # Keep product UUIDs vendor-scoped to avoid collisions where multiple vendors
    # legitimately ship products with the same product token.
    return str(
        uuid5(
            PRODUCT_UUID_NAMESPACE,
            f"{normalize_token(vendor_name)}:{normalize_token(product_name)}",
        )
    )
