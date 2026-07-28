from __future__ import annotations

from datetime import datetime
from uuid import NAMESPACE_URL, uuid4, uuid5
from werkzeug.security import check_password_hash, generate_password_hash
import secrets

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


def generate_api_key() -> tuple[str, str, str]:
    prefix = secrets.token_hex(8)
    secret = secrets.token_urlsafe(32)
    token = f"{prefix}_{secret}"

    return token, prefix, secret


def create_api_client(
    name: str,
    instance_url: str | None = None,
    rate_limit_per_hour: int = 100,
    expires_at=None,
) -> tuple[APIClient, str]:
    from .models import APIClient

    token, prefix, secret = generate_api_key()

    client = APIClient(
        uuid=new_uuid(),
        name=name,
        instance_url=instance_url,
        key_prefix=prefix,
        key_hash=generate_password_hash(secret),
        rate_limit_per_hour=rate_limit_per_hour,
        created_at=datetime.utcnow(),
        expires_at=expires_at,
    )
    return client, token


def authenticate_api_client(token: str) -> APIClient | None:
    from .models import APIClient

    try:
        prefix, secret = token.split("_", 1)
    except ValueError:
        return None

    if not prefix or not secret:
        return None

    client = APIClient.query.filter_by(key_prefix=prefix).first()

    if client is None:
        return None

    if not check_password_hash(client.key_hash, secret):
        return None

    return client
