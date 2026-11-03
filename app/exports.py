"""Disk-backed JSON exports and a bounded Valkey snapshot cache."""

from datetime import datetime, timezone
from io import BytesIO
import json
from tempfile import TemporaryFile

from flask import current_app

from .cache import get_valkey_client


def build_export_artifact(entity, filters, items):
    """Serialize records incrementally; never retain the whole catalog in RAM."""
    artifact = TemporaryFile(mode="w+b")
    encoder = json.JSONEncoder(ensure_ascii=True, separators=(",", ":"))
    try:
        header = {
            "entity": entity,
            "filters": filters,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        artifact.write((encoder.encode(header)[:-1] + ',"items":[').encode("ascii"))
        total = 0
        for item in items:
            if total:
                artifact.write(b",")
            for chunk in encoder.iterencode(item):
                artifact.write(chunk.encode("ascii"))
            total += 1
        artifact.write(f'],"total":{total}}}'.encode("ascii"))
        artifact.seek(0)
        return artifact
    except BaseException:
        artifact.close()
        raise


def _cache_limits():
    return (
        int(current_app.config["EXPORT_CACHE_MAX_BYTES"]),
        int(current_app.config["EXPORT_CACHE_SLOTS"]),
        int(current_app.config["EXPORT_CACHE_TTL_SECONDS"]),
    )


def _slot_key(fingerprint, slots):
    # A fixed number of slots bounds total storage even for adversarial filters.
    # Every value carries its full fingerprint so collisions can only evict.
    slot = int(fingerprint, 16) % slots
    return f"cpe-editor:export:v2:slot:{slot}"


def _forget_client():
    current_app.extensions.setdefault("cpe_editor", {}).pop("valkey_client", None)


def get_cached_export(fingerprint):
    max_bytes, slots, ttl = _cache_limits()
    if min(max_bytes, slots, ttl) <= 0:
        return None
    client = get_valkey_client()
    if client is None:
        return None
    try:
        cached = client.get(_slot_key(fingerprint, slots))
        if not cached:
            return None
        prefix = fingerprint + "\n"
        if not cached.startswith(prefix) or len(cached) > max_bytes + len(prefix):
            return None
        # Artifacts are ASCII JSON. Reads are bounded by the per-entry limit.
        return BytesIO(cached[len(prefix):].encode("ascii"))
    except Exception:
        _forget_client()
        return None


def cache_export(fingerprint, artifact):
    """Cache only small artifacts; large downloads remain on disk throughout."""
    max_bytes, slots, ttl = _cache_limits()
    if min(max_bytes, slots, ttl) <= 0:
        return False
    try:
        size = artifact.seek(0, 2)
        if size > max_bytes:
            return False
        client = get_valkey_client()
        if client is None:
            return False
        artifact.seek(0)
        body = artifact.read(max_bytes + 1).decode("ascii")
        client.setex(_slot_key(fingerprint, slots), ttl, fingerprint + "\n" + body)
        return True
    except Exception:
        _forget_client()
        return False
    finally:
        artifact.seek(0)
