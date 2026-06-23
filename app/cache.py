import importlib
import json
from types import SimpleNamespace

from flask import current_app


def _cache_config():
    url = (current_app.config.get("VALKEY_URL") or "").strip()
    ttl = int(current_app.config.get("STATISTICS_CACHE_TTL_SECONDS") or 0)
    return url, ttl


def get_valkey_client():
    """Return a ping-verified Valkey client, or None when unavailable."""
    url, ttl = _cache_config()
    if not url or ttl <= 0:
        return None

    extensions = current_app.extensions.setdefault("cpe_editor", {})
    client = extensions.get("valkey_client")
    if client is None:
        try:
            valkey = importlib.import_module("valkey")
            client = valkey.Valkey.from_url(
                url,
                socket_connect_timeout=0.2,
                socket_timeout=0.2,
                decode_responses=True,
            )
            client.ping()
        except Exception:
            extensions.pop("valkey_client", None)
            return None
        extensions["valkey_client"] = client
    return client


def cache_get_json(key):
    client = get_valkey_client()
    if client is None:
        return None
    try:
        cached = client.get(key)
    except Exception:
        current_app.extensions.setdefault("cpe_editor", {}).pop("valkey_client", None)
        return None
    if not cached:
        return None
    try:
        return json.loads(cached)
    except json.JSONDecodeError:
        return None


def cache_set_json(key, value):
    client = get_valkey_client()
    if client is None:
        return False
    _, ttl = _cache_config()
    try:
        client.setex(key, ttl, json.dumps(value))
    except Exception:
        current_app.extensions.setdefault("cpe_editor", {}).pop("valkey_client", None)
        return False
    return True


def dict_to_namespace(value):
    return SimpleNamespace(**value)
