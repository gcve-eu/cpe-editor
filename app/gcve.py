"""On-demand GCVE lookups for an exact vendor/product tuple."""

import json
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from flask import current_app


def _text(*values):
    return next((value.strip() for value in values if isinstance(value, str) and value.strip()), None)


def _match(record, identifier, source, web_base):
    metadata = record.get("cveMetadata") or {}
    containers = record.get("containers") or {}
    cna = containers.get("cna") if isinstance(containers, dict) else {}
    if not isinstance(metadata, dict):
        metadata = {}
    if not isinstance(cna, dict):
        cna = {}
    descriptions = cna.get("descriptions")
    if not isinstance(descriptions, list):
        descriptions = []
    description = next((entry.get("value") for entry in descriptions
                        if isinstance(entry, dict) and entry.get("lang") == "en"), None)
    vuln_id = _text(identifier, record.get("id"), record.get("vulnerability_id"), metadata.get("cveId"))
    if not vuln_id:
        return None
    return {
        "id": vuln_id,
        "source": source,
        "summary": _text(record.get("summary"), record.get("title"), record.get("details"), record.get("description"), description),
        "updated_at": _text(record.get("modified"), record.get("updated_at"), metadata.get("dateUpdated")),
        "url": f"{web_base}/vuln/{quote(vuln_id, safe='')}",
    }


def fetch_tuple_matches(vendor, product, page, per_page):
    api_base = (current_app.config.get("GCVE_API_BASE_URL") or "https://db.gcve.eu/api").rstrip("/")
    web_base = (current_app.config.get("GCVE_WEB_BASE_URL") or "https://db.gcve.eu").rstrip("/")
    endpoint = (
        f"{api_base}/vulnerability/search/{quote(vendor, safe='')}/{quote(product, safe='')}?"
        + urlencode({"page": page, "per_page": per_page})
    )
    request = Request(endpoint, headers={"Accept": "application/json", "User-Agent": "cpe-editor/1.0"})
    try:
        with urlopen(request, timeout=8) as response:
            payload = json.load(response)
    except HTTPError as exc:
        return {"ok": False, "error": f"GCVE returned HTTP {exc.code}."}
    except (URLError, OSError, ValueError):
        return {"ok": False, "error": "GCVE vulnerability lookup is currently unavailable. Please retry."}

    # Current GCVE responses wrap source groups in results. Older versions
    # returned the source groups directly. Each entry can be [id, record].
    groups = payload.get("results", payload) if isinstance(payload, dict) else None
    if not isinstance(groups, dict) or any(not isinstance(rows, list) for rows in groups.values()):
        return {"ok": False, "error": "GCVE returned an unexpected response format."}
    items, seen = [], set()
    raw_count = 0
    for source, rows in groups.items():
        raw_count += len(rows)
        for entry in rows:
            identifier = None
            if isinstance(entry, list) and len(entry) == 2:
                identifier, entry = entry
            if not isinstance(entry, dict):
                continue
            item = _match(entry, identifier, source, web_base)
            if item is None or item["id"].lower() in seen:
                continue
            seen.add(item["id"].lower())
            items.append(item)
    total = payload.get("total_count")
    if type(total) is not int or total < 0:
        total = None
    return {
        "ok": True, "vendor": vendor, "product": product,
        "page": page, "per_page": per_page,
        "count": len(items), "items": items, "total": total,
        "has_next": page * per_page < total if total is not None else raw_count >= per_page,
        "search_url": f"{web_base}/search?" + urlencode({"vendor": vendor, "product": product}),
    }
