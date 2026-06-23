import json

from app import cache
from app import views


class FakeValkeyClient:
    def __init__(self):
        self.values = {}
        self.ttls = {}
        self.pings = 0

    def ping(self):
        self.pings += 1
        return True

    def get(self, key):
        return self.values.get(key)

    def setex(self, key, ttl, value):
        self.ttls[key] = ttl
        self.values[key] = value
        return True


class FakeValkeyModule:
    def __init__(self, client):
        self.client = client
        self.Valkey = self

    def from_url(self, url, **kwargs):
        self.url = url
        self.kwargs = kwargs
        return self.client


def test_valkey_json_cache_uses_running_client_when_configured(app, monkeypatch):
    fake_client = FakeValkeyClient()
    fake_module = FakeValkeyModule(fake_client)
    app.config.update(
        VALKEY_URL="redis://valkey.test:6379/0",
        STATISTICS_CACHE_TTL_SECONDS=42,
    )
    monkeypatch.setattr(cache.importlib, "import_module", lambda name: fake_module)

    with app.app_context():
        assert cache.cache_set_json("statistics:test", {"ok": True}) is True
        assert cache.cache_get_json("statistics:test") == {"ok": True}

    assert fake_module.url == "redis://valkey.test:6379/0"
    assert fake_module.kwargs["decode_responses"] is True
    assert fake_client.ttls["statistics:test"] == 42
    assert json.loads(fake_client.values["statistics:test"]) == {"ok": True}


def test_statistics_payload_uses_cached_value_when_available(app, monkeypatch):
    cached_payload = {
        "counts": {"vendors": 99},
        "averages": {},
        "top_vendor": None,
        "cpe_part_counts": [],
        "metadata_key_counts": [],
        "relationship_type_counts": [],
        "proposal_status_counts": {},
    }
    monkeypatch.setattr(views, "cache_get_json", lambda key: cached_payload)

    def fail_if_uncached():
        raise AssertionError("statistics payload should be served from cache")

    monkeypatch.setattr(views, "_build_statistics_payload_uncached", fail_if_uncached)

    with app.app_context():
        assert views._build_statistics_payload() == cached_payload


def test_statistics_payload_populates_cache_on_miss(app, monkeypatch):
    writes = []
    monkeypatch.setattr(views, "cache_get_json", lambda key: None)
    monkeypatch.setattr(
        views, "cache_set_json", lambda key, value: writes.append((key, value))
    )

    with app.app_context():
        payload = views._build_statistics_payload()

    assert payload["counts"]["vendors"] == 2
    assert writes == [("cpe-editor:statistics:payload:v1", payload)]
