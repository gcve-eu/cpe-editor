import importlib
import sys


def test_wsgi_entrypoint_exposes_non_debug_app(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    sys.modules.pop("wsgi", None)

    wsgi = importlib.import_module("wsgi")

    assert wsgi.app.debug is False
