import io
import json

from app.views import _request_ollama_metadata_suggestion


def _fake_ollama_response():
    return io.BytesIO(
        json.dumps(
            {
                "response": json.dumps(
                    {
                        "gcve:description": "demo description",
                        "gcve:url": "https://example.com",
                    }
                )
            }
        ).encode("utf-8")
    )


def test_ollama_uses_base_url_when_configured(app, monkeypatch):
    captured = {}

    def fake_urlopen(request_obj, timeout):
        captured["url"] = request_obj.full_url
        return _fake_ollama_response()

    app.config.update(OLLAMA_BASE_URL="http://ollama.internal:11434")
    monkeypatch.setattr("app.views.urlopen", fake_urlopen)

    with app.app_context():
        result = _request_ollama_metadata_suggestion("apache", "", "")

    assert result["ok"] is True
    assert captured["url"] == "http://ollama.internal:11434/api/generate"


def test_ollama_accepts_host_with_scheme(app, monkeypatch):
    captured = {}

    def fake_urlopen(request_obj, timeout):
        captured["url"] = request_obj.full_url
        return _fake_ollama_response()

    app.config.update(OLLAMA_HOST="http://ollama.internal:11434", OLLAMA_BASE_URL="")
    monkeypatch.setattr("app.views.urlopen", fake_urlopen)

    with app.app_context():
        result = _request_ollama_metadata_suggestion("apache", "", "")

    assert result["ok"] is True
    assert captured["url"] == "http://ollama.internal:11434/api/generate"


def test_ollama_falls_back_to_plain_text_when_response_is_not_json(app, monkeypatch):
    def fake_urlopen(request_obj, timeout):
        return io.BytesIO(json.dumps({"response": "plain text output"}).encode("utf-8"))

    monkeypatch.setattr("app.views.urlopen", fake_urlopen)

    with app.app_context():
        result = _request_ollama_metadata_suggestion("apache", "", "")

    assert result == {"ok": True, "description": "plain text output", "url": ""}
