import io
import json
from unittest.mock import patch

import pytest

from cerberus.ai.ollama_client import OllamaClient, OllamaError


def _fake_response(payload: dict) -> io.BytesIO:
    # Ollama /api/generate (stream=false) -> {"response": "<inner json string>", ...}
    body = json.dumps({"response": json.dumps(payload)}).encode("utf-8")
    return io.BytesIO(body)


def test_ask_json_parses_inner_json():
    client = OllamaClient(base_url="http://127.0.0.1:11434", timeout_seconds=5.0, retries=1)
    inner = {"severity": "HIGH", "confidence": 0.7}
    with patch("cerberus.ai.ollama_client.urllib.request.urlopen",
               return_value=_fake_response(inner)):
        out = client.ask_json(model="m", prompt="p")
    assert out["severity"] == "HIGH"
    assert out["confidence"] == 0.7


def test_ask_json_raises_on_connection_error():
    import urllib.error
    client = OllamaClient(base_url="http://127.0.0.1:11434", timeout_seconds=1.0, retries=2)
    with patch("cerberus.ai.ollama_client.urllib.request.urlopen",
               side_effect=urllib.error.URLError("refused")):
        with pytest.raises(OllamaError):
            client.ask_json(model="m", prompt="p")


def test_ask_json_raises_on_malformed_inner_json():
    client = OllamaClient(base_url="http://127.0.0.1:11434", timeout_seconds=1.0, retries=1)
    bad = io.BytesIO(json.dumps({"response": "not json {{{"}).encode("utf-8"))
    with patch("cerberus.ai.ollama_client.urllib.request.urlopen", return_value=bad):
        with pytest.raises(OllamaError):
            client.ask_json(model="m", prompt="p")


def test_candidates_prefers_explicit_base_url():
    client = OllamaClient(base_url="http://example:1234")
    assert client.candidates()[0] == "http://example:1234"


def test_candidates_autodetect_includes_localhost(monkeypatch):
    monkeypatch.delenv("HADES_OLLAMA_URL", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    client = OllamaClient(base_url=None)
    assert "http://127.0.0.1:11434" in client.candidates()
