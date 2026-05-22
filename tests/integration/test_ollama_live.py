import urllib.error
import urllib.request

import pytest

from cerberus.ai.ollama_client import OllamaClient, OllamaError

_MODEL = "qwen2.5-coder:14b"


def _ollama_up() -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=3):
            return True
    except (urllib.error.URLError, OSError):
        return False


@pytest.mark.skipif(not _ollama_up(), reason="Ollama no disponible en :11434")
def test_ollama_live_returns_json_object():
    client = OllamaClient(base_url="http://127.0.0.1:11434", timeout_seconds=60.0, retries=1)
    prompt = (
        'Return ONLY a JSON object with a key "severity" whose value is the '
        'string "LOW". No prose.'
    )
    try:
        out = client.ask_json(model=_MODEL, prompt=prompt)
    except OllamaError as exc:
        pytest.skip(f"modelo no disponible o error: {exc}")
    assert isinstance(out, dict)
    assert "severity" in out
