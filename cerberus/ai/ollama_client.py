from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from cerberus.core.logger import get_logger

_log = get_logger("cerberus.ai.ollama_client")


class OllamaError(Exception):
    """Fallo al contactar o parsear la respuesta de Ollama."""


class OllamaClient:
    """Cliente mínimo de Ollama (POST /api/generate, stream=false, format=json).

    Bloqueante por diseño (usa urllib stdlib); el llamador async debe envolverlo
    con asyncio.to_thread. Autodetecta la URL base si no se especifica.
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout_seconds: float = 20.0,
        retries: int = 2,
    ) -> None:
        self._base_url = base_url
        self._timeout = timeout_seconds
        self._retries = max(1, retries)

    def candidates(self) -> list[str]:
        if self._base_url:
            return [self._base_url.rstrip("/")]
        out: list[str] = []
        for env in ("HADES_OLLAMA_URL", "OLLAMA_HOST"):
            val = os.environ.get(env)
            if val:
                url = val if val.startswith("http") else f"http://{val}"
                out.append(url.rstrip("/"))
        out.append("http://127.0.0.1:11434")
        out.append("http://host.docker.internal:11434")
        # dedup preservando orden
        seen: set[str] = set()
        uniq: list[str] = []
        for u in out:
            if u not in seen:
                seen.add(u)
                uniq.append(u)
        return uniq

    def ask_json(self, model: str, prompt: str) -> dict[str, Any]:
        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0},
        }).encode("utf-8")

        last_err: Exception | None = None
        for base in self.candidates():
            url = f"{base}/api/generate"
            for attempt in range(self._retries):
                try:
                    req = urllib.request.Request(
                        url, data=payload,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                        raw = resp.read().decode("utf-8")
                    outer = json.loads(raw)
                    inner = outer.get("response", "")
                    parsed = json.loads(inner)
                    if not isinstance(parsed, dict):
                        raise OllamaError("inner response is not a JSON object")
                    return parsed
                except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
                    last_err = exc
                    _log.warning("ollama_attempt_failed",
                                 extra={"url": url, "attempt": attempt, "error": str(exc)})
        raise OllamaError(f"all Ollama candidates failed: {last_err!r}")
