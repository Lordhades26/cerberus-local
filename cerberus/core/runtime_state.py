from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from cerberus.core.config import _VALID_MODES
from cerberus.core.logger import get_logger

_log = get_logger("cerberus.core.runtime_state")


class RuntimeState:
    """Estado de runtime persistido en JSON (atómico). Fuente del `mode` en caliente."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def _read(self) -> dict[str, object]:
        try:
            return dict(json.loads(self.path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, ValueError):
            return {}

    def _write(self, data: dict[str, object]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def get_mode(self, default: str) -> str:
        mode = self._read().get("mode")
        if isinstance(mode, str) and mode in _VALID_MODES:
            return mode
        return default

    def set_mode(self, mode: str) -> None:
        if mode not in _VALID_MODES:
            raise ValueError(f"Invalid mode {mode!r}; valid: {sorted(_VALID_MODES)}")
        data = self._read()
        data["mode"] = mode
        self._write(data)
        _log.info("mode_persisted", extra={"mode": mode})
