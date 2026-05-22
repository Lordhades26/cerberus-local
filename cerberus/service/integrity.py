from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

_CHUNK = 65536


@dataclass(frozen=True)
class IntegrityResult:
    ok: bool
    mismatched: list[str]
    missing: list[str]
    extra: list[str]


class IntegrityVerifier:
    """Anti-tampering por checksum SHA256 sobre los .py del paquete. Solo lee archivos."""

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while chunk := fh.read(_CHUNK):
                h.update(chunk)
        return h.hexdigest()

    def build_manifest(self, root: Path | str, subdir: str = "cerberus") -> dict[str, str]:
        root = Path(root)
        base = root / subdir
        manifest: dict[str, str] = {}
        for path in sorted(base.rglob("*.py")):
            rel = path.relative_to(root).as_posix()
            manifest[rel] = self._sha256(path)
        return manifest

    def write_manifest(self, path: Path | str, manifest: dict[str, str]) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(manifest, indent=2, sort_keys=True),
                              encoding="utf-8")

    def load_manifest(self, path: Path | str) -> dict[str, str]:
        return dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def verify(self, root: Path | str, manifest: dict[str, str],
               subdir: str = "cerberus") -> IntegrityResult:
        current = self.build_manifest(root, subdir=subdir)
        cur_keys, exp_keys = set(current), set(manifest)
        missing = sorted(exp_keys - cur_keys)
        extra = sorted(cur_keys - exp_keys)
        mismatched = sorted(k for k in (cur_keys & exp_keys) if current[k] != manifest[k])
        ok = not (missing or extra or mismatched)
        return IntegrityResult(ok=ok, mismatched=mismatched, missing=missing, extra=extra)
