from pathlib import Path

from cerberus.service.integrity import IntegrityVerifier


def _mk(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_build_manifest_hashes_py_files(tmp_path: Path):
    _mk(tmp_path, "pkg/a.py", "print('a')")
    _mk(tmp_path, "pkg/sub/b.py", "print('b')")
    _mk(tmp_path, "pkg/notes.txt", "ignore me")
    v = IntegrityVerifier()
    manifest = v.build_manifest(tmp_path, subdir="pkg")
    assert set(manifest.keys()) == {"pkg/a.py", "pkg/sub/b.py"}
    assert all(len(h) == 64 for h in manifest.values())


def test_verify_detects_no_tampering(tmp_path: Path):
    _mk(tmp_path, "pkg/a.py", "x = 1")
    v = IntegrityVerifier()
    manifest = v.build_manifest(tmp_path, subdir="pkg")
    result = v.verify(tmp_path, manifest, subdir="pkg")
    assert result.ok is True
    assert result.mismatched == [] and result.missing == [] and result.extra == []


def test_verify_detects_modified_file(tmp_path: Path):
    _mk(tmp_path, "pkg/a.py", "x = 1")
    v = IntegrityVerifier()
    manifest = v.build_manifest(tmp_path, subdir="pkg")
    _mk(tmp_path, "pkg/a.py", "x = 2  # tampered")
    result = v.verify(tmp_path, manifest, subdir="pkg")
    assert result.ok is False
    assert "pkg/a.py" in result.mismatched


def test_verify_detects_missing_and_extra(tmp_path: Path):
    _mk(tmp_path, "pkg/a.py", "x = 1")
    v = IntegrityVerifier()
    manifest = v.build_manifest(tmp_path, subdir="pkg")
    (tmp_path / "pkg" / "a.py").unlink()
    _mk(tmp_path, "pkg/c.py", "y = 9")
    result = v.verify(tmp_path, manifest, subdir="pkg")
    assert result.ok is False
    assert "pkg/a.py" in result.missing
    assert "pkg/c.py" in result.extra


def test_write_and_load_manifest_roundtrip(tmp_path: Path):
    _mk(tmp_path, "pkg/a.py", "x = 1")
    v = IntegrityVerifier()
    manifest = v.build_manifest(tmp_path, subdir="pkg")
    mp = tmp_path / "manifest.json"
    v.write_manifest(mp, manifest)
    loaded = v.load_manifest(mp)
    assert loaded == manifest
