"""Tests for crypto utilities."""

from __future__ import annotations

from pathlib import Path

from aishield.utils.crypto import (
    compute_combined_hash,
    hash_directory,
    sha256_bytes,
    sha256_file,
    sha256_string,
    verify_directory_hash,
)


class TestSha256File:
    def test_hash_known_file(self, tmp_path: Path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        h = sha256_file(f)
        assert len(h) == 64
        assert isinstance(h, str)

    def test_hash_empty_file(self, tmp_path: Path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        h = sha256_file(f)
        assert len(h) == 64

    def test_hash_different_files(self, tmp_path: Path):
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_text("hello")
        f2.write_text("world")
        assert sha256_file(f1) != sha256_file(f2)

    def test_hash_same_content(self, tmp_path: Path):
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_text("same")
        f2.write_text("same")
        assert sha256_file(f1) == sha256_file(f2)


class TestSha256Bytes:
    def test_hash_bytes(self):
        h = sha256_bytes(b"hello")
        assert len(h) == 64

    def test_hash_empty_bytes(self):
        h = sha256_bytes(b"")
        assert len(h) == 64


class TestSha256String:
    def test_hash_string(self):
        h = sha256_string("hello")
        assert len(h) == 64

    def test_hash_unicode(self):
        h = sha256_string("hello 🌍")
        assert len(h) == 64


class TestComputeCombinedHash:
    def test_combined_hash(self):
        hashes = ["aaa", "bbb", "ccc"]
        h = compute_combined_hash(hashes)
        assert len(h) == 64

    def test_combined_hash_empty(self):
        h = compute_combined_hash([])
        assert len(h) == 64

    def test_combined_hash_deterministic(self):
        hashes = ["zzz", "aaa", "mmm"]
        h1 = compute_combined_hash(hashes)
        h2 = compute_combined_hash(hashes)
        assert h1 == h2


class TestHashDirectory:
    def test_hash_directory(self, tmp_path: Path):
        (tmp_path / "a.txt").write_text("hello")
        (tmp_path / "b.txt").write_text("world")
        result = hash_directory(tmp_path, patterns=["*.txt"])
        assert len(result["files"]) == 2
        assert result["integrity_hash"] != ""
        assert "directory" in result

    def test_hash_directory_empty(self, tmp_path: Path):
        result = hash_directory(tmp_path, patterns=["*.txt"])
        assert result["files"] == []
        assert result["integrity_hash"] == ""

    def test_hash_directory_with_patterns(self, tmp_path: Path):
        (tmp_path / "a.txt").write_text("hello")
        (tmp_path / "b.json").write_text("{}")
        result = hash_directory(tmp_path, patterns=["*.txt"])
        assert len(result["files"]) == 1


class TestVerifyDirectoryHash:
    def test_verify_pass(self, tmp_path: Path):
        (tmp_path / "a.txt").write_text("hello")
        manifest = hash_directory(tmp_path, patterns=["*.txt"])
        issues = verify_directory_hash(tmp_path, manifest)
        assert issues == []

    def test_verify_missing_file(self, tmp_path: Path):
        manifest = {
            "files": [{"path": "missing.txt", "sha256": "abc"}],
            "integrity_hash": "xyz",
        }
        issues = verify_directory_hash(tmp_path, manifest)
        assert len(issues) > 0
        assert "Missing file" in issues[0]

    def test_verify_tampered_file(self, tmp_path: Path):
        f = tmp_path / "a.txt"
        f.write_text("original")
        manifest = hash_directory(tmp_path, patterns=["*.txt"])
        f.write_text("tampered")
        issues = verify_directory_hash(tmp_path, manifest)
        assert len(issues) > 0
        assert "Hash mismatch" in issues[0]
