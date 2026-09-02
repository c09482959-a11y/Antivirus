"""Trusted identity calculations for cached Enterprise ATT&CK bundles."""
from __future__ import annotations

from hashlib import sha1, sha256
from pathlib import Path, PosixPath, WindowsPath

_PATH_TYPES = (Path, PosixPath, WindowsPath)


def git_blob_sha1_bytes(data: bytes) -> str:
    if type(data) is not bytes:
        raise TypeError("attack_git_blob_bytes_required")
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return sha1(header + data).hexdigest()


def sha256_bytes(data: bytes) -> str:
    if type(data) is not bytes:
        raise TypeError("attack_sha256_bytes_required")
    return sha256(data).hexdigest()


def file_integrity(path: Path) -> tuple[str, str, int]:
    if type(path) not in _PATH_TYPES:
        raise TypeError("attack_integrity_path_required")
    data = path.read_bytes()
    return git_blob_sha1_bytes(data), sha256_bytes(data), len(data)


def verify_git_blob_identity(data: bytes, expected_sha1: str) -> tuple[str, str]:
    if type(expected_sha1) is not str or len(expected_sha1) != 40:
        raise ValueError("attack_expected_git_blob_sha1_invalid")
    expected = str.__str__(expected_sha1).lower()
    if any(ch not in "0123456789abcdef" for ch in expected):
        raise ValueError("attack_expected_git_blob_sha1_invalid")
    computed = git_blob_sha1_bytes(data)
    if computed != expected:
        raise ValueError("attack_git_blob_sha1_mismatch")
    return computed, sha256_bytes(data)


__all__ = (
    "file_integrity", "git_blob_sha1_bytes", "sha256_bytes",
    "verify_git_blob_identity",
)
