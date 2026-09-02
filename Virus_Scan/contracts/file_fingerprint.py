"""Canonical import-light file fingerprint contracts."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
import hashlib
import os
from typing import NoReturn

from Virus_Scan.contracts.no_hook_materialization import no_hook_text

_STDLIB_PATH_TYPES = (PurePosixPath, PureWindowsPath, PosixPath, WindowsPath)
_UNSAFE_FILE_PATH_REJECTED = "unsafe file path rejected"


def _raise_unsafe_file_path_rejected() -> NoReturn:
    raise TypeError(_UNSAFE_FILE_PATH_REJECTED)


def _safe_path_text(path: object) -> tuple[str, str]:
    if isinstance(path, str):
        return str.__str__(path), ""
    if type(path) in _STDLIB_PATH_TYPES:
        try:
            return PurePath.as_posix(path), ""
        except (TypeError, ValueError, OSError, RuntimeError):
            return "", "path_text_unavailable"
    return no_hook_text(path, missing_reason="missing_path", unsupported_reason="unsafe_path_value_rejected")


def _safe_int_status(value: object) -> tuple[int, str]:
    if type(value) is bool:
        return (0, "unsafe_fingerprint_int_rejected")
    if type(value) is int:
        return (value, "")
    text, reason = no_hook_text(value, unsupported_reason="unsafe_fingerprint_int_rejected")
    if reason:
        return (0, reason)
    try:
        return (int(str.__str__(text).strip()), "")
    except (TypeError, ValueError, OverflowError):
        return (0, "parse_error")


def _safe_int(value: object) -> int:
    number, _reason = _safe_int_status(value)
    return number


@dataclass(frozen=True, slots=True)
class FileFingerprintSnapshot:
    """Immutable source-file fingerprint used before JSON materialization."""

    path: str
    size: int
    mtime: int
    sha256: str

    def __post_init__(self) -> None:
        path_text, path_reason = _safe_path_text(self.path)
        sha_text, sha_reason = no_hook_text(self.sha256, missing_reason="missing_sha256", unsupported_reason="unsafe_sha256_rejected")
        object.__setattr__(self, "path", os.path.abspath(path_text) if (not path_reason and path_text) else "")
        object.__setattr__(self, "size", _safe_int(self.size))
        object.__setattr__(self, "mtime", _safe_int(self.mtime))
        object.__setattr__(self, "sha256", "" if sha_reason else sha_text)

    def as_dict(self) -> dict[str, object]:
        """Materialize the deterministic JSON fingerprint shape."""
        return {
            "path": self.path,
            "size": self.size,
            "mtime": self.mtime,
            "sha256": self.sha256,
        }


def sha256_file(path: str | os.PathLike[str], chunk_size: int = 1024 * 1024) -> str:
    path_text, reason = _safe_path_text(path)
    if reason:
        _raise_unsafe_file_path_rejected()
    h = hashlib.sha256()
    with open(path_text, 'rb') as fh:
        while True:
            b = fh.read(_safe_int(chunk_size) or 1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def source_fingerprint_snapshot(path: str | os.PathLike[str]) -> FileFingerprintSnapshot:
    """Return an immutable source fingerprint, failing closed for unreadable paths."""
    path_text, path_reason = _safe_path_text(path)
    if path_reason:
        return FileFingerprintSnapshot(path="", size=0, mtime=0, sha256="")
    try:
        st = os.stat(path_text)
        return FileFingerprintSnapshot(
            path=os.path.abspath(path_text),
            size=_safe_int(st.st_size),
            mtime=_safe_int(st.st_mtime),
            sha256=sha256_file(path_text),
        )
    except (OSError, ValueError, TypeError):
        return FileFingerprintSnapshot(
            path=os.path.abspath(path_text),
            size=0,
            mtime=0,
            sha256="",
        )


def source_fingerprint(path: str | os.PathLike[str]) -> dict[str, object]:
    """Return the deterministic JSON shape from the immutable contract."""
    return source_fingerprint_snapshot(path).as_dict()


__all__ = ("FileFingerprintSnapshot", "sha256_file", "source_fingerprint", "source_fingerprint_snapshot")
