"""Binary scanner strict-fast benign text gate."""

from __future__ import annotations

from pathlib import Path
import re

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.scanners.config import load_binary_policy_snapshot
from Virus_Scan.scanners.binary_io import read_binary_file_bytes
from Virus_Scan.scanners.entropy import _strict_fast_entropy
from Virus_Scan.scanners.binary_path_identity import binary_path_text_with_reason, get_binary_scan_extension_with_reason
from Virus_Scan.scanners.binary_strict_fast_evidence import (
    append_strict_fast_failure_evidence,
    append_strict_fast_rejection_evidence,
)


_BINARY_POLICY = load_binary_policy_snapshot()
STRICT_FAST_BENIGN_EXTENSIONS = _BINARY_POLICY.strict_fast_benign_extensions
STRICT_FAST_BENIGN_MAX_BYTES = _BINARY_POLICY.strict_fast_benign_max_bytes
STRICT_FAST_BENIGN_BINARY_MAGIC = _BINARY_POLICY.strict_fast_benign_binary_magic
STRICT_FAST_BENIGN_DENY_TOKENS = _BINARY_POLICY.strict_fast_benign_deny_tokens
_STRICT_FAST_READ_FAILURE = object()


def _strict_fast_base_metadata(path: object) -> tuple[Path | None, dict[str, object]]:
    text, reason = binary_path_text_with_reason(path)
    extension, extension_reason = get_binary_scan_extension_with_reason(path)
    rejection_reason = reason or extension_reason
    meta = {"extension": extension}
    if rejection_reason:
        append_strict_fast_rejection_evidence(meta, "path", rejection_reason)
        return None, meta
    return Path(text), meta


def _strict_fast_reject_for_size(path: Path, meta: dict[str, object]) -> bool:
    try:
        size = path.stat().st_size
    except SCAN_CONTENT_ERRORS as exc:
        append_strict_fast_failure_evidence(meta, "stat", exc)
        return bool(meta.get("scanner_failure_evidence_recorded"))
    meta["size"] = size
    return bool(size > STRICT_FAST_BENIGN_MAX_BYTES)


def _strict_fast_read_candidate(path: Path, meta: dict[str, object]) -> bytes | object | None:
    try:
        data = read_binary_file_bytes(path.as_posix(), max_size=STRICT_FAST_BENIGN_MAX_BYTES + 1)
    except SCAN_CONTENT_ERRORS as exc:
        append_strict_fast_failure_evidence(meta, "read", exc)
        return _STRICT_FAST_READ_FAILURE
    if not data or len(data) > STRICT_FAST_BENIGN_MAX_BYTES:
        return None
    return data


def _strict_fast_binary_prefix_rejected(data: bytes) -> bool:
    return any(data.startswith(magic) for magic in STRICT_FAST_BENIGN_BINARY_MAGIC)


def _strict_fast_visibility_ok(data: bytes, meta: dict[str, object]) -> bool:
    nul_ratio = data.count(b"\x00") / max(1, len(data))
    meta["nul_ratio"] = round(float(nul_ratio), 5)
    if nul_ratio > 0.0:
        return False
    printable = sum(1 for byte in data if byte in (9, 10, 13) or 32 <= byte <= 126)
    printable_ratio = printable / max(1, len(data))
    meta["printable_ratio"] = round(float(printable_ratio), 5)
    return bool(printable_ratio >= 0.97)


def _strict_fast_entropy_ok(data: bytes, meta: dict[str, object], *, entropy_calculator: object = _strict_fast_entropy) -> bool:
    try:
        entropy = entropy_calculator(data)
    except SCAN_CONTENT_ERRORS as exc:
        append_strict_fast_failure_evidence(meta, "entropy", exc)
        return bool(not meta.get("scanner_failure_evidence_recorded"))
    meta["entropy"] = round(float(entropy), 4)
    return bool(entropy < 5.2)


def _strict_fast_text_markers_ok(text: str, meta: dict[str, object]) -> bool:
    lowered = text.lower()
    matched = [token for token in STRICT_FAST_BENIGN_DENY_TOKENS if token in lowered]
    if matched:
        meta["deny_token"] = matched[0]
        return False
    if re.search(r"[A-Za-z0-9+/]{80,}={0,2}", text):
        meta["encoded_blob"] = True
        return False
    if re.search(r"(?:\\x[0-9a-fA-F]{2}){8,}", text):
        meta["hex_escape_blob"] = True
        return False
    return True


def _strict_fast_line_lengths_ok(text: str, meta: dict[str, object]) -> bool:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return True
    longest = max(len(line) for line in lines)
    if longest > 240:
        meta["long_line"] = longest
        return False
    return True


def _strict_fast_file_is_boring_text(path: object, *, entropy_calculator: object = _strict_fast_entropy) -> tuple[bool, dict[str, object]]:
    """Return whether a file is safe for strict-fast benign text bypass."""
    candidate, meta = _strict_fast_base_metadata(path)
    if candidate is None:
        return False, meta
    if meta["extension"] not in STRICT_FAST_BENIGN_EXTENSIONS:
        return False, meta
    if _strict_fast_reject_for_size(candidate, meta):
        return False, meta
    data = _strict_fast_read_candidate(candidate, meta)
    if data is _STRICT_FAST_READ_FAILURE or data is None or type(data) is not bytes:
        return False, meta
    if _strict_fast_binary_prefix_rejected(data):
        return False, meta
    if not _strict_fast_visibility_ok(data, meta):
        return False, meta
    if not _strict_fast_entropy_ok(data, meta, entropy_calculator=entropy_calculator):
        return False, meta
    text = data.decode("utf-8", errors="ignore")
    if not text or not _strict_fast_text_markers_ok(text, meta):
        return False, meta
    return _strict_fast_line_lengths_ok(text, meta), meta


__all__ = ("_strict_fast_entropy", "_strict_fast_file_is_boring_text")
