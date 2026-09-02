"""Scanner-owned binary IO and bootstrap-free string evidence helpers."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.scanners.binary_path_identity import binary_path_text_with_reason
from Virus_Scan.scanners.config import load_binary_policy_snapshot
from Virus_Scan.scanners.contracts import scanner_failure_evidence_tags

_BINARY_POLICY = load_binary_policy_snapshot()


def _binary_read_limit(max_size: object) -> tuple[int | None, str]:
    """Return exact read limit without invoking caller-owned numeric hooks."""
    if max_size is None:
        return None, ''
    if type(max_size) is not int or type(max_size) is bool:
        return 0, 'binary_read_max_size_rejected'
    if max_size < 0:
        return None, ''
    return max_size, ''


def read_binary_file_bytes(path: str | Path, max_size: int | None = 5_000_000) -> bytes:
    """Read bounded binary content for binary scanners without runtime-owned dependency injection."""
    path_text, path_reason = binary_path_text_with_reason(path)
    if path_reason:
        raise TypeError(path_reason)
    limit, limit_reason = _binary_read_limit(max_size)
    if limit_reason:
        raise TypeError(limit_reason)
    target = Path(path_text)
    with target.open("rb") as handle:
        if limit is None:
            return handle.read()
        return handle.read(limit)


def binary_log_message(_message: object) -> None:
    """No-op binary-owned log sink; returned evidence is the publication path."""
    return None


def _binary_string_rejection_tags(reason: str) -> list[str]:
    return scanner_failure_evidence_tags(
        'binary',
        'binary_string_evidence',
        TypeError(reason),
        ['binary_string_input_rejected', 'binary_final_json_must_record'],
        state='degraded',
        error_category='binary_string_input_rejected',
        error_source='binary.binary_string_evidence_tags',
        file_type='binary',
    )


def binary_string_evidence_tags(data: object, *, path: object = None, finalize: bool = True) -> list[str]:
    """Return deterministic binary string evidence from schema-validated policy."""
    del path, finalize
    text, reason = no_hook_text(
        data,
        missing_reason='binary_string_input_missing',
        unsupported_reason='binary_string_input_rejected',
    )
    if reason == 'binary_string_input_missing':
        return []
    if reason:
        return _binary_string_rejection_tags(reason)
    lowered = " " + str.lower(text) + " "
    tags: list[str] = []
    seen: set[str] = set()
    for needle, tag in _BINARY_POLICY.binary_string_rules:
        if needle in lowered and tag not in seen:
            seen.add(tag)
            tags.append(tag)
    if {"network_download", "url_present"} <= seen and "download_observable" not in seen:
        tags.append("download_observable")
    if {"powershell_exec", "encoded_powershell"} <= seen and "encoded_script_execution" not in seen:
        tags.append("encoded_script_execution")
    return tags


def binary_scan_content_error(exc: BaseException) -> bool:
    return isinstance(exc, SCAN_CONTENT_ERRORS)


__all__ = (
    "binary_log_message",
    "binary_scan_content_error",
    "binary_string_evidence_tags",
    "read_binary_file_bytes",
)
