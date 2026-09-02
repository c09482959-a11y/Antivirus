"""Canonical no-hook path telemetry helpers for raw queue modules."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path, scheduler_path_text


def materialize_raw_queue_path(value: object, *, reason: str) -> Path:
    """Materialize a queue filesystem path or raise the caller-owned reason."""
    safe_path, path_reason = scheduler_filesystem_path(value)
    if path_reason:
        raise ValueError(reason)
    return Path(safe_path)


def raw_queue_path_text_or_error(value: object, *, reason: str) -> str:
    """Return accepted no-hook path text or raise the caller-owned reason."""
    text, path_reason = scheduler_path_text(value)
    if path_reason == "" and text != "":
        return text
    raise ValueError(reason)


def raw_queue_path_extra(key: str, value: object) -> dict[str, str]:
    """Return no-hook path text and rejection reason fields for telemetry."""
    text, reason = scheduler_path_text(value)
    return {key: text, key + "_reason": reason}


def raw_queue_accepted_path_extra(key: str, value: object) -> dict[str, str]:
    """Return path telemetry while hiding rejected path text from reports."""
    text, reason = scheduler_path_text(value)
    return {key: text if reason == "" else "", key + "_reason": reason}


def raw_queue_report_path_extra(extra: dict[str, object], key: str, value: object) -> dict[str, object]:
    """Merge existing report metadata with canonical no-hook path telemetry."""
    merged = dict(extra)
    merged.update(raw_queue_path_extra(key, value))
    return merged


__all__ = ("materialize_raw_queue_path", "raw_queue_path_text_or_error", "raw_queue_path_extra", "raw_queue_accepted_path_extra", "raw_queue_report_path_extra")
