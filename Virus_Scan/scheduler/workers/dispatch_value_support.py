"""Canonical no-hook scalar/path helpers for worker dispatch request surfaces."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_filesystem_path,
    scheduler_text,
)


def worker_dispatch_path(value: object, *, replacement_path: str) -> Path:
    path_value, reason = scheduler_filesystem_path(value)
    if reason:
        return Path(replacement_path)
    return Path(path_value)


def worker_dispatch_text(value: object, *, replacement_text: str, reason: str) -> str:
    text, _text_reason = scheduler_text(
        value,
        replacement_text=replacement_text,
        unsupported_reason=reason,
    )
    return text


def positive_worker_int(value: object, rejected_reason: str) -> int:
    parsed, reason = no_hook_exact_nonnegative_int(
        value,
        default=1,
        reason=rejected_reason,
    )
    if reason or parsed < 1:
        return 1
    return parsed
