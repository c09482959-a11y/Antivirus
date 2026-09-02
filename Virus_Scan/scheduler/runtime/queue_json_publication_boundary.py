"""No-hook boundaries for scheduler queue JSON publication."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_text,
)
from Virus_Scan.scheduler.runtime.queue_filesystem_common import queue_filesystem_path_text


def queue_json_context(value: object, *, default_text: str) -> str:
    text, reason = scheduler_text(
        value,
        replacement_text=default_text,
        unsupported_reason="queue_json_context_rejected",
    )
    return text if reason == "" and text else default_text


def queue_json_tmp_suffix(value: object) -> str:
    text, reason = scheduler_text(
        value,
        replacement_text=".tmp",
        unsupported_reason="queue_json_tmp_suffix_rejected",
    )
    return text if reason == "" and text else ".tmp"


def queue_json_verify_flag(value: object) -> bool:
    parsed, reason = scheduler_bool(
        value,
        default=False,
        reason="queue_json_verify_rejected",
    )
    return parsed if reason == "" else False


def queue_json_path_name(filesystem_path: object) -> str:
    text, reason = queue_filesystem_path_text(filesystem_path)
    if reason:
        return "scheduler_path_unavailable"
    return Path(text).name or "scheduler_path_unavailable"


def queue_json_read_failure(reason: str) -> dict[str, object]:
    return {
        "queue_json_read_failed": True,
        "queue_failure": True,
        "allow_learning": False,
        "path_unavailable_reason": reason,
    }


__all__ = (
    "queue_json_context",
    "queue_json_path_name",
    "queue_json_read_failure",
    "queue_json_tmp_suffix",
    "queue_json_verify_flag",
)
