"""Shared exception and path-key helpers for scheduler queue filesystem ownership."""
from __future__ import annotations

from pathlib import Path
import os

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path, scheduler_path_text

QUEUE_FILESYSTEM_EXCEPTIONS = (OSError, ValueError, TypeError, RuntimeError, AttributeError)
_UNSUPPORTED_QUEUE_PATH_KEY = "unsupported_scheduler_queue_path"


def record_queue_filesystem_failure(stage: str, reason: str, value: object) -> None:
    try:
        record_suppressed_failure(
            stage,
            ValueError(reason),
            domain="scheduler",
            context={"reason": reason, "value_type": no_hook_type_name(value)},
            fatal=False,
        )
    except QUEUE_FILESYSTEM_EXCEPTIONS as reporting_exc:
        _ = reporting_exc


def path_key(path: object) -> str:
    """Return a deterministic queue path key without invoking caller-owned hooks."""
    safe_path, reason = queue_filesystem_path_text(path)
    if reason:
        record_queue_filesystem_failure("queue_path_key_path_rejected", reason, path)
        return ":".join((_UNSUPPORTED_QUEUE_PATH_KEY, no_hook_type_name(path), reason))
    try:
        return os.path.normcase(str(Path(safe_path).resolve()))
    except QUEUE_FILESYSTEM_EXCEPTIONS as exc:
        record_queue_filesystem_failure("queue_path_key_path_unavailable", type.__getattribute__(type(exc), "__name__"), path)
        return ":".join((_UNSUPPORTED_QUEUE_PATH_KEY, "unavailable", no_hook_type_name(path)))


def queue_filesystem_path_text(path: object) -> tuple[str, str]:
    safe_path, reason = scheduler_filesystem_path(path)
    if reason:
        return "", reason
    if type(safe_path) is str:
        return str.__str__(safe_path), ""
    return scheduler_path_text(safe_path)


_path_key = path_key

_record_queue_filesystem_failure = record_queue_filesystem_failure
