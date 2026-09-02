"""Queue-owned process-queue feed marker persistence."""
from __future__ import annotations

import time
from pathlib import Path
import re
import stat
from typing import NoReturn


from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.runtime.api import flush_open_writable_file, path_contains_filesystem_alias
from Virus_Scan.scheduler.evidence.process_queue_errors import process_queue_record_suppressed as _process_queue_record_suppressed
from Virus_Scan.scheduler.internal.evidence_projection import scheduler_evidence_path
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_atomic_replace as _queue_atomic_replace, queue_safe_unlink as _queue_safe_unlink

_FEED_MARKER_FAILED = False
_FEED_MARKER_READBACK_MISMATCH = "queue feed-complete marker readback mismatch"
_QUEUE_DIRECTORY_REJECTED_BEFORE_PATH_CONVERSION = "scheduler queue directory rejected before path conversion"
_FEED_MARKER_ATOMIC_REPLACE_FAILED = "queue feed-complete marker atomic replace failed"
_FEED_MARKER_PATTERN = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


def _raise_feed_marker_readback_mismatch() -> NoReturn:
    raise OSError(_FEED_MARKER_READBACK_MISMATCH)


def queue_feed_complete_path(queue_dir: object, *, record_suppressed: object=_process_queue_record_suppressed) -> Path:
    """Return the canonical process-queue feed-complete marker path."""
    safe_queue_dir, reason = scheduler_filesystem_path(queue_dir)
    if reason:
        record_suppressed(
            "queue_feed_complete_path_resolution_failed",
            ValueError(reason),
            extra={
                "queue_dir_type": no_hook_type_name(queue_dir),
                "queue_dir_unavailable_reason": reason,
            },
            fatal=True,
        )
        raise ValueError(_QUEUE_DIRECTORY_REJECTED_BEFORE_PATH_CONVERSION)
    return Path(safe_queue_dir) / "feed_complete.marker"


def mark_process_queue_feed_complete(
    queue_dir: object,
    *,
    safe_unlink: object=_queue_safe_unlink,
    record_suppressed: object=_process_queue_record_suppressed,
    feed_complete_path: object=queue_feed_complete_path,
    time_formatter: object=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
) -> bool:
    """Durably publish the queue-authority feed-complete marker or fail closed."""
    tmp: Path | None = None
    try:
        marker = feed_complete_path(queue_dir, record_suppressed=record_suppressed)
        marker.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = marker.with_name(marker.name + ".tmp")
        tmp = tmp_path
        marker_value = time_formatter()
        with tmp_path.open("w", encoding="utf-8") as fh:
            fh.write(marker_value)
            fh.flush()
            flush_open_writable_file(fh.fileno())
        if not _queue_atomic_replace(tmp, marker, log_context="queue_marker"):
            raise OSError(_FEED_MARKER_ATOMIC_REPLACE_FAILED)
        observed = marker.read_text(encoding="utf-8").strip()
        if observed != marker_value:
            _raise_feed_marker_readback_mismatch()
        return True
    except (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError, UnicodeError) as exc:
        try:
            if tmp:
                cleanup_log_context = "queue_feed_complete_tmp_cleanup"
                safe_unlink(tmp, log_context=cleanup_log_context)
        except (OSError, RuntimeError, ValueError) as cleanup_exc:
            record_suppressed(
                "queue_feed_complete_tmp_cleanup_failed",
                cleanup_exc,
                extra={
                    "queue_dir_type": no_hook_type_name(queue_dir),
                    "tmp": scheduler_evidence_path(tmp, field_name="tmp") if tmp is not None else "missing_tmp",
                },
            )
        record_suppressed(
            "queue_feed_complete_persist_failed",
            exc,
            fatal=True,
            extra={"queue_dir_type": no_hook_type_name(queue_dir)},
        )
        return _FEED_MARKER_FAILED


def process_queue_feed_is_complete(
    queue_dir: object,
    *,
    feed_complete_path: object=queue_feed_complete_path,
    record_suppressed: object=_process_queue_record_suppressed,
) -> bool:
    """Return True only for the exact durable queue-authority marker contract."""
    try:
        marker = feed_complete_path(queue_dir)
        try:
            marker_state = marker.lstat()
        except FileNotFoundError:
            return _FEED_MARKER_FAILED
        if path_contains_filesystem_alias(marker) or not stat.S_ISREG(marker_state.st_mode):
            record_suppressed(
                "queue_feed_complete_marker_kind_invalid",
                ValueError("queue feed-complete marker must be a non-aliased regular file"),
                extra={"queue_dir_type": no_hook_type_name(queue_dir)},
                fatal=True,
            )
            return _FEED_MARKER_FAILED
        marker_value = marker.read_text(encoding="utf-8", errors="strict")
        if _FEED_MARKER_PATTERN.fullmatch(marker_value) is None:
            record_suppressed(
                "queue_feed_complete_marker_content_invalid",
                ValueError("queue feed-complete marker content is invalid"),
                extra={"queue_dir_type": no_hook_type_name(queue_dir)},
                fatal=True,
            )
            return _FEED_MARKER_FAILED
        time.strptime(marker_value, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except (FileNotFoundError, PermissionError, OSError, RuntimeError, TypeError, ValueError) as exc:
        record_suppressed(
            "queue_feed_complete_probe_failed_closed",
            exc,
            extra={"queue_dir_type": no_hook_type_name(queue_dir)},
            fatal=True,
        )
        return _FEED_MARKER_FAILED


__all__ = ("mark_process_queue_feed_complete", "process_queue_feed_is_complete", "queue_feed_complete_path")
