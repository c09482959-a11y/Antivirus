"""Queue-owned time observations for claim/recovery decisions."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path, scheduler_float, scheduler_path_text


def queue_now() -> float:
    """Queue-authority timestamp source for claim/recovery decisions."""
    return time.time()


def queue_path_mtime_age(path: object, now: float | None = None, *, record_suppressed: Callable[..., object]) -> float | None:
    """Return queue artifact age for active-claim authority decisions."""
    filesystem_path, path_reason = scheduler_filesystem_path(path)
    path_text, _ = scheduler_path_text(filesystem_path)
    if path_reason or filesystem_path == "":
        record_suppressed(
            "process_queue_active_claim_mtime_unavailable",
            ValueError(path_reason or "scheduler_path_missing"),
            extra={"path": path_text, "path_unavailable_reason": path_reason or "scheduler_path_missing"},
            fatal=False,
        )
        return None
    now_value, now_reason = scheduler_float(
        now if now is not None else time.time(),
        reason="process_queue_active_claim_now_rejected",
    )
    if now_reason:
        record_suppressed(
            "process_queue_active_claim_mtime_unavailable",
            ValueError(now_reason),
            extra={"path": path_text, "time_unavailable_reason": now_reason},
            fatal=False,
        )
        return None
    try:
        stat_path = Path(path_text)
        return max(0.0, now_value - stat_path.stat().st_mtime)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        record_suppressed(
            "process_queue_active_claim_mtime_unavailable",
            exc,
            extra={"path": path_text},
            fatal=False,
        )
        return None


__all__ = ("queue_now", "queue_path_mtime_age")
