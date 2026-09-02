"""In-memory scheduler progress logging ownership."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_finite_float

ProgressLogCallback = Callable[[str], object]


class ProgressLogger(Protocol):
    def info(self, message: str, *args: object) -> object:
        ...


@dataclass(frozen=True, slots=True)
class InMemoryProgressLogState:
    last_progress_total: int
    last_log_time: float
    emitted: bool


def _emit_progress_rejection(log_error: ProgressLogCallback | None, field: str, reason: str) -> None:
    if log_error is not None:
        try:
            log_error(str.__add__(str.__add__(str.__add__("inmemory_progress_logging: ", field), " rejected without caller hooks: "), reason))
        except (OSError, RuntimeError, TypeError, ValueError):
            log_error = None


def _progress_reason(field: str) -> str:
    return str.__add__("unsafe_", field)


def _progress_int(value: object, *, field: str, default_value: int, log_error: ProgressLogCallback | None) -> int:
    parsed, reason = no_hook_exact_nonnegative_int(value, default=default_value, reason=_progress_reason(field))
    if reason:
        _emit_progress_rejection(log_error, field, reason)
    return parsed


def _progress_float(value: object, *, field: str, default_value: float, minimum: float = 0.0, log_error: ProgressLogCallback | None) -> float:
    parsed, reason = no_hook_finite_float(value, default=default_value, minimum=minimum, reason=_progress_reason(field))
    if reason:
        _emit_progress_rejection(log_error, field, reason)
    return parsed


def maybe_log_inmemory_progress(
    *,
    now: object,
    last_log_time: object,
    progress_every: object,
    completed: object,
    total_files: object,
    active_count: object,
    pending_count: object,
    live_workers: object,
    logical_inflight_count: object,
    queued_unstarted_count: object,
    logger: ProgressLogger,
    last_progress_total: object,
    log_error: ProgressLogCallback | None = None,
) -> InMemoryProgressLogState:
    safe_last_progress_total = _progress_int(
        last_progress_total,
        field="last_progress_total",
        default_value=0,
        log_error=log_error,
    )
    safe_last_log_time = _progress_float(
        last_log_time,
        field="last_log_time",
        default_value=0.0,
        minimum=0.0,
        log_error=log_error,
    )
    safe_now = _progress_float(now, field="now", default_value=safe_last_log_time, minimum=0.0, log_error=log_error)
    safe_progress_every = _progress_float(
        progress_every,
        field="progress_every",
        default_value=10.0,
        minimum=0.0,
        log_error=log_error,
    )
    if safe_now - safe_last_log_time < max(15.0, safe_progress_every):
        return InMemoryProgressLogState(safe_last_progress_total, safe_last_log_time, emitted=False)

    safe_completed = _progress_int(
        completed,
        field="completed",
        default_value=safe_last_progress_total,
        log_error=log_error,
    )
    if safe_completed != safe_last_progress_total:
        safe_active_count = _progress_int(active_count, field="active_count", default_value=0, log_error=log_error)
        safe_pending_count = _progress_int(pending_count, field="pending_count", default_value=0, log_error=log_error)
        safe_total_files = _progress_int(total_files, field="total_files", default_value=0, log_error=log_error)
        safe_live_workers = _progress_int(live_workers, field="live_workers", default_value=0, log_error=log_error)
        inflight = _progress_int(
            logical_inflight_count,
            field="logical_inflight_count",
            default_value=safe_active_count,
            log_error=log_error,
        )
        queued_unstarted = _progress_int(
            queued_unstarted_count,
            field="queued_unstarted_count",
            default_value=0,
            log_error=log_error,
        )
        logger.info(
            'bulk scan inmemory progress: files_done=%s/%s files_active=%s files_pending=%s in_flight=%s queued_unstarted=%s live_workers=%s',
            safe_completed,
            safe_total_files,
            safe_active_count,
            safe_pending_count,
            inflight,
            queued_unstarted,
            safe_live_workers,
        )
        safe_last_progress_total = safe_completed
    return InMemoryProgressLogState(safe_last_progress_total, safe_now, emitted=True)
