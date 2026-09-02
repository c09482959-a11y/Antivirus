"""Recovery/progress helpers for raw queue scheduler.

These helpers own recovery progress accounting that used to live inside the
raw queue monolith.  They are dependency-injected so recovery decisions remain
replay-visible and testable without shared-state hydration.
"""
from __future__ import annotations

from typing import Callable, TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_int, scheduler_path_text
from Virus_Scan.scheduler.queue.raw_queue_recovery_evidence import (
    RawStageProgressCountEvidence,
    RawStageProgressPathKey,
    RawStageProgressStateEvidence,
)

if TYPE_CHECKING:
    from collections.abc import MutableMapping

_COUNT_KEYS = ("raw_pending", "raw_active", "raw_done", "raw_failed")


def _path_key(value: object, report: Callable[[str, BaseException], None]) -> RawStageProgressPathKey:
    text, reason = scheduler_path_text(value)
    if reason == "" and text != "":
        return RawStageProgressPathKey(text, available=True)
    rejection_reason = reason or "raw_stage_progress_queue_dir_missing"
    report("raw_stage_progress_queue_dir_rejected", ValueError(rejection_reason))
    return RawStageProgressPathKey("", available=False, reason=rejection_reason)


def _raw_count_total(counts: object, report: Callable[[str, BaseException], None]) -> RawStageProgressCountEvidence:
    items = no_hook_mapping_items(counts, allow_dict_subclass=True)
    if items is None:
        reason = "raw_stage_progress_counts_rejected"
        report("raw_stage_progress_count_failed", TypeError(reason))
        return RawStageProgressCountEvidence(0, available=False, reason=reason)
    total = 0
    rejected_fields: list[str] = []
    for key, value in items:
        if type(key) is not str or str.__str__(key) not in _COUNT_KEYS:
            continue
        parsed, reason = scheduler_int(value, default=0, minimum=0, reason="raw_stage_progress_count_rejected")
        if reason == "":
            total += parsed
        else:
            rejected_fields.append(str.__str__(key))
    if rejected_fields:
        return RawStageProgressCountEvidence(total, available=False, reason="raw_stage_progress_count_rejected")
    return RawStageProgressCountEvidence(total, available=True)



def _last_state(state: object, key: str, now: float, report: Callable[[str, BaseException], None]) -> RawStageProgressStateEvidence:
    if type(state) is not dict:
        reason = "raw_stage_progress_state_rejected"
        report(reason, TypeError(reason))
        return RawStageProgressStateEvidence(None, now, available=False, reason=reason)
    previous = dict.get(state, key, (None, now))
    if type(previous) is not tuple or len(previous) != 2:
        return RawStageProgressStateEvidence(None, now, available=True, reason="raw_stage_progress_previous_state_rejected")
    previous_count, previous_time = previous
    last_count = previous_count if type(previous_count) is int and type(previous_count) is not bool else None
    last_time, reason = scheduler_float(previous_time, default=now, minimum=0.0, reason="raw_stage_progress_last_time_rejected")
    if reason != "":
        last_time = now
    return RawStageProgressStateEvidence(last_count, last_time, available=True, reason=reason)


def raw_stage_progress_recent(
    queue_dir: object,
    quiet_sec: float | None = None,
    *,
    progress_counts: Callable[[object], object],
    queue_now: Callable[[], float],
    state: MutableMapping[str, tuple[int | None, float]],
    report: Callable[[str, BaseException], None],
    default_quiet_sec: Callable[[], object] | None = None,
) -> bool:
    """Return True when raw-stage queue accounting changed recently."""
    configured_quiet = quiet_sec
    if configured_quiet is None and default_quiet_sec is not None:
        configured_quiet = default_quiet_sec()
    quiet, quiet_reason = scheduler_float(
        configured_quiet if configured_quiet is not None else 120.0,
        default=120.0,
        minimum=15.0,
        reason="raw_stage_progress_quiet_rejected",
    )
    if quiet_reason != "":
        report("raw_stage_progress_quiet_invalid", ValueError(quiet_reason))
    key_evidence = _path_key(queue_dir, report)
    if not key_evidence.available:
        return True
    key = key_evidence.key
    try:
        raw_count_evidence = _raw_count_total(progress_counts(queue_dir), report)
        raw_accounted = raw_count_evidence.total
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        report("raw_stage_progress_count_failed", exc)
        raw_accounted = 0
    now, now_reason = scheduler_float(queue_now(), default=0.0, minimum=0.0, reason="raw_stage_progress_now_rejected")
    if now_reason != "":
        report("raw_stage_progress_now_invalid", ValueError(now_reason))
    previous = _last_state(state, key, now, report)
    if not previous.available:
        return True
    last_count, last_time = previous.previous_count, previous.previous_time
    if last_count is None or raw_accounted != last_count:
        state[key] = (raw_accounted, now)
        return True
    state[key] = (raw_accounted, last_time)
    return (now - last_time) < quiet
