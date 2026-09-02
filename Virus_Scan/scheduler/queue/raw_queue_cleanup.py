"""Canonical cleanup helpers for raw queue lifecycle artifacts.

These helpers own diagnostic tmp cleanup and orphan claim sidecar cleanup so
cleanup and reclaim lifecycle policy remains inside reconciliation ownership.
"""
from __future__ import annotations

import os
import time
from pathlib import Path


from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_int
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import queue_listdir_names
from Virus_Scan.scheduler.queue.raw_queue_path_support import raw_queue_path_extra
from Virus_Scan.scheduler.queue.raw_queue_cleanup_evidence import (
    raw_queue_cleanup_name_decision,
    raw_queue_cleanup_path_decision,
    raw_queue_diagnostic_cleanup_decision,
)



def _safe_cleanup_path(value: object) -> Path | None:
    return raw_queue_cleanup_path_decision(value).path


def _sorted_cleanup_names(listed: object, *, field_name: str) -> tuple[str, ...]:
    names = []
    for value in listed:
        text = raw_queue_cleanup_name_decision(value, field_name=field_name).text
        if text:
            names.append(text)
    return tuple(sorted(names))


def cleanup_diagnostic_tmp_files(queue_dir: object, *, failure_diagnostics_dir: object, safe_listdir: object, safe_unlink: object, report: object, max_age_sec: object=600.0, recoverable_exceptions: object=(OSError, RuntimeError, TypeError, ValueError)) -> object:
    """Remove stale diagnostic .tmp files with explicit queue telemetry."""
    removed = 0
    max_age, max_age_reason = scheduler_float(max_age_sec, default=600.0, minimum=0.0, reason="queue_diagnostic_tmp_max_age_rejected")
    if max_age_reason:
        max_age = 600.0
    try:
        raw_dir = failure_diagnostics_dir(queue_dir)
        d = _safe_cleanup_path(raw_dir)
        if d is None:
            report("queue_diagnostic_tmp_cleanup_failed", TypeError("queue diagnostic directory rejected"), fatal=False, extra=raw_queue_path_extra("queue_dir", raw_dir))
            return raw_queue_diagnostic_cleanup_decision(removed, completed=False, reason="queue_diagnostic_directory_rejected")
        now = time.time()
        listed = queue_listdir_names(safe_listdir(d), context=d)
        for name in _sorted_cleanup_names(listed, field_name="queue_diagnostic_tmp_name"):
            if not name.endswith(".tmp"):
                continue
            p = d / name
            try:
                age = now - os.path.getmtime(Path.as_posix(p))
            except recoverable_exceptions as exc:
                report("queue_diagnostic_tmp_age_failed", exc, fatal=False, extra=raw_queue_path_extra("path", p))
                age = max_age + 1.0
            if age >= max_age:
                try:
                    unlink_result = safe_unlink(p, log_context="queue_unlink")
                    if unlink_result is True:
                        removed += 1
                except OSError as exc:
                    report("queue_diagnostic_tmp_cleanup_failed", exc, fatal=False, extra=raw_queue_path_extra("path", p))
        return raw_queue_diagnostic_cleanup_decision(removed, completed=True, reason="queue_diagnostic_tmp_cleanup_completed")
    except recoverable_exceptions as exc:
        report("queue_diagnostic_tmp_cleanup_failed", exc, fatal=False, extra=raw_queue_path_extra("queue_dir", queue_dir))
        return raw_queue_diagnostic_cleanup_decision(removed, completed=False, reason="queue_diagnostic_tmp_cleanup_failed")


def cleanup_orphan_claim_meta(active_dir: object, *, safe_listdir: object, safe_unlink: object, queue_now: object, report: object, max_remove: object=512, min_age_sec: object=0.0) -> object:
    """Remove active/*.json.claim sidecars that no longer have active/*.json."""
    removed = 0
    max_remove_value, max_remove_reason = scheduler_int(max_remove, default=512, minimum=0, reason="queue_orphan_claim_meta_max_remove_rejected")
    if max_remove_reason:
        max_remove_value = 0
    min_age_value, min_age_reason = scheduler_float(min_age_sec, default=0.0, minimum=0.0, reason="queue_orphan_claim_meta_min_age_rejected")
    if min_age_reason:
        min_age_value = 0.0
    try:
        d = _safe_cleanup_path(active_dir)
        if d is None:
            report("queue_orphan_claim_meta_cleanup_failed", TypeError("queue active directory rejected"), fatal=False, extra=raw_queue_path_extra("active_dir", active_dir))
            return removed
        raw_now = queue_now()
        now, now_reason = scheduler_float(raw_now, default=0.0, minimum=0.0, reason="queue_orphan_claim_meta_now_rejected")
        if now_reason:
            now = 0.0
        listed = queue_listdir_names(safe_listdir(d), context=d)
        for name in _sorted_cleanup_names(listed, field_name="queue_orphan_claim_meta_name"):
            if removed >= max_remove_value:
                break
            if not name.endswith(".json.claim"):
                continue
            mp = d / name
            base = d / name[:-6]
            try:
                if base.exists():
                    continue
            except OSError as exc:
                report("queue_orphan_claim_meta_base_exists_failed", exc, fatal=False, extra=raw_queue_path_extra("path", base))
                continue
            if min_age_value > 0.0:
                try:
                    mtime, mtime_reason = scheduler_float(os.path.getmtime(Path.as_posix(mp)), default=now, minimum=0.0, reason="queue_orphan_claim_meta_mtime_rejected")
                    if mtime_reason:
                        report("queue_orphan_claim_meta_age_failed", ValueError(mtime_reason), fatal=False, extra=raw_queue_path_extra("path", mp))
                        continue
                    age = max(0.0, now - mtime)
                    if age < min_age_value:
                        continue
                except (OSError, TypeError, ValueError, OverflowError) as exc:
                    report("queue_orphan_claim_meta_age_failed", exc, fatal=False, extra=raw_queue_path_extra("path", mp))
                    continue
            removed_ok = safe_unlink(mp, retries=3, delay=0.01, log_context="queue_orphan_claim_meta_cleanup")
            if removed_ok is True:
                removed += 1
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        report("queue_orphan_claim_meta_cleanup_failed", exc, fatal=False, extra=raw_queue_path_extra("active_dir", active_dir))
    return removed
