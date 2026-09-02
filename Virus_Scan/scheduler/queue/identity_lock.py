"""Process-queue identity lock ownership.

Owns durable identity lock paths for queue admission. Returns immutable lock
acquisition/release outcomes only; it does not execute scans, reconcile queues,
or serialize evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import time
from dataclasses import dataclass
from pathlib import Path

from Virus_Scan.runtime.api import flush_open_writable_file

from Virus_Scan.scheduler.evidence.process_queue_errors import process_queue_record_suppressed as _process_queue_record_suppressed
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_filesystem_path
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_safe_unlink as _queue_safe_unlink
from Virus_Scan.scheduler.runtime.queue_json import make_json_safe

_RECOVERABLE_IDENTITY_LOCK_ERRORS = (OSError, RuntimeError, TypeError, ValueError)


@dataclass(frozen=True)
class IdentityLockAcquireDecision:
    acquired: bool
    lock_path: Path | None
    reason: str


@dataclass(frozen=True)
class IdentityLockReleaseDecision:
    released: bool
    reason: str




def queue_identity_lock_dir(queue_dir: object) -> Path:
    """Return the process-queue identity-lock directory owned by queue authority."""
    safe_queue_dir, queue_dir_reason = scheduler_filesystem_path(queue_dir)
    if queue_dir_reason:
        raise ValueError(queue_dir_reason)
    return Path(safe_queue_dir) / "identity_locks"


def acquire_identity_lock_decision(queue_dir: object, identity: object, *, stale_sec: float = 30.0) -> IdentityLockAcquireDecision:
    ident = identity if type(identity) is str else ""
    if ident == "" or ident.startswith(("invalid:", "file_incomplete:", "raw_incomplete:")):
        return IdentityLockAcquireDecision(acquired=False, lock_path=None, reason="process_queue_identity_lock_identity_rejected")
    lock_path: Path | None = None
    failed_reason = ""
    already_locked = False
    try:
        lock_dir = queue_identity_lock_dir(queue_dir)
        lock_dir.mkdir(parents=True, exist_ok=True)
        identity_token = hashlib.sha256(ident.encode("utf-8", "surrogatepass")).hexdigest()
        lock_path = lock_dir / (identity_token + ".lock")
        if type(stale_sec) is bool:
            stale_seconds, stale_reason = 30.0, "process_queue_identity_stale_seconds_rejected"
        elif type(stale_sec) is int:
            stale_seconds, stale_reason = float(stale_sec), ""
        elif type(stale_sec) is float:
            stale_seconds, stale_reason = stale_sec, ""
        else:
            stale_seconds, stale_reason = 30.0, "process_queue_identity_stale_seconds_rejected"
        if stale_reason == "" and (not math.isfinite(stale_seconds) or stale_seconds < 0.0):
            stale_seconds, stale_reason = 30.0, "process_queue_identity_stale_seconds_rejected"
        if stale_reason:
            _process_queue_record_suppressed(stale_reason, ValueError(stale_reason), extra={"identity": ident}, fatal=True)
            failed_reason = stale_reason
        elif lock_path.exists() and (time.time() - lock_path.stat().st_mtime) > stale_seconds:
            _queue_safe_unlink(lock_path, log_context="process_queue_identity_stale_lock_cleanup")
        if failed_reason == "":
            try:
                lock_stream = lock_path.open("x", encoding="utf-8")
            except FileExistsError:
                already_locked = True
            else:
                try:
                    with lock_stream as fh:
                        json.dump(make_json_safe({"identity": ident, "pid": os.getpid(), "time": time.time()}), fh, separators=(",", ":"), allow_nan=False)
                        fh.flush()
                        flush_open_writable_file(fh.fileno())
                except _RECOVERABLE_IDENTITY_LOCK_ERRORS:
                    _queue_safe_unlink(lock_path, log_context="process_queue_identity_lock_write_failed_cleanup")
                    raise
    except _RECOVERABLE_IDENTITY_LOCK_ERRORS as exc:
        _process_queue_record_suppressed("process_queue_identity_lock_failed_closed", exc, extra={"identity": ident}, fatal=True)
        failed_reason = "process_queue_identity_lock_failed_closed"
    if already_locked:
        return IdentityLockAcquireDecision(acquired=False, lock_path=None, reason="process_queue_identity_lock_already_locked")
    if failed_reason:
        return IdentityLockAcquireDecision(acquired=False, lock_path=None, reason=failed_reason)
    if lock_path is None:
        return IdentityLockAcquireDecision(acquired=False, lock_path=None, reason="process_queue_identity_lock_path_missing")
    return IdentityLockAcquireDecision(acquired=True, lock_path=lock_path, reason="process_queue_identity_lock_acquired")


def release_identity_lock_decision(lock_path: object, *, safe_unlink: object=_queue_safe_unlink, report_issue: object=_process_queue_record_suppressed) -> IdentityLockReleaseDecision:
    """Return the replayable release decision for a process-queue identity lock."""
    if lock_path is None or lock_path is False:
        return IdentityLockReleaseDecision(released=True, reason="process_queue_identity_lock_release_empty")
    if type(lock_path) is str and lock_path == "":
        return IdentityLockReleaseDecision(released=True, reason="process_queue_identity_lock_release_empty")
    release_failed = False
    released = False
    released_raw: object = False
    lock_path_failure_extra = {
        "lock_path_type": type(lock_path).__qualname__,
        "lock_path_module": type(lock_path).__module__,
    }
    try:
        released_raw = safe_unlink(lock_path, log_context="process_queue_identity_lock_release")
    except _RECOVERABLE_IDENTITY_LOCK_ERRORS as exc:
        report_issue("process_queue_identity_lock_release_failed", exc, extra=lock_path_failure_extra, fatal=True)
        release_failed = True
    if not release_failed:
        released, released_reason = scheduler_bool(released_raw, default=False, reason="process_queue_identity_lock_release_result_rejected")
        if released_reason:
            report_issue("process_queue_identity_lock_release_result_rejected", ValueError(released_reason), extra=lock_path_failure_extra, fatal=True)
            release_failed = True
    if release_failed:
        return IdentityLockReleaseDecision(released=False, reason="process_queue_identity_lock_release_failed")
    if not released:
        report_issue("process_queue_identity_lock_release_unsuccessful", RuntimeError("identity lock release returned false"), extra=lock_path_failure_extra, fatal=True)
        return IdentityLockReleaseDecision(released=False, reason="process_queue_identity_lock_release_unsuccessful")
    return IdentityLockReleaseDecision(released=True, reason="process_queue_identity_lock_released")


__all__ = (
    "IdentityLockAcquireDecision",
    "IdentityLockReleaseDecision",
    "acquire_identity_lock_decision",
    "queue_identity_lock_dir",
    "release_identity_lock_decision",
)
