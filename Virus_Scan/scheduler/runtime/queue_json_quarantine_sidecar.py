"""Bounded quarantine sidecar publication for scheduler queue JSON."""
from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Callable

from Virus_Scan.runtime.api import flush_open_writable_file
from Virus_Scan.scheduler.runtime.queue_json_common import QUEUE_JSON_EXCEPTIONS

_SIDE_CAR_ATTEMPTS = 8


def queue_quarantine_sidecar_target(
    dest: object,
    *,
    filesystem_path_func: Callable[[object], tuple[object, str | None]],
    record_degraded: Callable[..., object],
) -> Path | None:
    """Materialize a quarantine sidecar target without caller-owned hooks."""

    filesystem_path, path_reason = filesystem_path_func(dest)
    if path_reason:
        record_degraded(
            "queue_quarantine_sidecar_path_rejected",
            ValueError(path_reason),
            domain="scheduler",
        )
        return None
    return Path(filesystem_path)


def queue_quarantine_sidecar_candidate(target: Path, attempt: int) -> Path:
    """Return the bounded sidecar candidate path for an attempt."""

    base = target.with_name(target.name + ".qmeta")
    if attempt == 0:
        return base
    return target.with_name(target.name + ".qmeta." + int.__str__(attempt).zfill(2))


def queue_quarantine_sidecar_write_once(
    meta_path: Path,
    payload: object,
) -> bool | None:
    """Write one sidecar candidate, returning None when the candidate exists."""

    try:
        if meta_path.exists():
            return None
        with open(meta_path, "x", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            handle.flush()
            flush_open_writable_file(handle.fileno())
        return True
    except FileExistsError:
        return None


def queue_quarantine_sidecar_write_failed(
    meta_path: Path,
    exc: BaseException,
    *,
    attempt: int,
    safe_unlink: object,
    record_degraded: Callable[..., object],
) -> None:
    """Clean and record one failed sidecar write attempt."""

    try:
        safe_unlink(meta_path, log_context="queue_quarantine_sidecar_failed")
    except QUEUE_JSON_EXCEPTIONS as cleanup_exc:
        record_degraded("queue_quarantine_sidecar_cleanup_failed", cleanup_exc, domain="scheduler")
    record_degraded("queue_quarantine_sidecar_write_failed", exc, domain="scheduler")
    time.sleep(0.01 * (attempt + 1))


def queue_quarantine_sidecar_write_candidates(
    target: Path,
    payload: object,
    *,
    safe_unlink: object,
    record_degraded: Callable[..., object],
) -> bool:
    """Try bounded quarantine sidecar candidate paths."""

    for attempt in range(_SIDE_CAR_ATTEMPTS):
        meta_path = queue_quarantine_sidecar_candidate(target, attempt)
        try:
            result = queue_quarantine_sidecar_write_once(meta_path, payload)
        except (PermissionError, OSError) as exc:
            queue_quarantine_sidecar_write_failed(
                meta_path,
                exc,
                attempt=attempt,
                safe_unlink=safe_unlink,
                record_degraded=record_degraded,
            )
            continue
        except QUEUE_JSON_EXCEPTIONS as exc:
            record_degraded("queue_quarantine_sidecar_write_failed", exc, domain="scheduler")
            return False
        if result is True:
            return True
    return False


def queue_write_quarantine_sidecar_with_dependencies(
    dest: object,
    meta: object,
    *,
    filesystem_path_func: Callable[[object], tuple[object, str | None]],
    make_safe_func: Callable[[object], object],
    safe_unlink: object,
    record_degraded: Callable[..., object],
) -> bool:
    """Publish queue quarantine sidecar metadata through explicit dependencies."""

    try:
        target = queue_quarantine_sidecar_target(
            dest,
            filesystem_path_func=filesystem_path_func,
            record_degraded=record_degraded,
        )
        if target is None:
            return False
        payload = make_safe_func(meta)
        return queue_quarantine_sidecar_write_candidates(
            target,
            payload,
            safe_unlink=safe_unlink,
            record_degraded=record_degraded,
        )
    except QUEUE_JSON_EXCEPTIONS as exc:
        record_degraded("queue_quarantine_sidecar_failed", exc, domain="scheduler")
        return False
