"""Deterministic hybrid queue state ownership for raw queue accounting.

Hybrid counts are owned by the queue directory itself, not by a module-global
cache.  Each operation reads or replaces the queue-local JSON snapshot using an
atomic write, which keeps process and thread accounting explicit and replayable.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Callable, Mapping, Optional

from Virus_Scan.contracts.no_hook_materialization import (
    exact_finite_float_or_none,
    no_hook_text,
)
from Virus_Scan.runtime.api import durable_replace_regular_file, flush_open_writable_file
from Virus_Scan.scheduler.api.contracts import HybridQueueStateError
from Virus_Scan.scheduler.internal.immutable_output_support import FrozenSchedulerMapping, frozen_scheduler_items_decision
from Virus_Scan.scheduler.replay.replay_snapshot_evidence import (
    hybrid_count_value_decision,
    hybrid_counts_items_decision,
    hybrid_snapshot_read_missing_decision,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_filesystem_path, scheduler_path_text

_STATE_FILE_NAME = "hybrid_queue_state.json"
_NO_HYBRID_SNAPSHOT: Optional[FrozenSchedulerMapping] = None
_INVALID_HYBRID_QUEUE_DIRECTORY = "invalid hybrid queue directory"
_INVALID_HYBRID_QUEUE_COUNT_KEY = "invalid hybrid queue count key"
_INVALID_HYBRID_QUEUE_DELTA_SNAPSHOT = "invalid hybrid queue delta snapshot"
_INVALID_HYBRID_QUEUE_MAX_AGE = "invalid hybrid queue max age"
_INVALID_HYBRID_QUEUE_STATE_FILE = "invalid hybrid queue state file"
_INVALID_HYBRID_QUEUE_STATE_PAYLOAD = "invalid hybrid queue state payload"
_FAILED_TO_WRITE_AND_CLEAN_HYBRID_QUEUE_STATE = "failed to write and clean hybrid queue state"
_FAILED_TO_WRITE_HYBRID_QUEUE_STATE = "failed to write hybrid queue state"



def _hybrid_state_error(prefix: str, path: object) -> str:
    text, reason = scheduler_path_text(path)
    path_text = text if reason == "" and text else "hybrid_queue_state_path_unavailable"
    return str.__str__(prefix) + ": " + path_text


def hybrid_queue_key(queue_dir: object) -> str:
    queue_path, reason = scheduler_filesystem_path(queue_dir)
    if reason or (type(queue_path) is str and queue_path == ""):
        reason_text = str.__str__(reason) if type(reason) is str and reason else "scheduler_path_missing"
        raise HybridQueueStateError(_INVALID_HYBRID_QUEUE_DIRECTORY + ":" + reason_text)
    try:
        return os.path.abspath(queue_path)
    except (TypeError, ValueError, OSError) as exc:
        raise HybridQueueStateError(_INVALID_HYBRID_QUEUE_DIRECTORY) from exc



def validate_hybrid_counts(counts: Optional[Mapping[str, object]]) -> FrozenSchedulerMapping:
    items: list[tuple[str, int]] = []
    for key, value in hybrid_counts_items_decision(counts).items:
        text, reason = no_hook_text(
            key,
            missing_reason="missing_hybrid_queue_count_key",
            unsupported_reason="invalid_hybrid_queue_count_key",
        )
        if reason != "" or text == "":
            raise HybridQueueStateError(_INVALID_HYBRID_QUEUE_COUNT_KEY)
        items.append((text, hybrid_count_value_decision(value).value))
    return FrozenSchedulerMapping(tuple(sorted(items)))


def _read_snapshot(queue_dir: object) -> Mapping[str, object] | None:
    path = Path(hybrid_queue_key(queue_dir)) / _STATE_FILE_NAME
    if not path.exists():
        return hybrid_snapshot_read_missing_decision(path).snapshot
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise HybridQueueStateError(_hybrid_state_error(_INVALID_HYBRID_QUEUE_STATE_FILE, path)) from exc
    if type(data) is not dict:
        raise HybridQueueStateError(_hybrid_state_error(_INVALID_HYBRID_QUEUE_STATE_PAYLOAD, path))
    return data


def _write_snapshot(queue_dir: object, counts: Mapping[str, object]) -> None:
    path = Path(hybrid_queue_key(queue_dir)) / _STATE_FILE_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"time": time.time(), "counts": dict(validate_hybrid_counts(counts))}
    tmp = path.with_name(path.name + "." + int.__str__(os.getpid()) + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, sort_keys=True, separators=(",", ":"))
            fh.flush()
            flush_open_writable_file(fh.fileno())
        durable_replace_regular_file(tmp, path)
    except OSError as exc:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError as cleanup_exc:
            raise HybridQueueStateError(_hybrid_state_error(_FAILED_TO_WRITE_AND_CLEAN_HYBRID_QUEUE_STATE, path)) from cleanup_exc
        raise HybridQueueStateError(_hybrid_state_error(_FAILED_TO_WRITE_HYBRID_QUEUE_STATE, path)) from exc


def hybrid_queue_state_delta(queue_dir: object, *, report: Callable[[str, BaseException], None] | None = None, **delta: object) -> None:
    """Apply all count deltas transactionally or report the invalid snapshot."""
    try:
        clean_delta = validate_hybrid_counts(delta)
        snapshot = _read_snapshot(queue_dir) or {"counts": {}}
        base = dict(validate_hybrid_counts(snapshot.get("counts")))
        clean_decision = frozen_scheduler_items_decision(clean_delta)
        if not clean_decision.accepted:
            raise HybridQueueStateError(_INVALID_HYBRID_QUEUE_DELTA_SNAPSHOT)
        for key, value in clean_decision.items:
            base[key] = max(
                0,
                hybrid_count_value_decision(base.get(key, 0)).value
                + hybrid_count_value_decision(value).value,
            )
        _write_snapshot(queue_dir, FrozenSchedulerMapping(tuple(sorted(dict.items(base)))))
    except HybridQueueStateError as exc:
        if report is not None:
            report("hybrid_queue_state_delta_invalid", exc)


def hybrid_queue_state_get(
    queue_dir: object,
    *,
    max_age_sec: float = 2.0,
    report: Callable[[str, BaseException], None] | None = None,
) -> Optional[FrozenSchedulerMapping]:
    """Return a deterministic count snapshot or None when unavailable/invalid."""
    try:
        if max_age_sec is None:
            max_age = 0.0
        else:
            max_age = exact_finite_float_or_none(max_age_sec)
            if max_age is None:
                raise TypeError(_INVALID_HYBRID_QUEUE_MAX_AGE)
        snapshot = _read_snapshot(queue_dir)
        if not snapshot:
            return _NO_HYBRID_SNAPSHOT
        snapshot_time = exact_finite_float_or_none(snapshot.get("time", 0.0))
        if snapshot_time is None:
            return _NO_HYBRID_SNAPSHOT
        if time.time() - snapshot_time > max_age:
            return _NO_HYBRID_SNAPSHOT
        return validate_hybrid_counts(snapshot.get("counts"))
    except (HybridQueueStateError, TypeError, ValueError, OverflowError) as exc:
        if report is not None:
            report("hybrid_queue_state_get_invalid", exc)
        return _NO_HYBRID_SNAPSHOT


def hybrid_queue_state_set(queue_dir: object, counts: Optional[Mapping[str, object]], *, report: Callable[[str, BaseException], None] | None = None) -> None:
    """Replace queue counts atomically with a validated snapshot."""
    try:
        _write_snapshot(queue_dir, validate_hybrid_counts(counts))
    except HybridQueueStateError as exc:
        if report is not None:
            report("hybrid_queue_state_set_invalid", exc)
