"""Memory-pressure snapshot helpers owned by scheduler runtime backpressure."""
from __future__ import annotations

import os
from types import MappingProxyType

from Virus_Scan.contracts.env_config import float_env
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_int, scheduler_text
from Virus_Scan.scheduler.runtime.execution_memory_capacity import execution_memory_snapshot

_UNKNOWN_PRESSURE = "unknown"
_MIB = 1024.0 * 1024.0


def _tuple_float_field(value: object, index: int) -> float:
    if isinstance(value, tuple) and index < tuple.__len__(value):
        safe, _reason = scheduler_float(tuple.__getitem__(value, index), default=0.0, minimum=0.0, reason="scheduler_backpressure_float_rejected")
        return safe
    return 0.0


def cpu_count_safe(default: object=4) -> object:
    fallback, _reason = scheduler_int(default, default=4, minimum=1, reason="scheduler_backpressure_integer_rejected")
    try:
        safe, _safe_reason = scheduler_int(os.cpu_count(), default=fallback, minimum=1, reason="scheduler_backpressure_integer_rejected")
        return safe
    except RECOVERABLE_RUNTIME_ERRORS:
        return fallback


def memory_pressure_snapshot() -> object:
    """Return pressure from the same execution-memory boundary used for process admission."""
    snap = {"available_mb": None, "percent": None, "rss_mb": None, "pressure": _UNKNOWN_PRESSURE, "source": "unavailable"}
    try:
        execution = execution_memory_snapshot()
        snap["source"] = execution.source
        if execution.bounded and execution.limit_bytes > 0:
            snap["available_mb"] = execution.available_bytes / _MIB
            snap["percent"] = max(0.0, min(100.0, 100.0 * execution.current_bytes / execution.limit_bytes))
        if execution.parent_rss_bytes >= 0:
            snap["rss_mb"] = execution.parent_rss_bytes / _MIB
        avail, pct = snap["available_mb"], snap["percent"]
        if avail is not None and avail < float_env("UMIGE_MEM_CRITICAL_AVAILABLE_MB", 2048.0, 0.0, None):
            snap["pressure"] = "critical"
        elif pct is not None and pct >= float_env("UMIGE_MEM_HIGH_PERCENT", 88.0, 0.0, 100.0):
            snap["pressure"] = "high"
        elif avail is not None and avail < float_env("UMIGE_MEM_LOW_AVAILABLE_MB", 4096.0, 0.0, None):
            snap["pressure"] = "medium"
        else:
            snap["pressure"] = "low" if avail is not None or pct is not None else _UNKNOWN_PRESSURE
    except RECOVERABLE_RUNTIME_ERRORS:
        snap["pressure"] = _UNKNOWN_PRESSURE
    return MappingProxyType(dict(snap))


def memory_pressure_level(snapshot: object=None) -> object:
    try:
        snap = memory_pressure_snapshot() if snapshot is None else snapshot
        if type(snap) is dict:
            raw_pressure = dict.get(snap, "pressure", _UNKNOWN_PRESSURE)
        elif type(snap) is MappingProxyType:
            raw_pressure = snap.get("pressure", _UNKNOWN_PRESSURE)
        else:
            raw_pressure = _UNKNOWN_PRESSURE
        pressure, reason = scheduler_text(raw_pressure, replacement_text=_UNKNOWN_PRESSURE, unsupported_reason="scheduler_pressure_rejected")
        return pressure if reason == "" and pressure else _UNKNOWN_PRESSURE
    except RECOVERABLE_RUNTIME_ERRORS:
        return _UNKNOWN_PRESSURE


__all__ = ("cpu_count_safe", "memory_pressure_level", "memory_pressure_snapshot")
