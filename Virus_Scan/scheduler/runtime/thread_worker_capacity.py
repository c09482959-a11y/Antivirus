"""Runtime-owned in-memory worker thread capacity calculations."""
from __future__ import annotations

import os

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_value
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_int
from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot

_THREAD_CAPACITY_MISSING = object()

def _record_thread_capacity_rejection(reason: str, value: object, *, field_name: str) -> None:
    try:
        record_suppressed_failure("scheduler_worker_thread_capacity_rejected", ValueError(reason), domain="scheduler", context={"field_name": field_name, "value_type": type(value).__name__})
    except RECOVERABLE_RUNTIME_ERRORS as reporting_exc:
        _ = reporting_exc

def _owned_mapping_value(mapping: object, key: str) -> object:
    value = _THREAD_CAPACITY_MISSING
    if mapping is not None:
        try:
            value = scheduler_mapping_value(immutable_mapping(mapping), key, default=_THREAD_CAPACITY_MISSING)
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            _record_thread_capacity_rejection("scheduler_worker_thread_mapping_rejected", exc, field_name=key)
    return value

def _scheduler_int_value(value: object, *, default_value: int, minimum: int = 1, maximum: int | None = None, field_name: str = "thread_capacity") -> int:
    parsed, reason = scheduler_int(value, default=default_value, minimum=minimum, maximum=maximum, reason="scheduler_worker_thread_integer_rejected")
    chosen = parsed
    if reason:
        _record_thread_capacity_rejection(reason, value, field_name=field_name)
        chosen = default_value
    return max(minimum, chosen if maximum is None else min(chosen, maximum))

def _thread_capacity_value(cfg: object, env: object, cfg_key: str, env_key: str, default_value: int) -> int:
    source = scheduler_environment_snapshot(env)
    hard = 16 if os.name == "nt" else 32
    cfg_value = _owned_mapping_value(cfg, cfg_key)
    value = cfg_value if cfg_value is not _THREAD_CAPACITY_MISSING and cfg_value is not None else scheduler_mapping_value(source, env_key, default=default_value)
    return _scheduler_int_value(value, default_value=default_value, minimum=1, maximum=hard, field_name=env_key)

def inmemory_worker_thread_count(cfg: object=None, *, env: object=None) -> int:
    return _thread_capacity_value(cfg, env, "worker_threads", "UMIGE_INMEMORY_WORKER_THREADS_PER_PROCESS", 4)

def inmemory_worker_thread_max(cfg: object=None, *, env: object=None) -> int:
    return _thread_capacity_value(cfg, env, "worker_threads_max", "UMIGE_INMEMORY_WORKER_THREADS_MAX_PER_PROCESS", 8)

def _cpu_scaled_choice(cpu: object, *, has_backlog: bool, base: int, max_threads: int) -> int:
    if not has_backlog:
        return base
    if cpu is None:
        return max_threads
    if type(cpu) is int and type(cpu) is not bool:
        cpu_f = cpu + 0.0
    elif type(cpu) is float:
        cpu_f = cpu
    else:
        return base
    if cpu_f < 55.0:
        return max_threads
    if cpu_f < 70.0:
        return min(max_threads, max(base + 4, max_threads - 2))
    if cpu_f < 85.0:
        return min(max_threads, base + 2)
    if cpu_f < 94.0:
        return min(max_threads, base + 1)
    return base

def inmemory_adaptive_worker_thread_count(base_threads: object=None, *, workers: object=1, total_files: object=0, env: object=None) -> object:
    source = scheduler_environment_snapshot(env)
    default_base = inmemory_worker_thread_count(env=source)
    base = default_base if base_threads is None else _scheduler_int_value(base_threads, default_value=default_base, minimum=1, field_name="base_threads")
    max_threads = inmemory_worker_thread_max(env=source)
    adaptive_raw = scheduler_mapping_value(source, "UMIGE_INMEMORY_ADAPTIVE_WORKER_THREADS", default="1")
    adaptive, adaptive_reason = scheduler_bool(adaptive_raw, default=True, reason="scheduler_worker_thread_bool_rejected")
    if adaptive_reason:
        adaptive = True
    if adaptive is not True:
        return (max(1, min(base, max_threads)), None)
    try:
        cpu = None
        mem_snap = {}
        pressure_value = dict.get(mem_snap, "pressure")
        mem_pressure = str.__str__(pressure_value) if type(pressure_value) is str and str.__str__(pressure_value) else "unknown"
        worker_count = _scheduler_int_value(workers, default_value=1, minimum=1, field_name="workers")
        total_count = _scheduler_int_value(total_files, default_value=0, minimum=0, field_name="total_files")
        chosen = _cpu_scaled_choice(cpu, has_backlog=total_count > max(1, worker_count * max(1, base)), base=base, max_threads=max_threads)
        if mem_pressure == "critical":
            chosen = max(1, min(chosen, max(2, base // 2)))
        elif mem_pressure == "high":
            chosen = max(1, min(chosen, max(base, 2)))
    except RECOVERABLE_RUNTIME_ERRORS:
        chosen, mem_pressure, mem_snap, cpu = base, "unknown", {}, None
    diag = cpu
    try:
        if mem_pressure not in {"low", "unknown"}:
            available_mb = _scheduler_int_value(dict.get(mem_snap, "available_mb"), default_value=0, minimum=0, field_name="available_mb")
            cpu_text = "n/a" if cpu is None else (int.__str__(cpu) if type(cpu) is int and type(cpu) is not bool else float.__str__(cpu) if type(cpu) is float else "unknown")
            diag = cpu_text + " mem=" + mem_pressure + " avail=" + int.__str__(available_mb) + "MB"
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        try:
            record_suppressed_failure("suppressed_exception", exc, domain="runtime")
        except RECOVERABLE_RUNTIME_ERRORS as reporting_exc:
            _ = reporting_exc
    return (max(1, min(chosen, max_threads)), diag)

__all__ = ("inmemory_adaptive_worker_thread_count", "inmemory_worker_thread_count", "inmemory_worker_thread_max")
