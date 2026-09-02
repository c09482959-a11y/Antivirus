"""Worker-target backpressure calculations owned by scheduler runtime."""
from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.contracts.env_config import int_env
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float
from Virus_Scan.scheduler.runtime.backpressure_worker_target_rules import (
    cpu_pressure_worker_target,
    io_pressure_worker_target,
    nonnegative_raw_live,
    positive_worker_count,
    raw_live_cap_thresholds,
    raw_live_worker_target,
)
from Virus_Scan.scheduler.runtime.optional_psutil import psutil

_UNAVAILABLE_CPU_PERCENT = None


def elastic_target_workers(
    cpu_pct: object,
    io_pressure: object,
    raw_live: object = 0,
    max_workers: object = 100,
) -> int:
    """Resource-profile-aware CPU/I-O/raw-pressure scaling curve."""

    try:
        max_workers_int = positive_worker_count(max_workers, default=100)
    except RECOVERABLE_RUNTIME_ERRORS:
        max_workers_int = 100
    try:
        raw_live_int = nonnegative_raw_live(raw_live)
    except RECOVERABLE_RUNTIME_ERRORS:
        raw_live_int = 0
    io_pressure_is_active = (
        io_pressure
        if type(io_pressure) is bool
        else type(io_pressure) is int and io_pressure != 0
    )
    if io_pressure_is_active:
        return io_pressure_worker_target(max_workers=max_workers_int)
    target = raw_live_worker_target(
        raw_live_int,
        max_workers=max_workers_int,
        thresholds=raw_live_cap_thresholds(),
    )
    if target is not None:
        return target
    try:
        if cpu_pct is None:
            cpu_pct_float = None
        else:
            cpu_pct_float, _cpu_pct_reason = scheduler_float(
                cpu_pct,
                default=0.0,
                minimum=0.0,
                reason="scheduler_backpressure_float_rejected",
            )
    except RECOVERABLE_RUNTIME_ERRORS:
        cpu_pct_float = None
    return cpu_pressure_worker_target(cpu_pct_float, max_workers=max_workers_int)


def smooth_worker_target(prev: object, target: object) -> object:
    """Hysteresis: resource-profile-aware scale-up/down smoothing."""
    try:
        target = positive_worker_count(target, default=1)
    except RECOVERABLE_RUNTIME_ERRORS:
        target = 1
    try:
        if prev is None:
            return target
        prev = positive_worker_count(prev, default=1)
    except RECOVERABLE_RUNTIME_ERRORS:
        return target
    try:
        up_step = int_env("UMIGE_ELASTIC_SCALE_UP_STEP", 20, 1, None)
        down_step = int_env("UMIGE_ELASTIC_SCALE_DOWN_STEP", 10, 1, None)
    except RECOVERABLE_RUNTIME_ERRORS:
        up_step, down_step = (20, 10)
    if target > prev:
        return min(target, prev + max(1, up_step))
    if target < prev:
        return max(target, prev - max(1, down_step))
    return target


def cpu_percent_sample() -> object:
    try:
        cpu_percent, _cpu_percent_reason = scheduler_float(
            psutil.cpu_percent(interval=None),
            default=0.0,
            minimum=0.0,
            reason="scheduler_backpressure_float_rejected",
        )
        return cpu_percent
    except RECOVERABLE_RUNTIME_ERRORS:
        return _UNAVAILABLE_CPU_PERCENT


def io_adjusted_elastic_target(
    process_count: object,
    requested_process_count: object,
    queue_dir: object = None,
) -> tuple[int, object, MappingProxyType]:
    """Return an immutable execution backpressure snapshot."""
    del queue_dir
    try:
        process_count = positive_worker_count(
            process_count,
            default=positive_worker_count(requested_process_count, default=1),
        )
    except RECOVERABLE_RUNTIME_ERRORS:
        process_count = 1
    cpu = cpu_percent_sample()
    io_sample = MappingProxyType({"pressure": False})
    raw_live = 0
    io_pressure_sample = io_sample.get("pressure")
    target = elastic_target_workers(
        cpu,
        io_pressure=(
            io_pressure_sample
            if type(io_pressure_sample) is bool
            else type(io_pressure_sample) is int and io_pressure_sample != 0
        ),
        raw_live=raw_live,
        max_workers=process_count,
    )
    try:
        target_int = positive_worker_count(target, default=1)
    except RECOVERABLE_RUNTIME_ERRORS:
        target_int = 1
    return (max(1, min(process_count, target_int)), cpu, io_sample)


def dynamic_process_queue_target(
    process_count: object,
    requested_process_count: object,
) -> object:
    """Return immutable dynamic queue-feed target owned by execution backpressure."""
    try:
        process_count = positive_worker_count(
            process_count,
            default=positive_worker_count(requested_process_count, default=1),
        )
    except RECOVERABLE_RUNTIME_ERRORS:
        process_count = 1
    cpu = cpu_percent_sample()
    target = elastic_target_workers(
        cpu,
        io_pressure=False,
        raw_live=0,
        max_workers=process_count,
    )
    try:
        target_int = positive_worker_count(target, default=1)
    except RECOVERABLE_RUNTIME_ERRORS:
        target_int = 1
    return (max(1, min(process_count, target_int)), cpu)


__all__ = (
    "cpu_percent_sample",
    "dynamic_process_queue_target",
    "elastic_target_workers",
    "io_adjusted_elastic_target",
    "smooth_worker_target",
)
