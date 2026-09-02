"""Scheduler runtime backpressure policy ownership facade.

Concrete CPU/I/O target calculations and memory pressure sampling live in bounded
runtime-owned modules. This module preserves the existing public scheduler
runtime import surface without keeping mixed backpressure responsibilities in one
oversized file.
"""
from __future__ import annotations

from Virus_Scan.scheduler.runtime.backpressure_memory import (
    cpu_count_safe,
    memory_pressure_level,
    memory_pressure_snapshot,
)
from Virus_Scan.scheduler.runtime.backpressure_targets import (
    dynamic_process_queue_target,
    elastic_target_workers,
    io_adjusted_elastic_target,
    smooth_worker_target,
    cpu_percent_sample,
)

__all__ = (
    "cpu_count_safe",
    "cpu_percent_sample",
    "dynamic_process_queue_target",
    "elastic_target_workers",
    "io_adjusted_elastic_target",
    "memory_pressure_level",
    "memory_pressure_snapshot",
    "smooth_worker_target",
)
