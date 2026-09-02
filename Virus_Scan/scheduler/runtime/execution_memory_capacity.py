"""Canonical execution-memory capacity ownership for scheduler processes."""
from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Mapping

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float
from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot
from Virus_Scan.scheduler.runtime.execution_memory_cgroup import cgroup_v2_memory_boundary
from Virus_Scan.scheduler.runtime.optional_psutil import psutil

_MIB = 1024 * 1024
_DEFAULT_WORKER_RSS_LIMIT_MB = 2048.0
_DEFAULT_HIGH_PERCENT = 88.0


@dataclass(frozen=True, slots=True)
class ExecutionMemorySnapshot:
    source: str
    limit_bytes: int
    current_bytes: int
    committed_bytes: int
    parent_rss_bytes: int
    bounded: bool

    @property
    def available_bytes(self) -> int:
        return max(0, self.limit_bytes - self.current_bytes) if self.bounded else 0


UNBOUNDED_EXECUTION_MEMORY = ExecutionMemorySnapshot("unbounded", 0, 0, 0, 0, False)


def _parent_rss_bytes() -> int:
    try:
        return max(0, int(psutil.Process(os.getpid()).memory_info().rss))
    except (OSError, ValueError, TypeError, RuntimeError, AttributeError):
        return 0


def _cgroup_v2_snapshot() -> ExecutionMemorySnapshot | None:
    boundary = cgroup_v2_memory_boundary()
    if boundary is None:
        return None
    limit, current, committed = boundary
    return ExecutionMemorySnapshot("cgroup_v2", limit, current, committed, _parent_rss_bytes(), True)

def execution_memory_snapshot() -> ExecutionMemorySnapshot:
    cgroup = _cgroup_v2_snapshot()
    if cgroup is not None:
        return cgroup
    try:
        vm = psutil.virtual_memory()
        total, available = max(0, int(vm.total)), max(0, int(vm.available))
        if total > 0:
            current = max(0, total - min(total, available))
            return ExecutionMemorySnapshot("host", total, current, current, _parent_rss_bytes(), True)
    except (OSError, ValueError, TypeError, RuntimeError, AttributeError):
        return UNBOUNDED_EXECUTION_MEMORY
    return UNBOUNDED_EXECUTION_MEMORY


def worker_rss_limit_decision(env: Mapping[str, str]) -> tuple[float, str]:
    source = scheduler_environment_snapshot(env)
    raw = source.get("UMIGE_INMEMORY_WORKER_RSS_LIMIT_MB", "2048")
    candidate = "2048" if type(raw) is str and str.__str__(raw) == "" else raw
    value, reason = scheduler_float(candidate, default=_DEFAULT_WORKER_RSS_LIMIT_MB, minimum=0.0,
                                    reason="worker_rss_limit_mb_rejected", non_finite_reason="worker_rss_limit_mb_non_finite")
    if reason or value <= 0.0:
        return _DEFAULT_WORKER_RSS_LIMIT_MB, reason or "worker_rss_limit_mb_nonpositive"
    return value, ""


def process_memory_worker_cap(env: Mapping[str, str], snapshot: ExecutionMemorySnapshot) -> int | None:
    if type(snapshot) is not ExecutionMemorySnapshot or not snapshot.bounded or snapshot.limit_bytes <= 0:
        return None
    source = scheduler_environment_snapshot(env)
    high_percent, reason = scheduler_float(source.get("UMIGE_MEM_HIGH_PERCENT", _DEFAULT_HIGH_PERCENT),
                                           default=_DEFAULT_HIGH_PERCENT, minimum=1.0, maximum=99.0,
                                           reason="scheduler_memory_high_percent_rejected",
                                           non_finite_reason="scheduler_memory_high_percent_non_finite")
    if reason:
        high_percent = _DEFAULT_HIGH_PERCENT
    worker_limit_mb, _worker_reason = worker_rss_limit_decision(source)
    safe_boundary = int(snapshot.limit_bytes * (high_percent / 100.0))
    safe_for_workers = max(0, safe_boundary - max(snapshot.committed_bytes, snapshot.parent_rss_bytes))
    return safe_for_workers // max(1, int(worker_limit_mb * _MIB))


__all__ = ("ExecutionMemorySnapshot", "UNBOUNDED_EXECUTION_MEMORY", "execution_memory_snapshot", "process_memory_worker_cap", "worker_rss_limit_decision")
