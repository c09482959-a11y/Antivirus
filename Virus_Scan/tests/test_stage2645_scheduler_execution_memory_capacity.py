from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.runtime import backpressure_memory
from Virus_Scan.scheduler.runtime.execution_memory_capacity import (
    ExecutionMemorySnapshot,
    execution_memory_snapshot,
    process_memory_worker_cap,
    worker_rss_limit_decision,
)
from Virus_Scan.scheduler.runtime.execution_memory_cgroup import cgroup_committed_bytes
from Virus_Scan.scheduler.runtime.process_queue_runtime_policy import compute_process_queue_child_capacity
from Virus_Scan.scheduler.runtime.process_worker_capacity import default_process_scheduler_workers, longlived_worker_count

_MIB = 1024 * 1024
_GIB = 1024 * _MIB


def _four_gib_snapshot(*, current_gib: float = 1.0) -> ExecutionMemorySnapshot:
    return ExecutionMemorySnapshot(
        source="cgroup_v2",
        limit_bytes=4 * _GIB,
        current_bytes=int(current_gib * _GIB),
        committed_bytes=256 * _MIB,
        parent_rss_bytes=128 * _MIB,
        bounded=True,
    )




def test_cgroup_committed_memory_excludes_reclaimable_slab_from_kernel_total() -> None:
    stat = "\n".join((
        f"anon {1400 * _MIB}",
        f"file {2000 * _MIB}",
        f"kernel {600 * _MIB}",
        f"slab_reclaimable {500 * _MIB}",
        f"slab_unreclaimable {50 * _MIB}",
    ))
    committed = cgroup_committed_bytes(stat, current_bytes=int(3.9 * _GIB))
    assert committed == 1500 * _MIB

    snapshot = ExecutionMemorySnapshot(
        source="cgroup_v2",
        limit_bytes=4 * _GIB,
        current_bytes=int(3.9 * _GIB),
        committed_bytes=committed,
        parent_rss_bytes=1300 * _MIB,
        bounded=True,
    )
    assert process_memory_worker_cap({}, snapshot) == 1


def test_cgroup_committed_memory_fails_closed_when_required_counters_are_missing() -> None:
    current = int(3.5 * _GIB)
    assert cgroup_committed_bytes("file 1000", current_bytes=current) == current

def test_process_capacity_is_bounded_by_execution_memory_not_cpu_only() -> None:
    snapshot = _four_gib_snapshot()
    assert process_memory_worker_cap({}, snapshot) == 1
    assert default_process_scheduler_workers(
        env={"UMIGE_PROCESS_QUEUE_MAX_CHILDREN": "64"},
        cpu_count=5,
        recoverable_exceptions=(),
        memory_snapshot=snapshot,
    ) == 1
    assert longlived_worker_count(
        20,
        total_files=10_000,
        env={"UMIGE_PROCESS_QUEUE_MAX_CHILDREN": "64"},
        memory_snapshot=snapshot,
    ) == 1


def test_filesystem_process_queue_cannot_expand_past_same_memory_owner() -> None:
    capacity = compute_process_queue_child_capacity(
        requested_process_count=5,
        file_count=10_000,
        cpu_count=5,
        env={"UMIGE_PROCESS_QUEUE_MAX_CHILDREN": "100"},
        recoverable_exceptions=(),
        memory_snapshot=_four_gib_snapshot(),
    )
    assert capacity.cpu_fill_cap == 100
    assert capacity.process_count == 1


def test_worker_rss_limit_has_one_shared_parser_for_capacity_and_toxicity() -> None:
    value, reason = worker_rss_limit_decision({"UMIGE_INMEMORY_WORKER_RSS_LIMIT_MB": "512"})
    assert value == 512.0
    assert reason == ""
    value, reason = worker_rss_limit_decision({"UMIGE_INMEMORY_WORKER_RSS_LIMIT_MB": "bad"})
    assert value == 2048.0
    assert reason != ""


def test_memory_pressure_uses_execution_boundary() -> None:
    original_snapshot = backpressure_memory.execution_memory_snapshot
    try:
        backpressure_memory.execution_memory_snapshot = lambda: _four_gib_snapshot(current_gib=3.75)
        snapshot = backpressure_memory.memory_pressure_snapshot()
    finally:
        backpressure_memory.execution_memory_snapshot = original_snapshot
    assert snapshot["source"] == "cgroup_v2"
    assert snapshot["available_mb"] == 256.0
    assert snapshot["percent"] == 93.75
    assert snapshot["pressure"] == "critical"


def test_live_execution_memory_snapshot_reports_one_authoritative_boundary() -> None:
    snapshot = execution_memory_snapshot()
    assert snapshot.source in {"cgroup_v2", "host", "unbounded"}
    if snapshot.bounded:
        assert snapshot.limit_bytes > 0
        assert snapshot.current_bytes >= 0
        assert snapshot.committed_bytes >= 0
        assert snapshot.parent_rss_bytes >= 0


def test_dispatcher_has_no_duplicate_cpu_only_process_capacity_formula() -> None:
    source = (Path(__file__).resolve().parents[1] / "scheduler" / "orchestration" / "scheduler_mode_dispatch.py").read_text(encoding="utf-8")
    assert "cpu_count_safe() * 4" not in source
    assert "default_process_scheduler_workers(" in source
    assert "default_filesystem_queue_workers(" in source
