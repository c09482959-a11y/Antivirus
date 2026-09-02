from pathlib import Path

from Virus_Scan.scheduler.workers.process_liveness import check_process_queue_worker_liveness
from Virus_Scan.scheduler.workers.process_termination import WorkerTerminationResult, terminate_queue_worker_pid
from Virus_Scan.scheduler.workers.heartbeat import (
    cooperative_cancel_requested,
    read_shared_heartbeat,
    update_shared_heartbeat,
)
from Virus_Scan.scheduler.workers.inmemory_worker_death import snapshot_inmemory_worker_liveness


def test_worker_process_control_returns_immutable_evidence_for_invalid_inputs():
    reports = []
    liveness = check_process_queue_worker_liveness("not-a-pid", record_suppressed=lambda *a, **k: reports.append((a, k)))
    assert liveness.alive is False
    assert liveness.reason == "pid_parse_failed"
    assert liveness.as_evidence()["pid_alive"] is False

    termination = terminate_queue_worker_pid("not-a-pid", reason="unit_test")
    assert isinstance(termination, WorkerTerminationResult)
    assert termination.terminated is False
    assert termination.as_evidence()["termination_reason"] == "unit_test"


def test_heartbeat_public_worker_boundary_names_remain_canonical():
    table = {
        "generation": [0, 2],
        "stage": [0, 0],
        "monotonic_ns": [0, 0],
        "pid": [0, 0],
        "thread_id": [0, 0],
        "progress_counter": [0, 0],
        "bytes_processed": [0, 0],
        "last_progress_ns": [0, 0],
        "flags": [0, 0],
        "completed_jobs": [0, 0],
    }
    assert cooperative_cancel_requested({"generation": [0], "flags": [0]}, 0, 0) is False
    assert update_shared_heartbeat(table, 1, 2, stage="scan", progress_counter=3) is True
    row = read_shared_heartbeat(table, 1, 2)
    assert row["stage"] == "scan"
    assert row["progress_counter"] == 3


def test_orchestration_no_longer_performs_direct_worker_liveness_probes():
    scheduler_root = Path(__file__).resolve().parents[1] / "scheduler"
    for relative in (
        "orchestration/inmemory_parent_maintenance.py",
        "orchestration/process_queue_monitor_recovery.py",
    ):
        source = (scheduler_root / relative).read_text(encoding="utf-8")
        assert ".is_alive()" not in source
        assert ".poll()" not in source


def test_inmemory_worker_liveness_snapshot_is_worker_owned():
    class Proc:
        def __init__(self, pid, alive):
            self.pid = pid
            self._alive = alive

        def is_alive(self):
            return self._alive

    snapshot = snapshot_inmemory_worker_liveness(procs=(Proc(11, True), Proc(12, False)))
    assert snapshot.live_count == 1
    assert snapshot.dead_pids == (12,)
