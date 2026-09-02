from __future__ import annotations

from Virus_Scan.scheduler.workers.ipc_lifecycle import (
    close_owned_ipc_queue,
    shutdown_worker_processes,
    stop_worker_heartbeat,
)


class RaisingThread:
    def join(self, timeout=0.0):
        raise RuntimeError("join failed")


class RaisingQueue:
    def cancel_join_thread(self):
        raise RuntimeError("cancel failed")


class RaisingProcess:
    def join(self, timeout=0.0):
        raise RuntimeError("join failed")

    def is_alive(self):
        return False


def failing_recorder(stage, exc):
    raise RuntimeError(f"recorder failed for {stage}")


def test_stage751_stop_worker_heartbeat_recorder_failure_stays_in_status():
    status = stop_worker_heartbeat(None, RaisingThread(), failure_recorder=failing_recorder)

    assert status["joined"] is True
    assert status["error"] == "RuntimeError: join failed"
    assert status["recorder_error"] == "RuntimeError: recorder failed for worker_heartbeat_shutdown_failed"


def test_stage751_close_owned_ipc_queue_recorder_failure_is_evidence_not_abort():
    status = close_owned_ipc_queue(RaisingQueue(), failure_recorder=failing_recorder)

    stages = [entry["stage"] for entry in status["errors"]]
    assert "queue_cancel_join_thread_failed" in stages
    assert "queue_cancel_join_thread_failed_recorder_failed" in stages


def test_stage751_shutdown_worker_processes_recorder_failure_is_evidence_not_abort():
    summary = shutdown_worker_processes([RaisingProcess()], terminate=False, failure_recorder=failing_recorder)

    stages = [entry["stage"] for entry in summary["errors"]]
    assert "worker_join_failed" in stages
    assert "worker_join_failed_recorder_failed" in stages
