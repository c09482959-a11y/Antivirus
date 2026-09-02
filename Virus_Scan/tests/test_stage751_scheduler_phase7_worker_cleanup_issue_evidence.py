from __future__ import annotations

import signal
import subprocess

from Virus_Scan.scheduler.workers import cleanup as cleanup_module
from Virus_Scan.scheduler.workers.cleanup import wait_for_process_queue_worker_exit
from Virus_Scan.scheduler.workers.cleanup_wait_steps import WorkerExitWaitStepContext


class TimeoutThenFailedWaitProcess:
    pid = 123

    def __init__(self):
        self.calls = 0

    def wait(self, timeout=0.0):
        self.calls += 1
        if self.calls == 1:
            raise subprocess.TimeoutExpired(cmd="worker", timeout=timeout)
        raise RuntimeError("wait failed after cleanup")

    def poll(self):
        return 1


def _wait_context(*, worker_idx, output, timeout_sec, report_issue):
    return WorkerExitWaitStepContext(
        worker_idx=worker_idx,
        output=output,
        timeout_sec=timeout_sec,
        report_issue=report_issue,
        os_ops=None,
        default_os_ops=cleanup_module.os,
        terminate_signal=signal.SIGTERM,
        kill_signal=getattr(signal, "SIGKILL", signal.SIGTERM),
    )


def test_stage751_worker_cleanup_issue_recorder_failure_stays_in_evidence(tmp_path):
    def failing_report_issue(stage, exc, *, fatal=False, extra=None):
        raise RuntimeError(f"record failed for {stage}")

    result = wait_for_process_queue_worker_exit(
        TimeoutThenFailedWaitProcess(),
        _wait_context(
            worker_idx=5,
            output=tmp_path / "worker.out",
            timeout_sec=0.0,
            report_issue=failing_report_issue,
        ),
    )

    assert result.timed_out is True
    assert result.status == -1
    assert "queue_worker_final_wait_timeout" in result.failure_markers
    assert "queue_worker_final_wait_timeout_record_failed" in result.failure_markers
    assert "queue_worker_final_terminate_wait_failed" in result.failure_markers
    assert "queue_worker_final_terminate_wait_failed_record_failed" in result.failure_markers
    evidence = result.as_evidence()
    assert "queue_worker_final_wait_timeout_record_failed" in evidence["worker_failure_markers"]
