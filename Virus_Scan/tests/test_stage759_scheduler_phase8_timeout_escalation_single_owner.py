from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scheduler.timeout.escalation_engine import (
    ProcessQueueStallEscalationDependencies,
    ProcessQueueStallEscalationRequest,
    terminate_stalled_process_queue_workers,
)
from Virus_Scan.scheduler.timeout.longtask_controller import FileScanTimeoutError, per_file_timeout


class _Proc:
    pid = 4242


class _Result:
    pid = 4242
    error = ""

    def as_evidence(self):
        return {"pid": self.pid, "error": self.error}


def test_phase8_hard_timeout_guard_has_single_longtask_owner():
    escalation_source = read_python_file(Path("Virus_Scan/scheduler/timeout/escalation_engine.py"))
    longtask_source = read_python_file(Path("Virus_Scan/scheduler/timeout/longtask_controller.py"))

    assert "class FileScanTimeoutError" not in escalation_source
    assert "class per_file_timeout" not in escalation_source
    assert "import signal" not in escalation_source
    assert "class FileScanTimeoutError" in longtask_source
    assert "class per_file_timeout" in longtask_source
    assert issubclass(FileScanTimeoutError, TimeoutError)
    assert per_file_timeout(0).__enter__() is not None


def test_phase8_stall_escalation_still_owns_process_queue_termination():
    calls: list[tuple[str, int]] = []

    def worker_terminator(*, worker_idx, proc, action, reason):
        calls.append((action, int(worker_idx)))
        return _Result()

    result = terminate_stalled_process_queue_workers(
        ProcessQueueStallEscalationRequest(procs=((1, _Proc(), None, None),), elapsed_sec=9.5),
        ProcessQueueStallEscalationDependencies(
            log_error=lambda message: None,
            record_issue=lambda **kwargs: None,
            sleep=lambda seconds: None,
            worker_terminator=worker_terminator,
        ),
    )

    assert calls == [("terminate", 1), ("kill", 1)]
    assert result.terminated == 1
    assert result.killed == 1
    assert result.evidence == ()
