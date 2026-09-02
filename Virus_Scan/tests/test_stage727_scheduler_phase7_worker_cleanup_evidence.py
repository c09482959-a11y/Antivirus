from __future__ import annotations

from Virus_Scan.scheduler.queue.terminal_accounting import (
    IdleQueueFinalizationRequest,
    idle_queue_finalization_decision,
)
from Virus_Scan.scheduler.workers.cleanup import terminate_process_queue_worker


class DummyWorkerProc:
    def __init__(self):
        self.pid = 727001
        self.actions = []
        self.alive = True

    def poll(self):
        return None if self.alive else 0

    def terminate(self):
        self.actions.append("terminate")

    def kill(self):
        self.actions.append("kill")
        self.alive = False


def test_stage727_idle_finalization_uses_worker_owned_termination_evidence():
    proc = DummyWorkerProc()
    reported = []
    observed = []

    def terminate_worker(proc_arg, *, action, worker_idx):
        result = terminate_process_queue_worker(
            proc_arg,
            action=action,
            worker_idx=worker_idx,
            report_failure=lambda marker, exc: reported.append((marker, str(exc))),
        )
        observed.append(result)
        return result

    terminated, next_notice = idle_queue_finalization_decision(IdleQueueFinalizationRequest(
        no_live_queue_work=True,
        accounted_files=1,
        total_files=1,
        idle_elapsed=40.0,
        idle_notice_sec=5.0,
        idle_grace_sec=30.0,
        live_workers=1,
        procs=((3, proc, "out", ()),),
        terminate_worker=terminate_worker,
        report=lambda *args, **kwargs: None,
        log_info=lambda *args, **kwargs: None,
        sleep=lambda _sec: None,
    ))

    assert terminated is True
    assert next_notice == 5.0
    assert proc.actions == ["terminate", "kill"]
    assert [item.action for item in observed] == ["terminate", "kill"]
    assert all(item.worker_idx == 3 for item in observed)
    assert all(item.requested for item in observed)
    assert all(item.completed for item in observed)
    assert reported == []
