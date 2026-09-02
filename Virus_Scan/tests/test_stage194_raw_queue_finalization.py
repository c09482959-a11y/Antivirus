import json
from pathlib import Path

from Virus_Scan.scheduler.queue.terminal_accounting import (
    IdleQueueFinalizationRequest,
    idle_queue_finalization_decision,
)
from Virus_Scan.scheduler.queue.terminal_missing_finalization import finalize_missing_file_accounting


class DummyProc:
    def __init__(self):
        self.actions = []
        self.alive = True

    def poll(self):
        return None if self.alive else 0

    def terminate(self):
        self.actions.append("terminate")

    def kill(self):
        self.actions.append("kill")
        self.alive = False


def test_missing_file_accounting_synthesizes_failed_result_and_terminates(tmp_path):
    reports = []
    logs = []
    actions = []

    def worker_error_result(path, exc):
        return {"file": str(path), "error": str(exc), "tags": ["queue_missing_result"]}

    def terminate_worker(proc, *, action, worker_idx):
        actions.append((worker_idx, action))

    terminated, had_error = finalize_missing_file_accounting(
        feed_complete=True,
        no_live_queue_work=True,
        accounted_files=1,
        total_files=3,
        idle_elapsed=31.0,
        idle_grace_sec=30.0,
        all_files=["a.bin", "b.bin", "c.bin"],
        queue_dir=tmp_path / "queue",
        outputs_dir=tmp_path / "outputs",
        procs=[(7, object(), "out", [])],
        load_queue_file_results=lambda _queue_dir: {"a.bin": {"ok": True}},
        worker_error_result=worker_error_result,
        terminate_worker=terminate_worker,
        report=lambda marker, exc, **kwargs: reports.append((marker, str(exc), kwargs)),
        log_error=logs.append,
        sleep=lambda _sec: None,
    )

    assert terminated is True
    assert had_error is True
    published = json.loads(
        (tmp_path / "outputs" / "worker_missing_finalization.json").read_text(encoding="utf-8")
    )
    assert sorted(published) == ["a.bin", "b.bin", "c.bin"]
    assert actions == [(7, "terminate"), (7, "kill")]
    assert logs and "synthesized_failed_results=2" in logs[0]
    assert reports == []


def test_idle_queue_finalization_terminates_after_grace():
    proc = DummyProc()
    logs = []
    reports = []

    actions = []

    def terminate_worker(proc_arg, *, action, worker_idx):
        actions.append((worker_idx, action))
        getattr(proc_arg, action)()

    terminated, next_notice = idle_queue_finalization_decision(IdleQueueFinalizationRequest(
        no_live_queue_work=True,
        accounted_files=3,
        total_files=3,
        idle_elapsed=40.0,
        idle_notice_sec=5.0,
        idle_grace_sec=30.0,
        live_workers=1,
        procs=[(3, proc, "out", [])],
        terminate_worker=terminate_worker,
        report=lambda marker, exc, **kwargs: reports.append((marker, str(exc), kwargs)),
        log_info=logs.append,
        sleep=lambda _sec: None,
    ))

    assert terminated is True
    assert next_notice == 5.0
    assert proc.actions == ["terminate", "kill"]
    assert actions == [(3, "terminate"), (3, "kill")]
    assert any("terminating 1 idle worker" in msg for msg in logs)
    assert reports == []
