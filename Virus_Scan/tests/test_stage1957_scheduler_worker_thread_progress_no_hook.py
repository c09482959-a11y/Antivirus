from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.workers.inmemory_worker_thread_progress import InMemoryWorkerThreadProgress


class HostileValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned str hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned repr hook executed")

    def __format__(self, _spec):
        type(self).touched += 1
        raise AssertionError("caller-owned format hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned bool hook executed")

    def __int__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned int hook executed")

    def __float__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned float hook executed")

    def __iter__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned iter hook executed")


class Flags:
    running = 1
    cancel_request = 2
    poisoned_or_retire_mask = 4


def test_stage1957_thread_progress_records_rejected_inputs_without_hooks() -> None:
    HostileValue.reset()
    task_meta: dict[str, object] = {}
    hostile = HostileValue()
    progress = InMemoryWorkerThreadProgress(
        cfg={"worker_rss_limit_mb": hostile},
        job_id=hostile,
        generation=hostile,
        cancel_table=None,
        heartbeat_table={},
        heartbeat_flags=Flags(),
        completed_jobs=hostile,
        task_meta=task_meta,
        cancel_requested=lambda *_args: hostile,
        update_shared_heartbeat=lambda *_args, **_kwargs: hostile,
        record_heartbeat_failure=None,
        recoverable_exceptions=(Exception,),
    )

    assert progress(hostile, inc=hostile, bytes_delta=hostile) is True

    assert task_meta["stage"] == "scan"
    assert task_meta["progress_counter"] == 1
    assert task_meta["bytes_processed"] == 0
    assert task_meta["thread_progress_heartbeat_publish_failed"] is True
    rejections = task_meta["thread_progress_input_rejections"]
    assert "unsupported_worker_thread_progress_stage" in rejections
    assert "worker_thread_progress_increment_rejected" in rejections
    assert "worker_thread_progress_bytes_delta_rejected" in rejections
    assert "worker_thread_progress_rss_limit_rejected" in rejections
    assert "worker_thread_progress_cancel_flag_rejected" in rejections
    assert "worker_thread_progress_publish_flag_rejected" in rejections
    assert HostileValue.touched == 0


def test_stage1957_thread_progress_recorder_failure_is_evidence_not_clean_return() -> None:
    task_meta: dict[str, object] = {}

    def recorder(_label, _exc):
        raise RuntimeError("recorder down")

    progress = InMemoryWorkerThreadProgress(
        cfg={},
        job_id="job-1",
        generation=2,
        cancel_table=None,
        heartbeat_table={},
        heartbeat_flags=Flags(),
        completed_jobs=0,
        task_meta=task_meta,
        cancel_requested=lambda *_args: False,
        update_shared_heartbeat=lambda *_args, **_kwargs: False,
        record_heartbeat_failure=recorder,
        recoverable_exceptions=(RuntimeError,),
    )

    assert progress("scan") is True
    assert task_meta["thread_progress_heartbeat_publish_failed"] is True
    assert progress.last_heartbeat_failure["worker_thread_progress_failure_reason"] == "shared heartbeat update returned false"
    assert any(reason.startswith("RuntimeError:") for reason in task_meta["thread_progress_input_rejections"])


def test_stage1957_thread_progress_source_guards_remove_fallback_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scheduler" / "workers" / "inmemory_worker_thread_progress.py").read_text(encoding="utf-8")

    assert "safe_worker_thread_progress_evidence_inputs" not in source
    assert "default=" not in source
    assert "fallback=" not in source
    assert "reason=f" not in source
    assert "except self.recoverable_exceptions:\n            return" not in source
    assert len(source.splitlines()) < 200
