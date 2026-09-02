from __future__ import annotations

from Virus_Scan.scheduler.workers.ipc_lifecycle import (
    close_owned_ipc_queue,
    shutdown_worker_processes,
)
from Virus_Scan.scheduler.workers.inmemory_worker_thread_progress import InMemoryWorkerThreadProgress


class HostileSchedulerValue:
    touched = 0

    def __str__(self):  # pragma: no cover - failure proves caller hook was invoked
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ invoked")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __repr__ invoked")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __int__ invoked")

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __float__ invoked")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __bool__ invoked")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __iter__ invoked")


class HostileSchedulerException(RuntimeError):
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned exception __str__ invoked")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned exception __repr__ invoked")


class RaisingQueue:
    def cancel_join_thread(self):
        raise HostileSchedulerException("queue cancelled badly")


class RaisingProcess:
    def join(self, timeout=0.0):
        raise HostileSchedulerException("join failed badly")

    def is_alive(self):
        return False


class Flags:
    running = 1
    cancel_request = 2
    poisoned_or_retire_mask = 4


def _reset() -> None:
    HostileSchedulerValue.touched = 0
    HostileSchedulerException.touched = 0


def test_stage1605_ipc_lifecycle_exception_evidence_does_not_stringify_hostile_exception() -> None:
    _reset()

    queue_status = close_owned_ipc_queue(RaisingQueue())
    process_summary = shutdown_worker_processes(
        [RaisingProcess()],
        sentinels=HostileSchedulerValue(),
        exit_grace_sec=HostileSchedulerValue(),
        terminate=HostileSchedulerValue(),
    )

    assert queue_status["errors"][0]["stage"] == "queue_cancel_join_thread_failed"
    assert queue_status["errors"][0]["error"].startswith("HostileSchedulerException:")
    assert process_summary["errors"][0]["stage"] == "worker_join_failed"
    assert process_summary["errors"][0]["error"].startswith("HostileSchedulerException:")
    assert HostileSchedulerException.touched == 0
    assert HostileSchedulerValue.touched == 0


def test_stage1605_worker_thread_progress_rejects_hostile_public_scalars_without_hooks() -> None:
    _reset()
    hostile = HostileSchedulerValue()
    task_meta: dict[str, object] = {}

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

    evidence = task_meta["thread_progress_heartbeat_evidence"]
    assert evidence["worker_thread_progress_heartbeat_failed"] is True
    assert evidence["worker_thread_progress_job_id"] == "worker"
    assert evidence["worker_thread_progress_attempt"] == 0
    assert evidence["worker_thread_progress_stage"] == "scan"
    assert evidence["worker_thread_progress_counter"] == 1
    assert evidence["worker_thread_progress_failure_reason"] == "shared heartbeat update returned false"
    assert HostileSchedulerValue.touched == 0
    assert HostileSchedulerException.touched == 0


def test_stage1605_worker_thread_progress_exception_reason_uses_no_hook_exception_boundary() -> None:
    _reset()
    task_meta: dict[str, object] = {}

    def raise_update(*_args, **_kwargs):
        raise HostileSchedulerException("heartbeat failed badly")

    progress = InMemoryWorkerThreadProgress(
        cfg={},
        job_id="worker-1",
        generation=3,
        cancel_table=None,
        heartbeat_table={},
        heartbeat_flags=Flags(),
        completed_jobs=0,
        task_meta=task_meta,
        cancel_requested=lambda *_args: False,
        update_shared_heartbeat=raise_update,
        record_heartbeat_failure=lambda *_args: None,
        recoverable_exceptions=(Exception,),
    )

    assert progress("scan") is True

    evidence = task_meta["thread_progress_heartbeat_evidence"]
    assert evidence["worker_thread_progress_failure_reason"].startswith(
        "shared heartbeat update raised HostileSchedulerException:"
    )
    assert HostileSchedulerException.touched == 0
