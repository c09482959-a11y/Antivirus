from types import SimpleNamespace

from Virus_Scan.scheduler.workers.inmemory_worker_submission import submit_inmemory_worker_task


class _FailingThreadPool:
    def submit(self, *_args, **_kwargs):
        raise RuntimeError("thread pool unavailable")


def test_stage750_submission_failure_publishes_degraded_worker_result():
    result_items = []
    suppressed = []
    task = SimpleNamespace(job_id=23, path="submit.bin", attempt=4)
    worker_deps = SimpleNamespace(
        result_put=lambda item: result_items.append(item),
        worker_error_result=lambda path, exc: {"file": str(path), "error": str(exc), "scan_integrity": {}},
    )

    submission = submit_inmemory_worker_task(
        task=task,
        tpool=_FailingThreadPool(),
        active={},
        execute_job=lambda *_args, **_kwargs: None,
        worker_execution_deps=worker_deps,
        worker_config={},
        cancel_table={},
        heartbeat_table={},
        heartbeat_flags={},
        completed_jobs=0,
        recoverable_exceptions=(RuntimeError,),
        record_suppressed=lambda stage, exc: suppressed.append((stage, str(exc))),
    )

    assert submission.submitted is False
    assert submission.job_id == 23
    assert submission.attempt == 4
    assert suppressed == [("inmemory_worker_task_submission_failure", "thread pool unavailable")]
    assert result_items and result_items[0][0] == "result"
    _kind, job_id, path, result, _pid, _time, attempt = result_items[0]
    assert (job_id, path, attempt) == (23, "submit.bin", 4)
    integrity = result["scan_integrity"]
    assert result["queue_failure"] is True
    assert result["worker_lifecycle_publication_failed"] is True
    assert integrity["worker_lifecycle_publication_failed"] is True
    assert integrity["worker_lifecycle_publication_operation"] == "task_submission"
    assert integrity["worker_lifecycle_publication_job_id"] == 23
    assert integrity["worker_lifecycle_publication_generation"] == 4
    assert integrity["allow_learning"] is False


def test_stage750_submission_failure_error_result_constructor_failure_still_publishes_degraded_result():
    result_items = []
    task = SimpleNamespace(job_id=24, path="submit-fallback.bin", attempt=5)

    def broken_error_result(_path, _exc):
        raise RuntimeError("error constructor unavailable")

    worker_deps = SimpleNamespace(
        result_put=lambda item: result_items.append(item),
        worker_error_result=broken_error_result,
    )

    submission = submit_inmemory_worker_task(
        task=task,
        tpool=_FailingThreadPool(),
        active={},
        execute_job=lambda *_args, **_kwargs: None,
        worker_execution_deps=worker_deps,
        worker_config={},
        cancel_table={},
        heartbeat_table={},
        heartbeat_flags={},
        completed_jobs=0,
        recoverable_exceptions=(RuntimeError,),
        record_suppressed=lambda _stage, _exc: None,
    )

    assert submission.submitted is False
    result = result_items[0][3]
    integrity = result["scan_integrity"]
    assert result["scheduler_failure_reason"] == "worker_error_result_construction_failed"
    assert integrity["worker_error_result_construction_failed"] is True
    assert integrity["worker_lifecycle_publication_failed"] is True
    assert integrity["worker_failure_error"] == "thread pool unavailable"
    assert integrity["worker_error_result_error"] == "error constructor unavailable"
