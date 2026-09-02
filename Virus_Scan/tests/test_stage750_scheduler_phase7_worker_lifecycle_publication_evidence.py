from dataclasses import FrozenInstanceError

from Virus_Scan.scheduler.workers.inmemory_worker_job import (
    InMemoryWorkerJobExecutionDependencies,
    InMemoryWorkerJobExecutionRequest,
    execute_inmemory_worker_job,
)
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_evidence import (
    InMemoryWorkerLifecyclePublicationEvidence,
)


class _ThreadProgress:
    heartbeat_failure_count = 0
    last_heartbeat_failure = None

    def __init__(self, **_kwargs):
        self.events = []

    def __call__(self, event):
        self.events.append(event)
        return True


def _request():
    return InMemoryWorkerJobExecutionRequest.build(
        job_id=17,
        path="life.bin",
        attempt=3,
        worker_config={},
        cancel_table={},
        heartbeat_table={},
        heartbeat_flags=object(),
        completed_jobs=0,
        task_meta={"source": "unit"},
    )


def _deps(*, result_put, scan_one_file, worker_error_result=None, record_scheduler_suppressed=None):
    return InMemoryWorkerJobExecutionDependencies(
        cancel_requested=lambda _table, _job_id, _generation: False,
        cancel_result=lambda path, reason: (path, {"file": str(path), "error": reason}),
        result_put=result_put,
        worker_thread_progress_type=_ThreadProgress,
        scan_one_file=scan_one_file,
        worker_error_result=worker_error_result or (lambda path, exc: {"file": str(path), "error": str(exc), "scan_integrity": {}}),
        update_shared_heartbeat=lambda *_args, **_kwargs: True,
        record_scheduler_suppressed=record_scheduler_suppressed or (lambda _stage, _exc: None),
        cooperative_cancel_type=RuntimeError,
        recoverable_exceptions=(RuntimeError,),
    )


def test_stage750_running_publication_failure_is_attached_to_worker_result():
    recorded = []

    def failing_put(_message):
        raise RuntimeError("running queue unavailable")

    output = execute_inmemory_worker_job(
        _request(),
        _deps(
            result_put=failing_put,
            scan_one_file=lambda path, _cfg: (path, {"file": str(path), "tags": [], "scan_integrity": {}}),
            record_scheduler_suppressed=lambda stage, exc: recorded.append((stage, str(exc))),
        ),
    )

    assert recorded == [("suppressed_exception", "running queue unavailable")]
    assert output[0] == "life.bin"
    result = output[1]
    integrity = result["scan_integrity"]
    assert result["queue_failure"] is True
    assert result["worker_lifecycle_publication_failed"] is True
    assert integrity["worker_lifecycle_publication_failed"] is True
    assert integrity["worker_lifecycle_publication_operation"] == "running"
    assert integrity["worker_lifecycle_publication_job_id"] == 17
    assert integrity["worker_lifecycle_publication_generation"] == 3
    assert "running queue unavailable" in integrity["worker_lifecycle_publication_failure_reason"]
    assert integrity["allow_learning"] is False


def test_stage750_running_publication_report_failure_is_immutable_evidence():
    evidence = InMemoryWorkerLifecyclePublicationEvidence(
        operation="running",
        job_id=7,
        path="x.bin",
        generation=1,
        reason="RuntimeError: queue unavailable",
        report_failed=True,
        report_error="RuntimeError: reporter unavailable",
    )

    ctx = evidence.as_scan_integrity()
    assert ctx["worker_lifecycle_publication_report_failed"] is True
    assert ctx["worker_lifecycle_publication_report_error"] == "RuntimeError: reporter unavailable"
    try:
        evidence.job_id = 99
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("lifecycle publication evidence must be immutable")


def test_stage750_worker_error_result_construction_failure_returns_degraded_result():
    def scan_raises(_path, _cfg):
        raise RuntimeError("scan exploded")

    def broken_error_result(_path, _exc):
        raise RuntimeError("error-result constructor exploded")

    output = execute_inmemory_worker_job(
        _request(),
        _deps(
            result_put=lambda _message: None,
            scan_one_file=scan_raises,
            worker_error_result=broken_error_result,
        ),
    )

    assert output[0] == "life.bin"
    result = output[1]
    integrity = result["scan_integrity"]
    assert result["queue_failure"] is True
    assert result["scheduler_failure_reason"] == "worker_error_result_construction_failed"
    assert integrity["worker_error_result_construction_failed"] is True
    assert integrity["worker_failure_error"] == "scan exploded"
    assert integrity["worker_error_result_error"] == "error-result constructor exploded"
    assert integrity["allow_learning"] is False
