from dataclasses import FrozenInstanceError

from Virus_Scan.scheduler.workers.inmemory_result_publication import (
    InMemoryWorkerResultPublication,
    publish_completed_inmemory_worker_result,
)


class _FailingFuture:
    def result(self):
        raise RuntimeError("worker exploded")


class _SuccessfulFuture:
    def result(self):
        return "a.bin", {"file": "a.bin", "scan_integrity": {}}


class _ResultQueue:
    def __init__(self, fail=False):
        self.fail = fail
        self.items = []

    def put(self, item):
        if self.fail:
            raise RuntimeError("result queue unavailable")
        self.items.append(item)


def test_worker_result_publication_records_error_result_construction_failure():
    future = _FailingFuture()
    active = {future: {"job_id": 41, "path": "bad.bin", "attempt": 2}}
    result_q = _ResultQueue()

    def broken_error_result(_path, _exc):
        raise RuntimeError("error constructor unavailable")

    evidence = publish_completed_inmemory_worker_result(
        future=future,
        active=active,
        result_q=result_q,
        max_jobs_per_worker=10,
        processed_jobs=0,
        worker_error_result=broken_error_result,
        recoverable_exceptions=(RuntimeError,),
        record_suppressed=lambda _stage, _exc: None,
    )

    assert isinstance(evidence, InMemoryWorkerResultPublication)
    assert evidence.worker_error_result_failed is True
    assert evidence.queue_publish_failed is False
    assert evidence.job_id == 41
    published = result_q.items[0][3]
    integrity = published["scan_integrity"]
    assert integrity["worker_error_result_construction_failed"] is True
    assert integrity["worker_failure_error"] == "worker exploded"
    assert integrity["worker_error_result_error"] == "error constructor unavailable"
    assert published["scheduler_failure_reason"] == "worker_error_result_construction_failed"
    try:
        evidence.worker_error_result_failed = False
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("publication failure evidence must be immutable")


def test_worker_result_publication_records_queue_and_report_failure():
    future = _SuccessfulFuture()
    active = {future: {"job_id": 42, "path": "a.bin", "attempt": 1}}
    result_q = _ResultQueue(fail=True)

    def broken_report(_stage, _exc):
        raise RuntimeError("reporter unavailable")

    evidence = publish_completed_inmemory_worker_result(
        future=future,
        active=active,
        result_q=result_q,
        max_jobs_per_worker=10,
        processed_jobs=4,
        worker_error_result=lambda path, exc: {"file": str(path), "error": str(exc), "scan_integrity": {}},
        recoverable_exceptions=(RuntimeError,),
        record_suppressed=broken_report,
    )

    assert evidence.queue_publish_failed is True
    assert evidence.queue_publish_report_failed is True
    assert evidence.processed_jobs == 5
    assert active == {}

from Virus_Scan.scheduler.workers.process_queue_child_job import (
    ProcessQueueChildJobRequest,
    process_queue_child_job,
)


def test_process_queue_child_job_normalizes_invalid_worker_success_payload(tmp_path):
    child_results = {}
    finish_calls = []

    def finish_job(*args, **kwargs):
        finish_calls.append((args, kwargs))

    request = ProcessQueueChildJobRequest(
        work_queue_dir=tmp_path,
        worker_output_path=None,
        total_files=1,
        scan_started_at=0.0,
        progress_every=1,
        throttle_sec=0.0,
        worker=lambda _path, _label, _flag: ("bad.bin", ["not", "a", "dict"]),
        job={"file": "bad.bin", "attempt": 0, "worker_id": "worker-a"},
        claim_path=tmp_path / "claim.json",
        claim_heartbeat_update=lambda *_args, **_kwargs: True,
        write_queue_file_result=lambda _queue, _claim, _file, _result: True,
        finish_process_queue_job=finish_job,
        append_raw_stage_result=lambda *_args, **_kwargs: None,
        execute_raw_stage_job=lambda _job: {},
        bulk_scan_maintenance=lambda _count: None,
        log_bulk_progress=lambda *_args, **_kwargs: None,
        sleep=lambda _seconds: None,
        log_error=lambda _message: None,
        record_heartbeat_failure=lambda _stage, _exc: None,
        done_count=0,
        child_results=child_results,
    )

    result = process_queue_child_job(request)

    assert result.done_count == 1
    assert finish_calls and finish_calls[0][1]["ok"] is True
    normalized = child_results["bad.bin"]
    integrity = normalized["scan_integrity"]
    assert integrity["worker_result_schema_invalid"] is True
    assert normalized["queue_failure"] is True
    assert normalized["scheduler_mode"] == "process-queue-child"
    assert normalized["worker_id"] == "worker-a"
