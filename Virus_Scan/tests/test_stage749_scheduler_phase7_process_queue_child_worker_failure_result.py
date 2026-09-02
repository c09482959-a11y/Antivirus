from Virus_Scan.scheduler.workers.process_queue_child_job import (
    ProcessQueueChildJobRequest,
    process_queue_child_job,
)


def test_stage749_child_worker_exception_records_worker_result_evidence():
    child_results = {}
    finalized = {}

    def worker(_path, _mode, _deep):
        raise RuntimeError("worker exploded")

    def finish(_queue_dir, _claim_path, *, ok, error_info, job):
        finalized["ok"] = ok
        finalized["error_info"] = error_info
        finalized["job"] = job
        return True

    result = process_queue_child_job(
        ProcessQueueChildJobRequest(
            work_queue_dir="queue",
            worker_output_path=None,
            total_files=1,
            scan_started_at=0.0,
            progress_every=1,
            throttle_sec=0.0,
            worker=worker,
            job={"file": "bad.bin", "attempt": 2, "worker_id": "w1"},
            claim_path="claim.json",
            claim_heartbeat_update=lambda *a, **k: True,
            write_queue_file_result=lambda _queue, _claim, _file, _result: True,
            finish_process_queue_job=finish,
            append_raw_stage_result=lambda *_a, **_k: None,
            execute_raw_stage_job=lambda _job: {},
            bulk_scan_maintenance=lambda _done: None,
            log_bulk_progress=lambda *_a, **_k: None,
            sleep=lambda _seconds: None,
            log_error=lambda _message: None,
            record_heartbeat_failure=lambda _label, _exc: None,
            done_count=0,
            child_results=child_results,
        )
    )

    assert result.done_count == 1
    assert finalized["ok"] is False
    assert finalized["error_info"]["stage"] == "process_queue_child_worker"
    assert "bad.bin" in child_results
    worker_result = child_results["bad.bin"]
    assert worker_result["queue_failure"] is True
    assert worker_result["failure_info"]["stage"] == "process_queue_child_worker"
    assert worker_result["scan_integrity"]["file_failed"] is True
    assert worker_result["scan_integrity"]["allow_learning"] is False
