from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.workers.process_queue_child_failure import (
    attach_child_worker_metadata,
    record_child_loop_failure,
)
from Virus_Scan.scheduler.workers.process_queue_child_failure_contracts import (
    ChildLoopFailureRequest,
)
from Virus_Scan.scheduler.workers.process_queue_child_job import (
    ProcessQueueChildJobRequest,
    process_queue_child_job,
)


class HostileChildValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify child value")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr child value")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("do not format child value")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not int child value")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not float child value")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool child value")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate child value")


class HostileChildMapping:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool mapping")

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("do not get mapping")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate mapping")


def _reset() -> None:
    HostileChildValue.reset()
    HostileChildMapping.reset()


def test_stage1616_child_worker_metadata_rejects_hostile_worker_id_without_hooks() -> None:
    _reset()
    result = attach_child_worker_metadata({"file": "sample.bin"}, job={"worker_id": HostileChildValue()})

    assert HostileChildValue.touched == 0
    assert result["worker_id"] == "umige"
    assert result["scheduler_mode"] == "process-queue-child"


def test_stage1616_child_loop_failure_rejects_hostile_exception_and_job_file_without_hooks() -> None:
    _reset()
    child_results = {}
    done_count, failure_info = record_child_loop_failure(
        ChildLoopFailureRequest(
            job={"file": HostileChildValue(), "worker_id": HostileChildValue()},
            child_results=child_results,
            worker_output_path=None,
            queue_dir="queue",
            claim_path="claim.json",
            write_result=lambda _queue, _claim, _file, _result: True,
            log_error=lambda _message: None,
            exc=RuntimeError(HostileChildValue()),
            done_count=HostileChildValue(),
        )
    )

    assert HostileChildValue.touched == 0
    assert done_count == 0
    assert child_results == {}
    assert failure_info is not None
    assert "scheduler diagnostic detail unavailable" in failure_info["error"]


def test_stage1616_process_queue_child_request_rejects_hostile_scalars_and_mapping_without_hooks(tmp_path) -> None:
    _reset()
    finishes = []
    appended = []
    logs = []
    claim_path = tmp_path / "claim.json"
    claim_path.write_text("{}", encoding="utf-8")

    request = ProcessQueueChildJobRequest(
        work_queue_dir=tmp_path,
        worker_output_path=None,
        total_files=HostileChildValue(),
        scan_started_at=0.0,
        progress_every=HostileChildValue(),
        throttle_sec=HostileChildValue(),
        worker=lambda file_path, engine, strict: (file_path, {"file": file_path}),
        job=HostileChildMapping(),
        claim_path=claim_path,
        claim_heartbeat_update=lambda *args, **kwargs: True,
        write_queue_file_result=lambda _queue, _claim, _file, _result: True,
        finish_process_queue_job=lambda *args, **kwargs: finishes.append((args, kwargs)),
        append_raw_stage_result=lambda job, result: appended.append((job, result)),
        execute_raw_stage_job=lambda job: {"ok": True},
        bulk_scan_maintenance=lambda done_count: None,
        log_bulk_progress=lambda *args, **kwargs: None,
        sleep=lambda seconds: None,
        log_error=lambda message: logs.append(message),
        record_heartbeat_failure=lambda label, exc: None,
        done_count=HostileChildValue(),
        child_results={},
    )
    result = process_queue_child_job(request)

    assert HostileChildValue.touched == 0
    assert HostileChildMapping.touched == 0
    assert result.done_count == 0
    assert finishes
    assert finishes[0][1]["ok"] is False
    assert appended == []


def test_stage1616_process_queue_child_raw_stage_exception_uses_no_hook_error_detail(tmp_path) -> None:
    _reset()
    appended = []
    finishes = []
    claim_path = tmp_path / "claim.json"
    claim_path.write_text("{}", encoding="utf-8")

    request = ProcessQueueChildJobRequest(
        work_queue_dir=tmp_path,
        worker_output_path=None,
        total_files=1,
        scan_started_at=0.0,
        progress_every=0,
        throttle_sec=0.0,
        worker=lambda file_path, engine, strict: (file_path, {"file": file_path}),
        job={"job_type": "raw_stage", "file": "sample.bin", "collector": HostileChildValue(), "attempt": HostileChildValue()},
        claim_path=claim_path,
        claim_heartbeat_update=lambda *args, **kwargs: True,
        write_queue_file_result=lambda _queue, _claim, _file, _result: True,
        finish_process_queue_job=lambda *args, **kwargs: finishes.append((args, kwargs)),
        append_raw_stage_result=lambda job, result: appended.append((job, result)),
        execute_raw_stage_job=lambda job: (_ for _ in ()).throw(RuntimeError(HostileChildValue())),
        bulk_scan_maintenance=lambda done_count: None,
        log_bulk_progress=lambda *args, **kwargs: None,
        sleep=lambda seconds: None,
        log_error=lambda message: None,
        record_heartbeat_failure=lambda label, exc: None,
        done_count=0,
        child_results={},
    )

    result = process_queue_child_job(request)

    assert HostileChildValue.touched == 0
    assert result.done_count == 0
    assert appended
    raw_result = appended[0][1]
    assert raw_result["ok"] is False
    assert raw_result["infra_error"] is True
    assert "scheduler diagnostic detail unavailable" in raw_result["error"]
    assert finishes and finishes[0][1]["ok"] is True


def test_stage1959_process_queue_child_failure_source_has_no_fallback_or_truthiness_copy_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scheduler" / "workers" / "process_queue_child_failure.py").read_text(encoding="utf-8")

    assert "fallback" not in source
    assert "scheduler_int" not in source
    assert "default=" not in source
    assert "dict(failure_info or {})" not in source
    assert "failure_info or {}" not in source


def test_stage1959_process_queue_child_job_source_has_no_fallback_or_fstring_scalar_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scheduler" / "workers" / "process_queue_child_job.py").read_text(encoding="utf-8")

    assert "fallback" not in source
    assert "scheduler_int" not in source
    assert "scheduler_float" not in source
    assert "default=" not in source
    assert 'f"{safe_finished_path}' not in source
