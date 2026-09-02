from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.workers.process_queue_child_failure import (
    build_child_failure_result,
    record_child_loop_failure,
)
from Virus_Scan.scheduler.workers.process_queue_child_failure_contracts import (
    ChildLoopFailureRequest,
)


class Stage2134HostileValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("stage2134 hostile str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("stage2134 hostile repr")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("stage2134 hostile format")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("stage2134 hostile bool")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("stage2134 hostile iter")


class Stage2134HostileJob:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("stage2134 hostile job bool")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("stage2134 hostile job iter")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("stage2134 hostile job items")


def _reset() -> None:
    Stage2134HostileValue.reset()
    Stage2134HostileJob.reset()


def test_stage2134_process_queue_child_failure_source_uses_typed_canonical_route() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scheduler" / "workers" / "process_queue_child_failure.py").read_text(encoding="utf-8")

    assert "from typing import Any" not in source
    assert "build_child_worker_error_result" not in source
    assert "worker_error_result" in source
    assert "ChildJob = Mapping[str, object] | None" in source
    assert "FailureInfo = dict[str, object]" in source
    assert "return {}" not in source
    assert "process_queue_child_failure_info_missing" in source


def test_stage2134_build_child_failure_result_rejects_hostile_worker_fields_without_hooks() -> None:
    _reset()
    result, failure_info = build_child_failure_result(
        "sample.bin",
        RuntimeError(Stage2134HostileValue()),
        stage="stage2134",
        job={"worker_id": Stage2134HostileValue(), "attempt": Stage2134HostileValue()},
    )

    assert Stage2134HostileValue.touched == 0
    assert isinstance(result, dict)
    assert result["worker_id"] == "umige"
    assert result["scheduler_mode"] == "process-queue-child"
    assert failure_info["attempt"] == 0
    assert failure_info["error"] == "RuntimeError"


def test_stage2134_record_child_loop_failure_rejects_hostile_job_object_without_hooks() -> None:
    _reset()
    child_results = {}
    done_count, failure_info = record_child_loop_failure(
        ChildLoopFailureRequest(
            job=Stage2134HostileJob(),
            child_results=child_results,
            worker_output_path=None,
            queue_dir="queue",
            claim_path="claim.json",
            write_result=lambda _queue, _claim, _file, _result: True,
            log_error=lambda _message: None,
            exc=RuntimeError(Stage2134HostileValue()),
            done_count=Stage2134HostileValue(),
        )
    )

    assert Stage2134HostileValue.touched == 0
    assert Stage2134HostileJob.touched == 0
    assert done_count == 0
    assert child_results == {}
    assert failure_info is not None
    assert "scheduler diagnostic detail unavailable" in failure_info["error"]
