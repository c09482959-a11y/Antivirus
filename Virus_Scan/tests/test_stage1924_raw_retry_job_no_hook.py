from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scheduler.queue.raw_retry_job import prepare_raw_retry_job


class HostileValue:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile bool hook touched")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile str hook touched")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile repr hook touched")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile int hook touched")

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("hostile float hook touched")


class HostileMapping(dict):
    def get(self, *_args, **_kwargs):  # pragma: no cover
        HostileValue.touched += 1
        raise AssertionError("hostile mapping get touched")

    def __iter__(self):  # pragma: no cover
        HostileValue.touched += 1
        raise AssertionError("hostile mapping iter touched")

    def __bool__(self):  # pragma: no cover
        HostileValue.touched += 1
        raise AssertionError("hostile mapping bool touched")


def test_stage1924_rejects_hostile_job_mapping_without_mapping_or_bool_hooks() -> None:
    HostileValue.touched = 0

    assert prepare_raw_retry_job(HostileMapping(attempt=0, max_retries=1), {"error": "boom"}, now=1.0) is None
    assert HostileValue.touched == 0


def test_stage1924_rejects_hostile_result_error_pid_and_now_without_text_numeric_hooks() -> None:
    HostileValue.touched = 0
    job = {"job_type": "raw_stage", "file": "x.bin", "file_id": "f1", "attempt": 0, "max_retries": 2, "worker_pid": HostileValue()}

    retry = prepare_raw_retry_job(job, {"error": HostileValue()}, now=HostileValue())

    assert retry is not None
    assert retry["attempt"] == 1
    assert retry["retry_pending_reason"] == "raw_retry"
    assert retry["last_error"] == ""
    assert retry["raw_retry_from_attempt"] == 0
    assert retry["job_type"] == "raw_stage"
    assert HostileValue.touched == 0


def test_stage1924_rejects_hostile_result_mapping_without_get_bool_or_iter_hooks() -> None:
    HostileValue.touched = 0
    job = {"job_type": "raw_stage", "file": "x.bin", "file_id": "f1", "attempt": 0, "max_retries": 2}

    retry = prepare_raw_retry_job(job, HostileMapping(error=HostileValue()), now=2.0)

    assert retry is not None
    assert retry["retry_pending_reason"] == "raw_retry"
    assert retry["last_error"] == ""
    assert HostileValue.touched == 0


def test_stage1924_raw_retry_job_source_guard_closes_unsafe_routes() -> None:
    source = read_python_file(Path(__file__).resolve().parents[2] / "Virus_Scan/scheduler/queue/raw_retry_job.py")

    assert "str((result or {}).get" not in source
    assert "job.get(" not in source
    assert "result or {}" not in source
    assert ".get(\"error\")" not in source
    assert ".get(\"worker_pid\")" not in source
