from Virus_Scan.contracts.result_record import make_worker_error_result
from Virus_Scan.scheduler.workers.child_failure_metadata import (
    build_safe_exception_info,
    safe_exception_info,
    worker_error_result,
)
from Virus_Scan.scheduler.workers.child_result_publication import (
    WorkerOutputUpdateRequest,
    update_worker_output,
)


class HostilePath:
    touched = 0

    def __str__(self):
        HostilePath.touched += 1
        raise RuntimeError("path string hook executed")

    def __repr__(self):
        HostilePath.touched += 1
        raise RuntimeError("path repr hook executed")

    def __format__(self, _spec):
        HostilePath.touched += 1
        raise RuntimeError("path format hook executed")

    def __bool__(self):
        HostilePath.touched += 1
        raise RuntimeError("path bool hook executed")


class HostileError(RuntimeError):
    touched = 0

    def __str__(self):
        HostileError.touched += 1
        raise RuntimeError("error string hook executed")

    def __repr__(self):
        HostileError.touched += 1
        raise RuntimeError("error repr hook executed")

    def __format__(self, _spec):
        HostileError.touched += 1
        raise RuntimeError("error format hook executed")


class HostileJob(dict):
    touched = 0

    def get(self, *_args, **_kwargs):
        HostileJob.touched += 1
        raise RuntimeError("job get hook executed")

    def items(self):
        HostileJob.touched += 1
        raise RuntimeError("job items hook executed")


class HostileMapping(dict):
    touched = 0

    def get(self, *_args, **_kwargs):
        HostileMapping.touched += 1
        raise RuntimeError("result get hook executed")

    def items(self):
        HostileMapping.touched += 1
        raise RuntimeError("result items hook executed")


def _reset():
    HostilePath.touched = 0
    HostileError.touched = 0
    HostileJob.touched = 0
    HostileMapping.touched = 0


def test_stage1586_build_safe_exception_info_does_not_stringify_hostile_exception():
    _reset()
    info = build_safe_exception_info(HostileError("boom"), stage="stage1586")

    assert HostileError.touched == 0
    assert info["exception_type"] == "HostileError"
    assert info["error"] == "HostileError"
    assert info["traceback_unavailable_reason"] == "scheduler_exception_traceback_not_materialized_without_hooks"


def test_stage1586_safe_exception_info_fallback_avoids_job_mapping_and_exception_hooks():
    _reset()

    def bad_builder(*_args, **_kwargs):
        raise HostileError("metadata boom")

    reports = []
    info = safe_exception_info(
        HostileError("root boom"),
        stage="stage1586",
        job=HostileJob(attempt=9),
        exception_info_builder=bad_builder,
        report=lambda where, exc: reports.append((where, type(exc).__name__)),
        recoverable_exceptions=(HostileError,),
    )

    assert HostileError.touched == 0
    assert HostileJob.touched == 0
    assert info["error"] == "HostileError"
    assert info["exception_info_builder_unavailable_reason"] == "caller_owned_exception_info_builder_rejected"
    assert info["attempt"] == 0
    assert reports == []


def test_stage1586_worker_error_result_rejects_hostile_path_and_nonmaterializable_result():
    _reset()

    def hostile_result(_path, _exc):
        return HostileMapping(file="x", scan_integrity={})

    result, info = worker_error_result(
        HostilePath(),
        HostileError("boom"),
        stage="stage1586",
        job=HostileJob(attempt=5),
        make_error_result=hostile_result,
        exception_info_builder=build_safe_exception_info,
        report=lambda *_args: None,
        recoverable_exceptions=(RuntimeError,),
    )

    assert HostilePath.touched == 0
    assert HostileError.touched == 0
    assert HostileJob.touched == 0
    assert HostileMapping.touched == 0
    assert info["file_path_unavailable_reason"] == "unsafe_scheduler_worker_path_rejected"
    assert info["worker_error_result_unavailable_reason"] == "non_materializable_worker_error_result"
    assert result["queue_failure"] is True
    assert result["scan_integrity"]["allow_learning"] is False


def test_stage1586_update_worker_output_rejects_hostile_output_path_without_str_bool_or_write():
    _reset()
    child_results = {}
    reports = []

    ok = update_worker_output(
        WorkerOutputUpdateRequest(
            worker_output_path=HostilePath(),
            file_path="a.bin",
            result={"file": "a.bin", "tags": []},
            child_results=child_results,
            context="stage1586.worker_output",
            report=lambda where, exc: reports.append((where, type(exc).__name__, exc.args)),
        )
    )

    assert ok is False
    assert HostilePath.touched == 0
    assert "__scheduler_worker_output_publication_failure__" in child_results
    evidence = child_results["__scheduler_worker_output_publication_failure__"]
    assert evidence["queue_failure"] is True
    assert evidence["worker_output_publication_reason"] == "RuntimeError"
    assert reports == [
        (
            "stage1586.worker_output.aggregate_write_rejected",
            "RuntimeError",
            ("aggregate worker output publication rejected",),
        )
    ]


def test_stage1586_existing_worker_error_result_still_preserves_builtin_message(tmp_path):
    _reset()
    result, info = worker_error_result(
        str(tmp_path / "bad.bin"),
        RuntimeError("boom"),
        stage="stage1586",
        job={"attempt": 2},
        make_error_result=make_worker_error_result,
        exception_info_builder=build_safe_exception_info,
        report=lambda *_args: None,
        recoverable_exceptions=(RuntimeError,),
    )

    assert info["error"] == "boom"
    assert info["attempt"] == 2
    assert result["queue_failure"] is True
    assert {"scanner_failure", "scanner_degraded", "scan_incomplete"} <= set(result["tags"])
