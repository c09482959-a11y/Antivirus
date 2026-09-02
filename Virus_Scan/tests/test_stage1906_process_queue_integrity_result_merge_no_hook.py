from contextlib import contextmanager
import os
from pathlib import Path

from Virus_Scan.scheduler.queue.process_queue_integrity_repair import (
    ProcessQueueIntegrityRepairDependencies,
    ProcessQueueIntegrityRepairRequest,
    reconcile_process_queue_integrity_repair,
)
from Virus_Scan.scheduler.queue.process_queue_result_merge import (
    ProcessQueueResultMergeDependencies,
    ProcessQueueResultMergeRequest,
    merge_process_queue_results,
)


class HostileScalar:
    def __bool__(self):
        raise AssertionError("bool hook executed")

    def __str__(self):
        raise AssertionError("str hook executed")

    def __format__(self, spec):
        raise AssertionError("format hook executed")

    def __fspath__(self):
        raise AssertionError("fspath hook executed")

    def get(self, key, default=None):
        raise AssertionError("mapping get hook executed")


class HostileException(RuntimeError):
    def __str__(self):
        raise AssertionError("exception str hook executed")

    def __format__(self, spec):
        raise AssertionError("exception format hook executed")


@contextmanager
def _working_directory(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _queue_dirs(base: Path):
    pending = base / "pending"
    active = base / "active"
    done = base / "done"
    failed = base / "failed"
    for path in (pending, active, done, failed):
        path.mkdir(parents=True, exist_ok=True)
    return pending, active, done, failed


def _merge_dependencies(tmp_path: Path, **overrides):
    logs = []
    issues = []
    pending, active, done, failed = _queue_dirs(tmp_path / "queue")
    values = {
        "read_json_file": lambda *_args, **_kwargs: {},
        "load_queue_file_results": lambda _queue_dir: {},
        "queue_job_dirs": lambda _queue_dir: (pending, active, done, failed),
        "is_job_json_name": lambda _name: True,
        "done_jobs_missing_results": lambda _queue_dir, _merged: [],
        "repair_failed_queue_job_diagnostics": lambda _queue_dir: None,
        "cleanup_diagnostic_tmp_files": lambda _queue_dir, **_kwargs: None,
        "collect_failed_queue_report": lambda *_args, **_kwargs: [],
        "summarize_failed_queue_report": lambda *_args, **_kwargs: [],
        "safe_queue_listdir": lambda _path: [],
        "record_issue": lambda stage, exc, **extra: issues.append((stage, extra)),
        "log_error": logs.append,
        "log_info": logs.append,
        "recoverable_exceptions": (OSError, RuntimeError, TypeError, ValueError),
    }
    values.update(overrides)
    return ProcessQueueResultMergeDependencies(**values), issues, logs


def test_integrity_repair_failure_message_rejects_hostile_phase_and_exception_without_hooks():
    logs = []
    deps = ProcessQueueIntegrityRepairDependencies(
        verify_and_repair=lambda *_args, **_kwargs: (_ for _ in ()).throw(HostileException("boom")),
        log_error=logs.append,
        report_suppressed=lambda *_args, **_kwargs: None,
        recoverable_exceptions=(RuntimeError,),
    )

    result = reconcile_process_queue_integrity_repair(
        ProcessQueueIntegrityRepairRequest(
            queue_dir="queue",
            all_files=(),
            phase=HostileScalar(),
            repair=HostileScalar(),
        ),
        deps,
    )

    assert result is False
    assert logs == [
        "process queue unknown integrity repair failed: "
        + "HostileException: scheduler diagnostic detail unavailable without caller hooks"
    ]


def test_result_merge_rejects_hostile_queue_and_missing_result_record_without_hooks(tmp_path):
    hostile = HostileScalar()
    deps, issues, logs = _merge_dependencies(
        tmp_path,
        load_queue_file_results=lambda _queue_dir: (_ for _ in ()).throw(HostileException("durable")),
        done_jobs_missing_results=lambda _queue_dir, _merged: [hostile],
    )

    with _working_directory(tmp_path):
        output = merge_process_queue_results(
            ProcessQueueResultMergeRequest(
                queue_dir=hostile,
                outputs=(),
                all_files=(),
                partial_output_path=None,
                strict_had_error=hostile,
            ),
            deps,
        )

    assert output.had_error is True
    assert issues and issues[0][0] == "process_queue_durable_result_merge_failed"
    assert issues[0][1]["extra"]["queue_dir"].startswith("<HostileScalar unsupported_process_queue_dir")
    assert any(message.startswith("process queue durable result merge failed: ") for message in logs)
    assert any("done markers without durable merged results=1" in message for message in logs)
    assert any("process_queue_queue_job_rejected" in message for message in logs)
    assert not (tmp_path / "missing_process_queue_partial_output_path.partial").exists()


def test_result_merge_missing_partial_path_uses_default_failure_report_without_sentinel(tmp_path):
    pending, active, done, failed = _queue_dirs(tmp_path / "q3")
    deps, _issues, logs = _merge_dependencies(
        tmp_path,
        queue_job_dirs=lambda _queue_dir: (pending, active, done, failed),
        safe_queue_listdir=lambda path: ["job.json"] if path is pending else [],
        collect_failed_queue_report=lambda *_args, **_kwargs: [{"stage": "failed"}],
        summarize_failed_queue_report=lambda *_args, **_kwargs: [(("job", "stage", "error", "detail"), 1)],
    )

    with _working_directory(tmp_path):
        output = merge_process_queue_results(
            ProcessQueueResultMergeRequest(
                queue_dir=tmp_path / "q3",
                outputs=(),
                all_files=(),
                partial_output_path=None,
                strict_had_error=False,
            ),
            deps,
        )

    assert output.had_error is True
    assert (tmp_path / "umige_queue_failures.json").exists()
    assert not (tmp_path / "missing_process_queue_partial_output_path.queue_failures.json").exists()
    assert not (tmp_path / "missing_process_queue_partial_output_path.partial").exists()
    assert any(message.startswith("process queue failure diagnostics written: ") for message in logs)


def test_result_merge_incomplete_failure_report_and_partial_path_reject_hostile_values_without_hooks(tmp_path):
    hostile = HostileScalar()
    pending, active, done, failed = _queue_dirs(tmp_path / "q2")
    deps, _issues, logs = _merge_dependencies(
        tmp_path,
        queue_job_dirs=lambda _queue_dir: (pending, active, done, failed),
        safe_queue_listdir=lambda path: ["job.json"] if path is pending else [],
        collect_failed_queue_report=lambda *_args, **_kwargs: [{"stage": "failed"}],
        summarize_failed_queue_report=lambda *_args, **_kwargs: [((hostile, hostile, hostile, hostile), hostile)],
    )

    with _working_directory(tmp_path):
        output = merge_process_queue_results(
            ProcessQueueResultMergeRequest(
                queue_dir=tmp_path / "q2",
                outputs=(),
                all_files=(),
                partial_output_path=hostile,
                strict_had_error=False,
            ),
            deps,
        )

    assert output.had_error is True
    assert any("process queue incomplete: pending=1 active=0 failed=0" == message for message in logs)
    assert any("process_queue_failed_reason_count_rejected" in message for message in logs)
    assert any(message.startswith("process queue failure report path rejected: <HostileScalar") for message in logs)
    assert any(message.startswith("process queue failure diagnostics written: ") for message in logs)
    assert any(message.startswith("process queue partial output path rejected: <HostileScalar") for message in logs)
