from pathlib import Path, PurePosixPath
import threading

from Virus_Scan.scheduler.api.thread_lifecycle import SchedulerThreadPool
from Virus_Scan.scheduler.evidence.checkpoint_writer import write_scheduler_checkpoint
from Virus_Scan.scheduler.evidence.trace_writer import write_scheduler_trace
from Virus_Scan.scheduler.ownership.raw_stage_jobs import (
    RawStageJobBuildDependencies,
    build_raw_stage_jobs,
)
from Virus_Scan.scheduler.queue.process_queue_result_merge import (
    ProcessQueueResultMergeDependencies,
    ProcessQueueResultMergeRequest,
    merge_process_queue_results,
)
from Virus_Scan.runtime.yara_rules_state import YaraRulesState


def _merge_dependencies(*, read_json_file=lambda *_args, **_kwargs: {}):
    issues = []
    logs = []
    deps = ProcessQueueResultMergeDependencies(
        read_json_file=read_json_file,
        load_queue_file_results=lambda _queue_dir: {},
        queue_job_dirs=lambda queue_dir: (
            Path(queue_dir) / "pending",
            Path(queue_dir) / "active",
            Path(queue_dir) / "done",
            Path(queue_dir) / "failed",
        ),
        is_job_json_name=lambda _name: True,
        done_jobs_missing_results=lambda _queue_dir, _merged: [],
        repair_failed_queue_job_diagnostics=lambda _queue_dir: None,
        cleanup_diagnostic_tmp_files=lambda _queue_dir, **_kwargs: None,
        collect_failed_queue_report=lambda *_args, **_kwargs: [],
        summarize_failed_queue_report=lambda *_args, **_kwargs: [],
        safe_queue_listdir=lambda _path: [],
        record_issue=lambda stage, exc, **extra: issues.append((stage, type(exc).__name__, extra)),
        log_error=logs.append,
        log_info=logs.append,
        recoverable_exceptions=(OSError, RuntimeError, TypeError, ValueError),
    )
    return deps, issues, logs


def test_stage1755_missing_worker_output_is_an_explicit_merge_failure(tmp_path) -> None:
    missing_output = tmp_path / "missing-worker.json"
    deps, issues, logs = _merge_dependencies()

    output = merge_process_queue_results(
        ProcessQueueResultMergeRequest(
            queue_dir=tmp_path / "queue",
            outputs=(str(missing_output),),
            all_files=(),
            partial_output_path=None,
            strict_had_error=False,
        ),
        deps,
    )

    assert output.had_error is True
    assert issues[0][0] == "process_queue_worker_output_missing"
    assert issues[0][2]["fatal"] is True
    assert logs


def test_stage1755_invalid_worker_output_mapping_is_rejected_without_iteration(tmp_path) -> None:
    class HostileOutput:
        touched = 0

        def __iter__(self):
            type(self).touched += 1
            raise RuntimeError("worker output iteration executed")

        def __bool__(self):
            type(self).touched += 1
            raise RuntimeError("worker output bool executed")

    output_path = tmp_path / "worker.json"
    output_path.write_text("{}", encoding="utf-8")
    deps, issues, _logs = _merge_dependencies(read_json_file=lambda *_args, **_kwargs: HostileOutput())

    output = merge_process_queue_results(
        ProcessQueueResultMergeRequest(
            queue_dir=tmp_path / "queue",
            outputs=(str(output_path),),
            all_files=(),
            partial_output_path=None,
            strict_had_error=False,
        ),
        deps,
    )

    assert output.had_error is True
    assert issues[0][0] == "process_queue_worker_output_invalid"
    assert HostileOutput.touched == 0


def test_stage1755_false_partial_writer_marks_merge_failed(tmp_path) -> None:
    deps, issues, _logs = _merge_dependencies()
    blocked_parent = tmp_path / "blocked-parent"
    blocked_parent.write_text("not a directory", encoding="utf-8")

    output = merge_process_queue_results(
        ProcessQueueResultMergeRequest(
            queue_dir=tmp_path / "queue",
            outputs=(),
            all_files=(),
            partial_output_path=blocked_parent / "partial.json",
            strict_had_error=False,
        ),
        deps,
    )

    assert output.had_error is True
    assert issues[-1][0] == "process_queue_partial_output_write_failed"
    assert issues[-1][2]["fatal"] is True


def test_stage1755_raw_job_probe_failures_are_recorded(tmp_path) -> None:
    failures = []
    missing_file = tmp_path / "missing.bin"
    deps = RawStageJobBuildDependencies(
        get_scan_extension=lambda _path: ".bin",
        runtime_value=lambda _name, default=None: default,
        raw_collector_cap=lambda _collector: 128,
        raw_chunk_bytes=lambda: 65536,
        raw_queue_max_chunks=lambda: 4,
        retry_max=lambda _kind: 0,
        record_suppressed=lambda stage, exc: failures.append((stage, type(exc).__name__)),
        yara_rules_state=YaraRulesState,
        yara_parallel_group_count=lambda _source: 1,
        deep_scan_thorough=lambda: False,
    )

    jobs = build_raw_stage_jobs(
        missing_file,
        "file-id",
        "binary",
        "binary",
        {},
        deps=deps,
    )

    assert jobs
    assert failures == [
        ("raw_build_jobs_file_size_failed", "FileNotFoundError"),
        ("raw_build_jobs_file_probe_failed", "FileNotFoundError"),
    ]



def test_stage2182_raw_stage_admission_caps_emit_replayable_evidence(tmp_path) -> None:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"A" * 40000)

    per_file_failures = []
    per_file_deps = RawStageJobBuildDependencies(
        get_scan_extension=lambda _path: ".bin",
        runtime_value=lambda name, default=None: 1 if name == "RAW_PER_FILE_ACTIVE_CAP" else default,
        raw_collector_cap=lambda _collector: 128,
        raw_chunk_bytes=lambda: 16384,
        raw_queue_max_chunks=lambda: 3,
        retry_max=lambda _kind: 0,
        record_suppressed=lambda stage, exc: per_file_failures.append((stage, type(exc).__name__)),
        yara_rules_state=YaraRulesState,
        yara_parallel_group_count=lambda _source: 1,
        deep_scan_thorough=lambda: False,
    )

    per_file_jobs = build_raw_stage_jobs(target, "file-id", "other", "other", {}, deps=per_file_deps)

    assert len(per_file_jobs) == 1
    assert ("raw_stage_job_per_file_cap_reached", "RuntimeError") in per_file_failures

    collector_failures = []
    collector_deps = RawStageJobBuildDependencies(
        get_scan_extension=lambda _path: ".bin",
        runtime_value=lambda name, default=None: 128 if name == "RAW_PER_FILE_ACTIVE_CAP" else default,
        raw_collector_cap=lambda _collector: 1,
        raw_chunk_bytes=lambda: 16384,
        raw_queue_max_chunks=lambda: 3,
        retry_max=lambda _kind: 0,
        record_suppressed=lambda stage, exc: collector_failures.append((stage, type(exc).__name__)),
        yara_rules_state=YaraRulesState,
        yara_parallel_group_count=lambda _source: 1,
        deep_scan_thorough=lambda: False,
    )

    collector_jobs = build_raw_stage_jobs(target, "file-id", "other", "other", {}, deps=collector_deps)

    assert collector_jobs
    assert ("raw_stage_job_collector_cap_reached", "RuntimeError") in collector_failures

def test_stage1755_repeated_scheduler_thread_pools_leave_no_named_threads() -> None:
    prefix = "stage1755-scheduler-leak-check"

    for _index in range(3):
        with SchedulerThreadPool(
            max_workers=2,
            thread_name_prefix=prefix,
            cancel_on_error=True,
        ) as pool:
            assert pool.submit(lambda: "done").result(timeout=2) == "done"

    leaked = [thread.name for thread in threading.enumerate() if thread.name.startswith(prefix)]
    assert leaked == []


def test_stage1755_checkpoint_and_trace_reject_path_subclasses_without_hooks() -> None:
    class HostilePurePath(PurePosixPath):
        touched = 0

        def __str__(self):
            type(self).touched += 1
            raise RuntimeError("path str hook executed")

        def as_posix(self):
            type(self).touched += 1
            raise RuntimeError("path as_posix hook executed")

    hostile = HostilePurePath("scheduler.json")
    writes = []

    checkpoint = write_scheduler_checkpoint(
        hostile,
        {},
        write_json=lambda *_args, **_kwargs: writes.append(True) or True,
    )
    trace = write_scheduler_trace(
        hostile,
        (),
        write_json=lambda *_args, **_kwargs: writes.append(True) or True,
    )

    assert checkpoint.status == "failed"
    assert checkpoint.evidence[0].error_category == "checkpoint_path_rejected"
    assert trace.status == "failed"
    assert trace.evidence[0].error_category == "trace_path_rejected"
    assert writes == []
    assert HostilePurePath.touched == 0


def test_stage1755_checkpoint_and_trace_preserve_exact_pure_paths() -> None:
    writes = []
    exact_path = PurePosixPath("scheduler.json")

    checkpoint = write_scheduler_checkpoint(
        exact_path,
        {},
        write_json=lambda *_args, **_kwargs: writes.append(True) or True,
    )
    trace = write_scheduler_trace(
        exact_path,
        (),
        write_json=lambda *_args, **_kwargs: writes.append(True) or True,
    )

    assert checkpoint.status == "written"
    assert trace.status == "written"
    assert writes == [True, True]
