"""Stage2636.11020 Phase 18 session-owned intrastage executor gates."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import MappingProxyType
import multiprocessing
import os
import threading
import time

from Virus_Scan.contracts.intrastage_execution import IntrastageExecutionPlan
from Virus_Scan.contracts.no_hook_materialization import materialize_json_no_hook
from Virus_Scan.contracts.scan_session_snapshot import scan_session_snapshot_from_record
from Virus_Scan.routing.extension_intrastage import run_raw_task_queue
from Virus_Scan.routing.intrastage_executor_session import (
    active_intrastage_execution_plan,
    close_intrastage_executor_session,
    intrastage_executor_metrics,
    start_intrastage_executor_session,
)
from Virus_Scan.runtime.api import (
    mitre_runtime_snapshot,
    scheduler_runtime_state,
    yara_runtime_snapshot,
)
from Virus_Scan.scheduler.api.runtime import (
    get_scheduler_multiprocessing_context,
    scheduler_worker_shared_persistence_writes_disabled,
    stage_limit_for_name,
    stage_semaphore_for_name,
)
from Virus_Scan.scheduler.workers.inmemory_worker_assignment import InMemoryAssignedTask
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture


def _tag_collector(tag: str) -> list[str]:
    return [tag]


def _slow_tag_collector(tag: str, delay: float = 0.002) -> list[str]:
    time.sleep(delay)
    return [tag]


def _raising_collector() -> list[str]:
    raise RuntimeError("phase18_expected_failure")


def _append_marker(path: str, marker: str) -> list[str]:
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(marker + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return [marker]


def _terminate_process() -> list[str]:
    os._exit(17)


def _length_collector(value: str) -> list[str]:
    return [str(len(value))]


def _process_runtime_probe() -> tuple[list[str], dict[str, object]]:
    plan = active_intrastage_execution_plan()
    metrics_before = intrastage_executor_metrics()
    nested = run_raw_task_queue(_tasks(3), max_workers=2)
    metrics_after = intrastage_executor_metrics()
    yara = yara_runtime_snapshot()
    mitre = mitre_runtime_snapshot()
    repository = mitre.repository
    stage_tables = scheduler_runtime_state().stage_tables_snapshot()
    return ["phase18_process_runtime"], {
        "defer_profile_writes": scheduler_runtime_state().defer_profile_writes,
        "generation_id": None if metrics_before is None else metrics_before.generation_id,
        "mitre_available": mitre.available,
        "mitre_dataset_version": None if repository is None else repository.version.dataset_version,
        "mitre_enabled": mitre.enabled,
        "mitre_repository_digest": None if repository is None else repository.digest,
        "nested_process_executor_starts": (
            None if metrics_after is None else metrics_after.process_executor_start_count
        ),
        "nested_tags": _tags(nested),
        "nested_thread_executor_starts": (
            None if metrics_after is None else metrics_after.thread_executor_start_count
        ),
        "persistence_writes_disabled": scheduler_worker_shared_persistence_writes_disabled(),
        "plan_digest": None if plan is None else plan.digest,
        "plan_present": plan is not None,
        "process_worker_flag": os.environ.get("UMIGE_INTRASTAGE_PROCESS_WORKER"),
        "stage_failure_evidence": materialize_json_no_hook(
            stage_tables["stage_table_evidence"],
            context="phase18_test_stage_failure_evidence",
        ),
        "stage_limit_generic": stage_limit_for_name("generic"),
        "stage_semaphore_present": stage_semaphore_for_name("generic") is not None,
        "yara_available": yara.available,
        "yara_enabled": yara.enabled,
    }


def _tasks(count: int = 3) -> list[tuple[object, object, tuple[object, ...], dict[str, object]]]:
    return [
        (f"task_{index}", _tag_collector, (f"tag_{index}",), {})
        for index in range(count)
    ]


def _tags(results: object) -> list[list[str]]:
    assert type(results) is list
    return [result["tags"] for result in results]


def test_concurrency_plan_and_scan_session_round_trip_are_exact() -> None:
    plan = IntrastageExecutionPlan(
        scheduler_mode="process",
        scheduler_worker_count=4,
        stage_parallel_enabled=True,
        intrastage_enabled=True,
        default_backend="thread",
        intrastage_workers=3,
        serial_task_threshold=2,
        max_pending_tasks=12,
        max_process_task_bytes=256 * 1024,
    )
    assert IntrastageExecutionPlan.from_record(plan.to_record()) == plan
    assert IntrastageExecutionPlan.from_record(plan.to_record()).digest == plan.digest
    changed = IntrastageExecutionPlan(
        scheduler_mode="process",
        scheduler_worker_count=4,
        stage_parallel_enabled=True,
        intrastage_enabled=True,
        default_backend="thread",
        intrastage_workers=4,
        serial_task_threshold=2,
        max_pending_tasks=16,
        max_process_task_bytes=256 * 1024,
    )
    assert changed.digest != plan.digest

    snapshot = scan_session_snapshot_fixture(scan_mode="serial", generation_seed="a")
    rebuilt = scan_session_snapshot_from_record(snapshot.to_record())
    assert rebuilt == snapshot
    assert rebuilt.concurrency_plan.digest == rebuilt.concurrency_digest
    assert rebuilt.schema_version == "scan_session_snapshot_v3"


def test_two_task_batch_runs_serially_without_executor_creation() -> None:
    close_intrastage_executor_session()
    snapshot = scan_session_snapshot_fixture(scan_mode="serial", generation_seed="b")
    start_intrastage_executor_session(snapshot)
    try:
        results = run_raw_task_queue(_tasks(2), max_workers=2, backend="thread")
        assert _tags(results) == [["tag_0"], ["tag_1"]]
        metrics = intrastage_executor_metrics()
        assert metrics is not None
        assert metrics.serial_batch_count == 1
        assert metrics.thread_executor_start_count == 0
        assert metrics.process_executor_start_count == 0
    finally:
        closed = close_intrastage_executor_session(snapshot)
    assert closed is not None and closed.closed is True


def test_thread_executor_starts_once_and_is_reused_across_batches() -> None:
    close_intrastage_executor_session()
    snapshot = scan_session_snapshot_fixture(scan_mode="serial", generation_seed="c")
    first = start_intrastage_executor_session(snapshot)
    second = start_intrastage_executor_session(snapshot)
    assert first.session_start_count == 1
    assert second.session_reuse_count == 1
    try:
        for _ in range(10):
            results = run_raw_task_queue(_tasks(3), max_workers=2, backend="thread")
            assert _tags(results) == [["tag_0"], ["tag_1"], ["tag_2"]]
        metrics = intrastage_executor_metrics()
        assert metrics is not None
        assert metrics.batch_count == 10
        assert metrics.thread_batch_count == 10
        assert metrics.thread_executor_start_count == 1
        assert metrics.executor_reuse_count == 9
        assert metrics.task_submission_count == 30
        assert metrics.task_completion_count == 30
        assert metrics.task_failure_count == 0
        assert metrics.max_inflight_tasks <= snapshot.concurrency_plan.max_pending_tasks
    finally:
        closed = close_intrastage_executor_session(snapshot)
    assert closed is not None
    assert closed.thread_executor_start_count == 1
    assert closed.closed is True
    assert not any(
        thread.name.startswith("umige-intrastage-")
        for thread in threading.enumerate()
    )


def test_process_executor_is_session_bounded_and_semantically_equal() -> None:
    close_intrastage_executor_session()
    prior_children = {child.pid for child in multiprocessing.active_children()}
    snapshot = scan_session_snapshot_fixture(scan_mode="serial", generation_seed="d")
    start_intrastage_executor_session(snapshot)
    try:
        expected = [["tag_0"], ["tag_1"], ["tag_2"]]
        first = run_raw_task_queue(_tasks(3), max_workers=2, backend="process")
        second = run_raw_task_queue(_tasks(3), max_workers=2, backend="process")
        assert _tags(first) == expected
        assert _tags(second) == expected
        metrics = intrastage_executor_metrics()
        assert metrics is not None
        assert metrics.process_executor_start_count == 1
        assert metrics.process_batch_count == 2
        assert metrics.executor_reuse_count >= 1
        assert metrics.process_request_bytes > 0
        assert metrics.process_result_bytes > 0
        assert metrics.task_submission_count == metrics.task_completion_count
    finally:
        close_intrastage_executor_session(snapshot)
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        remaining = {
            child.pid for child in multiprocessing.active_children()
            if child.pid not in prior_children
        }
        if not remaining:
            break
        time.sleep(0.05)
    assert not {
        child.pid for child in multiprocessing.active_children()
        if child.pid not in prior_children
    }


def test_sequential_process_sessions_restart_scheduler_helpers_without_spawn_stall() -> None:
    close_intrastage_executor_session()
    prior_children = {child.pid for child in multiprocessing.active_children()}
    expected = [["tag_0"], ["tag_1"], ["tag_2"]]

    for index in range(6):
        snapshot = scan_session_snapshot_fixture(
            scan_mode="serial",
            generation_seed=f"{index:x}",
        )
        started = start_intrastage_executor_session(snapshot)
        assert started.process_executor_start_count == 0
        try:
            output = run_raw_task_queue(
                _tasks(3),
                max_workers=2,
                backend="process",
            )
            assert _tags(output) == expected
            metrics = intrastage_executor_metrics()
            assert metrics is not None
            assert metrics.process_executor_start_count == 1
            assert metrics.process_backend_failure_count == 0
        finally:
            closed = close_intrastage_executor_session(snapshot)
        assert closed is not None
        assert closed.closed is True

    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        remaining = {
            child.pid
            for child in multiprocessing.active_children()
            if child.pid not in prior_children
        }
        if not remaining:
            break
        time.sleep(0.05)
    assert not {
        child.pid
        for child in multiprocessing.active_children()
        if child.pid not in prior_children
    }


def test_process_workers_bootstrap_exact_session_runtime_and_disable_nested_processes() -> None:
    close_intrastage_executor_session()
    runtime_state = scheduler_runtime_state()
    previous = runtime_state.stage_tables_snapshot()
    context = get_scheduler_multiprocessing_context()
    runtime_state.configure_worker_stage_tables(
        stage_limits={"generic": 3},
        stage_semaphores={"generic": context.BoundedSemaphore(3)},
        failure_evidence=(),
    )
    snapshot = scan_session_snapshot_fixture(scan_mode="serial", generation_seed="8")
    start_intrastage_executor_session(snapshot)
    try:
        output = run_raw_task_queue(
            [(f"probe_{index}", _process_runtime_probe, (), {}) for index in range(3)],
            max_workers=2,
            backend="process",
        )
        assert _tags(output) == [["phase18_process_runtime"]] * 3
        for result in output:
            meta = result["meta"]
            assert meta["generation_id"] == snapshot.generation_id
            assert meta["plan_present"] is True
            assert meta["plan_digest"] == snapshot.concurrency_digest
            assert meta["process_worker_flag"] == "1"
            assert meta["persistence_writes_disabled"] is True
            assert meta["defer_profile_writes"] is True
            assert meta["stage_limit_generic"] == 3
            assert meta["stage_semaphore_present"] is True
            assert meta["yara_enabled"] is False
            assert meta["yara_available"] is False
            assert meta["mitre_enabled"] is False
            assert meta["mitre_available"] is False
            assert meta["mitre_repository_digest"] is None
            assert meta["mitre_dataset_version"] is None
            assert meta["nested_tags"] == [["tag_0"], ["tag_1"], ["tag_2"]]
            assert meta["nested_process_executor_starts"] == 0
            assert meta["nested_thread_executor_starts"] == 1
    finally:
        close_intrastage_executor_session(snapshot)
        runtime_state.configure_worker_stage_tables(
            stage_limits=previous["stage_limits"],
            stage_semaphores=previous["stage_semaphores"],
            failure_evidence=previous["stage_table_evidence"],
        )


def test_process_bootstrap_is_lazy_and_materializes_nested_stage_failure_evidence() -> None:
    close_intrastage_executor_session()
    runtime_state = scheduler_runtime_state()
    previous = runtime_state.stage_tables_snapshot()
    context = get_scheduler_multiprocessing_context()
    runtime_state.configure_worker_stage_tables(
        stage_limits={"generic": 2},
        stage_semaphores={"generic": context.BoundedSemaphore(2)},
        failure_evidence=(
            {
                "reason": "phase18_nested_stage_failure",
                "nested": MappingProxyType({"items": ("alpha", "beta")}),
            },
        ),
    )
    snapshot = scan_session_snapshot_fixture(scan_mode="serial", generation_seed="9")
    start_intrastage_executor_session(snapshot)
    try:
        thread_output = run_raw_task_queue(_tasks(3), max_workers=2, backend="thread")
        assert _tags(thread_output) == [["tag_0"], ["tag_1"], ["tag_2"]]
        before_process = intrastage_executor_metrics()
        assert before_process is not None
        assert before_process.process_executor_start_count == 0

        process_output = run_raw_task_queue(
            [("nested_stage_probe", _process_runtime_probe, (), {})] * 3,
            max_workers=2,
            backend="process",
        )
        assert _tags(process_output) == [["phase18_process_runtime"]] * 3
        expected_evidence = [
            {
                "nested": {"items": ["alpha", "beta"]},
                "reason": "phase18_nested_stage_failure",
            }
        ]
        assert all(
            result["meta"]["stage_failure_evidence"] == expected_evidence
            for result in process_output
        )
        after_process = intrastage_executor_metrics()
        assert after_process is not None
        assert after_process.process_executor_start_count == 1
    finally:
        close_intrastage_executor_session(snapshot)
        runtime_state.configure_worker_stage_tables(
            stage_limits=previous["stage_limits"],
            stage_semaphores=previous["stage_semaphores"],
            failure_evidence=previous["stage_table_evidence"],
        )


def test_unpicklable_process_tasks_are_rejected_without_thread_execution() -> None:
    close_intrastage_executor_session()
    snapshot = scan_session_snapshot_fixture(scan_mode="serial", generation_seed="e")
    start_intrastage_executor_session(snapshot)
    try:
        task_rows = [
            ("lambda_0", lambda: ["lambda_0"], (), {}),
            ("lambda_1", lambda: ["lambda_1"], (), {}),
            ("lambda_2", lambda: ["lambda_2"], (), {}),
        ]
        rejected = run_raw_task_queue(task_rows, max_workers=2, backend="process")
        accepted = run_raw_task_queue(_tasks(3), max_workers=2, backend="process")
        assert [row["error"] for row in rejected] == ["_ProcessTaskNotSerializable"] * 3
        assert _tags(rejected) == [[], [], []]
        assert _tags(accepted) == [["tag_0"], ["tag_1"], ["tag_2"]]
        metrics = intrastage_executor_metrics()
        assert metrics is not None
        assert metrics.process_executor_start_count == 1
        assert metrics.process_backend_failure_count == 0
        assert metrics.serialization_measurement_failures == 3
        assert metrics.thread_executor_start_count == 0
        assert metrics.task_failure_count == 3
    finally:
        close_intrastage_executor_session(snapshot)


def test_process_preflight_rejects_only_invalid_task_without_duplicate_side_effects(tmp_path) -> None:
    close_intrastage_executor_session()
    snapshot = scan_session_snapshot_fixture(scan_mode="serial", generation_seed="0")
    start_intrastage_executor_session(snapshot)
    marker_path = tmp_path / "preflight_markers.txt"
    tasks = [
        ("record_0", _append_marker, (str(marker_path), "record_0"), {}),
        ("lambda", lambda: ["lambda"], (), {}),
        ("record_1", _append_marker, (str(marker_path), "record_1"), {}),
    ]
    try:
        output = run_raw_task_queue(tasks, max_workers=2, backend="process")
        assert _tags(output) == [["record_0"], [], ["record_1"]]
        assert output[1]["error"] == "_ProcessTaskNotSerializable"
        assert sorted(marker_path.read_text(encoding="utf-8").splitlines()) == ["record_0", "record_1"]
        metrics = intrastage_executor_metrics()
        assert metrics is not None
        assert metrics.process_executor_start_count == 1
        assert metrics.process_backend_failure_count == 0
        assert metrics.serialization_measurement_failures == 1
        assert metrics.thread_executor_start_count == 0
        assert metrics.task_submission_count == 3
        assert metrics.task_completion_count == 3
    finally:
        close_intrastage_executor_session(snapshot)


def test_oversized_process_payload_is_rejected_without_thread_execution() -> None:
    close_intrastage_executor_session()
    snapshot = scan_session_snapshot_fixture(scan_mode="serial", generation_seed="6")
    start_intrastage_executor_session(snapshot)
    oversized = "x" * (snapshot.concurrency_plan.max_process_task_bytes + 1024)
    tasks = [
        ("oversized", _length_collector, (oversized,), {}),
        ("small_0", _tag_collector, ("small_0",), {}),
        ("small_1", _tag_collector, ("small_1",), {}),
    ]
    try:
        output = run_raw_task_queue(tasks, max_workers=2, backend="process")
        assert output[0]["error"] == "_ProcessTaskPayloadTooLarge"
        assert _tags(output) == [[], ["small_0"], ["small_1"]]
        metrics = intrastage_executor_metrics()
        assert metrics is not None
        assert metrics.process_executor_start_count == 1
        assert metrics.process_payload_rejection_count == 1
        assert metrics.process_backend_failure_count == 0
        assert metrics.thread_executor_start_count == 0
    finally:
        close_intrastage_executor_session(snapshot)


def test_mid_batch_process_failure_does_not_replay_or_switch_backend(tmp_path) -> None:
    close_intrastage_executor_session()
    snapshot = scan_session_snapshot_fixture(scan_mode="serial", generation_seed="5")
    start_intrastage_executor_session(snapshot)
    marker_path = tmp_path / "process_markers.txt"
    tasks = [
        ("first", _append_marker, (str(marker_path), "first"), {}),
        ("second", _append_marker, (str(marker_path), "second"), {}),
        ("terminate", _terminate_process, (), {}),
        ("third", _append_marker, (str(marker_path), "third"), {}),
    ]
    try:
        output = run_raw_task_queue(tasks, max_workers=2, backend="process")
        assert len(output) == 4
        markers = marker_path.read_text(encoding="utf-8").splitlines()
        assert markers.count("first") == 1
        assert markers.count("second") == 1
        assert markers.count("third") <= 1
        rejected = run_raw_task_queue(_tasks(3), max_workers=2, backend="process")
        assert _tags(rejected) == [[], [], []]
        assert {row["error"] for row in rejected} == {"_ProcessBackendUnavailable"}
        metrics = intrastage_executor_metrics()
        assert metrics is not None
        assert metrics.process_executor_start_count == 1
        assert metrics.process_backend_failure_count == 2
        assert metrics.thread_executor_start_count == 0
    finally:
        close_intrastage_executor_session(snapshot)


def test_collector_failure_is_bounded_and_session_remains_reusable() -> None:
    close_intrastage_executor_session()
    snapshot = scan_session_snapshot_fixture(scan_mode="serial", generation_seed="1")
    start_intrastage_executor_session(snapshot)
    try:
        failed = run_raw_task_queue(
            [("expected_failure", _raising_collector, (), {})] + _tasks(2),
            max_workers=2,
            backend="thread",
        )
        assert failed[0]["error"] == "RuntimeError"
        assert _tags(failed[1:]) == [["tag_0"], ["tag_1"]]
        recovered = run_raw_task_queue(_tasks(3), max_workers=2, backend="thread")
        assert _tags(recovered) == [["tag_0"], ["tag_1"], ["tag_2"]]
        metrics = intrastage_executor_metrics()
        assert metrics is not None
        assert metrics.thread_executor_start_count == 1
        assert metrics.task_failure_count == 1
    finally:
        close_intrastage_executor_session(snapshot)


def test_active_session_plan_is_immutable_against_environment_drift() -> None:
    close_intrastage_executor_session()
    snapshot = scan_session_snapshot_fixture(scan_mode="serial", generation_seed="2")
    keys = (
        "UMIGE_INTRASTAGE_PARALLEL",
        "UMIGE_STAGE_PARALLEL_WORKERS",
        "UMIGE_INTRASTAGE_BACKEND",
    )
    original = {key: os.environ.get(key) for key in keys}
    start_intrastage_executor_session(snapshot)
    try:
        os.environ["UMIGE_INTRASTAGE_PARALLEL"] = "0"
        os.environ["UMIGE_STAGE_PARALLEL_WORKERS"] = "1"
        os.environ["UMIGE_INTRASTAGE_BACKEND"] = "process"
        assert active_intrastage_execution_plan() == snapshot.concurrency_plan
        output = run_raw_task_queue(_tasks(3))
        assert _tags(output) == [["tag_0"], ["tag_1"], ["tag_2"]]
        metrics = intrastage_executor_metrics()
        assert metrics is not None
        assert metrics.thread_executor_start_count == 1
        assert metrics.process_executor_start_count == 0
    finally:
        close_intrastage_executor_session(snapshot)
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_direct_api_without_session_is_serial_and_does_not_create_pool() -> None:
    close_intrastage_executor_session()
    before_threads = {thread.ident for thread in threading.enumerate()}
    output = run_raw_task_queue(_tasks(3), max_workers=3, backend="thread")
    assert _tags(output) == [["tag_0"], ["tag_1"], ["tag_2"]]
    assert active_intrastage_execution_plan() is None
    assert {thread.ident for thread in threading.enumerate()} == before_threads


def test_active_generation_cannot_be_replaced_until_closed() -> None:
    close_intrastage_executor_session()
    first = scan_session_snapshot_fixture(scan_mode="serial", generation_seed="3")
    second = scan_session_snapshot_fixture(scan_mode="serial", generation_seed="4")
    start_intrastage_executor_session(first)
    try:
        try:
            start_intrastage_executor_session(second)
        except RuntimeError as exc:
            assert str(exc) == "intrastage_executor_generation_already_active"
        else:
            raise AssertionError("active executor generation was replaced")
    finally:
        close_intrastage_executor_session(first)

def test_shared_executor_backpressure_is_bounded_across_concurrent_file_calls() -> None:
    close_intrastage_executor_session()
    snapshot = scan_session_snapshot_fixture(scan_mode="serial", generation_seed="f")
    start_intrastage_executor_session(snapshot)
    task_rows = [
        (f"slow_{index}", _slow_tag_collector, (f"slow_tag_{index}",), {})
        for index in range(6)
    ]
    try:
        with ThreadPoolExecutor(max_workers=4) as callers:
            futures = [
                callers.submit(run_raw_task_queue, task_rows, 2, "thread")
                for _ in range(8)
            ]
            outputs = [future.result(timeout=30) for future in futures]
        assert all(
            _tags(output) == [[f"slow_tag_{index}"] for index in range(6)]
            for output in outputs
        )
        metrics = intrastage_executor_metrics()
        assert metrics is not None
        assert metrics.thread_executor_start_count == 1
        assert metrics.batch_count == 8
        assert metrics.task_submission_count == 48
        assert metrics.task_completion_count == 48
        assert metrics.max_inflight_tasks <= snapshot.concurrency_plan.max_pending_tasks
        assert metrics.backpressure_wait_ns >= 0
        assert metrics.queue_wait_ns >= 0
    finally:
        close_intrastage_executor_session(snapshot)



def test_worker_ipc_assignment_is_compact_and_session_bootstrap_occurs_once() -> None:
    assert tuple(InMemoryAssignedTask.__dataclass_fields__) == ("job_id", "path", "attempt")
    root = Path(__file__).resolve().parents[2]
    bootstrap_source = (
        root / "Virus_Scan/scheduler/workers/inmemory_worker_bootstrap.py"
    ).read_text(encoding="utf-8")
    worker_source = (
        root / "Virus_Scan/scheduler/workers/inmemory_worker_process.py"
    ).read_text(encoding="utf-8")
    assignment_source = (
        root / "Virus_Scan/scheduler/workers/inmemory_worker_assignment.py"
    ).read_text(encoding="utf-8")
    assert bootstrap_source.count('worker_config.pop("scan_session_manifest", None)') == 1
    assert worker_source.count("start_intrastage_executor_session(snapshot)") == 1
    assert "scan_session_snapshot" not in assignment_source.split("class InMemoryAssignedTask", 1)[1].split("class InMemoryWorkerAssignmentPublicationResult", 1)[0]

def test_executor_ownership_and_lifecycle_are_singular_in_current_source() -> None:
    root = Path(__file__).resolve().parents[2]
    extension_source = (root / "Virus_Scan/routing/extension_intrastage.py").read_text(encoding="utf-8")
    owner_source = (root / "Virus_Scan/routing/intrastage_executor_session.py").read_text(encoding="utf-8")
    runner_source = (root / "Virus_Scan/scheduler/orchestration/scheduler_runner.py").read_text(encoding="utf-8")
    worker_source = (root / "Virus_Scan/scheduler/workers/inmemory_worker_process.py").read_text(encoding="utf-8")

    assert "ThreadPoolExecutor(" not in extension_source
    assert "ProcessPoolExecutor(" not in extension_source
    assert owner_source.count("ThreadPoolExecutor(") == 1
    assert owner_source.count("ProcessPoolExecutor(") == 1
    assert "start_intrastage_executor_session(scan_session_snapshot)" in runner_source
    assert "close_intrastage_executor_session(scan_session_snapshot)" in runner_source
    assert "start_intrastage_executor_session(snapshot)" in worker_source
    assert "if executor_session_started:" in worker_source
    assert "close_intrastage_executor_session(snapshot)" in worker_source
    assert "thread_name_prefix" not in extension_source


def test_process_backend_has_no_thread_fallback_path() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "routing"
        / "intrastage_executor_session.py"
    ).read_text(encoding="utf-8")
    assert "process_backend_fallback" not in source
    assert "using session thread executor" not in source
    assert '_execute_parallel(\n                        tasks,\n                        backend="thread"' not in source
