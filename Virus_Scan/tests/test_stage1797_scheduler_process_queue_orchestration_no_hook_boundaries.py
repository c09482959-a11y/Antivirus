from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from Virus_Scan.scheduler.orchestration.process_queue_monitor_idle import (
    MonitorIdleFinalizationRequest,
    MonitorIdleFinalizationResult,
)
from Virus_Scan.scheduler.orchestration.process_queue_startup_admission import (
    ProcessQueueStartupAdmissionRequest,
    ProcessQueueStartupAdmissionResult,
)
from Virus_Scan.scheduler.orchestration.process_queue_startup_workers import (
    ProcessQueueStartupWorkerRequest,
    ProcessQueueStartupWorkerResult,
)
from Virus_Scan.scheduler.orchestration.process_queue_monitor_progress_publish import (
    MonitorProgressPublicationRequest,
)
from Virus_Scan.scheduler.orchestration.process_queue_monitor_stall import MonitorStallRequest
from Virus_Scan.scheduler.orchestration.process_queue_worker_pool_state import (
    ProcessQueueParentWorkerPool,
)
from Virus_Scan.scheduler.runtime.process_queue_environment import (
    ProcessQueueChildEnvironmentDependencies,
    ProcessQueueChildEnvironmentRequest,
    build_process_queue_child_environment,
)


class HostileValue:
    str_calls = 0
    repr_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    getattribute_calls = 0

    def __getattribute__(self, name):
        if name == "__class__":
            type(self).getattribute_calls += 1
            raise AssertionError("__class__ hook must not execute")
        return object.__getattribute__(self, name)

    def __str__(self):
        type(self).str_calls += 1
        raise AssertionError("__str__ hook must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise AssertionError("__repr__ hook must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise AssertionError("__bool__ hook must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise AssertionError("__iter__ hook must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise AssertionError("__float__ hook must not execute")

    def __int__(self):
        type(self).int_calls += 1
        raise AssertionError("__int__ hook must not execute")


def _reset() -> None:
    HostileValue.str_calls = 0
    HostileValue.repr_calls = 0
    HostileValue.bool_calls = 0
    HostileValue.iter_calls = 0
    HostileValue.float_calls = 0
    HostileValue.int_calls = 0
    HostileValue.getattribute_calls = 0


def _assert_no_hooks() -> None:
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.iter_calls == 0
    assert HostileValue.float_calls == 0
    assert HostileValue.int_calls == 0
    assert HostileValue.getattribute_calls == 0


def test_stage1797_startup_admission_request_rejects_hostile_primitives_without_hooks() -> None:
    _reset()

    request = cast(Any, ProcessQueueStartupAdmissionRequest)(
        queue_dir=Path("queue"),
        all_files=HostileValue(),
        process_count=HostileValue(),
        requested_process_count=HostileValue(),
        dynamic_queue_feed=HostileValue(),
    )

    assert request.process_count == 0
    assert request.requested_process_count == 0
    assert request.dynamic_queue_feed is False
    assert request.all_files[0]["unsupported_scheduler_value"] is True
    _assert_no_hooks()


def test_stage1797_startup_admission_result_rejects_hostile_scalars_without_hooks() -> None:
    _reset()

    result = cast(Any, ProcessQueueStartupAdmissionResult)(
        ordered_queue_items=(),
        queue_feed_cursor=HostileValue(),
        queue_enqueued_identities=HostileValue(),
        queue_total_enqueued=HostileValue(),
    )

    assert result.queue_feed_cursor == 0
    assert result.queue_total_enqueued == 0
    assert result.queue_enqueued_identities == frozenset()
    _assert_no_hooks()


def test_stage1797_monitor_idle_request_rejects_hostile_scalars_without_hooks() -> None:
    _reset()

    request = cast(Any, MonitorIdleFinalizationRequest)(
        worker_pool=object(),
        queue_dir=Path("queue"),
        outputs_dir=Path("out"),
        all_files=HostileValue(),
        ordered_queue_items=(),
        queue_feed_cursor=HostileValue(),
        file_pending_count=HostileValue(),
        file_active_count=HostileValue(),
        raw_live=HostileValue(),
        file_done_count=HostileValue(),
        file_failed_count=HostileValue(),
        live_workers=HostileValue(),
        idle_done_since=None,
        now=HostileValue(),
        idle_grace_sec=HostileValue(),
        idle_notice_sec=HostileValue(),
        recoverable_exceptions=HostileValue(),
    )

    assert request.all_files[0]["unsupported_scheduler_value"] is True
    assert request.queue_feed_cursor == 0
    assert request.file_pending_count == 0
    assert request.file_active_count == 0
    assert request.raw_live == 0
    assert request.file_done_count == 0
    assert request.file_failed_count == 0
    assert request.live_workers == 0
    assert request.now == 0.0
    assert request.idle_grace_sec == 0.0
    assert request.idle_notice_sec == 0.0
    assert request.recoverable_exceptions == ()
    _assert_no_hooks()


def test_stage1797_monitor_idle_result_rejects_hostile_scalars_without_hooks() -> None:
    _reset()

    result = cast(Any, MonitorIdleFinalizationResult)(
        idle_done_since=None,
        idle_notice_sec=HostileValue(),
        had_error=HostileValue(),
        should_stop=HostileValue(),
    )

    assert result.idle_notice_sec == 0.0
    assert result.had_error is False
    assert result.should_stop is False
    _assert_no_hooks()


def test_stage1797_startup_worker_contracts_reject_hostile_scalars_without_hooks() -> None:
    _reset()

    request = cast(Any, ProcessQueueStartupWorkerRequest)(
        queue_dir=Path("queue"),
        worker_pool=object(),
        process_count=HostileValue(),
        requested_process_count=HostileValue(),
    )
    result = cast(Any, ProcessQueueStartupWorkerResult)(
        elastic_scheduler=HostileValue(),
        elastic_min_workers=HostileValue(),
        next_worker_spawn_id=HostileValue(),
        worker_spawn_failures=(),
    )

    assert request.process_count == 0
    assert request.requested_process_count == 0
    assert result.elastic_scheduler is False
    assert result.elastic_min_workers == 0
    assert result.next_worker_spawn_id == 0
    _assert_no_hooks()

def test_stage1797_monitor_progress_request_rejects_hostile_scalars_without_hooks() -> None:
    _reset()

    request = cast(Any, MonitorProgressPublicationRequest)(
        worker_pool=object(),
        partial_output_path=None,
        file_done_count=HostileValue(),
        file_failed_count=HostileValue(),
        file_active_count=HostileValue(),
        file_pending_count=HostileValue(),
        raw_live=HostileValue(),
        raw_done=HostileValue(),
        raw_failed=HostileValue(),
        live_workers=HostileValue(),
        total_files=HostileValue(),
        progress_every=HostileValue(),
        last_done_count=HostileValue(),
        last_progress_time=HostileValue(),
        progress_interval_sec=HostileValue(),
        last_monitor_heartbeat_time=HostileValue(),
        monitor_heartbeat_sec=HostileValue(),
        accounted_total=HostileValue(),
        elastic_cpu_sample=None,
        now=HostileValue(),
        recoverable_exceptions=HostileValue(),
    )

    assert request.file_done_count == 0
    assert request.progress_every == 1
    assert request.now == 0.0
    assert request.recoverable_exceptions == ()
    _assert_no_hooks()


def test_stage1797_monitor_stall_request_rejects_hostile_scalars_without_hooks() -> None:
    _reset()

    request = cast(Any, MonitorStallRequest)(
        worker_pool=object(),
        live_workers=HostileValue(),
        file_active_count=HostileValue(),
        file_pending_count=HostileValue(),
        raw_live=HostileValue(),
        accounted_total=HostileValue(),
        last_accounted_total=HostileValue(),
        last_accounted_change_time=HostileValue(),
        now=HostileValue(),
        queue_progress_stall_sec=HostileValue(),
        queue_dir=Path("queue"),
        raw_stage_progress_state=HostileValue(),
        recoverable_exceptions=HostileValue(),
    )

    assert request.live_workers == 0
    assert request.accounted_total == 0
    assert request.last_accounted_change_time == 0.0
    assert request.raw_stage_progress_state["scheduler_mapping_unavailable"] is True
    assert request.recoverable_exceptions == ()
    _assert_no_hooks()


def test_stage1797_worker_pool_state_rejects_hostile_collections_without_hooks() -> None:
    _reset()

    pool = cast(Any, ProcessQueueParentWorkerPool)(
        root=Path("root"),
        queue_dir=Path("queue"),
        outputs_dir=Path("out"),
        script_path=Path("worker.py"),
        python_executable=Path("python"),
        env_base=HostileValue(),
        progress_every=HostileValue(),
        partial_output_every=HostileValue(),
        slow_file_warn_sec=HostileValue(),
        per_file_timeout_sec=HostileValue(),
        throttle_sec=HostileValue(),
        strict=HostileValue(),
        subprocess_stdin=lambda: None,
        windows_creationflags=lambda: 0,
        log_error=lambda _message: None,
        recoverable_exceptions=HostileValue(),
        scan_session_manifest_path=Path("scan_session_snapshot.json"),
        outputs=HostileValue(),
        workers=HostileValue(),
    )

    assert pool.env_base == {}
    assert pool.outputs == []
    assert pool.workers == []
    assert pool.progress_every == 1
    assert pool.strict is False
    assert pool.recoverable_exceptions == ()
    _assert_no_hooks()


def test_stage1797_child_environment_rejects_hostile_runtime_value_without_hooks() -> None:
    _reset()

    request = cast(Any, ProcessQueueChildEnvironmentRequest)(
        env={"UMIGE_DEEP_SCAN_MODE": "auto"},
        dynamic_queue_feed=HostileValue(),
    )
    output = build_process_queue_child_environment(
        request,
        cast(Any, ProcessQueueChildEnvironmentDependencies)(
            runtime_value=lambda _name, _default: HostileValue(),
        ),
    )

    assert output.env["UMIGE_DYNAMIC_QUEUE_FEED"] == "0"
    assert output.env["UMIGE_DEEP_SCAN_MODE"] == "auto"
    _assert_no_hooks()
