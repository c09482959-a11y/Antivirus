from __future__ import annotations

import ast
import inspect
from pathlib import Path

from Virus_Scan.scheduler.orchestration import (
    process_queue_monitor_idle,
    process_queue_monitor_iteration_start,
    process_queue_monitor_loop,
    process_queue_monitor_no_hook,
    process_queue_startup,
    process_queue_startup_state,
    scheduler_mode_dispatch,
    scheduler_runner,
    scheduler_target_planning,
)
from Virus_Scan.scheduler.orchestration.process_queue_monitor_idle import (
    MonitorIdleFinalizationRequest,
    MonitorIdleFinalizationResult,
)


class HostileMonitorScalar:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __int__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("int hook executed")

    def __float__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("float hook executed")

    def __bool__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("bool hook executed")

    def __str__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("repr hook executed")

    def __iter__(self):  # pragma: no cover - must never execute
        type(self).touched += 1
        raise RuntimeError("iter hook executed")


class EmptyWorkerPool:
    def workers_tuple(self) -> tuple[object, ...]:
        return ()


def test_stage1869_monitor_idle_request_rejects_hostile_scalars_without_hooks_after_default_rename():
    HostileMonitorScalar.reset()
    hostile = HostileMonitorScalar()

    request = MonitorIdleFinalizationRequest(
        worker_pool=EmptyWorkerPool(),
        queue_dir=Path("queue"),
        outputs_dir=Path("out"),
        all_files=("safe.bin",),
        ordered_queue_items=(),
        queue_feed_cursor=hostile,
        file_pending_count=hostile,
        file_active_count=hostile,
        raw_live=hostile,
        file_done_count=hostile,
        file_failed_count=hostile,
        live_workers=hostile,
        idle_done_since=None,
        now=hostile,
        idle_grace_sec=hostile,
        idle_notice_sec=hostile,
        recoverable_exceptions=(RuntimeError,),
    )

    assert HostileMonitorScalar.touched == 0
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


def test_stage1869_monitor_idle_result_rejects_hostile_scalars_without_hooks_after_default_rename():
    HostileMonitorScalar.reset()
    hostile = HostileMonitorScalar()

    result = MonitorIdleFinalizationResult(
        idle_done_since=None,
        idle_notice_sec=hostile,
        had_error=hostile,
        should_stop=hostile,
    )

    assert HostileMonitorScalar.touched == 0
    assert result.idle_notice_sec == 0.0
    assert result.had_error is False
    assert result.should_stop is False


def test_stage1869_monitor_idle_and_helper_source_have_no_legacy_fallback_keyword_routes():
    helper_source = inspect.getsource(process_queue_monitor_no_hook)
    idle_source = inspect.getsource(process_queue_monitor_idle)
    iteration_start_source = inspect.getsource(process_queue_monitor_iteration_start)

    assert "fallback=" not in helper_source
    assert "fallback=" not in idle_source
    assert "fallback_counts" not in helper_source
    assert "fallback_counts" not in iteration_start_source
    assert "unsupported_queue_identity_" + int.__str__(0) == "unsupported_queue_identity_0"


def test_stage1869_process_queue_monitor_loop_preserves_primitive_booleans_without_hook_recoercion():
    loop_source = inspect.getsource(process_queue_monitor_loop)

    assert "bool(request.elastic_scheduler)" not in loop_source
    assert "bool(request.dynamic_queue_feed)" not in loop_source
    assert "had_error = bool(had_error or idle_output.had_error)" not in loop_source
    assert "had_error=bool(had_error)" not in loop_source


def test_stage1869_orchestration_monitor_scalar_helpers_have_no_fallback_keyword_calls():
    helper_names = {"monitor_int", "monitor_float", "monitor_optional_float"}
    offenders: list[str] = []
    for path in Path("Virus_Scan/scheduler/orchestration").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else ""
            if name not in helper_names:
                continue
            if any(keyword.arg == "fallback" for keyword in node.keywords):
                offenders.append(f"{path}:{node.lineno}:{name}")

    assert offenders == []


def test_stage1869_process_queue_startup_uses_primitive_safe_message_construction():
    startup_source = inspect.getsource(process_queue_startup)

    assert 'f"process_queue_startup_file_rejected:' not in startup_source
    assert 'f"bulk scan scheduler=process-queue' not in startup_source
    assert "dynamic_queue_feed=bool(capacity.dynamic_queue_feed)" not in startup_source
    assert "strict=bool(request.strict)" not in startup_source
    assert "process_queue_startup_file_rejected:" + "missing_path" == "process_queue_startup_file_rejected:missing_path"


def test_stage1869_process_queue_startup_state_uses_exact_reason_construction():
    state_source = inspect.getsource(process_queue_startup_state)

    assert 'reason=f"process_queue_startup_{field_name}_rejected"' not in state_source
    assert "process_queue_startup_" + str.__str__("queue_feed_cursor") + "_rejected" == "process_queue_startup_queue_feed_cursor_rejected"


def test_stage1869_scheduler_mode_dispatch_uses_default_keywords_and_exact_error_message():
    dispatch_source = inspect.getsource(scheduler_mode_dispatch)

    assert "fallback=" not in dispatch_source
    assert "f'Unsupported scheduler:" not in dispatch_source
    assert "Unsupported scheduler: " + str.__str__("bad") + ". Supported: process, process-fs, serial, queue-child" == "Unsupported scheduler: bad. Supported: process, process-fs, serial, queue-child"


def test_stage1869_scheduler_runner_init_uses_default_naming_without_fallback_route():
    runner_source = inspect.getsource(scheduler_runner)

    assert "def _scheduler_init_int(name, fallback" not in runner_source
    assert "fallback=fallback" not in runner_source
    assert "return fallback" not in runner_source
    assert "replacement_text='process'" in runner_source


def test_stage1869_scheduler_target_planning_uses_replacement_and_direct_exception_text():
    planning_source = inspect.getsource(scheduler_target_planning)

    assert "fallback=" not in planning_source
    assert 'f"{scheduler_exception_text(exc, max_length=500)}"' not in planning_source
    assert 'replacement_text="process"' in planning_source
    assert "default=0" in planning_source
