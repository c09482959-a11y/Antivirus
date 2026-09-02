from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, cast

from Virus_Scan.scheduler.orchestration.process_queue_monitor_iteration_start import (
    MonitorIterationStartRequest,
    _apply_feed_counts,
)
from Virus_Scan.scheduler.orchestration.process_queue_monitor_recovery import MonitorRecoveryRequest, MonitorRecoveryResult
from Virus_Scan.scheduler.orchestration.process_queue_monitor_scaling_feed import MonitorScalingFeedRequest, MonitorScalingFeedResult


class HostileMonitorBoundaryValue:
    touched = 0

    @classmethod
    def reset(cls):
        cls.touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str monitor boundary value")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr monitor boundary value")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("do not format monitor boundary value")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not int monitor boundary value")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not float monitor boundary value")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool monitor boundary value")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate monitor boundary value")


class HostileMappingLike:
    touched = 0

    @classmethod
    def reset(cls):
        cls.touched = 0

    def __getattribute__(self, name):
        if name not in {"touched", "reset", "__class__"}:
            type(self).touched += 1
            raise RuntimeError("do not inspect mapping-like object")
        return object.__getattribute__(self, name)

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool mapping-like object")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate mapping-like object")


class DummyWorkerPool:
    pass


def setup_function(_func):
    HostileMonitorBoundaryValue.reset()
    HostileMappingLike.reset()


def test_stage1625_iteration_contract_rejects_hostile_scalars_paths_and_identities_without_hooks():
    hostile = HostileMonitorBoundaryValue()

    request = cast(Any, MonitorIterationStartRequest)(
        worker_pool=DummyWorkerPool(),
        queue_dir=Path("queue"),
        all_files=["safe.bin", hostile],
        ordered_queue_items=(hostile,),
        raw_stage_progress_state={"safe": ["value"]},
        progress_stall_sec=hostile,
        per_file_timeout_sec=hostile,
        last_integrity_repair_time=hostile,
        elastic_scheduler=hostile,
        process_count=hostile,
        requested_process_count=hostile,
        queue_feed_cursor=hostile,
        next_worker_spawn_id=hostile,
        dynamic_queue_feed=hostile,
        queue_total_enqueued=hostile,
        queue_enqueued_identities=["job-a", hostile],
        queue_last_feed_log=hostile,
        recoverable_exceptions=hostile,
    )

    assert HostileMonitorBoundaryValue.touched == 0
    assert request.all_files[0] == "safe.bin"
    assert request.all_files[1]["unsupported_scheduler_value"] is True
    assert request.all_files[1]["field_name"] == "scheduler_path"
    assert request.ordered_queue_items[0]["unsupported_scheduler_value"] is True
    assert request.progress_stall_sec == 0.0
    assert request.per_file_timeout_sec == 0.0
    assert request.elastic_scheduler is False
    assert request.process_count == 0
    assert request.queue_enqueued_identities == frozenset({"job-a", "unsupported_queue_identity_1"})
    assert request.recoverable_exceptions == ()


def test_stage1625_recovery_contract_rejects_hostile_files_scalars_and_exceptions_without_hooks():
    hostile = HostileMonitorBoundaryValue()

    request = cast(Any, MonitorRecoveryRequest)(
        worker_pool=DummyWorkerPool(),
        queue_dir=Path("queue"),
        all_files=[hostile],
        raw_stage_progress_state=hostile,
        progress_stall_sec=hostile,
        per_file_timeout_sec=hostile,
        last_integrity_repair_time=hostile,
        recoverable_exceptions=hostile,
    )
    result = cast(Any, MonitorRecoveryResult)(
        live_workers=hostile,
        raw_stage_progress_state=hostile,
        last_integrity_repair_time=hostile,
        stale_recovery_evidence=(hostile,),
    )

    assert HostileMonitorBoundaryValue.touched == 0
    assert request.all_files[0]["unsupported_scheduler_value"] is True
    assert request.progress_stall_sec == 0.0
    assert request.per_file_timeout_sec == 0.0
    assert request.last_integrity_repair_time == 0.0
    assert request.recoverable_exceptions == ()
    assert result.live_workers == 0
    assert result.raw_stage_progress_state["unsupported_scheduler_value"] is True
    assert result.stale_recovery_evidence[0]["unsupported_scheduler_value"] is True


def test_stage1625_scaling_contract_rejects_hostile_mappings_and_scalars_without_hooks():
    hostile = HostileMonitorBoundaryValue()
    hostile_mapping = HostileMappingLike()

    request = cast(Any, MonitorScalingFeedRequest)(
        worker_pool=DummyWorkerPool(),
        enabled_elastic_scheduler=hostile,
        process_count=hostile,
        requested_process_count=hostile,
        queue_dir=Path("queue"),
        ordered_queue_items=(hostile,),
        queue_feed_cursor=hostile,
        file_pending_count=hostile,
        file_active_count=hostile,
        raw_live=hostile,
        live_workers=hostile,
        next_worker_spawn_id=hostile,
        dynamic_queue_feed=hostile,
        queue_total_enqueued=hostile,
        queue_enqueued_identities=[hostile],
        elastic_io_sample=hostile_mapping,
        all_files_count=hostile,
        queue_last_feed_log=hostile,
        recoverable_exceptions=hostile,
    )
    result = cast(Any, MonitorScalingFeedResult)(
        live_workers=hostile,
        next_worker_spawn_id=hostile,
        elastic_target_workers=hostile,
        elastic_cpu_sample=None,
        elastic_io_sample=hostile_mapping,
        queue_feed_cursor=hostile,
        queue_total_enqueued=hostile,
        queue_enqueued_identities=[hostile],
        queue_last_feed_log=hostile,
        counts=None,
        worker_spawn_failures=(hostile,),
    )

    assert HostileMonitorBoundaryValue.touched == 0
    assert HostileMappingLike.touched == 0
    assert request.enabled_elastic_scheduler is False
    assert request.process_count == 0
    assert request.ordered_queue_items[0]["unsupported_scheduler_value"] is True
    assert request.elastic_io_sample["scheduler_monitor_elastic_io_sample_unavailable"] is True
    assert request.elastic_io_sample["reason"] == "process_queue_monitor_elastic_io_sample_rejected"
    assert result.live_workers == 0
    assert result.elastic_io_sample["scheduler_monitor_elastic_io_sample_unavailable"] is True
    assert result.worker_spawn_failures[0]["unsupported_scheduler_value"] is True


def test_stage1625_feed_counts_rejects_hostile_mapping_like_without_bool_iter_or_item_hooks():
    hostile_mapping = HostileMappingLike()

    done, failed, active, pending, raw_live, counts = cast(Any, _apply_feed_counts)(
        hostile_mapping,
        file_done_count=1,
        file_failed_count=2,
        file_active_count=3,
        file_pending_count=4,
        raw_live=5,
        default_counts={"safe": "default"},
    )

    assert HostileMappingLike.touched == 0
    assert (done, failed, active, pending, raw_live) == (1, 2, 3, 4, 5)
    assert counts["scheduler_monitor_feed_counts_unavailable"] is True
    assert counts["reason"] == "process_queue_monitor_feed_counts_rejected"


def test_stage1625_monitor_iteration_files_no_longer_use_direct_hookable_scalar_conversions():
    forbidden = {"str", "repr", "format", "int", "float", "bool", "dict", "vars", "getattr", "hasattr"}
    checked = (
        Path("Virus_Scan/scheduler/orchestration/process_queue_monitor_iteration_start.py"),
        Path("Virus_Scan/scheduler/orchestration/process_queue_monitor_recovery.py"),
        Path("Virus_Scan/scheduler/orchestration/process_queue_monitor_scaling_feed.py"),
    )
    offenders: list[str] = []
    for path in checked:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in forbidden:
                offenders.append(f"{path}:{node.lineno}:{node.func.id}")
    assert offenders == []
