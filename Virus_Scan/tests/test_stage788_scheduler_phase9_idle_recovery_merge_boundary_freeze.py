from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from Virus_Scan.scheduler.orchestration.process_queue_monitor_idle import (
    MonitorIdleFinalizationRequest,
    MonitorIdleFinalizationResult,
)
from Virus_Scan.scheduler.orchestration.process_queue_monitor_recovery import (
    MonitorRecoveryRequest,
    MonitorRecoveryResult,
)
from Virus_Scan.scheduler.queue.process_queue_idle_finalization import ProcessQueueIdleFinalizationRequest
from Virus_Scan.scheduler.queue.process_queue_result_merge import ProcessQueueResultMergeRequest


class _WorkerPool:
    workers = ()

    def workers_tuple(self):
        return tuple(self.workers)


def _assert_immutable_mapping(value: object) -> None:
    assert isinstance(value, Mapping)
    with pytest.raises(TypeError):
        value["late"] = "mutation"  # type: ignore[index]


def test_stage788_idle_finalization_contracts_freeze_direct_inputs() -> None:
    all_files = ["a.bin", "b.bin"]
    procs: list[list[Any]] = [["proc", {"pid": 1}]]
    request = cast(Any, ProcessQueueIdleFinalizationRequest)(
        feed_complete=1,
        no_live_queue_work=1,
        accounted_files="1",
        total_files="2",
        idle_done_since=None,
        now="3.5",
        idle_grace_sec="1.25",
        idle_notice_sec="0.5",
        all_files=all_files,
        queue_dir=Path("queue"),
        outputs_dir=Path("outputs"),
        procs=procs,
        live_workers="0",
    )
    all_files.append("late.bin")
    procs[0].append("late")

    assert request.feed_complete is True
    assert request.no_live_queue_work is True
    assert request.accounted_files == 1
    assert request.total_files == 2
    assert request.now == 3.5
    assert request.idle_grace_sec == 1.25
    assert request.idle_notice_sec == 0.5
    assert request.all_files == ("a.bin", "b.bin")
    assert request.procs == (("proc", {"pid": 1}),)
    _assert_immutable_mapping(request.procs[0][1])
    assert request.live_workers == 0


def test_stage788_monitor_idle_contracts_freeze_ordered_queue_items() -> None:
    all_files = [Path("a.bin")]
    ordered_queue_items = [{"job": ["a", "b"]}]
    request = cast(Any, MonitorIdleFinalizationRequest)(
        worker_pool=_WorkerPool(),
        queue_dir=Path("queue"),
        outputs_dir=Path("outputs"),
        all_files=all_files,
        ordered_queue_items=ordered_queue_items,
        queue_feed_cursor="1",
        file_pending_count="2",
        file_active_count="3",
        raw_live="4",
        file_done_count="5",
        file_failed_count="6",
        live_workers="7",
        idle_done_since=None,
        now="8.0",
        idle_grace_sec="9.0",
        idle_notice_sec="10.0",
        recoverable_exceptions=[RuntimeError],
    )
    all_files.append(Path("late.bin"))
    ordered_queue_items[0]["job"].append("late")

    assert request.all_files == ("a.bin",)
    assert request.ordered_queue_items[0]["job"] == ("a", "b")
    _assert_immutable_mapping(request.ordered_queue_items[0])
    assert request.queue_feed_cursor == 1
    assert request.file_pending_count == 2
    assert request.file_active_count == 3
    assert request.raw_live == 4
    assert request.file_done_count == 5
    assert request.file_failed_count == 6
    assert request.live_workers == 7
    assert request.recoverable_exceptions == (RuntimeError,)

    result = cast(Any, MonitorIdleFinalizationResult)(idle_done_since=None, idle_notice_sec="1.5", had_error=1, should_stop=0)
    assert result.idle_notice_sec == 1.5
    assert result.had_error is True
    assert result.should_stop is False


def test_stage788_monitor_recovery_contracts_freeze_state_and_evidence() -> None:
    all_files = [Path("a.bin")]
    raw_state = {"stage": {"items": ["x"]}}
    evidence = [{"event": ["stale"]}]
    request = cast(Any, MonitorRecoveryRequest)(
        worker_pool=_WorkerPool(),
        queue_dir=Path("queue"),
        all_files=all_files,
        raw_stage_progress_state=raw_state,
        progress_stall_sec="2.5",
        per_file_timeout_sec="3.5",
        last_integrity_repair_time="4.5",
        recoverable_exceptions=[RuntimeError],
    )
    result = cast(Any, MonitorRecoveryResult)(
        live_workers="5",
        raw_stage_progress_state=raw_state,
        last_integrity_repair_time="6.5",
        stale_recovery_evidence=evidence,
    )
    all_files.append(Path("late.bin"))
    raw_state["stage"]["items"].append("late")
    evidence[0]["event"].append("late")

    assert request.all_files == ("a.bin",)
    assert request.raw_stage_progress_state["stage"]["items"] == ("x",)
    _assert_immutable_mapping(request.raw_stage_progress_state)
    assert request.progress_stall_sec == 2.5
    assert request.per_file_timeout_sec == 3.5
    assert request.last_integrity_repair_time == 4.5
    assert request.recoverable_exceptions == (RuntimeError,)

    assert result.live_workers == 5
    assert result.raw_stage_progress_state["stage"]["items"] == ("x",)
    assert result.stale_recovery_evidence[0]["event"] == ("stale",)
    _assert_immutable_mapping(result.raw_stage_progress_state)
    _assert_immutable_mapping(result.stale_recovery_evidence[0])


def test_stage788_result_merge_request_freezes_direct_sequences() -> None:
    outputs = [{"worker": ["out"]}]
    files = [{"path": ["a"]}]
    request = cast(Any, ProcessQueueResultMergeRequest)(
        queue_dir=Path("queue"),
        outputs=outputs,
        all_files=files,
        partial_output_path=None,
        strict_had_error=1,
    )
    outputs[0]["worker"].append("late")
    files[0]["path"].append("late")

    assert request.outputs[0]["worker"] == ("out",)
    assert request.all_files[0]["path"] == ("a",)
    _assert_immutable_mapping(request.outputs[0])
    _assert_immutable_mapping(request.all_files[0])
    assert request.strict_had_error is True
