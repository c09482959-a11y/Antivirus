from __future__ import annotations

from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from Virus_Scan.tests.support.static_inventory import read_python_file


from collections import deque
from pathlib import Path

from Virus_Scan.scheduler.workers.inmemory_file_scan import execute_inmemory_scan_one_file
from Virus_Scan.scheduler.workers.inmemory_job_dispatch import dispatch_ready_inmemory_jobs
from Virus_Scan.scheduler.workers.inmemory_lifecycle_policy import (
    deterministic_lifecycle_epoch,
    deterministic_worker_process_name,
    inmemory_stage_is_pre_execution,
    inmemory_start_wait_budget,
)


class HostileScalar:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("repr hook executed")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("format hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("bool hook executed")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("int hook executed")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("float hook executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("iter hook executed")


class HostileMapping(dict):
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def get(self, *_args, **_kwargs):
        type(self).touched += 1
        raise RuntimeError("mapping get hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("mapping bool hook executed")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("mapping items hook executed")


class CapturingQueue:
    def __init__(self) -> None:
        self.items = []

    def put(self, item, *, timeout):
        self.items.append((item, timeout))


def test_stage1950_lifecycle_policy_rejects_hostile_values_without_hooks() -> None:
    HostileScalar.reset()
    HostileMapping.reset()
    hostile = HostileScalar()

    epoch = deterministic_lifecycle_epoch(hostile, hostile)
    worker_name = deterministic_worker_process_name(prefix=hostile, epoch=hostile, sequence=hostile)
    is_pre_execution = inmemory_stage_is_pre_execution(hostile)
    wait_budget = inmemory_start_wait_budget(HostileMapping(timeout_budget=HostileMapping(timeout_budget=hostile)), hostile)

    assert isinstance(epoch, int)
    assert worker_name == "umige-inmem-r00000000-00000"
    assert is_pre_execution is False
    assert wait_budget == 300.0
    assert HostileScalar.touched == 0
    assert HostileMapping.touched == 0


def test_stage1950_dispatch_rejects_hostile_attempt_and_reason_without_hooks() -> None:
    HostileScalar.reset()
    hostile = HostileScalar()
    pending = deque([(1, "sample.bin", hostile)])
    task_queue = CapturingQueue()
    reasons = []
    lifecycle = []
    retried = []

    result = dispatch_ready_inmemory_jobs(
        pending=pending,
        job_records={1: {"attempt": 0, "cost": {"heavy": True, "weight": hostile}}},
        terminal=set(),
        task_queue=task_queue,
        state_index=InMemorySchedulerStateIndex(),
        max_inflight=2,
        max_queued_unstarted=2,
        logical_slots=1,
        workers=1,
        heavy_cap=10,
        decide_backpressure=lambda **_kwargs: (False, hostile),
        mark_retry_admitted=lambda rec, *, attempt, now: retried.append((rec, attempt, now)),
        lifecycle_recorder=lambda request: lifecycle.append((request.job_id, request.attempt, request.transition, {"worker_pid": request.worker_pid, "reason": request.reason, "state": request.state})),
        backpressure_recorder=lambda reason: reasons.append(reason),
        queue_full_exception=RuntimeError,
        now=lambda: 12.5,
    )

    assert result.submitted == 1
    assert result.blocked is False
    assert result.block_reason == ""
    assert task_queue.items == [((1, "sample.bin", 0), 0.05)]
    assert retried[0][1] == 0
    assert lifecycle[0][1] == 0
    assert reasons == []
    assert HostileScalar.touched == 0


def test_stage1950_dispatch_block_reason_falls_back_without_str_hook() -> None:
    HostileScalar.reset()
    hostile = HostileScalar()
    reasons = []

    result = dispatch_ready_inmemory_jobs(
        pending=deque([(1, "sample.bin", 0)]),
        job_records={1: {"attempt": 0}},
        terminal=set(),
        task_queue=CapturingQueue(),
        state_index=InMemorySchedulerStateIndex(),
        max_inflight=2,
        max_queued_unstarted=2,
        logical_slots=1,
        workers=1,
        heavy_cap=1,
        decide_backpressure=lambda **_kwargs: (True, hostile),
        mark_retry_admitted=lambda *_args, **_kwargs: None,
        lifecycle_recorder=lambda _request: None,
        backpressure_recorder=lambda reason: reasons.append(reason),
        queue_full_exception=RuntimeError,
        now=lambda: 0.0,
    )

    assert result.submitted == 0
    assert result.blocked is True
    assert result.block_reason == "dispatch_backpressure"
    assert reasons == ["dispatch_backpressure"]
    assert HostileScalar.touched == 0


def test_stage1950_inmemory_file_scan_rejects_hostile_cfg_without_hooks() -> None:
    HostileScalar.reset()
    HostileMapping.reset()
    result_path, result = execute_inmemory_scan_one_file(HostileScalar(), cfg=HostileMapping())

    assert isinstance(result_path, HostileScalar)
    assert result["class"] == "error"
    assert result["scan_integrity"]["file_failed"] is True
    assert HostileScalar.touched == 0
    assert HostileMapping.touched == 0


def test_stage1950_parent_loop_initial_progress_total_is_nonnegative() -> None:
    text = read_python_file(Path("Virus_Scan/scheduler/orchestration/inmemory_parent_loop.py"))
    assert "last_progress_total = -1" not in text
    assert "last_progress_total = 0" in text
