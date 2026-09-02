from __future__ import annotations
from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

import ast
from collections import deque
from pathlib import Path
from queue import Queue

from Virus_Scan.scheduler.orchestration import inmemory_parent_dispatch
from Virus_Scan.scheduler.orchestration.inmemory_parent_dispatch import (
    _submitted_count,
    dispatch_inmemory_parent_jobs,
)
from Virus_Scan.scheduler.workers.inmemory_job_dispatch import InMemoryDispatchBatch


class HostileDispatchBatch:
    touched = False

    def __getattribute__(self, name):  # pragma: no cover - must not execute for submitted
        if name == "submitted":
            type(self).touched = True
            raise AssertionError("submitted attribute hook executed")
        return object.__getattribute__(self, name)


class HostileSubmitted:
    touched = False

    def __int__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("submitted int hook executed")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("submitted bool hook executed")


class Recovery:
    def __init__(self) -> None:
        self.lifecycle = []

    def record_lifecycle_request(self, *args, **kwargs):
        self.lifecycle.append((args, kwargs))


def test_submitted_count_accepts_exact_dispatch_batch_without_int_hooks() -> None:
    assert _submitted_count(InMemoryDispatchBatch(4, False, "")) == 4
    assert _submitted_count(InMemoryDispatchBatch(HostileSubmitted(), False, "")) == 0  # type: ignore[arg-type]
    assert HostileSubmitted.touched is False


def test_submitted_count_rejects_non_owned_batch_without_attribute_hooks() -> None:
    HostileDispatchBatch.touched = False

    assert _submitted_count(HostileDispatchBatch()) == 0

    assert HostileDispatchBatch.touched is False


def test_dispatch_inmemory_parent_jobs_reports_submitted_count_from_owned_batch() -> None:
    pending = deque([(1, "sample.bin", 0)])
    job_records = {1: {"attempt": 0, "cost": {}}}
    recovery = Recovery()
    task_queue = Queue()

    submitted = dispatch_inmemory_parent_jobs(
        pending=pending,
        job_records=job_records,
        terminal=set(),
        task_queue=task_queue,
        active=[],
        state_index=InMemorySchedulerStateIndex(),
        max_inflight=4,
        max_queued_unstarted=4,
        logical_slots=1,
        workers=1,
        recovery=recovery,
        ewma_state={},
        now=lambda: 123.0,
    )

    assert submitted == 1
    assert pending == deque()
    assert task_queue.get_nowait() == (1, "sample.bin", 0)
    assert job_records[1]["state"] == "queued"
    assert recovery.lifecycle


def test_inmemory_parent_dispatch_has_no_submitted_int_hook_route() -> None:
    source = Path(inmemory_parent_dispatch.__file__).read_text(encoding="utf-8")
    assert "int(dispatch_batch.submitted" not in source
    assert "dispatch_batch.submitted or" not in source
    tree = ast.parse(source)
    assert not any(
        isinstance(node, ast.Call)
        and getattr(node.func, "id", "") == "int"
        and node.args
        and isinstance(node.args[0], ast.Attribute)
        and node.args[0].attr == "submitted"
        for node in ast.walk(tree)
    )
