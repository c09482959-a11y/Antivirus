from Virus_Scan.tests.support.static_inventory import read_python_file

from dataclasses import FrozenInstanceError
from pathlib import Path


def _append_and_return_true(target, value):
    target.append(value)
    return True

from Virus_Scan.scheduler.workers.inmemory_worker_completion import (
    InMemoryWorkerCompletionDrainRequest,
    InMemoryWorkerCompletionDrainResult,
    collect_done_inmemory_worker_futures,
    drain_completed_inmemory_worker_futures,
)
from Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_cycle import (
    InMemoryWorkerHeartbeatCycleResult,
    publish_inmemory_worker_heartbeat_cycle,
)


class _Future:
    def __init__(self, value=None, *, done=True):
        self._value = value
        self._done = done

    def done(self):
        return self._done

    def result(self):
        return self._value


class _ResultQueue:
    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)


def _worker_error(path, exc):
    return {"file": str(path), "error": str(exc), "scan_integrity": {"worker_error": True}}


def test_inmemory_worker_completion_drain_returns_immutable_evidence_and_publishes_result():
    future = _Future(("a.bin", {"file": "a.bin", "tags": []}))
    active = {future: {"job_id": 7, "path": "a.bin", "attempt": 2}}
    result_q = _ResultQueue()

    result = drain_completed_inmemory_worker_futures(InMemoryWorkerCompletionDrainRequest(
        done_futures=collect_done_inmemory_worker_futures(active),
        active=active,
        result_q=result_q,
        max_jobs_per_worker=10,
        processed_jobs=0,
        worker_error_result=_worker_error,
        recoverable_exceptions=(Exception,),
        record_suppressed=lambda _stage, _exc: None,
    ))

    assert isinstance(result, InMemoryWorkerCompletionDrainResult)
    assert result.processed_jobs == 1
    assert result.completed_futures == 1
    assert result.stop_requested is False
    assert active == {}
    assert result_q.items[0][0] == "result"
    assert result_q.items[0][1] == 7
    try:
        result.processed_jobs = 9
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("completion drain evidence must be immutable")


def test_inmemory_worker_heartbeat_cycle_returns_immutable_evidence_and_updates_shared_heartbeat():
    updates = []

    class Flags:
        running = 1
        cancel_request = 2
        poisoned_or_retire_mask = 4

    result = publish_inmemory_worker_heartbeat_cycle(
        active={object(): {"job_id": 3, "attempt": 1, "stage": "scan", "progress_counter": 1}},
        cfg={},
        cancel_table={},
        heartbeat_table={},
        heartbeat_flags=Flags(),
        completed_jobs=2,
        cancel_requested=lambda _table, _job_id, _attempt: False,
        update_shared_heartbeat=lambda *args, **kwargs: _append_and_return_true(updates, (args, kwargs)),
        process_id=1234,
        now_hb=10.0,
        last_heartbeat_emit=1.0,
        heartbeat_interval=1.0,
        heartbeat_seq=4,
        recoverable_exceptions=(Exception,),
        record_suppressed=lambda _stage, _exc: None,
    )

    assert isinstance(result, InMemoryWorkerHeartbeatCycleResult)
    assert result.heartbeat_published is True
    assert result.heartbeat_seq == 5
    assert result.last_heartbeat_emit == 10.0
    assert result.stop_requested is False
    assert updates
    try:
        result.heartbeat_seq = 99
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("heartbeat cycle evidence must be immutable")


def test_inmemory_worker_process_delegates_completion_and_heartbeat_cycle_to_worker_modules():
    text = read_python_file(Path("Virus_Scan/scheduler/workers/inmemory_worker_process.py"))
    assert "collect_done_inmemory_worker_futures" in text
    assert "drain_completed_inmemory_worker_futures" in text
    assert "publish_inmemory_worker_heartbeat_cycle" in text
    assert "publish_completed_inmemory_worker_result" not in text
    assert "publish_active_worker_heartbeats" not in text
