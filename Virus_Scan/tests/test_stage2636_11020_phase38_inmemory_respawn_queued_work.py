from __future__ import annotations
from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

from types import SimpleNamespace

from Virus_Scan.scheduler.workers.inmemory_spawn import (
    InMemoryWorkerRespawnRequest,
    respawn_missing_inmemory_workers,
)


class _SpawnedProcess:
    def __init__(self, kwargs: dict[str, object], *, pid: int) -> None:
        self.kwargs = kwargs
        self.daemon = None
        self.started = False
        self._popen = SimpleNamespace(pid=pid)

    def start(self) -> None:
        self.started = True

    def is_alive(self) -> bool:
        return True


class _Context:
    def __init__(self) -> None:
        self.processes: list[_SpawnedProcess] = []

    def Process(self, **kwargs: object) -> _SpawnedProcess:
        proc = _SpawnedProcess(kwargs, pid=200 + len(self.processes))
        self.processes.append(proc)
        return proc


def _request(*, ctx: _Context, procs: list[object], job_records: object, worker_metrics: object) -> InMemoryWorkerRespawnRequest:
    state_index = InMemorySchedulerStateIndex()
    if type(job_records) is dict:
        for job_id, record in dict.items(job_records):
            state_index.sync_record(job_id, record)
    return InMemoryWorkerRespawnRequest(
        ctx=ctx,
        procs=procs,
        pending=[],
        active={},
        target_workers=1,
        task_queue=object(),
        result_queue=object(),
        worker_config={"max_jobs_per_worker": 1},
        lifecycle_epoch=7,
        respawn_sequence=3,
        state_index=state_index,
        worker_metrics=worker_metrics,
    )


def test_phase38_queued_unstarted_work_respawns_after_worker_reaches_lifecycle_limit() -> None:
    ctx = _Context()
    retiring = _SpawnedProcess({}, pid=101)

    result = respawn_missing_inmemory_workers(
        _request(
            ctx=ctx,
            procs=[retiring],
            job_records={9: {"state": "queued", "file": "queued.bin"}},
            worker_metrics={101: {"completed_jobs": 1}},
        ),
        deterministic_process_name=lambda **kwargs: f"{kwargs['prefix']}{kwargs['sequence']}",
    )

    assert result.started == 1
    assert result.respawn_sequence == 4
    assert len(ctx.processes) == 1
    assert ctx.processes[0].started is True


def test_phase38_alive_worker_below_lifecycle_limit_remains_schedulable() -> None:
    ctx = _Context()
    live = _SpawnedProcess({}, pid=101)

    result = respawn_missing_inmemory_workers(
        _request(
            ctx=ctx,
            procs=[live],
            job_records={9: {"state": "queued", "file": "queued.bin"}},
            worker_metrics={101: {"completed_jobs": 0}},
        ),
        deterministic_process_name=lambda **kwargs: f"{kwargs['prefix']}{kwargs['sequence']}",
    )

    assert result.started == 0
    assert result.respawn_sequence == 3
    assert ctx.processes == []


def test_phase38_no_queued_pending_or_active_work_does_not_respawn_retiring_worker() -> None:
    ctx = _Context()
    retiring = _SpawnedProcess({}, pid=101)

    result = respawn_missing_inmemory_workers(
        _request(
            ctx=ctx,
            procs=[retiring],
            job_records={},
            worker_metrics={101: {"completed_jobs": 1}},
        ),
        deterministic_process_name=lambda **kwargs: f"{kwargs['prefix']}{kwargs['sequence']}",
    )

    assert result.started == 0
    assert result.respawn_sequence == 3
    assert ctx.processes == []
