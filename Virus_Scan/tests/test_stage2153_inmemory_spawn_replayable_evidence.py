from __future__ import annotations
from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

from pathlib import Path

from Virus_Scan.scheduler.workers.inmemory_spawn import InMemoryWorkerRespawnRequest, respawn_missing_inmemory_workers
from Virus_Scan.scheduler.workers.inmemory_spawn_evidence import (
    inmemory_owned_nonempty_decision,
    inmemory_process_alive_decision,
)


class HostileCollection:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):  # pragma: no cover - failure proves unsafe hook execution
        type(self).touched += 1
        raise AssertionError("bool hook executed")

    def __len__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("len hook executed")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("iter hook executed")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("repr hook executed")


class HostileAliveProperty:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    @property
    def is_alive(self):  # pragma: no cover - failure proves descriptor execution
        type(self).touched += 1
        raise AssertionError("is_alive property executed")


class LiveProcess:
    def __init__(self, alive: bool) -> None:
        self.alive = alive
        self.calls = 0

    def is_alive(self) -> bool:
        self.calls += 1
        return self.alive


class ProcessFactory:
    def __init__(self) -> None:
        self.processes: list[SpawnedProcess] = []

    def Process(self, **kwargs):
        proc = SpawnedProcess(kwargs)
        self.processes.append(proc)
        return proc


class SpawnedProcess:
    def __init__(self, kwargs) -> None:
        self.kwargs = kwargs
        self.daemon = None
        self.started = False

    def start(self) -> None:
        self.started = True


def test_stage2153_owned_nonempty_rejection_is_replayable_without_hooks() -> None:
    HostileCollection.reset()

    decision = inmemory_owned_nonempty_decision(HostileCollection(), field_name="pending_workers")

    assert HostileCollection.touched == 0
    assert decision.nonempty is False
    assert decision.accepted is False
    assert decision.reason == "unsafe_pending_workers_rejected"
    assert ("decision", "inmemory_owned_nonempty") in decision.evidence
    assert ("reason", "unsafe_pending_workers_rejected") in decision.evidence


def test_stage2153_process_alive_rejection_is_replayable_without_descriptor_hooks() -> None:
    HostileAliveProperty.reset()

    decision = inmemory_process_alive_decision(HostileAliveProperty())

    assert HostileAliveProperty.touched == 0
    assert decision.alive is False
    assert decision.accepted is False
    assert decision.reason == "unsafe_inmemory_respawn_process_descriptor_rejected"
    assert ("decision", "inmemory_process_alive") in decision.evidence


def test_stage2153_respawn_preserves_public_bool_behavior_with_typed_decisions() -> None:
    ctx = ProcessFactory()
    live = LiveProcess(True)

    result = respawn_missing_inmemory_workers(
        InMemoryWorkerRespawnRequest(
            ctx=ctx,
            procs=[live],
            pending=["job-1", "job-2"],
            active={},
            target_workers=3,
            task_queue=object(),
            result_queue=object(),
            worker_config={},
            lifecycle_epoch=2,
            respawn_sequence=10,
            state_index=InMemorySchedulerStateIndex(),
            worker_metrics={},
        ),
        deterministic_process_name=lambda **kwargs: f"{kwargs['prefix']}{kwargs['epoch']}-{kwargs['sequence']}",
    )

    assert live.calls == 1
    assert result.started == 2
    assert result.respawn_sequence == 12
    assert tuple(proc.started for proc in ctx.processes) == (True, True)
    assert tuple(proc.daemon for proc in ctx.processes) == (False, False)


def test_stage2153_inmemory_spawn_source_removed_hidden_false_sentinels() -> None:
    source = (Path(__file__).resolve().parents[1] / "scheduler" / "workers" / "inmemory_spawn.py").read_text(encoding="utf-8")
    assert "return False" not in source
    assert "safe_scheduler_bound_method" not in source
