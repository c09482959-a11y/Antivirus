from pathlib import Path

from Virus_Scan.scheduler.workers.process_termination import (
    WorkerProcessHandleTerminationResult,
    terminate_idle_inmemory_worker_for_toxicity,
    terminate_process_queue_worker_handle,
)


class _PopenLike:
    pid = 123

    def __init__(self, alive=True):
        self.alive = alive
        self.terminated = False
        self.killed = False

    def poll(self):
        return None if self.alive else 0

    def terminate(self):
        self.terminated = True
        self.alive = False

    def kill(self):
        self.killed = True
        self.alive = False


class _InMemoryProc:
    def __init__(self, pid=77, alive=True):
        self.pid = pid
        self.alive = alive
        self.terminated = False

    def is_alive(self):
        return self.alive

    def terminate(self):
        self.terminated = True
        self.alive = False


def test_stage726_process_queue_timeout_termination_is_worker_owned_evidence():
    proc = _PopenLike(alive=True)
    result = terminate_process_queue_worker_handle(
        worker_idx=4,
        proc=proc,
        action="terminate",
        reason="unit_stall",
    )
    assert isinstance(result, WorkerProcessHandleTerminationResult)
    assert result.completed is True
    assert proc.terminated is True
    assert result.as_evidence()["worker_idx"] == 4
    assert result.as_evidence()["termination_reason"] == "unit_stall"


def test_stage726_toxic_inmemory_idle_worker_termination_is_worker_owned():
    proc = _InMemoryProc()
    result = terminate_idle_inmemory_worker_for_toxicity(
        proc=proc,
        toxic_pid=77,
        owned_job_ids=(),
        reason="unit_toxic",
    )
    assert result.requested is True
    assert result.terminated is True
    assert proc.terminated is True


def test_stage726_timeout_modules_delegate_process_lifecycle_to_workers():
    root = Path(__file__).resolve().parents[1] / "scheduler" / "timeout"
    for rel in ("escalation_engine.py", "inmemory_memory_toxicity.py"):
        src = (root / rel).read_text(encoding="utf-8")
        assert ".poll()" not in src
        assert ".is_alive()" not in src
        assert ".terminate()" not in src
        assert ".kill()" not in src
        assert "Virus_Scan.scheduler.workers.process_termination" not in src
        assert ("worker_terminator" in src) or ("idle_worker_terminator" in src)


def test_stage726_inmemory_parent_state_is_worker_owned_not_execution_owned():
    scheduler_root = Path(__file__).resolve().parents[1] / "scheduler"
    assert not (scheduler_root / "execution" / "inmemory_parent_state.py").exists()
    assert (scheduler_root / "workers" / "inmemory_parent_state.py").exists()
    parent_message = (scheduler_root / "orchestration" / "inmemory_parent_message.py").read_text(encoding="utf-8")
    assert "Virus_Scan.scheduler.workers.inmemory_parent_state" in parent_message
    assert "Virus_Scan.scheduler.execution.inmemory_parent_state" not in parent_message


def test_stage726_inmemory_worker_heartbeat_modules_are_worker_owned():
    scheduler_root = Path(__file__).resolve().parents[1] / "scheduler"
    for name in (
        "inmemory_worker_heartbeat_message.py",
        "inmemory_worker_heartbeat_publisher.py",
        "inmemory_shared_heartbeat.py",
    ):
        assert not (scheduler_root / "timeout" / name).exists()
        assert (scheduler_root / "workers" / name).exists()
    parent_message = (scheduler_root / "orchestration" / "inmemory_parent_message.py").read_text(encoding="utf-8")
    timeout_sweep = (scheduler_root / "timeout" / "inmemory_timeout_sweep.py").read_text(encoding="utf-8")
    worker_process = (scheduler_root / "workers" / "inmemory_worker_process.py").read_text(encoding="utf-8")
    heartbeat_cycle = (scheduler_root / "workers" / "inmemory_worker_heartbeat_cycle.py").read_text(encoding="utf-8")
    assert "Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_message" in parent_message
    assert "Virus_Scan.scheduler.workers.inmemory_shared_heartbeat" not in timeout_sweep
    assert "heartbeat_ingester" in timeout_sweep
    assert "publish_inmemory_worker_heartbeat_cycle" in worker_process
    assert "Virus_Scan.scheduler.workers.inmemory_worker_heartbeat_publisher" in heartbeat_cycle
    assert "Virus_Scan.scheduler.timeout.inmemory_worker_heartbeat" not in parent_message + timeout_sweep + worker_process
