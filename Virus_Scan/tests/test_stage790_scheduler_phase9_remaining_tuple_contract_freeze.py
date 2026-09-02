from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from types import SimpleNamespace

from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_contracts import InMemoryParentRuntimeSetupRequest
from Virus_Scan.scheduler.orchestration.scheduler_serial_mode import SchedulerSerialModeRequest
from Virus_Scan.scheduler.queue.process_queue_integrity_repair import ProcessQueueIntegrityRepairRequest
from Virus_Scan.scheduler.queue.snapshots import QueueBehaviorSnapshot, QueuePhaseLedger
from Virus_Scan.scheduler.replay.replay_validator import QueueReplayComparisonRecord, QueueReplayComparisonSnapshot
from Virus_Scan.scheduler.timeout.escalation_engine import ProcessQueueStallEscalationRequest
from Virus_Scan.scheduler.workers.inmemory_worker_death import InMemoryWorkerDeathSweep, InMemoryWorkerLivenessSnapshot
from Virus_Scan.scheduler.workers.inmemory_worker_exit import InMemoryWorkerExitEvidence
from Virus_Scan.scheduler.workers.inmemory_worker_pool import InMemoryWorkerPoolStartupResult
from Virus_Scan.scheduler.workers.inmemory_scan_progress import InMemoryScanProgressEmitter
from Virus_Scan.scheduler.workers.inmemory_spawn import InMemoryWorkerRespawnRequest, respawn_missing_inmemory_workers
from Virus_Scan.scheduler.workers.process_queue_worker_exit import ProcessQueueWorkerExitRequest
from Virus_Scan.scheduler.workers.process_snapshots import ProcessQueueWorkerSnapshot


def test_phase9_parent_and_serial_requests_freeze_direct_sequence_inputs():
    files = ["b.bin", "a.bin"]
    recoverable = [RuntimeError, ValueError]
    runtime_request = InMemoryParentRuntimeSetupRequest(
        root="/tmp/root",
        all_files=files,
        process_count=2,
        strict=False,
        yara_enabled=False,
        per_file_timeout_sec=5.0,
        slow_file_warn_sec=1.0,
        recoverable_exceptions=recoverable,

        scan_session_snapshot=scan_session_snapshot_fixture(),    )
    serial_request = SchedulerSerialModeRequest(
        files=files,
        total_files=2,
        started_at=1.0,
        progress_every=1,
        throttle_sec=0.0,
    )
    integrity_request = ProcessQueueIntegrityRepairRequest(
        queue_dir="queue",
        all_files=files,
        phase="finalize",
        repair=True,
    )
    files.append("late.bin")
    recoverable.clear()

    assert runtime_request.all_files == ("b.bin", "a.bin")
    assert runtime_request.recoverable_exceptions == (RuntimeError, ValueError)
    assert serial_request.files == ("b.bin", "a.bin")
    assert integrity_request.all_files == ("b.bin", "a.bin")


def test_phase9_queue_replay_worker_snapshots_freeze_direct_sequence_inputs():
    first = QueueBehaviorSnapshot.from_counts("admit", {"pending": 1, "total": 1})
    snapshots = [first]
    ledger = QueuePhaseLedger(snapshots)
    snapshots.clear()
    assert ledger.snapshots == (first,)

    high = QueueReplayComparisonRecord(
        job_id="job-b",
        file_identity="b",
        verdict="clean",
        tags=["z", "z"],
        chains=["chain"],
        engine_routing="engine",
        duplicate_count=0,
        recovery_count=0,
        failed_count=0,
    )
    low = QueueReplayComparisonRecord(
        job_id="job-a",
        file_identity="a",
        verdict="clean",
        tags=["a"],
        chains=[],
        engine_routing="engine",
        duplicate_count=0,
        recovery_count=0,
        failed_count=0,
    )
    records = [high, low]
    replay_snapshot = QueueReplayComparisonSnapshot(records)
    records.reverse()
    assert high.tags == ("z",)
    assert replay_snapshot.records == (low, high)

    dead = [7]
    retried = [42]
    death = InMemoryWorkerDeathSweep(dead_pids=dead, retried_jobs=retried)
    liveness = InMemoryWorkerLivenessSnapshot(live_count=1, dead_pids=dead)
    exit_evidence = InMemoryWorkerExitEvidence(worker_pid=7, active_jobs=[1], retried_jobs=[2], ignored_jobs=[3])
    dead.append(8)
    retried.append(99)
    assert death.dead_pids == (7,)
    assert death.retried_jobs == (42,)
    assert liveness.dead_pids == (7,)
    assert exit_evidence.active_jobs == (1,)
    assert exit_evidence.retried_jobs == (2,)
    assert exit_evidence.ignored_jobs == (3,)


def test_phase9_worker_and_timeout_boundary_requests_freeze_direct_process_sequences():
    proc = SimpleNamespace()
    cmd = ["python", "worker.py"]
    procs = [(0, proc, "worker-output.json", cmd)]
    stall_request = ProcessQueueStallEscalationRequest(procs=procs, elapsed_sec=3.0)
    worker_exit_request = ProcessQueueWorkerExitRequest(procs=procs, strict=True, had_error=False)
    worker_snapshot = ProcessQueueWorkerSnapshot(
        live_count=1,
        active_processes=procs,
        suppressed_failures=["one"],
    )
    pool_result = InMemoryWorkerPoolStartupResult(processes=[proc], started=1)
    procs.clear()
    cmd.append("late")

    assert isinstance(stall_request.procs, tuple)
    assert isinstance(worker_exit_request.procs, tuple)
    assert worker_snapshot.active_processes == ((0, proc, "worker-output.json", ("python", "worker.py")),)
    assert worker_snapshot.suppressed_failures == ("one",)
    assert pool_result.processes == (proc,)


def test_phase9_inmemory_worker_respawn_request_is_snapshot_and_returns_started_processes():
    class _Proc:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.daemon = None
            self.started = False

        def start(self):
            self.started = True

        def is_alive(self):
            return False

    class _Ctx:
        def Process(self, **kwargs):
            return _Proc(**kwargs)

    procs = []
    request = InMemoryWorkerRespawnRequest(
        ctx=_Ctx(),
        procs=procs,
        pending=["job"],
        active={},
        target_workers=1,
        task_queue=object(),
        result_queue=object(),
        worker_config={},
        lifecycle_epoch=1,
        respawn_sequence=0,
        state_index=InMemorySchedulerStateIndex(),
        worker_metrics={},
    )
    procs.append(object())
    result = respawn_missing_inmemory_workers(
        request,
        deterministic_process_name=lambda **kwargs: f"{kwargs['prefix']}{kwargs['sequence']}",
    )
    assert request.procs == ()
    assert result.started == 1
    assert len(result.processes) == 1
    assert result.processes[0].started is True


def test_phase9_inmemory_scan_progress_freezes_recoverable_exceptions():
    recoverable = [RuntimeError]
    emitter = InMemoryScanProgressEmitter(
        progress_callback=lambda *_args: True,
        cancel_error_type=KeyboardInterrupt,
        recoverable_exceptions=recoverable,
        record_suppressed=lambda *_args: None,
    )
    recoverable.clear()
    assert emitter.recoverable_exceptions == (RuntimeError,)
