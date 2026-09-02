from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from collections import deque

def _append_and_return_true(target, value):
    target.append(value)
    return True

from Virus_Scan.scheduler.workers.inmemory_worker_exit import reconcile_inmemory_worker_exit, worker_exit_pid_from_message
from Virus_Scan.scheduler.orchestration.inmemory_parent_message import InMemoryParentMessageRequest, handle_inmemory_parent_message
from Virus_Scan.scheduler.queue.inmemory_recovery_coordinator import InMemoryRecoveryCoordinator
from Virus_Scan.scheduler.queue.inmemory_lifecycle_journal import InMemoryLifecycleJournal


def _worker_error(path, exc):
    return {"file": str(path), "tags": [], "error": str(exc), "scan_integrity": {"file_failed": True}}


def test_stage733_worker_exit_pid_parser_fails_closed():
    assert worker_exit_pid_from_message(("worker_exit", None, None, "123", 1.0)) == 123
    assert worker_exit_pid_from_message(("worker_exit",)) == 0
    assert worker_exit_pid_from_message(("worker_exit", None, None, "bad", 1.0)) == 0


def test_stage733_worker_exit_retries_active_jobs_owned_by_pid():
    active = {7: {"pid": 123, "file": "a.bin", "attempt": 0}, 8: {"pid": 999, "file": "b.bin", "attempt": 0}}
    calls = []
    evidence = reconcile_inmemory_worker_exit(
        message=("worker_exit", None, None, 123, 10.0),
        active=active,
        terminal=set(),
        retry_or_fail=lambda job_id, reason, *, pid=None: _append_and_return_true(calls, (job_id, reason, pid)),
    )
    assert evidence.worker_pid == 123
    assert evidence.active_jobs == (7,)
    assert evidence.retried_jobs == (7,)
    assert calls == [(7, "worker_exit", 123)]


def test_stage733_parent_worker_exit_message_requeues_active_job():
    pending = deque()
    active = {3: {"pid": 456, "file": "lost.bin", "attempt": 0}}
    job_records = {3: {"file": "lost.bin", "attempt": 0, "state": "running", "history": ()}}
    terminal = set()
    state_index = InMemorySchedulerStateIndex()
    state_index.sync_record(3, job_records[3])
    recovery = InMemoryRecoveryCoordinator(
        job_records=job_records,
        active=active,
        pending=pending,
        results={},
        failed=set(),
        terminal=terminal,
        lifecycle_journal=InMemoryLifecycleJournal(epoch=733),
        state_index=state_index,
        max_job_retries=1,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        cancel_stall_poison_mask=0,
        total_files=1,
        worker_error_result=_worker_error,
    )
    result = handle_inmemory_parent_message(
        InMemoryParentMessageRequest(
            message=("worker_exit", None, None, 456, 11.0),
            job_records=job_records,
            active=active,
            terminal=terminal,
            failed=set(),
            done=set(),
            results={},
            recovery=recovery,
            state_index=state_index,
            root=".",
            routing_evidence_context=None,
            worker_heartbeats={},
            worker_metrics={},
            heartbeat_flags=None,
            partial_output_path=None,
            partial_output_every=0,
            partial_writer=lambda *a, **k: True,
            started_at=0.0,
            progress_every=1,
            throttle_sec=0.0,
            result_retainer=lambda _path, result: result,
            derived_cache_writer=lambda _result: False,
        wall_time=lambda: 11.0,
            sleep=lambda _: None,
            recoverable_exceptions=(Exception,),
        )
    )
    assert result.handled is True
    assert list(pending) == [(3, "lost.bin", 1)]
    assert 3 not in active
    assert job_records[3]["state"] == "pending_retry"
