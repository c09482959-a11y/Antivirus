from __future__ import annotations

from Virus_Scan.scheduler.workers.heartbeat import UmigeCooperativeCancel
from Virus_Scan.scheduler.workers.inmemory_worker_job import (
    InMemoryWorkerJobExecutionDependencies,
    InMemoryWorkerJobExecutionRequest,
    execute_inmemory_worker_job,
)

from dataclasses import FrozenInstanceError

from Virus_Scan.scheduler.workers.inmemory_worker_thread_progress import (
    InMemoryWorkerThreadProgress,
    WorkerThreadProgressHeartbeatEvidence,
)


class Flags:
    running = 1
    cancel_request = 2
    poisoned_or_retire_mask = 4


def test_worker_thread_progress_heartbeat_failure_is_evidence_backed_not_clean():
    meta = {"job_id": 4, "attempt": 2}
    reports: list[tuple[str, str]] = []
    progress = InMemoryWorkerThreadProgress(
        cfg={},
        job_id="4",
        generation=2,
        cancel_table=None,
        heartbeat_table={},
        heartbeat_flags=Flags(),
        completed_jobs=0,
        task_meta=meta,
        cancel_requested=lambda *_args: False,
        update_shared_heartbeat=lambda *_args, **_kwargs: False,
        record_heartbeat_failure=lambda label, exc: reports.append((label, str(exc))),
        recoverable_exceptions=(Exception,),
    )

    assert progress("scan") is True
    assert meta["thread_progress_heartbeat_publish_failed"] is True
    evidence = meta["thread_progress_heartbeat_evidence"]
    assert evidence["worker_thread_progress_heartbeat_failed"] is True
    assert evidence["worker_thread_progress_job_id"] == "4"
    assert evidence["worker_thread_progress_attempt"] == 2
    assert evidence["worker_thread_progress_stage"] == "scan"
    assert reports and reports[0][0] == "worker_thread_progress_heartbeat_failed"


def test_worker_thread_progress_heartbeat_exception_is_reported_as_worker_evidence():
    reports: list[tuple[str, str]] = []

    def raise_update(*_args, **_kwargs):
        raise RuntimeError("shared heartbeat unavailable")

    progress = InMemoryWorkerThreadProgress(
        cfg={},
        job_id="5",
        generation=1,
        cancel_table=None,
        heartbeat_table={},
        heartbeat_flags=Flags(),
        completed_jobs=0,
        task_meta={},
        cancel_requested=lambda *_args: False,
        update_shared_heartbeat=raise_update,
        record_heartbeat_failure=lambda label, exc: reports.append((label, str(exc))),
        recoverable_exceptions=(RuntimeError,),
    )

    assert progress("raw") is True
    assert reports == [("worker_thread_progress_heartbeat_failed", "shared heartbeat unavailable")]


def test_worker_thread_progress_heartbeat_evidence_is_immutable_metadata_contract():
    evidence = WorkerThreadProgressHeartbeatEvidence(
        job_id="8",
        attempt=6,
        stage="complete",
        progress_counter=9,
        reason="unit failure",
    )
    metadata = evidence.as_metadata()
    assert metadata["worker_thread_progress_heartbeat_failed"] is True
    assert metadata["worker_thread_progress_job_id"] == "8"
    assert metadata["worker_thread_progress_attempt"] == 6
    assert metadata["worker_thread_progress_stage"] == "complete"
    assert metadata["worker_thread_progress_counter"] == 9
    try:
        evidence.reason = "changed"
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("heartbeat evidence must be immutable")


def test_inmemory_worker_job_projects_thread_heartbeat_failure_into_result_integrity():

    reports: list[tuple[str, str]] = []
    request = InMemoryWorkerJobExecutionRequest.build(
        job_id=3,
        path="sample.bin",
        attempt=1,
        worker_config={},
        cancel_table=None,
        heartbeat_table={},
        heartbeat_flags=Flags(),
        completed_jobs=0,
        task_meta={},
    )
    deps = InMemoryWorkerJobExecutionDependencies(
        cancel_requested=lambda *_args: False,
        cancel_result=lambda path, reason: (path, {"cancelled": reason}),
        result_put=lambda _item: None,
        worker_thread_progress_type=InMemoryWorkerThreadProgress,
        scan_one_file=lambda path, _cfg: (path, {"ok": True, "scan_integrity": {}}),
        worker_error_result=lambda path, exc: {"file": path, "error": str(exc), "scan_integrity": {"file_failed": True}},
        update_shared_heartbeat=lambda *_args, **_kwargs: False,
        record_scheduler_suppressed=lambda label, exc: reports.append((label, str(exc))),
        cooperative_cancel_type=UmigeCooperativeCancel,
        recoverable_exceptions=(Exception,),
    )

    path, result = execute_inmemory_worker_job(request, deps)

    assert path == "sample.bin"
    integrity = result["scan_integrity"]
    assert integrity["worker_thread_progress_heartbeat_failed"] is True
    assert integrity["worker_thread_progress_heartbeat_evidence"]["worker_thread_progress_job_id"] == "3"
    assert integrity["had_degraded_stage"] is True
    assert integrity["allow_learning"] is False
    assert reports
