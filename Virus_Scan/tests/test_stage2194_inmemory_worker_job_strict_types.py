from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.workers.heartbeat import UmigeCooperativeCancel
from Virus_Scan.scheduler.workers.inmemory_worker_job import (
    InMemoryWorkerJobExecutionDependencies,
    InMemoryWorkerJobExecutionRequest,
    execute_inmemory_worker_job,
)
from Virus_Scan.scheduler.workers.inmemory_worker_thread_progress import InMemoryWorkerThreadProgress


class _Flags:
    running = 1
    cancel_request = 2
    poisoned_or_retire_mask = 4


def test_stage2194_worker_job_source_removes_any_annotations_from_boundary() -> None:
    source = Path("Virus_Scan/scheduler/workers/inmemory_worker_job.py").read_text(encoding="utf-8")
    assert "typing import Any" not in source
    assert ": Any" not in source
    assert "[Any" not in source
    assert ", Any" not in source
    assert "-> Any" not in source


def test_stage2194_worker_job_typed_contract_preserves_cancel_and_success_paths() -> None:
    request = InMemoryWorkerJobExecutionRequest.build(
        job_id=12,
        path="typed-worker.bin",
        attempt=2,
        worker_config={"worker_rss_limit_mb": 0},
        cancel_table={},
        heartbeat_table={},
        heartbeat_flags=_Flags(),
        completed_jobs=1,
        task_meta={"route": "stage2194"},
    )
    cancel_deps = InMemoryWorkerJobExecutionDependencies(
        cancel_requested=lambda _table, _job_id, _generation: True,
        cancel_result=lambda path, reason: (path, {"cancelled": reason}),
        result_put=lambda _item: None,
        worker_thread_progress_type=InMemoryWorkerThreadProgress,
        scan_one_file=lambda path, _cfg: (path, {"scan_integrity": {}}),
        worker_error_result=lambda path, exc: (path, {"error": str(exc), "scan_integrity": {}}),
        update_shared_heartbeat=lambda *_args, **_kwargs: True,
        record_scheduler_suppressed=lambda _label, _exc: None,
        cooperative_cancel_type=UmigeCooperativeCancel,
        recoverable_exceptions=(Exception,),
    )
    assert execute_inmemory_worker_job(request, cancel_deps) == (
        "typed-worker.bin",
        {"cancelled": "cancelled_before_start"},
    )

    observed: list[tuple[object, object]] = []
    run_deps = InMemoryWorkerJobExecutionDependencies(
        cancel_requested=lambda _table, _job_id, _generation: False,
        cancel_result=lambda path, reason: (path, {"cancelled": reason}),
        result_put=lambda item: observed.append((item[0], item[1])),
        worker_thread_progress_type=InMemoryWorkerThreadProgress,
        scan_one_file=lambda path, cfg: (path, {"ok": "progress_callback" in cfg, "scan_integrity": {}}),
        worker_error_result=lambda path, exc: (path, {"error": str(exc), "scan_integrity": {}}),
        update_shared_heartbeat=lambda *_args, **_kwargs: True,
        record_scheduler_suppressed=lambda _label, _exc: None,
        cooperative_cancel_type=UmigeCooperativeCancel,
        recoverable_exceptions=(Exception,),
    )

    output = execute_inmemory_worker_job(request, run_deps)
    assert type(output) is tuple
    path, result = output
    assert path == "typed-worker.bin"
    assert type(result) is dict
    assert result["ok"] is True
    assert observed and observed[0][0] == "running"
