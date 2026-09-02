from pathlib import Path

import pytest

from Virus_Scan.scheduler.internal.immutable_outputs import FrozenSchedulerMapping
from Virus_Scan.scheduler.orchestration.process_queue_worker_pool_state import ProcessQueueParentWorkerPool
from Virus_Scan.scheduler.workers.inmemory_worker_job import InMemoryWorkerJobExecutionRequest
from Virus_Scan.scheduler.workers.process_queue_child_job import ProcessQueueChildJobRequest


def test_inmemory_worker_job_request_direct_construction_freezes_mappings():
    worker_config = {"stage": {"limit": 2}}
    task_meta = {"route": ["a"]}

    request = InMemoryWorkerJobExecutionRequest(
        job_id="7",
        path="sample.bin",
        generation="3",
        worker_config=worker_config,
        cancel_table=None,
        heartbeat_table=None,
        heartbeat_flags=None,
        completed_jobs="4",
        task_meta=task_meta,
    )

    worker_config["stage"]["limit"] = 99
    task_meta["route"].append("b")

    assert request.job_id == 7
    assert request.generation == 3
    assert request.completed_jobs == 4
    assert isinstance(request.worker_config, FrozenSchedulerMapping)
    assert request.worker_config["stage"]["limit"] == 2
    assert tuple(request.task_meta["route"]) == ("a",)
    with pytest.raises(TypeError):
        request.worker_config["new"] = "blocked"  # type: ignore[index]


def test_process_queue_child_job_request_freezes_job_but_preserves_output_accumulator():
    job = {"file": "before.bin", "nested": {"attempt": 1}}
    child_results = {}

    request = ProcessQueueChildJobRequest(
        work_queue_dir=None,
        worker_output_path=None,
        total_files="5",
        scan_started_at=0.0,
        progress_every="2",
        throttle_sec="0.0",
        worker=lambda path, _unknown, _strict: (path, {}),
        job=job,
        claim_path=None,
        claim_heartbeat_update=lambda *args, **kwargs: True,
        write_queue_file_result=lambda _queue, _claim, _file, _result: True,
        finish_process_queue_job=lambda *args, **kwargs: None,
        append_raw_stage_result=lambda _job, _raw_result: None,
        execute_raw_stage_job=lambda _job: {},
        bulk_scan_maintenance=lambda _done: None,
        log_bulk_progress=lambda *args, **kwargs: None,
        sleep=lambda _seconds: None,
        log_error=lambda _message: None,
        record_heartbeat_failure=lambda _label, _exc: None,
        done_count="1",
        child_results=child_results,
    )

    job["file"] = "after.bin"
    job["nested"]["attempt"] = 9
    child_results["preserved"] = {"ok": True}

    assert request.total_files == 5
    assert request.progress_every == 2
    assert request.done_count == 1
    assert isinstance(request.job, FrozenSchedulerMapping)
    assert request.job["file"] == "before.bin"
    assert request.job["nested"]["attempt"] == 1
    assert request.child_results["preserved"]["ok"] is True
    with pytest.raises(TypeError):
        request.job["file"] = "blocked"  # type: ignore[index]


def test_process_queue_parent_worker_pool_isolates_constructor_collections():
    env_base = {"A": "1"}
    outputs = [Path("one.json")]
    workers = [(1, object(), Path("worker.json"), ["python", "child.py"])]

    pool = ProcessQueueParentWorkerPool(
        root=".",
        queue_dir=Path("queue"),
        outputs_dir=Path("outputs"),
        script_path="child.py",
        python_executable="python",
        env_base=env_base,
        progress_every=1,
        partial_output_every=1,
        slow_file_warn_sec=1.0,
        per_file_timeout_sec=2.0,
        throttle_sec=0.0,
        strict=False,
        subprocess_stdin=lambda: None,
        windows_creationflags=lambda: 0,
        log_error=lambda _message: None,
        recoverable_exceptions=(Exception,),
        scan_session_manifest_path=Path("scan-session.json"),
        outputs=outputs,
        workers=workers,
    )

    env_base["A"] = "2"
    outputs.append(Path("two.json"))
    workers[0][3].append("--mutated")

    assert pool.env_base == {"A": "1"}
    assert pool.outputs_tuple() == (Path("one.json"),)
    assert pool.workers_tuple()[0][3] == ("python", "child.py")
