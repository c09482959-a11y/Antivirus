from __future__ import annotations

from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from pathlib import Path
from types import SimpleNamespace

from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths
from Virus_Scan.scheduler.internal.live_worker_config import freeze_inmemory_worker_config
from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_contracts import InMemoryParentRuntimeSetupRequest
from Virus_Scan.scheduler.timeout.escalation_engine import ProcessQueueStallEscalationRequest
from Virus_Scan.scheduler.workers.process_queue_worker_exit import ProcessQueueWorkerExitRequest
from Virus_Scan.scheduler.workers.process_queue_worker_pool import (
    ProcessQueueWorkerPoolOutput,
    ProcessQueueWorkerPoolRequest,
)


def test_stage1026_timeout_and_worker_exit_requests_deep_freeze_process_commands() -> None:
    proc = SimpleNamespace(pid=101)
    command = ["python", "worker.py", {"flags": ["--safe"]}]
    procs = [(0, proc, "worker-output.json", command)]

    stall_request = ProcessQueueStallEscalationRequest(procs=procs, elapsed_sec=3.0)
    worker_exit_request = ProcessQueueWorkerExitRequest(procs=procs, strict=True, had_error=False)

    procs.clear()
    command.append("--mutated")
    command[2]["flags"].append("--late")

    assert stall_request.procs == ((0, proc, "worker-output.json", ("python", "worker.py", {"flags": ("--safe",)})),)
    assert worker_exit_request.procs == ((0, proc, "worker-output.json", ("python", "worker.py", {"flags": ("--safe",)})),)


def test_stage1026_timeout_and_worker_exit_requests_preserve_process_handle_identity() -> None:
    proc = SimpleNamespace(pid=202)
    procs = [(1, proc, "worker-output.json", ["python", "worker.py"])]

    stall_request = ProcessQueueStallEscalationRequest(procs=procs, elapsed_sec=7.5)
    worker_exit_request = ProcessQueueWorkerExitRequest(procs=procs, strict=False, had_error=True)

    assert stall_request.procs[0][1] is proc
    assert worker_exit_request.procs[0][1] is proc
    assert stall_request.procs[0][3] == ("python", "worker.py")
    assert worker_exit_request.procs[0][3] == ("python", "worker.py")



class HostileLiveProcessHandle:
    touched = 0

    def __str__(self):  # pragma: no cover - test fails if touched
        type(self).touched += 1
        raise RuntimeError("do not stringify live process handle")

    def __repr__(self):  # pragma: no cover - test fails if touched
        type(self).touched += 1
        raise RuntimeError("do not repr live process handle")


def test_stage1612_live_worker_entry_freeze_preserves_owned_process_without_hooks() -> None:
    HostileLiveProcessHandle.touched = 0
    proc = HostileLiveProcessHandle()
    command = ["python", "worker.py", {"args": ["--safe"]}]
    procs = [(4, proc, "worker-output.json", command)]

    stall_request = ProcessQueueStallEscalationRequest(procs=procs, elapsed_sec=2.0)
    worker_exit_request = ProcessQueueWorkerExitRequest(procs=procs, strict=False, had_error=False)

    command[2]["args"].append("--mutated")
    command.append("late")

    assert HostileLiveProcessHandle.touched == 0
    assert stall_request.procs[0][1] is proc
    assert worker_exit_request.procs[0][1] is proc
    assert stall_request.procs[0][3] == ("python", "worker.py", {"args": ("--safe",)})
    assert worker_exit_request.procs[0][3] == ("python", "worker.py", {"args": ("--safe",)})


def test_stage1026_process_queue_worker_pool_freezes_nested_worker_commands() -> None:
    proc = SimpleNamespace(pid=303)
    command = ["python", "worker.py", {"args": ["--strict"]}]
    workers = [(2, proc, "worker-output.json", command)]

    request = ProcessQueueWorkerPoolRequest(
        root=object(),
        queue_dir="queue",
        outputs_dir=Path("outputs"),
        worker_index=2,
        script_path=Path("worker.py"),
        python_executable="python",
        env_base={},
        progress_every=1,
        partial_output_every=1,
        slow_file_warn_sec=1.0,
        per_file_timeout_sec=2.0,
        throttle_sec=0.0,
        strict=True,
        scan_session_manifest_path=Path("scan_session_snapshot.json"),
        current_outputs=[],
        current_workers=workers,
    )
    output = ProcessQueueWorkerPoolOutput(success=True, outputs=[], workers=workers)

    workers.clear()
    command[2]["args"].append("--mutated")
    command.append("late")

    assert request.current_workers == ((2, proc, "worker-output.json", ("python", "worker.py", {"args": ("--strict",)})),)
    assert output.workers == ((2, proc, "worker-output.json", ("python", "worker.py", {"args": ("--strict",)})),)


def test_stage1612_live_scheduler_paths_preserve_paths_without_unknown_string_hooks() -> None:
    class HostilePathLike:
        touched = 0

        def __str__(self):
            HostilePathLike.touched += 1
            raise RuntimeError("do not stringify")

        def __fspath__(self):
            HostilePathLike.touched += 1
            raise RuntimeError("do not fspath")

    values = [Path("owned.bin"), "text.bin", HostilePathLike()]
    frozen = freeze_live_scheduler_paths(values)
    assert frozen[0] == "owned.bin"
    assert frozen[1] == "text.bin"
    assert frozen[2]["unsupported_scheduler_value"] is True
    assert frozen[2]["field_name"] == "scheduler_path"
    assert HostilePathLike.touched == 0

    request = InMemoryParentRuntimeSetupRequest(
        root="/tmp/root",
        all_files=[Path("owned.bin")],
        process_count=1,
        strict=False,
        yara_enabled=False,
        per_file_timeout_sec=1.0,
        slow_file_warn_sec=1.0,
        recoverable_exceptions=(RuntimeError,),

        scan_session_snapshot=scan_session_snapshot_fixture(),    )
    assert request.all_files == ("owned.bin",)


def test_stage1612_inmemory_worker_config_preserves_live_dependencies_without_string_hooks() -> None:
    class HostileCallback:
        touched = 0

        def __str__(self):
            HostileCallback.touched += 1
            raise RuntimeError("do not stringify")

        def __repr__(self):
            HostileCallback.touched += 1
            raise RuntimeError("do not repr")

        def __call__(self, *args, **kwargs):
            return None

    callback = HostileCallback()
    config = freeze_inmemory_worker_config({
        "timeout_budget_factory": callback,
        "timeout_result_annotator": callback,
        "progress_callback": callback,
        "deep_scan_mode": "auto",
    })
    materialized = dict(config)
    assert materialized["timeout_budget_factory"] is callback
    assert materialized["timeout_result_annotator"] is callback
    assert materialized["progress_callback"] is callback
    assert materialized["deep_scan_mode"] == "auto"
    assert HostileCallback.touched == 0
