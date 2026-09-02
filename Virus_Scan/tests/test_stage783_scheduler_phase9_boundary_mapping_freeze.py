from pathlib import Path
import pytest

from Virus_Scan.scheduler.evidence.process_queue_partial_output import (
    ProcessQueuePartialOutputPublication,
    ProcessQueuePartialOutputRequest,
)
from Virus_Scan.scheduler.evidence.process_queue_progress_counts import ProcessQueueProgressCounts
from Virus_Scan.scheduler.runtime.process_queue_environment import (
    ProcessQueueChildEnvironmentOutput,
    ProcessQueueChildEnvironmentRequest,
)
from Virus_Scan.scheduler.workers.process_queue_elastic_scaling import ProcessQueueElasticScaleOutput
from Virus_Scan.scheduler.workers.process_queue_worker_pool import (
    ProcessQueueWorkerPoolOutput,
    ProcessQueueWorkerPoolRequest,
)
from Virus_Scan.scheduler.workers.spawn import ProcessQueueWorkerSpawnRequest, ProcessQueueWorkerSpawnResult
from Virus_Scan.scheduler.workers.spawn_dispatch import ProcessQueueWorkerDispatchRequest


def test_phase9_progress_partial_and_environment_contracts_freeze_direct_inputs():
    counts = {"file_done": 1, "nested": {"values": ["a"]}}
    merged = {"sample.exe": {"tags": ["clean"]}}
    env = {"UMIGE_DEEP_SCAN_MODE": "fast", "nested": {"values": ["x"]}}
    outputs = ["worker_001.json"]

    progress = ProcessQueueProgressCounts(
        counts=counts,
        file_done_count=1,
        file_failed_count=0,
        file_active_count=0,
        file_pending_count=0,
        raw_total=0,
        raw_live=0,
        accounted_total=1,
    )
    request = ProcessQueuePartialOutputRequest(outputs=outputs, partial_output_path="partial.json")
    publication = ProcessQueuePartialOutputPublication(published=True, merged=merged)
    env_request = ProcessQueueChildEnvironmentRequest(env=env, dynamic_queue_feed=True)
    env_output = ProcessQueueChildEnvironmentOutput(env=env)

    counts["nested"]["values"].append("mutated")
    merged["sample.exe"]["tags"].append("mutated")
    env["nested"]["values"].append("mutated")
    outputs.append("worker_002.json")

    assert tuple(progress.counts["nested"]["values"]) == ("a",)
    assert tuple(request.outputs) == ("worker_001.json",)
    assert tuple(publication.merged["sample.exe"]["tags"]) == ("clean",)
    assert tuple(env_request.env["nested"]["values"]) == ("x",)
    assert tuple(env_output.env["nested"]["values"]) == ("x",)
    with pytest.raises(TypeError):
        publication.merged["sample.exe"] = {}


def test_phase9_worker_spawn_and_pool_contracts_freeze_direct_inputs():
    env = {"UMIGE_DEEP_SCAN_MODE": "auto", "nested": {"values": ["before"]}}
    command = ["python", "scanner.py"]
    outputs = ["worker_001.json"]
    workers = [(1, object(), "worker_001.json", ["python", "scanner.py"])]

    pool_request = ProcessQueueWorkerPoolRequest(
        root="root",
        queue_dir="queue",
        outputs_dir="outputs",
        worker_index=1,
        script_path="scanner.py",
        python_executable="python",
        env_base=env,
        progress_every=10,
        partial_output_every=0,
        slow_file_warn_sec=5.0,
        per_file_timeout_sec=30.0,
        throttle_sec=0.0,
        strict=False,
        scan_session_manifest_path=Path("scan_session_snapshot.json"),
        current_outputs=outputs,
        current_workers=workers,
    )
    pool_output = ProcessQueueWorkerPoolOutput(success=True, outputs=outputs, workers=workers)
    dispatch = ProcessQueueWorkerDispatchRequest(
        root="root",
        queue_dir="queue",
        outputs_dir="outputs",
        worker_index=1,
        script_path="scanner.py",
        python_executable="python",
        env_base=env,
        progress_every=10,
        partial_output_every=0,
        slow_file_warn_sec=5.0,
        per_file_timeout_sec=30.0,
        throttle_sec=0.0,
        strict=False,
        scan_session_manifest_path=Path("scan_session_snapshot.json"),
    )
    spawn_request = ProcessQueueWorkerSpawnRequest(
        root="root",
        queue_dir="queue",
        output="worker_001.json",
        worker_index=1,
        script_path="scanner.py",
        python_executable="python",
        env_base=env,
        progress_every=10,
        partial_output_every=0,
        slow_file_warn_sec=5.0,
        per_file_timeout_sec=30.0,
        throttle_sec=0.0,
        strict=False,
        scan_session_manifest_path=Path("scan_session_snapshot.json"),
    )
    spawn_result = ProcessQueueWorkerSpawnResult(True, 1, "worker_001.json", command)

    env["nested"]["values"].append("after")
    command.append("--mutated")
    outputs.append("worker_002.json")
    workers[0][3].append("--mutated")

    assert tuple(pool_request.env_base["nested"]["values"]) == ("before",)
    assert tuple(dispatch.env_base["nested"]["values"]) == ("before",)
    assert tuple(spawn_request.env_base["nested"]["values"]) == ("before",)
    assert tuple(pool_request.current_outputs) == ("worker_001.json",)
    assert tuple(pool_output.outputs) == ("worker_001.json",)
    assert pool_request.current_workers[0][3] == ("python", "scanner.py")
    assert pool_output.workers[0][3] == ("python", "scanner.py")
    assert spawn_result.command == ("python", "scanner.py")


def test_phase9_elastic_scale_output_freezes_io_sample():
    io_sample = {"pressure": True, "reasons": ["metadata"]}
    output = ProcessQueueElasticScaleOutput(
        live_workers=1,
        next_worker_spawn_id=2,
        elastic_target_workers=1,
        elastic_cpu_sample=10.0,
        elastic_io_sample=io_sample,
    )
    io_sample["reasons"].append("mutated")
    assert tuple(output.elastic_io_sample["reasons"]) == ("metadata",)
    with pytest.raises(TypeError):
        output.elastic_io_sample["pressure"] = False
