
"""Stage 1052 Phase 5 regression tests for scheduler env policy ownership."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path


def test_scheduler_config_scalars_use_public_env_contracts():
    source = read_python_file(Path("Virus_Scan/scheduler/internal/scheduler_config.py"))
    assert "from Virus_Scan.contracts.env_config import bool_env, float_env, int_env" in source
    assert "os.environ.get" not in source
    assert "GLOBAL_RAW_QUEUE_ENABLED = bool_env" in source
    assert "STAGE_PARALLEL_DEFAULT_WORKERS = int_env" in source


def test_scheduler_mode_raw_stage_and_spawn_env_reads_use_public_contracts():
    checked = (
        "Virus_Scan/scheduler/orchestration/scheduler_mode_dispatch.py",
        "Virus_Scan/scheduler/ownership/raw_stage_jobs.py",
        "Virus_Scan/scheduler/workers/spawn.py",
        "Virus_Scan/scheduler/workers/inmemory_worker_bootstrap.py",
    )
    for filename in checked:
        source = Path(filename).read_text()
        assert "os.environ.get" not in source
        assert "os.getenv" not in source
    assert "RuntimeEnvironmentOwner().publish" in read_python_file(Path("Virus_Scan/scheduler/workers/inmemory_worker_bootstrap.py"))


def test_scheduler_runtime_policy_modules_use_public_env_contracts():
    checked = (
        "Virus_Scan/scheduler/runtime/backpressure_memory.py",
        "Virus_Scan/scheduler/runtime/backpressure_targets.py",
        "Virus_Scan/scheduler/runtime/queue_filesystem_operations.py",
        "Virus_Scan/scheduler/runtime/queue_json_publication.py",
        "Virus_Scan/scheduler/runtime/resource_priority.py",
        "Virus_Scan/scheduler/workers/claim_heartbeat.py",
        "Virus_Scan/scheduler/workers/inmemory_worker_heartbeat_publisher.py",
        "Virus_Scan/scheduler/workers/inmemory_worker_thread_progress.py",
    )
    for filename in checked:
        source = Path(filename).read_text()
        assert "os.environ.get" not in source
        assert "os.getenv" not in source


def test_scheduler_dependency_defaults_do_not_bind_os_environ_get_directly():
    checked = (
        "Virus_Scan/scheduler/context/inmemory_raw_dependencies.py",
        "Virus_Scan/scheduler/execution/process_queue_loop.py",
        "Virus_Scan/scheduler/orchestration/process_queue_child_mode.py",
        "Virus_Scan/scheduler/orchestration/scheduler_runner.py",
        "Virus_Scan/scheduler/queue/raw_queue_live_work.py",
    )
    for filename in checked:
        source = Path(filename).read_text()
        assert "os.environ.get" not in source
        assert "env_reader=os.environ.get" not in source
        assert "= os.environ.get" not in source
