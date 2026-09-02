from pathlib import Path

from Virus_Scan.scheduler.runtime.execution_memory_capacity import UNBOUNDED_EXECUTION_MEMORY
from Virus_Scan.scheduler.runtime.multiprocessing_context import scheduler_worker_shared_persistence_writes_disabled
from Virus_Scan.scheduler.runtime.worker_capacity import (
    inmemory_worker_thread_count,
    inmemory_worker_thread_max,
    longlived_worker_count,
    raw_worker_pool_cap,
    stage_parallel_workers,
)


def test_worker_shard_shared_persistence_write_detection_is_runtime_owned():
    env = {}
    assert scheduler_worker_shared_persistence_writes_disabled(env) is False
    assert scheduler_worker_shared_persistence_writes_disabled({"UMIGE_PROCESS_QUEUE": "1"}) is True


def test_worker_resource_limits_are_runtime_owned():
    env = {
        "UMIGE_PROCESS_QUEUE_MAX_CHILDREN": "9",
        "UMIGE_INMEMORY_WORKER_THREADS_PER_PROCESS": "3",
        "UMIGE_INMEMORY_WORKER_THREADS_MAX_PER_PROCESS": "5",
        "UMIGE_STAGE_PARALLEL_WORKERS": "7",
        "UMIGE_RAW_WORKER_POOL_CAP": "11",
    }
    assert longlived_worker_count(0, total_files=4, env=env, memory_snapshot=UNBOUNDED_EXECUTION_MEMORY) == 4
    assert inmemory_worker_thread_count(env=env) == 3
    assert inmemory_worker_thread_max(env=env) == 5
    assert stage_parallel_workers(env=env) == 7
    assert raw_worker_pool_cap(env=env) == 11


def test_obsolete_execution_worker_policy_deleted():
    assert not Path("Virus_Scan/scheduler/execution/worker_policy.py").exists()
