from pathlib import Path

from Virus_Scan.scheduler.runtime.execution_memory_capacity import UNBOUNDED_EXECUTION_MEMORY
from Virus_Scan.scheduler.runtime import worker_capacity as facade
from Virus_Scan.scheduler.runtime.process_worker_capacity import longlived_worker_count
from Virus_Scan.scheduler.runtime.raw_worker_capacity import raw_collector_cap, raw_worker_pool_cap, stage_parallel_workers
from Virus_Scan.scheduler.runtime.thread_worker_capacity import inmemory_worker_thread_count, inmemory_worker_thread_max


def test_worker_capacity_facade_delegates_to_bounded_runtime_modules():
    assert facade.longlived_worker_count is longlived_worker_count
    assert facade.raw_collector_cap is raw_collector_cap
    assert facade.raw_worker_pool_cap is raw_worker_pool_cap
    assert facade.stage_parallel_workers is stage_parallel_workers
    assert facade.inmemory_worker_thread_count is inmemory_worker_thread_count
    assert facade.inmemory_worker_thread_max is inmemory_worker_thread_max


def test_worker_capacity_runtime_modules_stay_bounded_and_owned():
    root = Path(__file__).parents[1] / "scheduler" / "runtime"
    for name in (
        "worker_capacity.py",
        "process_worker_capacity.py",
        "execution_memory_capacity.py",
        "thread_worker_capacity.py",
        "raw_worker_capacity.py",
    ):
        path = root / name
        text = path.read_text(encoding="utf-8")
        assert len(text.splitlines()) < 120
        assert "scheduler.orchestration" not in text
        assert "scheduler.queue" not in text
        assert "scheduler.replay" not in text
        assert "scheduler.evidence" not in text


def test_worker_capacity_behavior_is_preserved_through_facade():
    env = {
        "UMIGE_PROCESS_QUEUE_MAX_CHILDREN": "12",
        "UMIGE_LONG_LIVED_PROCESS_CAP": "6",
        "UMIGE_INMEMORY_WORKER_THREADS_PER_PROCESS": "5",
        "UMIGE_INMEMORY_WORKER_THREADS_MAX_PER_PROCESS": "9",
        "UMIGE_RAW_WORKER_POOL_CAP": "11",
        "UMIGE_STAGE_PARALLEL_WORKERS": "7",
    }
    assert facade.longlived_worker_count(0, total_files=4, env=env, memory_snapshot=UNBOUNDED_EXECUTION_MEMORY) == 4
    assert facade.inmemory_worker_thread_count(env=env) == 5
    assert facade.inmemory_worker_thread_max(env=env) == 9
    assert facade.raw_worker_pool_cap(env=env) == 11
    assert facade.stage_parallel_workers(env=env) == 7
    assert facade.raw_collector_cap("yara_group", runtime_int=lambda name, default=0: default) == 128
