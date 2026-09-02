from __future__ import annotations

from Virus_Scan.scheduler.runtime.execution_memory_capacity import UNBOUNDED_EXECUTION_MEMORY
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.runtime.thread_worker_capacity import (
    inmemory_adaptive_worker_thread_count,
    inmemory_worker_thread_count,
    inmemory_worker_thread_max,
)


class HostileSchedulerScalar:
    touched = 0

    @classmethod
    def reset(cls):
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("caller hook executed")

    def __bool__(self):
        return self._touch()

    def __str__(self):
        return self._touch()

    def __repr__(self):
        return self._touch()

    def __format__(self, _format_spec):
        return self._touch()

    def __int__(self):
        return self._touch()

    def __float__(self):
        return self._touch()

    def __iter__(self):
        return self._touch()


class HostileConfig:
    touched = 0

    @classmethod
    def reset(cls):
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("config hook executed")

    def __bool__(self):
        return self._touch()

    def get(self, _key, _default=None):
        return self._touch()

    def __iter__(self):
        return self._touch()

    def __repr__(self):
        return self._touch()


def test_thread_worker_capacity_rejects_hostile_cfg_object_without_hooks():
    HostileConfig.reset()

    assert inmemory_worker_thread_count(cfg=HostileConfig(), env={}) == 4
    assert inmemory_worker_thread_max(cfg=HostileConfig(), env={}) == 8

    assert HostileConfig.touched == 0


def test_thread_worker_capacity_rejects_hostile_cfg_values_without_hooks():
    HostileSchedulerScalar.reset()
    hostile = HostileSchedulerScalar()

    assert inmemory_worker_thread_count(cfg={"worker_threads": hostile}, env={}) == 4
    assert inmemory_worker_thread_max(cfg={"worker_threads_max": hostile}, env={}) == 8

    assert HostileSchedulerScalar.touched == 0


def test_adaptive_thread_worker_capacity_rejects_hostile_scalars_without_hooks():
    HostileSchedulerScalar.reset()
    hostile = HostileSchedulerScalar()

    worker_threads, diag = inmemory_adaptive_worker_thread_count(
        hostile,
        workers=hostile,
        total_files=hostile,
        env={"UMIGE_INMEMORY_ADAPTIVE_WORKER_THREADS": hostile},
    )

    assert worker_threads == 4
    assert diag is None
    assert HostileSchedulerScalar.touched == 0


def test_thread_worker_capacity_preserves_exact_primitive_inputs():
    assert inmemory_worker_thread_count(cfg={"worker_threads": "3"}, env={}) == 3
    assert inmemory_worker_thread_max(cfg={"worker_threads_max": "5"}, env={}) == 5
    assert inmemory_adaptive_worker_thread_count("2", workers="4", total_files="99", env={}) == (8, None)

from Virus_Scan.scheduler.runtime.process_worker_capacity import (
    default_filesystem_queue_workers,
    default_process_scheduler_workers,
    longlived_worker_count,
    process_queue_is_child_shard,
)
from Virus_Scan.scheduler.runtime.raw_worker_capacity import raw_collector_cap, raw_worker_pool_cap, stage_parallel_workers


def test_process_worker_capacity_rejects_hostile_inputs_without_hooks():
    HostileSchedulerScalar.reset()
    hostile = HostileSchedulerScalar()

    assert process_queue_is_child_shard({"UMIGE_PROCESS_SHARD": hostile}) is False
    assert default_process_scheduler_workers(env={"UMIGE_PROCESS_QUEUE_MAX_CHILDREN": hostile}, cpu_count=hostile, recoverable_exceptions=(Exception,), memory_snapshot=UNBOUNDED_EXECUTION_MEMORY) == 4
    assert default_filesystem_queue_workers(cpu_count=hostile, env={}, memory_snapshot=UNBOUNDED_EXECUTION_MEMORY) == 2
    assert longlived_worker_count(hostile, total_files=hostile, env={"UMIGE_PROCESS_QUEUE_MAX_CHILDREN": hostile, "UMIGE_LONG_LIVED_PROCESS_CAP": hostile}, memory_snapshot=UNBOUNDED_EXECUTION_MEMORY) >= 1

    assert HostileSchedulerScalar.touched == 0


def test_raw_worker_capacity_rejects_hostile_inputs_without_hooks():
    HostileSchedulerScalar.reset()
    hostile = HostileSchedulerScalar()
    calls = []

    def runtime_int(name, default):
        calls.append((name, default))
        return default

    assert stage_parallel_workers(default=hostile, env={"UMIGE_STAGE_PARALLEL_WORKERS": hostile}) == 6
    assert raw_worker_pool_cap(env={"UMIGE_RAW_WORKER_POOL_CAP": hostile, "UMIGE_PROCESS_QUEUE_MAX_CHILDREN": hostile}) == 48
    assert raw_collector_cap(hostile, runtime_int=runtime_int) == 128

    assert calls == [("RAW_PER_FILE_ACTIVE_CAP", 128)]
    assert HostileSchedulerScalar.touched == 0


def test_stage1656_scheduler_int_rejects_non_integral_values_without_truncation():
    assert scheduler_int(2.9, default=4, minimum=1, reason="probe_decimal_rejected") == (4, "probe_decimal_rejected")
    assert scheduler_int("2.9", default=4, minimum=1, reason="probe_decimal_rejected") == (4, "probe_decimal_rejected")
    assert scheduler_int(b"2.9", default=4, minimum=1, reason="probe_decimal_rejected") == (4, "probe_decimal_rejected")
    assert scheduler_int(bytearray(b"2.9"), default=4, minimum=1, reason="probe_decimal_rejected") == (4, "probe_decimal_rejected")
    assert scheduler_int(2.0, default=4, minimum=1, reason="probe_decimal_rejected") == (2, "")
    assert scheduler_int("2", default=4, minimum=1, reason="probe_decimal_rejected") == (2, "")


def test_stage1656_thread_worker_capacity_rejects_decimal_cfg_and_env_without_truncation():
    assert inmemory_worker_thread_count(cfg={"worker_threads": 2.9}, env={}) == 4
    assert inmemory_worker_thread_count(cfg={"worker_threads": "2.9"}, env={}) == 4
    assert inmemory_worker_thread_count(cfg={}, env={"UMIGE_INMEMORY_WORKER_THREADS_PER_PROCESS": "2.9"}) == 4
    assert inmemory_worker_thread_max(cfg={"worker_threads_max": 8.9}, env={}) == 8
    assert inmemory_worker_thread_max(cfg={}, env={"UMIGE_INMEMORY_WORKER_THREADS_MAX_PER_PROCESS": "8.9"}) == 8


def test_stage1656_adaptive_thread_worker_capacity_rejects_decimal_inputs_without_truncation():
    assert inmemory_adaptive_worker_thread_count(
        "2.9",
        workers="4.9",
        total_files="10.9",
        env={"UMIGE_INMEMORY_ADAPTIVE_WORKER_THREADS": "0"},
    ) == (4, None)
    assert inmemory_adaptive_worker_thread_count(
        2.9,
        workers=4.9,
        total_files=10.9,
        env={"UMIGE_INMEMORY_ADAPTIVE_WORKER_THREADS": "1"},
    ) == (4, None)
