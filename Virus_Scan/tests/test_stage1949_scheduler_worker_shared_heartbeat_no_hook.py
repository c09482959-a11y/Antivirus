from pathlib import Path

from Virus_Scan.runtime.structured_failures import clear_failure_records, failure_snapshot
from Virus_Scan.scheduler.workers.heartbeat import (
    HB_CANCEL_REQUEST,
    cooperative_cancel_requested,
    read_shared_heartbeat,
    update_shared_heartbeat,
)

SCHEDULER_ROOT = Path(__file__).resolve().parents[1] / "scheduler"


class HostileScalar:
    touched = 0

    @classmethod
    def reset(cls):
        cls.touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("repr hook executed")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("format hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("bool hook executed")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("float hook executed")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("int hook executed")

    def __index__(self):
        type(self).touched += 1
        raise RuntimeError("index hook executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("iter hook executed")


class HostileDict(dict):
    touched = 0

    def get(self, *_args, **_kwargs):
        type(self).touched += 1
        raise RuntimeError("dict get hook executed")


def _heartbeat_table(size: int = 2):
    return {
        "monotonic_ns": [0] * size,
        "generation": [0] * size,
        "pid": [0] * size,
        "thread_id": [0] * size,
        "stage": [0] * size,
        "progress_counter": [0] * size,
        "bytes_processed": [0] * size,
        "last_progress_ns": [0] * size,
        "flags": [0] * size,
        "completed_jobs": [0] * size,
        "rss_mb": [0.0] * size,
    }


def test_stage1949_shared_heartbeat_sources_have_no_field_fstrings_or_sentinel_returns():
    support = (SCHEDULER_ROOT / "workers" / "heartbeat_support.py").read_text(encoding="utf-8")
    cancel = (SCHEDULER_ROOT / "workers" / "heartbeat_cancel.py").read_text(encoding="utf-8")
    reader = (SCHEDULER_ROOT / "workers" / "heartbeat_reader.py").read_text(encoding="utf-8")
    writer = (SCHEDULER_ROOT / "workers" / "heartbeat_writer.py").read_text(encoding="utf-8")

    assert "def _init_flag(name: str, fallback" not in support
    assert "def safe_heartbeat_int(value: Any, *, default" not in support
    assert "reason=f" not in support
    assert "non_finite_reason=f" not in support
    assert "ValueError(f\"heartbeat_table_" not in support
    assert "field=f\"heartbeat_" not in reader
    assert "raise ValueError(f\"heartbeat_table_" not in reader
    assert "field=f\"heartbeat_" not in writer
    assert "for key, value in defaults.items()" not in writer
    assert "for key, value in values.items()" not in writer
    assert "arrays.values()" not in writer
    assert "return False" not in cancel
    assert "return False" not in writer
    assert "return None" not in reader


def test_stage1949_shared_heartbeat_rejects_hostile_scalars_without_hooks():
    HostileScalar.reset()
    HostileDict.touched = 0
    clear_failure_records()
    hostile = HostileScalar()
    hostile_table = HostileDict()

    assert cooperative_cancel_requested(hostile_table, hostile, hostile) is False
    assert read_shared_heartbeat(hostile_table, hostile, hostile) is None
    assert update_shared_heartbeat(
        hostile_table,
        hostile,
        hostile,
        pid=hostile,
        thread_id=hostile,
        stage=hostile,
        progress_counter=hostile,
        bytes_processed=hostile,
        last_progress_ns=hostile,
        flags=hostile,
        rss_mb=hostile,
        completed_jobs=hostile,
    ) is False

    assert HostileScalar.touched == 0
    assert HostileDict.touched == 0
    wheres = tuple(record["where"] for record in failure_snapshot()["records"])
    assert "worker_shared_heartbeat_cancel_read_failed" in wheres
    assert "worker_shared_heartbeat_heartbeat_read_failed" in wheres
    assert "worker_shared_heartbeat_heartbeat_write_failed" in wheres


def test_stage1949_shared_heartbeat_preserves_list_backed_update_read_and_cancel():
    table = _heartbeat_table()

    assert update_shared_heartbeat(
        table,
        1,
        7,
        pid=123,
        thread_id=456,
        stage="archive",
        progress_counter=3,
        bytes_processed=4096,
        last_progress_ns=100,
        flags=HB_CANCEL_REQUEST,
        rss_mb=12.5,
        completed_jobs=2,
    ) is True

    row = read_shared_heartbeat(table, 1, 7)
    assert row is not None
    assert row["generation"] == 7
    assert row["pid"] == 123
    assert row["stage"] == "archive"
    assert row["progress_counter"] == 3
    assert row["bytes_processed"] == 4096
    assert row["rss_mb"] == 12.5
    assert cooperative_cancel_requested(table, 1, 7) is True

from Virus_Scan.scheduler.workers.initial_spawn import (
    ProcessQueueInitialSpawnDependencies,
    ProcessQueueInitialSpawnRequest,
    publish_initial_process_queue_workers,
)
from Virus_Scan.scheduler.workers.inmemory_capacity_plan import build_inmemory_capacity_plan
from Virus_Scan.scheduler.workers.inmemory_dispatch_backpressure import (
    decide_inmemory_dispatch_backpressure,
)


class HostileMapping(dict):
    touched = 0

    @classmethod
    def reset(cls):
        cls.touched = 0

    def get(self, *_args, **_kwargs):
        type(self).touched += 1
        raise RuntimeError("mapping get hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("mapping bool hook executed")


def test_stage1949_initial_spawn_log_rejects_hostile_cpu_and_io_without_hooks(tmp_path):
    HostileScalar.reset()
    HostileMapping.reset()
    logs = []

    output = publish_initial_process_queue_workers(
        ProcessQueueInitialSpawnRequest(
            elastic_scheduler=True,
            elastic_min_workers=1,
            process_count=2,
            requested_process_count=2,
            queue_dir=tmp_path,
            next_worker_spawn_id=3,
        ),
        ProcessQueueInitialSpawnDependencies(
            io_adjusted_elastic_target=lambda *_args: (1, HostileScalar(), HostileMapping()),
            spawn_worker=lambda _worker_id: True,
            launch_delay=lambda: 0.0,
            sleep=lambda _seconds: None,
            log_info=lambda message: logs.append(message),
            report_suppressed=lambda _stage, _exc: None,
            recoverable_exceptions=(RuntimeError,),
        ),
    )

    assert output.initial_spawn_target == 1
    assert logs == [
        "bulk scan elastic scheduler start: spawned_target=1/2 cpu=n/a io_pressure=unknown io_reason=n/a"
    ]
    assert HostileScalar.touched == 0
    assert HostileMapping.touched == 0


def test_stage1949_capacity_and_backpressure_reject_hostile_scalars_without_hooks():
    HostileScalar.reset()
    HostileMapping.reset()

    plan = build_inmemory_capacity_plan(
        {}, workers=HostileScalar(), worker_threads=HostileScalar()
    )
    should_pause, reason = decide_inmemory_dispatch_backpressure(
        active_heavy_weight=0,
        logical_slots=HostileScalar(),
        workers=HostileScalar(),
        pressure_snapshot=HostileMapping(pressure="high"),
    )

    assert plan.logical_slots == 1
    assert plan.queue_depth == 8
    assert should_pause is False
    assert reason == ""
    assert HostileScalar.touched == 0
    assert HostileMapping.touched == 0


def test_stage1949_initial_capacity_backpressure_sources_have_no_unsafe_rows():
    initial_spawn = (SCHEDULER_ROOT / "workers" / "initial_spawn.py").read_text(encoding="utf-8")
    capacity = (SCHEDULER_ROOT / "workers" / "inmemory_capacity_plan.py").read_text(encoding="utf-8")
    backpressure = (SCHEDULER_ROOT / "workers" / "inmemory_dispatch_backpressure.py").read_text(encoding="utf-8")

    assert "f\"bulk scan elastic scheduler start" not in initial_spawn
    assert "f'{initial_cpu:.1f}%'" not in initial_spawn
    assert "bool((initial_io or {}).get" not in initial_spawn
    assert "fallback=1" not in capacity
    assert "str(max(int(logical_slots or 1)" not in backpressure
    assert "int(workers or 1)" not in backpressure
