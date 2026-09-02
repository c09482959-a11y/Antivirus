from __future__ import annotations

from Virus_Scan.scheduler.workers.process_snapshots import (
    ProcessQueueWorkerSnapshot,
    snapshot_active_process_queue_workers,
)


class HostileIterableWorkers:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate workers")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr workers")


class HostilePollProperty:
    touched = 0

    @property
    def poll(self):
        type(self).touched += 1
        raise RuntimeError("do not touch poll property")


class HostileCommandIterable:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate command")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr command")


class HostileScalar:
    touched = 0

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not int")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


class LiveProcess:
    def __init__(self):
        self.poll_calls = 0

    def poll(self):
        self.poll_calls += 1
        return None


def _report_suppressed(label, exc):
    _report_suppressed.calls.append((label, type(exc).__name__))


_report_suppressed.calls = []


def setup_function(_func):
    HostileIterableWorkers.touched = 0
    HostilePollProperty.touched = 0
    HostileCommandIterable.touched = 0
    HostileScalar.touched = 0
    _report_suppressed.calls = []


def test_stage1624_snapshot_rejects_hostile_worker_iterable_without_iterating():
    result = snapshot_active_process_queue_workers(
        HostileIterableWorkers(),
        recoverable_exceptions=(RuntimeError,),
        report_suppressed=_report_suppressed,
    )

    assert HostileIterableWorkers.touched == 0
    assert result.live_count == 0
    assert result.active_processes == ()
    assert "unsupported_process_handle_getattribute" in result.suppressed_failures


def test_stage1624_snapshot_rejects_poll_property_without_touching_descriptor():
    proc = HostilePollProperty()

    result = snapshot_active_process_queue_workers(
        ((0, proc, "worker-output.json", ("python", "worker.py")),),
        recoverable_exceptions=(RuntimeError,),
        report_suppressed=_report_suppressed,
    )

    assert HostilePollProperty.touched == 0
    assert result.live_count == 0
    assert result.active_processes == ()
    assert "process_handle_method_descriptor_rejected" in result.suppressed_failures
    assert _report_suppressed.calls == [("monitor_loop_suppressed", "RuntimeError")]


def test_stage1624_snapshot_preserves_live_worker_and_rejects_hostile_command_iterable():
    proc = LiveProcess()
    command = HostileCommandIterable()

    result = snapshot_active_process_queue_workers(
        ((2, proc, "worker-output.json", command),),
        recoverable_exceptions=(RuntimeError,),
        report_suppressed=_report_suppressed,
    )

    assert HostileCommandIterable.touched == 0
    assert proc.poll_calls == 1
    assert result.live_count == 1
    assert result.active_processes[0][0:3] == (2, proc, "worker-output.json")
    assert result.active_processes[0][3][0]["unsupported_scheduler_value"] is True
    assert result.active_processes[0][3][0]["field_name"] == "scheduler_tuple"


def test_stage1624_snapshot_dataclass_rejects_hostile_scalars_without_string_or_int_hooks():
    proc = LiveProcess()
    snapshot = ProcessQueueWorkerSnapshot(
        live_count=HostileScalar(),
        active_processes=[(1, proc, "worker-output.json", ["python", "worker.py"])],
        suppressed_failures=(HostileScalar(),),
    )

    assert HostileScalar.touched == 0
    assert snapshot.live_count == 0
    assert snapshot.active_processes == ((1, proc, "worker-output.json", ("python", "worker.py")),)
    assert "process_worker_snapshot_live_count_rejected" in snapshot.suppressed_failures
    assert "process_worker_snapshot_suppressed_failure_rejected" in snapshot.suppressed_failures
