from __future__ import annotations

from Virus_Scan.scheduler.internal.immutable_outputs import FrozenSchedulerMapping
from Virus_Scan.scheduler.workers.inmemory_worker_job import (
    InMemoryWorkerJobExecutionDependencies,
    InMemoryWorkerJobExecutionRequest,
    execute_inmemory_worker_job,
)


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    getattribute_calls = 0

    def __getattribute__(self, name):
        if name == "__class__":
            type(self).getattribute_calls += 1
            raise AssertionError("__class__ hook must not execute")
        return object.__getattribute__(self, name)

    def __str__(self):
        type(self).str_calls += 1
        raise AssertionError("__str__ hook must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise AssertionError("__repr__ hook must not execute")

    def __format__(self, _spec):
        type(self).format_calls += 1
        raise AssertionError("__format__ hook must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise AssertionError("__bool__ hook must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise AssertionError("__iter__ hook must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise AssertionError("__float__ hook must not execute")

    def __int__(self):
        type(self).int_calls += 1
        raise AssertionError("__int__ hook must not execute")


class HostileThreadProgress:
    heartbeat_getattribute_calls = 0

    def __init__(self, **_kwargs):
        self.events = []

    def __getattribute__(self, name):
        if name in {"heartbeat_failure_count", "last_heartbeat_failure"}:
            type(self).heartbeat_getattribute_calls += 1
            raise AssertionError(f"{name} hook must not execute")
        return object.__getattribute__(self, name)

    def __call__(self, event):
        self.events.append(event)
        return True


class HostileCancelFlag(HostileValue):
    pass


def _reset() -> None:
    for cls in (HostileValue, HostileCancelFlag):
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.float_calls = 0
        cls.int_calls = 0
        cls.getattribute_calls = 0
    HostileThreadProgress.heartbeat_getattribute_calls = 0


def _assert_no_hooks() -> None:
    for cls in (HostileValue, HostileCancelFlag):
        assert cls.str_calls == 0
        assert cls.repr_calls == 0
        assert cls.format_calls == 0
        assert cls.bool_calls == 0
        assert cls.iter_calls == 0
        assert cls.float_calls == 0
        assert cls.int_calls == 0
        assert cls.getattribute_calls == 0
    assert HostileThreadProgress.heartbeat_getattribute_calls == 0


def _deps(*, cancel_requested, progress_type=HostileThreadProgress):
    return InMemoryWorkerJobExecutionDependencies(
        cancel_requested=cancel_requested,
        cancel_result=lambda path, reason: (path, {"cancelled": reason}),
        result_put=lambda _item: None,
        worker_thread_progress_type=progress_type,
        scan_one_file=lambda path, _cfg: (path, {"scan_integrity": {}, "ok": True}),
        worker_error_result=lambda path, exc: (path, {"error": type(exc).__name__, "scan_integrity": {}}),
        update_shared_heartbeat=lambda *_args, **_kwargs: True,
        record_scheduler_suppressed=lambda _label, _exc: None,
        cooperative_cancel_type=RuntimeError,
        recoverable_exceptions=(RuntimeError,),
    )


def test_stage1800_worker_job_request_rejects_hostile_scalars_without_hooks():
    _reset()

    request = InMemoryWorkerJobExecutionRequest(
        job_id=HostileValue(),
        path="sample.bin",
        generation=HostileValue(),
        worker_config=HostileValue(),
        cancel_table=None,
        heartbeat_table=None,
        heartbeat_flags=None,
        completed_jobs=HostileValue(),
        task_meta=None,
    )

    assert request.job_id == 0
    assert request.generation == 0
    assert request.completed_jobs == 0
    assert isinstance(request.worker_config, FrozenSchedulerMapping)
    assert "worker_config_unavailable" in request.worker_config
    _assert_no_hooks()


def test_stage1800_worker_job_build_does_not_bool_probe_worker_config():
    _reset()

    request = InMemoryWorkerJobExecutionRequest.build(
        job_id="4",
        path="sample.bin",
        attempt="2",
        worker_config=HostileValue(),
        cancel_table=None,
        heartbeat_table=None,
        heartbeat_flags=None,
        completed_jobs="3",
        task_meta=None,
    )

    assert request.job_id == 4
    assert request.generation == 2
    assert request.completed_jobs == 3
    assert "worker_config_unavailable" in request.worker_config
    _assert_no_hooks()


def test_stage1800_worker_job_cancel_flag_rejects_hostile_bool_without_hooks():
    _reset()
    request = InMemoryWorkerJobExecutionRequest.build(
        job_id=1,
        path="sample.bin",
        attempt=0,
        worker_config={},
        cancel_table=None,
        heartbeat_table=None,
        heartbeat_flags=None,
        completed_jobs=0,
        task_meta=None,
    )

    output = execute_inmemory_worker_job(
        request,
        _deps(cancel_requested=lambda *_args: HostileCancelFlag()),
    )

    assert output == ("sample.bin", {"scan_integrity": {}, "ok": True})
    _assert_no_hooks()


def test_stage1800_worker_job_does_not_getattr_hostile_thread_progress_heartbeat_fields():
    _reset()
    request = InMemoryWorkerJobExecutionRequest.build(
        job_id=2,
        path="sample.bin",
        attempt=0,
        worker_config={},
        cancel_table=None,
        heartbeat_table=None,
        heartbeat_flags=None,
        completed_jobs=0,
        task_meta=None,
    )

    output = execute_inmemory_worker_job(
        request,
        _deps(cancel_requested=lambda *_args: False),
    )

    assert output == ("sample.bin", {"scan_integrity": {}, "ok": True})
    _assert_no_hooks()
