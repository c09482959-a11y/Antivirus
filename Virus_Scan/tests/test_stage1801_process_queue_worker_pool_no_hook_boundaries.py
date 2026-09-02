from pathlib import Path

from Virus_Scan.scheduler.workers.process_queue_worker_pool import ProcessQueueWorkerPoolOutput, ProcessQueueWorkerPoolRequest
from Virus_Scan.scheduler.workers.spawn_dispatch import ProcessQueueWorkerDispatchRequest


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    fspath_calls = 0
    class_getattribute_calls = 0

    @classmethod
    def reset(cls):
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.float_calls = 0
        cls.int_calls = 0
        cls.fspath_calls = 0
        cls.class_getattribute_calls = 0

    def __getattribute__(self, name):
        if name == "__class__":
            type(self).class_getattribute_calls += 1
            raise RuntimeError("must not execute class lookup")
        return object.__getattribute__(self, name)

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("must not execute str")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("must not execute repr")

    def __format__(self, spec):
        type(self).format_calls += 1
        raise RuntimeError("must not execute format")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("must not execute bool")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("must not execute iter")

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("must not execute float")

    def __int__(self):
        type(self).int_calls += 1
        raise RuntimeError("must not execute int")

    def __fspath__(self):
        type(self).fspath_calls += 1
        raise RuntimeError("must not execute fspath")


def assert_hostile_untouched():
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.format_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.iter_calls == 0
    assert HostileValue.float_calls == 0
    assert HostileValue.int_calls == 0
    assert HostileValue.fspath_calls == 0
    assert HostileValue.class_getattribute_calls == 0


def test_stage1801_worker_pool_request_rejects_hostile_boundary_scalars_without_hooks():
    HostileValue.reset()
    request = ProcessQueueWorkerPoolRequest(
        root=object(),
        queue_dir="queue",
        outputs_dir=HostileValue(),
        worker_index=HostileValue(),
        script_path=HostileValue(),
        python_executable=HostileValue(),
        env_base=HostileValue(),
        progress_every=HostileValue(),
        partial_output_every=HostileValue(),
        slow_file_warn_sec=HostileValue(),
        per_file_timeout_sec=HostileValue(),
        throttle_sec=HostileValue(),
        strict=HostileValue(),
        scan_session_manifest_path=Path("scan_session_snapshot.json"),
        current_outputs=HostileValue(),
        current_workers=HostileValue(),
    )

    assert request.outputs_dir == Path("scheduler_worker_outputs_rejected")
    assert request.script_path == Path("scheduler_worker_script_rejected.py")
    assert request.worker_index == 0
    assert request.python_executable == "python"
    assert request.progress_every == 1
    assert request.partial_output_every == 0
    assert request.slow_file_warn_sec == 0.0
    assert request.per_file_timeout_sec == 0.0
    assert request.throttle_sec == 0.0
    assert request.strict is False
    assert request.current_outputs[0]["unsupported_scheduler_value"] is True
    assert request.current_workers[0][1]["unsupported_scheduler_value"] is True
    assert_hostile_untouched()


def test_stage1801_worker_pool_output_rejects_hostile_success_and_workers_without_hooks():
    HostileValue.reset()
    output = ProcessQueueWorkerPoolOutput(
        success=HostileValue(),
        outputs=HostileValue(),
        workers=HostileValue(),
    )

    assert output.success is False
    assert output.outputs[0]["unsupported_scheduler_value"] is True
    assert output.workers[0][1]["unsupported_scheduler_value"] is True
    assert_hostile_untouched()


def test_stage1801_worker_dispatch_request_rejects_hostile_boundary_scalars_without_hooks():
    HostileValue.reset()
    dispatch = ProcessQueueWorkerDispatchRequest(
        root=object(),
        queue_dir="queue",
        outputs_dir=HostileValue(),
        worker_index=HostileValue(),
        script_path=HostileValue(),
        python_executable=HostileValue(),
        env_base=HostileValue(),
        progress_every=HostileValue(),
        partial_output_every=HostileValue(),
        slow_file_warn_sec=HostileValue(),
        per_file_timeout_sec=HostileValue(),
        throttle_sec=HostileValue(),
        strict=HostileValue(),
        scan_session_manifest_path=Path("scan_session_snapshot.json"),
    )

    assert dispatch.outputs_dir == Path("scheduler_worker_outputs_rejected")
    assert dispatch.script_path == Path("scheduler_worker_script_rejected.py")
    assert dispatch.worker_index == 0
    assert dispatch.python_executable == "python"
    assert dispatch.progress_every == 1
    assert dispatch.partial_output_every == 0
    assert dispatch.slow_file_warn_sec == 0.0
    assert dispatch.per_file_timeout_sec == 0.0
    assert dispatch.throttle_sec == 0.0
    assert dispatch.strict is False
    assert_hostile_untouched()


def test_stage1959_worker_pool_source_has_no_fallback_or_default_scalar_routes():
    root = Path(__file__).resolve().parents[1]
    source = (root / "scheduler" / "workers" / "process_queue_worker_pool.py").read_text(encoding="utf-8")

    for snippet in ("fallback", "default=", "scheduler_int", "scheduler_float", "scheduler_bool"):
        assert snippet not in source
