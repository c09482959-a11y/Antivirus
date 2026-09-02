from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.workers.process_queue_elastic_scaling import (
    ProcessQueueElasticScaleDependencies,
    ProcessQueueElasticScaleOutput,
    ProcessQueueElasticScaleRequest,
    apply_process_queue_elastic_scaling,
)


class HostileScalar:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not int")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not float")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileMapping:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool mapping")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iter mapping")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not items")

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("do not get")


class HostileError(RuntimeError):
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify error")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr error")


def _deps(**overrides):
    values = {
        "io_adjusted_target": lambda process_count, requested, queue_dir: (process_count, None, {"pressure": False}),
        "spawn_worker": lambda worker_id: False,
        "request_worker_retire": lambda queue_dir, count: 0,
        "respawn_delay": lambda env, recoverable: 0.0,
        "env": {},
        "recoverable_exceptions": (RuntimeError,),
        "sleep": lambda seconds: None,
        "log_info": lambda *args, **kwargs: None,
        "log_error": lambda *args, **kwargs: None,
        "report_suppressed": lambda *args, **kwargs: None,
    }
    values.update(overrides)
    return ProcessQueueElasticScaleDependencies(**values)


def _request(**overrides):
    values = {
        "enabled": True,
        "process_count": 2,
        "requested_process_count": 2,
        "queue_dir": "queue",
        "ordered_queue_count": 1,
        "queue_feed_cursor": 0,
        "file_pending_count": 1,
        "file_active_count": 0,
        "raw_live": 0,
        "live_workers": 0,
        "next_worker_spawn_id": 7,
    }
    values.update(overrides)
    return ProcessQueueElasticScaleRequest(**values)


def test_stage1626_elastic_request_rejects_hostile_scalars_without_hooks():
    HostileScalar.touched = 0
    called = []

    output = apply_process_queue_elastic_scaling(
        _request(enabled=HostileScalar(), process_count=HostileScalar(), live_workers=HostileScalar(), next_worker_spawn_id=HostileScalar()),
        _deps(io_adjusted_target=lambda *args: called.append(args) or (1, None, {"pressure": False})),
    )

    assert HostileScalar.touched == 0
    assert called == []
    assert output.live_workers == 0
    assert output.elastic_target_workers == 0
    assert {item.action for item in output.worker_spawn_failures} >= {"enabled", "live_workers", "next_worker_spawn_id", "process_count"}


def test_stage1626_elastic_io_sample_rejects_hostile_mapping_without_hooks():
    HostileMapping.touched = 0
    logs: list[str] = []

    output = apply_process_queue_elastic_scaling(
        _request(process_count=2, ordered_queue_count=3, file_pending_count=1, live_workers=0),
        _deps(
            io_adjusted_target=lambda *args: (2, 12.5, HostileMapping()),
            spawn_worker=lambda worker_id: True,
            log_info=logs.append,
        ),
    )

    assert HostileMapping.touched == 0
    assert output.live_workers == 2
    assert output.elastic_io_sample["scheduler_elastic_io_sample_unavailable"] is True
    assert output.elastic_io_sample["reason"] == "process_queue_elastic_io_sample_rejected"
    assert any(item.action == "io_sample" for item in output.worker_spawn_failures)
    assert logs and "process_queue_elastic_io_sample_rejected" in logs[0]


def test_stage1626_spawn_result_rejects_hostile_bool_without_hooks():
    HostileScalar.touched = 0

    output = apply_process_queue_elastic_scaling(
        _request(process_count=2, ordered_queue_count=3, file_pending_count=1, live_workers=0),
        _deps(io_adjusted_target=lambda *args: (2, None, {"pressure": False}), spawn_worker=lambda worker_id: HostileScalar()),
    )

    assert HostileScalar.touched == 0
    assert output.live_workers == 0
    assert output.worker_spawn_failures[0].action == "spawn_worker"
    assert output.worker_spawn_failures[0].error_category == "process_queue_elastic_spawn_result_rejected"


def test_stage1626_elastic_exception_detail_does_not_stringify_hostile_exception():
    HostileError.touched = 0
    logs: list[str] = []

    def fail_target(*args):
        raise HostileError(HostileScalar())

    output = apply_process_queue_elastic_scaling(
        _request(),
        _deps(io_adjusted_target=fail_target, recoverable_exceptions=(HostileError,), log_error=logs.append),
    )

    assert HostileError.touched == 0
    assert HostileScalar.touched == 0
    assert output.worker_spawn_failures[0].action == "elastic_scaling"
    assert output.worker_spawn_failures[0].error_category == "HostileError"
    assert "scheduler diagnostic detail unavailable" in output.worker_spawn_failures[0].detail
    assert logs and "scheduler diagnostic detail unavailable" in logs[0]


def test_stage1626_elastic_output_rejects_hostile_io_sample_without_hooks():
    HostileMapping.touched = 0

    output = ProcessQueueElasticScaleOutput(
        live_workers=1,
        next_worker_spawn_id=2,
        elastic_target_workers=1,
        elastic_cpu_sample=None,
        elastic_io_sample=HostileMapping(),
    )

    assert HostileMapping.touched == 0
    assert output.elastic_io_sample["scheduler_elastic_io_sample_unavailable"] is True
    assert output.elastic_io_sample["reason"] == "process_queue_elastic_io_sample_rejected"


def test_stage1959_elastic_scaling_sources_have_no_fallback_or_dynamic_log_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    helper_source = (root / "scheduler" / "workers" / "process_queue_elastic_no_hook.py").read_text(encoding="utf-8")
    scaling_source = (root / "scheduler" / "workers" / "process_queue_elastic_scaling.py").read_text(encoding="utf-8")
    combined = helper_source + "\n" + scaling_source

    assert "fallback" not in combined
    assert "scheduler_int" not in helper_source
    assert "scheduler_float" not in helper_source
    assert not any(isinstance(node, ast.JoinedStr) for node in ast.walk(ast.parse(helper_source)))
    assert "fallback=" not in scaling_source
