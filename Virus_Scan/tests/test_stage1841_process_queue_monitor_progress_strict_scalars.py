
"""Stage 1841: monitor-progress scalar validation has no unsafe fallback path."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

import pytest

from Virus_Scan.scheduler.evidence.process_queue_monitor_progress import (
    ProcessQueueMonitorProgressRequest,
    ProcessQueueMonitorProgressDependencies,
    publish_process_queue_monitor_progress,
)


class HostileScalar:
    touched = 0

    def __str__(self):  # pragma: no cover - failure path
        type(self).touched += 1
        raise AssertionError("caller-owned str hook must not execute")

    def __int__(self):  # pragma: no cover - failure path
        type(self).touched += 1
        raise AssertionError("caller-owned int hook must not execute")

    def __float__(self):  # pragma: no cover - failure path
        type(self).touched += 1
        raise AssertionError("caller-owned float hook must not execute")

    def __format__(self, _spec):  # pragma: no cover - failure path
        type(self).touched += 1
        raise AssertionError("caller-owned format hook must not execute")


def _request(**overrides):
    values = dict(
        outputs=(),
        partial_output_path=None,
        file_done_count=0,
        file_failed_count=0,
        file_active_count=0,
        file_pending_count=0,
        raw_live=0,
        raw_done=0,
        raw_failed=0,
        live_workers=0,
        total_files=1,
        progress_every=1,
        last_done_count=0,
        last_progress_time=0.0,
        progress_interval_sec=1.0,
        last_monitor_heartbeat_time=0.0,
        monitor_heartbeat_sec=1.0,
        accounted_total=0,
        elastic_cpu_sample=None,
        now=0.0,
    )
    values.update(overrides)
    return ProcessQueueMonitorProgressRequest(**values)


def test_stage1841_monitor_progress_rejects_unknown_scalar_without_hooks():
    HostileScalar.touched = 0
    with pytest.raises(ValueError, match="scheduler_monitor_file_done_count_rejected"):
        _request(file_done_count=HostileScalar())
    with pytest.raises(ValueError, match="scheduler_monitor_last_progress_time_rejected"):
        _request(last_progress_time=HostileScalar())
    assert HostileScalar.touched == 0


def test_stage1841_monitor_progress_keeps_exact_primitive_coercion_and_clamp():
    request = _request(
        file_done_count="2",
        file_failed_count=b"1",
        file_active_count=1.0,
        file_pending_count=bytearray(b"3"),
        raw_live="4",
        raw_done=5,
        raw_failed=-1,
        live_workers=1,
        total_files=10,
        progress_every=2,
        last_done_count=-1,
        last_progress_time="1.5",
        progress_interval_sec=b"2.5",
        last_monitor_heartbeat_time=bytearray(b"3.5"),
        monitor_heartbeat_sec=4,
        accounted_total=-9,
        elastic_cpu_sample=101.0,
        now="5.0",
    )
    assert request.file_done_count == 2
    assert request.file_failed_count == 1
    assert request.file_active_count == 1
    assert request.file_pending_count == 3
    assert request.raw_live == 4
    assert request.raw_done == 5
    assert request.raw_failed == 0
    assert request.last_done_count == 0
    assert request.last_progress_time == 1.5
    assert request.progress_interval_sec == 2.5
    assert request.last_monitor_heartbeat_time == 3.5
    assert request.monitor_heartbeat_sec == 4.0
    assert request.accounted_total == 0
    assert request.elastic_cpu_sample == 100.0
    assert request.now == 5.0


def test_stage1841_monitor_progress_log_materialization_uses_owned_scalars():
    logs: list[str] = []
    output = publish_process_queue_monitor_progress(
        _request(
            file_done_count=1,
            file_failed_count=0,
            file_active_count=0,
            file_pending_count=0,
            raw_live=0,
            raw_done=1,
            raw_failed=0,
            live_workers=1,
            total_files=1,
            progress_every=1,
            last_done_count=0,
            now=1.0,
        ),
        ProcessQueueMonitorProgressDependencies(
            log_info=logs.append,
            read_json_file=lambda _path, *, default: default,
            log_error=lambda _message: None,
            recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError),
        ),
    )
    assert output.last_done_count == 1
    assert logs == [
        "bulk scan progress: files_done=1/1 files_active=0 files_pending=0 files_failed=0 raw_live=0 raw_done=1 raw_failed=0 live_workers=1"
    ]


def test_stage1841_monitor_progress_source_has_no_fallback_or_dynamic_reason_paths():
    sources = (
        read_python_file(Path("Virus_Scan/scheduler/evidence/process_queue_monitor_progress.py")),
        read_python_file(Path("Virus_Scan/scheduler/evidence/process_queue_monitor_progress_support.py")),
    )
    joined = "\n".join(sources)
    assert "fallback=" not in joined
    assert "scheduler_int(" not in joined
    assert "scheduler_float(" not in joined
    assert "object.__getattribute__(self, field_name)" not in joined
    assert 'f"scheduler_monitor_' not in joined
    assert 'f"bulk scan' not in joined
