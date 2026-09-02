"""Stage1607 raw-queue failure/degradation no-hook evidence closure."""
from __future__ import annotations

from Virus_Scan.scheduler.evidence.raw_queue_degradation import (
    record_raw_queue_degradation,
    record_raw_queue_issue as record_stage121_raw_queue_issue,
)
from Virus_Scan.scheduler.evidence.raw_queue_failure import default_failure_info
from Virus_Scan.scheduler.evidence.raw_queue_issue import record_raw_queue_issue
from Virus_Scan.scheduler.runtime.queue_json_failures import queue_default_failure_info


class HostileValue:
    touched = 0

    @property
    def text(self):
        HostileValue.touched += 1
        raise RuntimeError("text hook executed")

    @property
    def value(self):
        HostileValue.touched += 1
        raise RuntimeError("value hook executed")

    def __str__(self):
        HostileValue.touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):
        HostileValue.touched += 1
        raise RuntimeError("repr hook executed")

    def __format__(self, _spec):
        HostileValue.touched += 1
        raise RuntimeError("format hook executed")

    def __int__(self):
        HostileValue.touched += 1
        raise RuntimeError("int hook executed")

    def __float__(self):
        HostileValue.touched += 1
        raise RuntimeError("float hook executed")

    def __bool__(self):
        HostileValue.touched += 1
        raise RuntimeError("bool hook executed")

    def __iter__(self):
        HostileValue.touched += 1
        raise RuntimeError("iter hook executed")


class HostileException(Exception):
    touched = 0

    def __str__(self):
        HostileException.touched += 1
        raise RuntimeError("exception str hook executed")

    def __repr__(self):
        HostileException.touched += 1
        raise RuntimeError("exception repr hook executed")


def _reset_hostile_counters() -> None:
    HostileValue.touched = 0
    HostileException.touched = 0


def test_stage1607_stage121_raw_queue_issue_rejects_hostile_where_without_format_hooks():
    _reset_hostile_counters()
    calls: list[tuple[str, str]] = []

    record_stage121_raw_queue_issue(
        HostileValue(),
        HostileException("hidden"),
        report=lambda where, exc: calls.append((where, type(exc).__name__)),
    )

    assert HostileValue.touched == 0
    assert HostileException.touched == 0
    assert calls == [("stage121.raw_queue_issue", "HostileException")]


def test_stage1607_raw_queue_degradation_rejects_hostile_marker_integrity_and_exception_text():
    _reset_hostile_counters()
    captured: dict[str, object] = {}
    reports: list[tuple[object, str]] = []

    info = record_raw_queue_degradation(
        HostileValue(),
        HostileException("hidden"),
        where=HostileValue(),
        integrity=HostileValue(),
        set_scan_integrity=lambda _path, payload: captured.update(payload),
        report_issue=lambda where, exc: reports.append((where, type(exc).__name__)),
        recoverable_exceptions=(Exception,),
    )

    assert HostileValue.touched == 0
    assert HostileException.touched == 0
    assert info["raw_queue_degraded"] is True
    assert info["raw_queue_integrity_unavailable"] is True
    assert info["failure_info"]["stage"] == "global_raw_queue"
    assert info["failure_info"]["exception_type"] == "HostileException"
    assert info["failure_info"]["exception_text_unavailable"] is True
    assert captured["raw_queue_degraded"] is True
    assert reports == [("global_raw_queue", "HostileException")]


def test_stage1607_raw_queue_default_failure_info_rejects_hostile_fields_pid_attempt_and_extra():
    _reset_hostile_counters()

    info = default_failure_info(
        stage=HostileValue(),
        error=HostileValue(),
        exception_type=HostileValue(),
        worker_pid=HostileValue(),
        attempt=HostileValue(),
        extra={HostileValue(): HostileValue(), "safe": HostileValue()},
    )

    assert HostileValue.touched == 0
    assert info["stage"] == "queue_failed"
    assert info["error"] == "queue job failed"
    assert info["failure_info_has_rejected_fields"] is True
    assert info["worker_pid"]["unsupported_scheduler_value"] is True
    assert info["attempt"]["unsupported_scheduler_value"] is True
    assert info["unsupported_extra_key_0"]["unsupported_scheduler_value"] is True
    assert info["safe"]["unsupported_scheduler_value"] is True


def test_stage1607_raw_queue_issue_rejects_hostile_stage_fatal_and_extra_without_hooks():
    _reset_hostile_counters()
    calls: list[tuple[str, str, dict[str, object] | None]] = []

    record_raw_queue_issue(
        HostileValue(),
        HostileException("hidden"),
        fatal=HostileValue(),
        extra={HostileValue(): HostileValue(), "safe": HostileValue()},
        record_scheduler_suppressed=lambda marker, exc, extra=None: calls.append((marker, type(exc).__name__, extra)),
        record_raw_suppressed=lambda marker, exc: calls.append((marker, type(exc).__name__, None)),
        recoverable_exceptions=(Exception,),
    )

    assert HostileValue.touched == 0
    assert HostileException.touched == 0
    assert calls[0][0] == "raw_queue_issue"
    payload = calls[0][2]
    assert payload is not None
    assert payload["raw_queue_stage_rejected"] is True
    assert payload["fatal_rejected"] is True
    assert payload["unsupported_extra_key_0"]["unsupported_scheduler_value"] is True
    assert payload["safe"]["unsupported_scheduler_value"] is True


def test_stage1607_runtime_queue_default_failure_info_rejects_hostile_fields_and_extra():
    _reset_hostile_counters()

    info = queue_default_failure_info(
        HostileValue(),
        exception_type=HostileValue(),
        error=HostileValue(),
        worker_pid=HostileValue(),
        attempt=HostileValue(),
        extra={HostileValue(): HostileValue(), "safe": HostileValue()},
    )

    assert HostileValue.touched == 0
    assert info["stage"] == "queue_failed"
    assert info["exception_type"] == "QueueFailure"
    assert info["error"] == "queue job failed"
    assert info["failure_info_has_rejected_fields"] is True
    assert info["worker_pid"]["unsupported_scheduler_value"] is True
    assert info["attempt"]["unsupported_scheduler_value"] is True
    assert info["unsupported_extra_key_0"]["unsupported_scheduler_value"] is True
    assert info["safe"]["unsupported_scheduler_value"] is True
