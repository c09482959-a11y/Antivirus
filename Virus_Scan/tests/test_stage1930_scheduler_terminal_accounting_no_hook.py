"""Stage 1930 queue terminal accounting no-hook regressions."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.terminal_accounting import (
    IdleQueueFinalizationRequest,
    idle_queue_finalization_decision,
)
from Virus_Scan.scheduler.queue.terminal_worker_cleanup import terminate_processes


class HostileTerminalValue:
    calls = {
        "str": 0,
        "repr": 0,
        "format": 0,
        "bool": 0,
        "iter": 0,
        "int": 0,
        "float": 0,
        "call": 0,
    }

    def __str__(self):
        type(self).calls["str"] += 1
        raise RuntimeError("string hook must not run")

    def __repr__(self):
        type(self).calls["repr"] += 1
        raise RuntimeError("repr hook must not run")

    def __format__(self, spec):
        type(self).calls["format"] += 1
        raise RuntimeError("format hook must not run")

    def __bool__(self):
        type(self).calls["bool"] += 1
        raise RuntimeError("bool hook must not run")

    def __iter__(self):
        type(self).calls["iter"] += 1
        raise RuntimeError("iter hook must not run")

    def __int__(self):
        type(self).calls["int"] += 1
        raise RuntimeError("int hook must not run")

    def __float__(self):
        type(self).calls["float"] += 1
        raise RuntimeError("float hook must not run")

    def __call__(self, *args, **kwargs):
        type(self).calls["call"] += 1
        raise RuntimeError("callback hook must not run")


class HostileReport(HostileTerminalValue):
    pass


def _reset_hooks() -> None:
    for key in HostileTerminalValue.calls:
        HostileTerminalValue.calls[key] = 0


def _assert_no_hooks() -> None:
    assert HostileTerminalValue.calls == {
        "str": 0,
        "repr": 0,
        "format": 0,
        "bool": 0,
        "iter": 0,
        "int": 0,
        "float": 0,
        "call": 0,
    }


def test_terminal_accounting_rejects_hostile_report_callback_without_calling_it() -> None:
    _reset_hooks()
    hostile_report = HostileReport()

    terminated, next_notice = idle_queue_finalization_decision(IdleQueueFinalizationRequest(
        no_live_queue_work=HostileTerminalValue(),
        accounted_files=0,
        total_files=1,
        idle_elapsed=0.0,
        idle_notice_sec=5.0,
        idle_grace_sec=30.0,
        live_workers=0,
        procs=(),
        terminate_worker=lambda *_args, **_kwargs: None,
        report=hostile_report,
        log_info=lambda _message: None,
        sleep=lambda _seconds: None,
    ))

    assert terminated is False
    assert next_notice == 5.0
    _assert_no_hooks()


def test_terminal_accounting_log_messages_use_exact_primitive_formatting() -> None:
    _reset_hooks()
    logs: list[str] = []
    reports: list[tuple[str, str]] = []

    terminated, next_notice = idle_queue_finalization_decision(IdleQueueFinalizationRequest(
        no_live_queue_work=True,
        accounted_files=2,
        total_files=2,
        idle_elapsed=31.0,
        idle_notice_sec=5.0,
        idle_grace_sec=30.0,
        live_workers=2,
        procs=(),
        terminate_worker=lambda *_args, **_kwargs: None,
        report=lambda marker, exc, **_kwargs: reports.append((marker, type(exc).__name__)),
        log_info=logs.append,
        sleep=lambda _seconds: None,
    ))

    assert terminated is True
    assert next_notice == 5.0
    assert logs == [
        "bulk scan queue drained; waiting for 2 worker process(es) to exit/write final output",
        "bulk scan queue drained; terminating 2 idle worker process(es) after grace=30.0s",
    ]
    assert reports == []
    _assert_no_hooks()


def test_terminal_worker_cleanup_builds_rejection_markers_without_context_hooks() -> None:
    _reset_hooks()
    reports: list[tuple[str, str, dict[str, object]]] = []
    terminations: list[tuple[object, str, int]] = []

    terminate_processes(
        ((HostileTerminalValue(), object(), "out", ()),),
        actions=("terminate",),
        terminate_worker=lambda proc, *, action, worker_idx: terminations.append(
            (proc, action, worker_idx)
        ),
        report=lambda marker, exc, **kwargs: reports.append((marker, type(exc).__name__, kwargs)),
        sleep=lambda _seconds: None,
        context=HostileTerminalValue(),
    )

    assert terminations and terminations[0][1:] == ("terminate", 0)
    assert any(marker == "queue_termination_context_rejected" for marker, _name, _kwargs in reports)
    assert any(
        marker == "queue_idle_finalization_terminate_worker_index_rejected"
        for marker, _name, _kwargs in reports
    )
    _assert_no_hooks()
