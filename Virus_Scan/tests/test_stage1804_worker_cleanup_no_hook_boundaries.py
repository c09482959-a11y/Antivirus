from __future__ import annotations

import signal

from Virus_Scan.scheduler.workers import cleanup as cleanup_module
from Virus_Scan.scheduler.workers.cleanup import terminate_process_queue_worker, wait_for_process_queue_worker_exit
from Virus_Scan.scheduler.workers.cleanup_wait_steps import WorkerExitWaitStepContext


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    getattribute_calls = 0
    fspath_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.float_calls = 0
        cls.int_calls = 0
        cls.getattribute_calls = 0
        cls.fspath_calls = 0

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

    def __fspath__(self):
        type(self).fspath_calls += 1
        raise AssertionError("__fspath__ hook must not execute")


class HostileProcess:
    pid_touched = 0
    method_touched = 0

    @property
    def pid(self):
        type(self).pid_touched += 1
        raise AssertionError("pid property must not execute")

    def __getattribute__(self, name):
        if name in {"wait", "poll", "terminate", "kill"}:
            type(self).method_touched += 1
            raise AssertionError("process method lookup must not execute")
        return object.__getattribute__(self, name)

    def wait(self, timeout=None):
        raise AssertionError("wait must not execute")

    def poll(self):
        raise AssertionError("poll must not execute")

    def terminate(self):
        raise AssertionError("terminate must not execute")

    def kill(self):
        raise AssertionError("kill must not execute")


def _reset() -> None:
    HostileValue.reset()
    HostileProcess.pid_touched = 0
    HostileProcess.method_touched = 0


def _assert_no_hooks() -> None:
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.format_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.iter_calls == 0
    assert HostileValue.float_calls == 0
    assert HostileValue.int_calls == 0
    assert HostileValue.getattribute_calls == 0
    assert HostileValue.fspath_calls == 0
    assert HostileProcess.pid_touched == 0
    assert HostileProcess.method_touched == 0


def _wait_context(*, worker_idx, output, timeout_sec, report_issue, os_ops=None):
    return WorkerExitWaitStepContext(
        worker_idx=worker_idx,
        output=output,
        timeout_sec=timeout_sec,
        report_issue=report_issue,
        os_ops=os_ops,
        default_os_ops=cleanup_module.os,
        terminate_signal=signal.SIGTERM,
        kill_signal=getattr(signal, "SIGKILL", signal.SIGTERM),
    )


def test_stage1804_worker_exit_wait_rejects_hostile_process_and_scalars_without_hooks():
    _reset()
    issues: list[tuple[str, dict[str, object]]] = []

    result = wait_for_process_queue_worker_exit(
        HostileProcess(),
        _wait_context(
            worker_idx=HostileValue(),
            output=HostileValue(),
            timeout_sec=HostileValue(),
            report_issue=lambda marker, _exc, *, fatal=False, extra=None: issues.append((marker, dict(extra or {}))),
        ),
    )

    assert result.status == -1
    assert result.pid == 0
    assert result.worker_idx == -1
    assert result.output == "worker_output_rejected"
    assert result.reason == "worker_final_wait_failed"
    assert result.failure_markers == ("queue_worker_final_wait_failed",)
    assert issues[0][0] == "queue_worker_final_wait_failed"
    _assert_no_hooks()


def test_stage1804_terminate_worker_rejects_hostile_action_without_stringifying():
    _reset()
    reports: list[tuple[str, str]] = []

    result = terminate_process_queue_worker(
        HostileProcess(),
        action=HostileValue(),
        worker_idx=HostileValue(),
        report_failure=lambda label, exc: reports.append((label, type(exc).__name__)),
    )

    assert result.requested is False
    assert result.completed is False
    assert result.action == "terminate"
    assert result.error in {"process_handle_pid_descriptor_rejected", "unsupported_process_handle_getattribute"}
    assert reports == []
    _assert_no_hooks()
