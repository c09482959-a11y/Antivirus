from __future__ import annotations

import signal
import subprocess

import pytest

from Virus_Scan.scheduler.workers import cleanup as cleanup_module
from Virus_Scan.scheduler.workers.cleanup import wait_for_process_queue_worker_exit
from Virus_Scan.scheduler.workers.cleanup_wait_steps import WorkerExitWaitStepContext


class _TimeoutThenExitProc:
    pid = 999999

    def __init__(self) -> None:
        self.terminated = 0
        self.killed = 0
        self.wait_calls = 0

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self.wait_calls == 1:
            raise subprocess.TimeoutExpired(cmd="worker", timeout=timeout)
        return 0

    def poll(self):
        return None if self.wait_calls <= 1 else 0

    def terminate(self):
        self.terminated += 1

    def kill(self):
        self.killed += 1


class _UnkillableTimeoutProc:
    pid = 999998

    def __init__(self) -> None:
        self.terminated = 0
        self.killed = 0

    def wait(self, timeout=None):
        raise subprocess.TimeoutExpired(cmd="worker", timeout=timeout)

    def poll(self):
        return None

    def terminate(self):
        self.terminated += 1

    def kill(self):
        self.killed += 1


class _NoProcessGroupOps:
    name = "posix"

    @staticmethod
    def fspath(path):
        return str(path)

    @staticmethod
    def killpg(*args, **kwargs):
        raise OSError("no process group")

    @staticmethod
    def getpgid(pid):
        return pid


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


def test_stage372_final_worker_wait_timeout_is_accounted_and_cleaned():
    events = []
    report_issue = lambda marker, exc, fatal=False, extra=None: events.append((marker, fatal, dict(extra or {})))
    proc = _TimeoutThenExitProc()
    rc = wait_for_process_queue_worker_exit(
        proc,
        _wait_context(
            worker_idx=7,
            output="worker-7.json",
            timeout_sec=0.01,
            report_issue=report_issue,
            os_ops=_NoProcessGroupOps,
        ),
    )
    assert rc.status == 0
    assert rc.timed_out is True
    assert rc.cleanup_actions == ("terminate",)
    assert proc.terminated == 1
    assert proc.killed == 0
    assert events[0][0] == "queue_worker_final_wait_timeout"
    assert events[0][2]["worker_idx"] == 7


def test_stage372_final_worker_wait_returns_infrastructure_failure_after_kill():
    events = []
    report_issue = lambda marker, exc, fatal=False, extra=None: events.append(marker)
    proc = _UnkillableTimeoutProc()
    rc = wait_for_process_queue_worker_exit(
        proc,
        _wait_context(
            worker_idx=8,
            output="worker-8.json",
            timeout_sec=0.01,
            report_issue=report_issue,
            os_ops=_NoProcessGroupOps,
        ),
    )
    assert rc.status == -1
    assert rc.infrastructure_failed is True
    assert rc.cleanup_actions == ("terminate", "kill")
    assert proc.terminated == 1
    assert proc.killed == 1
    assert "queue_worker_final_wait_timeout" in events
