"""Stage1598: scanner binary runtime exception evidence is no-hook."""
from __future__ import annotations

from Virus_Scan.scanners.binary_runtime_evidence import _safe_exception_info


class HostileError(Exception):
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileStage:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify stage")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr stage")


class HostilePid:
    touched = 0

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not int")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str")


def test_stage1598_binary_runtime_exception_info_rejects_hostile_exception_without_hooks():
    HostileError.touched = 0
    info = _safe_exception_info(HostileError("boom"), stage="stage1598")

    assert HostileError.touched == 0
    assert info["exception_type"] == "HostileError"
    assert info["error"] == "HostileError"
    assert info["error_unavailable_reason"] == "unsupported_exception_object_rejected"
    assert info["traceback_unavailable_reason"] == "unsupported_exception_traceback_rejected"


def test_stage1598_binary_runtime_exception_info_rejects_hostile_stage_pid_and_attempt_without_hooks():
    HostileStage.touched = 0
    HostilePid.touched = 0
    info = _safe_exception_info(RuntimeError("boom"), stage=HostileStage(), worker_pid=HostilePid(), attempt=HostilePid())

    assert HostileStage.touched == 0
    assert HostilePid.touched == 0
    assert info["stage"] == "unknown"
    assert info["stage_unavailable_reason"] == "stage_rejected"
    assert info["worker_pid_unavailable_reason"] == "worker_pid_rejected"
    assert info["attempt"] is None
    assert info["attempt_unavailable_reason"] == "attempt_rejected"
    assert info["error"] == "boom"


def test_stage1598_binary_runtime_exception_info_preserves_builtin_exception_message():
    info = _safe_exception_info(ValueError("bad pe"), stage="pe", worker_pid=123, attempt=2)

    assert info["stage"] == "pe"
    assert info["worker_pid"] == 123
    assert info["attempt"] == 2
    assert info["exception_type"] == "ValueError"
    assert info["error"] == "bad pe"
