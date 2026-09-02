from pathlib import Path

from Virus_Scan.scheduler.internal.exception_projection import scheduler_exception_text
from Virus_Scan.scheduler.replay.replay_projection_failure import build_replay_projection_failure_result
from Virus_Scan.scheduler.workers.child_failure_metadata import build_safe_exception_info
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import safe_lifecycle_exception_message


class HostileArgsError(RuntimeError):
    touched = 0

    @property
    def args(self):
        type(self).touched += 1
        raise RuntimeError("exception args descriptor executed")


class HostileSchedulerError(RuntimeError):
    __module__ = "Virus_Scan.scheduler.hostile"
    touched = 0

    @property
    def args(self):
        type(self).touched += 1
        raise RuntimeError("scheduler exception args descriptor executed")


def _reset() -> None:
    HostileArgsError.touched = 0
    HostileSchedulerError.touched = 0


def test_stage1753_canonical_exception_projection_rejects_subclass_args_without_access() -> None:
    _reset()

    assert scheduler_exception_text(HostileArgsError("boom")) == (
        "HostileArgsError: scheduler diagnostic detail unavailable without caller hooks"
    )
    assert scheduler_exception_text(HostileSchedulerError("boom")) == (
        "HostileSchedulerError: scheduler diagnostic detail unavailable without caller hooks"
    )
    assert HostileArgsError.touched == 0
    assert HostileSchedulerError.touched == 0


def test_stage1753_scheduler_exception_callers_share_no_hook_projection() -> None:
    _reset()
    hostile = HostileArgsError("boom")

    info = build_safe_exception_info(hostile, stage="stage1753")
    lifecycle_message = safe_lifecycle_exception_message(hostile)
    replay = build_replay_projection_failure_result("actual", hostile, ())

    assert info["error"] == "HostileArgsError"
    assert lifecycle_message == "HostileArgsError"
    assert replay.mismatches[0]["message"] == "scheduler replay projection failed"
    assert HostileArgsError.touched == 0


def test_stage1753_exact_builtin_exception_messages_remain_available() -> None:
    assert scheduler_exception_text(RuntimeError("boom", 7)) == "boom; 7"
    assert build_safe_exception_info(ValueError("bad value"), stage="stage1753")["error"] == "bad value"


def test_stage1753_scheduler_exception_args_access_has_one_owner() -> None:
    scheduler_root = Path(__file__).parents[1] / "scheduler"
    offenders = []
    for source in scheduler_root.rglob("*.py"):
        text = source.read_text(encoding="utf-8")
        if '"args"' in text and "__getattribute__" in text:
            offenders.append(source.relative_to(scheduler_root).as_posix())

    assert offenders == ["internal/exception_projection.py"]
