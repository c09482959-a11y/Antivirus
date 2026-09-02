import os
from pathlib import Path

from Virus_Scan.scheduler.workers.process_liveness import check_process_queue_worker_liveness


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0

    @classmethod
    def reset(cls):
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.float_calls = 0
        cls.int_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("must not execute")

    def __format__(self, spec):
        type(self).format_calls += 1
        raise RuntimeError("must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("must not execute")

    def __int__(self):
        type(self).int_calls += 1
        raise RuntimeError("must not execute")


def _assert_no_hostile_hooks():
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.format_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.iter_calls == 0
    assert HostileValue.float_calls == 0
    assert HostileValue.int_calls == 0


def test_stage1790_process_liveness_rejects_hostile_pid_without_hooks():
    reports = []
    HostileValue.reset()
    result = check_process_queue_worker_liveness(
        HostileValue(),
        record_suppressed=lambda *args, **kwargs: reports.append((args, kwargs)),
    )
    assert result.pid == 0
    assert result.alive is False
    assert result.reason == "pid_parse_failed"
    assert reports and reports[0][0][0] == "process_queue_pid_liveness_probe_failed"
    extra = reports[0][1]["extra"]
    assert extra["pid_unavailable"] is True
    assert extra["pid_evidence"]["field_name"] == "worker_pid"
    _assert_no_hostile_hooks()


def test_stage1790_process_liveness_preserves_exact_current_pid():
    reports = []
    result = check_process_queue_worker_liveness(
        os.getpid(),
        record_suppressed=lambda *args, **kwargs: reports.append((args, kwargs)),
    )
    assert result.pid == os.getpid()
    assert result.alive is True
    assert result.reason == "current_process"
    assert reports == []


def test_stage1959_process_liveness_source_has_no_fallback_default_scalar_route():
    root = Path(__file__).resolve().parents[1]
    source = (root / "scheduler" / "workers" / "process_liveness.py").read_text(encoding="utf-8")

    assert "fallback" not in source
    assert "scheduler_int" not in source
    assert "default=" not in source
