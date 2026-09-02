from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scheduler.timeout.escalation_engine import (
    ProcessQueueStallEscalationDependencies,
    ProcessQueueStallEscalationRequest,
    terminate_stalled_process_queue_workers,
)


class HostileElapsed:
    touched = 0

    def __str__(self):
        HostileElapsed.touched += 1
        raise RuntimeError("elapsed __str__ must not run")

    def __repr__(self):
        HostileElapsed.touched += 1
        raise RuntimeError("elapsed __repr__ must not run")

    def __format__(self, _spec):
        HostileElapsed.touched += 1
        raise RuntimeError("elapsed __format__ must not run")

    def __float__(self):
        HostileElapsed.touched += 1
        raise RuntimeError("elapsed __float__ must not run")

    def __bool__(self):
        HostileElapsed.touched += 1
        raise RuntimeError("elapsed __bool__ must not run")


class _Proc:
    pid = 31337


class _Result:
    pid = 31337
    error = ""


def test_stage1939_stall_log_elapsed_rejects_hostile_object_without_hooks() -> None:
    HostileElapsed.touched = 0
    messages: list[str] = []

    result = terminate_stalled_process_queue_workers(
        ProcessQueueStallEscalationRequest(procs=(), elapsed_sec=HostileElapsed()),  # type: ignore[arg-type]
        ProcessQueueStallEscalationDependencies(
            log_error=messages.append,
            record_issue=lambda *_args, **_kwargs: None,
            sleep=lambda _seconds: None,
            worker_terminator=lambda **_kwargs: _Result(),
        ),
    )

    assert HostileElapsed.touched == 0
    assert result.terminated == 0
    assert result.killed == 0
    assert result.evidence == ()
    assert messages == [
        "bulk scan queue made no checkpoint progress for 0.0s; "
        "terminating live workers so incomplete claims can retry/fail cleanly"
    ]


def test_stage1939_timeout_escalation_source_removes_prior_hook_and_fallback_routes() -> None:
    escalation_source = read_python_file(Path("Virus_Scan/scheduler/timeout/escalation_engine.py"))
    reporting_source = read_python_file(Path("Virus_Scan/scheduler/timeout/process_queue_stall_reporting.py"))

    assert "{request.elapsed_sec:.1f}" not in escalation_source
    assert "fallback_pid" not in escalation_source
    assert "fallback_pid" not in reporting_source
    assert "termination_result_snapshot(result, replacement_pid=pid_for_process(proc))" in escalation_source

from Virus_Scan.scheduler.timeout.inmemory_memory_policy import build_inmemory_worker_memory_policy


class HostileMemoryLimit:
    touched = 0

    def __str__(self):
        HostileMemoryLimit.touched += 1
        raise RuntimeError("memory limit __str__ must not run")

    def __repr__(self):
        HostileMemoryLimit.touched += 1
        raise RuntimeError("memory limit __repr__ must not run")

    def __float__(self):
        HostileMemoryLimit.touched += 1
        raise RuntimeError("memory limit __float__ must not run")

    def __bool__(self):
        HostileMemoryLimit.touched += 1
        raise RuntimeError("memory limit __bool__ must not run")


def test_stage1939_memory_policy_rejects_hostile_limit_without_hooks() -> None:
    HostileMemoryLimit.touched = 0

    policy = build_inmemory_worker_memory_policy({"UMIGE_INMEMORY_WORKER_RSS_LIMIT_MB": HostileMemoryLimit()})  # type: ignore[dict-item]

    assert HostileMemoryLimit.touched == 0
    assert policy.rss_limit_mb == 2048.0
    assert len(policy.config_evidence) == 1
    record = policy.config_evidence[0]
    assert record["raw_value"]["unsupported_scheduler_value"] is True
    assert record["default_value"] == 2048.0
    assert record["error_category"] == "ValueError"


def test_stage1939_memory_policy_source_removes_prior_float_and_fallback_routes() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/timeout/inmemory_memory_policy.py"))

    assert "fallback_value" not in source
    assert "float(fallback_value)" not in source
    assert "float(raw_value or" not in source
    assert "scheduler_float(" in source
