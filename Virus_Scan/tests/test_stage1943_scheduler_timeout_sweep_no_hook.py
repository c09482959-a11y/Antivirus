from __future__ import annotations

import ast
import signal
from pathlib import Path
from typing import Any, Iterator, cast

from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep import enforce_inmemory_timeout_sweep
from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from Virus_Scan.scheduler.queue.inmemory_recovery_evidence_journal import InMemoryRecoveryEvidenceJournal
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_budget_values import timeout_budget_mapping_for_record
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_progress_cancel import record_progress_stall_cancel
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_result import InMemoryTimeoutSweepResult, build_inmemory_timeout_sweep_result
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_running_budget import build_running_timeout_budget_state
from Virus_Scan.scheduler.timeout.longtask_controller import FileScanTimeoutError, per_file_timeout
from Virus_Scan.scheduler.timeout.process_queue_monitor_policy import process_queue_monitor_policy

RECOVERABLE = (RuntimeError, TypeError, ValueError, OSError, OverflowError, AssertionError)


class HostileValue:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def _hit(self, name: str):
        self.calls.append(name)
        raise AssertionError(name)

    def __bool__(self):
        return self._hit("__bool__")

    def __float__(self):
        return self._hit("__float__")

    def __format__(self, _spec):
        return self._hit("__format__")

    def __int__(self):
        return self._hit("__int__")

    def __iter__(self) -> Iterator[object]:
        return self._hit("__iter__")

    def __repr__(self):
        return self._hit("__repr__")

    def __str__(self):
        return self._hit("__str__")


class HostileJobRecords(dict):
    def __init__(self) -> None:
        super().__init__({"job": {"state": "queued"}})
        self.calls: list[str] = []

    def items(self):
        self.calls.append("items")
        raise AssertionError("items")


class Recovery:
    def __init__(self) -> None:
        self.evidence_journal = InMemoryRecoveryEvidenceJournal()
        self.cancelled: list[tuple[object, str, object]] = []

    def request_cancel_only(self, jid, reason, *, pid=None):
        self.cancelled.append((jid, reason, pid))
        self.evidence_journal.append_cancel(({"job_id": "job", "reason": reason, "action": "cancel_only"},))

    def cancel_evidence_count(self):
        return self.evidence_journal.cancel_count()

    def cancel_evidence_since(self, cursor):
        return self.evidence_journal.cancel_since(cursor)

    def retry_evidence_count(self):
        return self.evidence_journal.retry_count()

    def retry_evidence_since(self, cursor):
        return self.evidence_journal.retry_since(cursor)


def _suppressed(_where, _exc):
    return None


def _noop(*_args, **_kwargs):
    return None


def _sweep_kwargs(job_records, *, state_index=None) -> dict[str, Any]:
    return dict(
        state_index=state_index if state_index is not None else InMemorySchedulerStateIndex(),
        job_records=job_records,
        active={},
        terminal=set(),
        worker_heartbeats={},
        worker_metrics={},
        heartbeat_table=None,
        heartbeat_flags=None,
        read_heartbeat=lambda **_kw: None,
        cancel_job=lambda *_args, **_kw: None,
        lifecycle_recorder=lambda _request: None,
        heartbeat_ingester=lambda **_kw: {"observed": 0, "cancel_requested": 0},
        monotonic_ns=lambda: 1,
        wall_time=lambda: 10.0,
        recovery=Recovery(),
        max_queued_unstarted=10,
        queued_start_timeout_sec=1.0,
        assigned_start_timeout_sec=1.0,
        heartbeat_stale_sec=1.0,
        progress_stale_sec=1.0,
        base_pf_timeout=1.0,
        cancel_grace_sec=1.0,
        start_wait_budget=lambda _record, default: default,
        stage_is_pre_execution=lambda _stage: False,
        update_ewma=_noop,
        ewma_state={},
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=RECOVERABLE,
    )


def test_stage1943_timeout_sweep_rejects_caller_owned_iteration_and_records_exact_dict_contract():
    hostile_records = HostileJobRecords()
    skipped = enforce_inmemory_timeout_sweep(**_sweep_kwargs(hostile_records))
    assert skipped.evaluated == 0
    assert hostile_records.calls == []

    hostile_record = HostileValue()
    state_index = InMemorySchedulerStateIndex()
    state_index.sync_record(1, {"state": "queued"}, due_at=0.0)
    result = enforce_inmemory_timeout_sweep(**_sweep_kwargs({1: hostile_record}, state_index=state_index))
    assert result.evaluated == 1
    assert hostile_record.calls == []
    assert result.timeout_retry_evidence[0]["reason"] == "job_record_malformed"


def test_stage1943_timeout_budget_and_progress_logging_do_not_call_hostile_hooks():
    hostile_budget = HostileValue()
    evidence: list[Any] = []
    budget = timeout_budget_mapping_for_record(
        jid="job",
        rec={"timeout_budget": hostile_budget, "attempt": HostileValue()},
        pid=HostileValue(),
        timeout_retry_evidence=evidence,
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=RECOVERABLE,
    )
    assert budget["timeout_budget_unavailable_reason"] == "timeout_budget_container_malformed"
    assert hostile_budget.calls == []

    hostile_job = HostileValue()
    hostile_attempt = HostileValue()
    hostile_stage = HostileValue()
    hostile_file = HostileValue()
    recovery = Recovery()
    progress_evidence: list[Any] = []
    reporting: list[Any] = []
    cast(Any, record_progress_stall_cancel)(
        jid=hostile_job,
        rec={"attempt": hostile_attempt, "stage": hostile_stage, "file": hostile_file},
        pid=HostileValue(),
        progress_age=HostileValue(),
        budget_info={},
        recovery=recovery,
        update_ewma=_noop,
        ewma_state={},
        timeout_retry_evidence=progress_evidence,
        timeout_reporting_failures=reporting,
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=RECOVERABLE,
    )
    assert hostile_job.calls == []
    assert hostile_attempt.calls == []
    assert hostile_stage.calls == []
    assert hostile_file.calls == []
    assert recovery.cancelled[0][1] == "queue_worker_progress_stalled"


def test_stage1943_result_running_budget_longtask_and_monitor_policy_reject_hostile_scalars_without_hooks():
    hostile_count = HostileValue()
    result = cast(Any, InMemoryTimeoutSweepResult)(evaluated=hostile_count, queued_waits=hostile_count, assigned_waits=1, hard_timeouts=0, orphaned_workers=0, progress_stalls=0, cancelled_after_stall=0)
    assert result.evaluated == 0
    assert result.queued_waits == 0
    assert hostile_count.calls == []

    shared = HostileValue()
    built = build_inmemory_timeout_sweep_result(
        evaluated=1,
        queued_waits=0,
        assigned_waits=0,
        hard_timeouts=0,
        orphaned_workers=0,
        progress_stalls=0,
        cancelled_after_stall=0,
        shared_heartbeat_result=shared,
        timeout_retry_evidence=(),
        timeout_reporting_failures=[],
    )
    assert built.shared_heartbeats_observed == 0
    assert shared.calls == []

    hostile_number = HostileValue()
    budget_failures: list[Any] = []
    state = build_running_timeout_budget_state(
        jid="job",
        rec={"pid": HostileValue(), "running_at": hostile_number, "timeout_budget": {}},
        now=10.0,
        heartbeat_stale_sec=hostile_number,  # type: ignore[arg-type]
        progress_stale_sec=hostile_number,  # type: ignore[arg-type]
        base_pf_timeout=hostile_number,  # type: ignore[arg-type]
        timeout_retry_evidence=budget_failures,
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=RECOVERABLE,
    )
    assert state.running_at == 0.0
    assert hostile_number.calls == []

    timeout = cast(Any, per_file_timeout)(HostileValue())
    assert timeout.seconds == 0

    ctx = per_file_timeout(3)
    if hasattr(signal, "SIGALRM"):
        sigalrm = cast(Any, signal).SIGALRM
        original = signal.getsignal(sigalrm)
        ctx.__enter__()
        try:
            try:
                handler = signal.getsignal(sigalrm)
                handler(sigalrm, None)  # type: ignore[misc]
            except FileScanTimeoutError as exc:
                assert exc.args == ("per-file timeout exceeded: 3s",)
        finally:
            ctx.__exit__(None, None, None)
            assert signal.getsignal(sigalrm) == original
    else:
        assert ctx.__enter__() is ctx
        assert ctx.__exit__(None, None, None) is False

    hostile_env = HostileJobRecords()
    policy = process_queue_monitor_policy(
        env=hostile_env,  # type: ignore[arg-type]
        configured_per_file_timeout_sec=HostileValue(),  # type: ignore[arg-type]
        recoverable_exceptions=RECOVERABLE,
    )
    assert policy.per_file_timeout_sec == 300.0
    assert hostile_env.calls == []


def test_stage1943_timeout_sweep_source_guards_block_hook_primitives_and_legacy_fallbacks():
    root = Path(__file__).resolve().parents[1]
    files = [
        "scheduler/timeout/inmemory_timeout_sweep.py",
        "scheduler/timeout/inmemory_timeout_sweep_budget_values.py",
        "scheduler/timeout/inmemory_timeout_sweep_progress_cancel.py",
        "scheduler/timeout/inmemory_timeout_sweep_progress_preexecution.py",
        "scheduler/timeout/inmemory_timeout_sweep_result.py",
        "scheduler/timeout/inmemory_timeout_sweep_running.py",
        "scheduler/timeout/inmemory_timeout_sweep_running_budget.py",
        "scheduler/timeout/inmemory_timeout_sweep_shared.py",
        "scheduler/timeout/inmemory_timeout_sweep_waits.py",
        "scheduler/timeout/inmemory_timeout_sweep_wall_time.py",
        "scheduler/timeout/longtask_controller.py",
        "scheduler/timeout/process_queue_monitor_evidence.py",
        "scheduler/timeout/process_queue_monitor_policy.py",
        "scheduler/timeout/process_queue_monitor_values.py",
    ]
    forbidden_text = [
        "list(job_records.items())",
        "job_records.items()",
        "rec.get(",
        "getattr(shared_heartbeat_result",
        "int(self.",
        "float(self.",
        "int(seconds",
        "RuntimeError(f",
        "FileScanTimeoutError(f",
        "fallback=",
        "fallback_value",
        "_fallback",
        "f\"{setting}",
    ]
    ast_violations = []
    text_violations = []
    for file_name in files:
        source = (root / file_name).read_text()
        for snippet in forbidden_text:
            if snippet in source:
                text_violations.append((file_name, snippet))
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                ast_violations.append((file_name, node.lineno, "f-string"))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"bool", "float", "int", "repr", "str", "vars"}:
                ast_violations.append((file_name, node.lineno, node.func.id))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                ast_violations.append((file_name, node.lineno, "get"))
    assert text_violations == []
    assert ast_violations == []
