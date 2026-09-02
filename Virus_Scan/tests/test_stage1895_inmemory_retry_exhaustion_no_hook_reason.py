from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file, read_python_file


import ast
from collections import deque
from pathlib import Path
from types import SimpleNamespace

from Virus_Scan.scheduler.queue.inmemory_retry_contracts import (
    retry_suppression_record_failure_error,
)
from Virus_Scan.scheduler.queue.inmemory_retry_exhaustion_integrity import (
    attach_retry_exhaustion_integrity,
)
from Virus_Scan.scheduler.queue.inmemory_retry_missing_record import (
    retry_duplicate_pending_evidence,
    retry_missing_record_evidence,
    retry_terminal_already_evidence,
)
from Virus_Scan.scheduler.queue.inmemory_retry_recovery import retry_or_fail


class _HookBomb:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def _called(self, name: str):
        self.calls.append(name)
        raise AssertionError("hostile hook called: " + name)

    def __bool__(self):
        return self._called("__bool__")

    def __format__(self, _spec):
        return self._called("__format__")

    def __int__(self):
        return self._called("__int__")

    def __iter__(self):
        return self._called("__iter__")

    def __repr__(self):
        return self._called("__repr__")

    def __str__(self):
        return self._called("__str__")

    def items(self):
        return self._called("items")


class _HookBombRuntimeError(RuntimeError):
    def __init__(self) -> None:
        RuntimeError.__init__(self, "stored message")
        self.calls: list[str] = []

    def _called(self, name: str):
        self.calls.append(name)
        raise AssertionError("hostile exception hook called: " + name)

    def __format__(self, _spec):
        return self._called("__format__")

    def __repr__(self):
        return self._called("__repr__")

    def __str__(self):
        return self._called("__str__")


class _RejectingPending(deque):
    def appendleft(self, _item):
        raise RuntimeError("pending unavailable")


def _worker_error_result(path, error):
    return {"file": path, "error": str(error), "scan_integrity": {}}


def test_stage1895_retry_exhaustion_integrity_rejects_hostile_reason_pid_and_integrity_without_hooks() -> None:
    hostile_reason = _HookBomb()
    hostile_pid = _HookBomb()
    hostile_history = _HookBomb()
    hostile_integrity = _HookBomb()
    res = {"scan_integrity": hostile_integrity}
    rec = {"history": hostile_history}
    job_records: dict[int, dict[str, object]] = {11: rec}

    attach_retry_exhaustion_integrity(
        res=res,
        rec=rec,
        job_records=job_records,
        job_id=11,
        reason=hostile_reason,
        old_generation=3,
        pid=hostile_pid,
        cancel_publication=SimpleNamespace(evidence=None),
    )

    assert hostile_reason.calls == []
    assert hostile_pid.calls == []
    assert hostile_history.calls == []
    assert hostile_integrity.calls == []
    assert res["scheduler_failure_reason"] == "<_HookBomb unsupported_retry_reason>"
    assert res["scheduler_retry_count"] == 3
    assert res["scan_integrity"]["inmemory_retry_contract_failed"] is True
    assert res["scan_integrity"]["inmemory_worker_failure_evidence"]["worker_pid"] == 0
    failures = job_records[11]["retry_contract_failures"]
    assert {item["field"] for item in failures} == {"history", "pid"}


def test_stage1895_retry_pending_publication_failure_rejects_hostile_reason_without_hooks() -> None:
    hostile_reason = _HookBomb()
    job_records = {5: {"file": "sample.bin", "attempt": 0, "history": ()}}
    results: dict[str, object] = {}
    failed: set[int] = set()
    terminal: set[int] = set()

    hostile_pid = _HookBomb()
    decision = retry_or_fail(
        job_records=job_records,
        active={5: object()},
        pending=_RejectingPending(),
        results=results,
        failed=failed,
        terminal=terminal,
        job_id=5,
        reason=hostile_reason,
        max_job_retries=1,
        cancel_table={},
        cancel_generation=None,
        cancel_flags=None,
        lifecycle_recorder=lambda _request: None,
        worker_error_result=_worker_error_result,
        pid=hostile_pid,
    )

    assert hostile_reason.calls == []
    assert hostile_pid.calls == []
    assert decision.retried is False
    assert decision.completed_delta == 1
    result = results["sample.bin"]
    assert result["retry_pending_publication_failed"] is True
    assert "<_HookBomb unsupported_retry_reason>" in result["error"]
    assert result["retry_pending_publication_evidence"]["reason"] == "<_HookBomb unsupported_retry_reason>"


def test_stage1895_suppression_record_error_projection_avoids_exception_hooks() -> None:
    primary = _HookBombRuntimeError()
    recorder = _HookBombRuntimeError()

    projected = retry_suppression_record_failure_error(primary, recorder)

    assert primary.calls == []
    assert recorder.calls == []
    assert isinstance(projected, RuntimeError)
    detail = projected.args[0]
    assert "suppression_record_failed=" in detail
    assert "scheduler diagnostic detail unavailable" in detail


def test_stage1895_retry_exhaustion_sources_have_no_fallback_or_targeted_fstrings() -> None:
    queue_root = Path(__file__).parents[1] / "scheduler" / "queue"
    guarded = (
        queue_root / "inmemory_retry_exhaustion_integrity.py",
        queue_root / "inmemory_retry_exhaustion_lifecycle.py",
        queue_root / "inmemory_retry_exhaustion_publication.py",
        queue_root / "inmemory_retry_failure_result.py",
        queue_root / "inmemory_retry_missing_contract.py",
        queue_root / "inmemory_retry_missing_record.py",
        queue_root / "inmemory_retry_publication.py",
        queue_root / "inmemory_retry_recovery_exhausted.py",
        queue_root / "inmemory_retry_recovery_requeue.py",
    )
    for source_path in guarded:
        source = read_python_file(source_path)
        tree = parse_python_file(source_path)
        assert "fallback=" not in source
        assert "pid or 0" not in source
        assert "suppression_record_failed={" not in source
        assert [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []


def test_stage1895_retry_missing_record_evidence_rejects_hostile_reason_and_record_without_hooks() -> None:
    hostile_reason = _HookBomb()
    hostile_record = _HookBomb()

    missing = retry_missing_record_evidence(
        job_id=9,
        reason=hostile_reason,
        record=hostile_record,
    )
    duplicate = retry_duplicate_pending_evidence(
        job_id=9,
        reason=hostile_reason,
        generation=2,
    )
    terminal = retry_terminal_already_evidence(
        job_id=9,
        reason=hostile_reason,
        record={"attempt": 4},
    )

    assert hostile_reason.calls == []
    assert hostile_record.calls == []
    assert missing["reason"] == "<_HookBomb unsupported_retry_reason>"
    assert missing["detail"] == "job record must be a mapping, got _HookBomb"
    assert duplicate["detail"] == "retry recovery ignored duplicate pending retry for job 9 generation 2"
    assert terminal["detail"] == "retry recovery was requested for terminal job 9 generation 4"
