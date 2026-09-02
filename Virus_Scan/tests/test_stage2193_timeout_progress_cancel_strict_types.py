"""Stage2193 strict typing closure for timeout progress-stall cancellation."""
from __future__ import annotations

import inspect

from Virus_Scan.scheduler.timeout import inmemory_timeout_sweep_progress_cancel as progress_cancel
from Virus_Scan.scheduler.queue.inmemory_recovery_evidence_journal import InMemoryRecoveryEvidenceJournal

RECOVERABLE = (RuntimeError, TypeError, ValueError, OSError, AssertionError)


class _Recovery:
    def __init__(self) -> None:
        self.evidence_journal = InMemoryRecoveryEvidenceJournal()
        self.cancelled: list[tuple[object, str, object | None]] = []
        self.retried: list[tuple[object, str, object | None]] = []

    def request_cancel_only(self, job_id: object, reason: str, *, pid: object | None = None) -> object:
        self.cancelled.append((job_id, reason, pid))
        self.evidence_journal.append_cancel(({"job_id": job_id, "reason": reason, "action": "cancel_only"},))
        return None

    def retry_or_fail(self, job_id: object, reason: str, *, pid: object | None = None) -> object:
        self.retried.append((job_id, reason, pid))
        self.evidence_journal.append_retry(({"job_id": job_id, "reason": reason, "action": "retry_or_fail"},))
        return None

    def cancel_evidence_count(self) -> int:
        return self.evidence_journal.cancel_count()

    def cancel_evidence_since(self, cursor: object):
        return self.evidence_journal.cancel_since(cursor)

    def retry_evidence_count(self) -> int:
        return self.evidence_journal.retry_count()

    def retry_evidence_since(self, cursor: object):
        return self.evidence_journal.retry_since(cursor)


def _suppressed(_where: str, _exc: BaseException) -> object:
    return None


def _ewma(_metric: str, _value: float, *, state: dict[str, object]) -> object:
    state["called"] = True
    return None


def test_stage2193_progress_cancel_source_removes_any_boundary_annotations() -> None:
    source = inspect.getsource(progress_cancel)
    assert "from typing import Any" not in source
    assert ": Any" not in source
    assert "Mapping[str, Any]" not in source
    assert "Callable[...," not in source
    assert "ProgressStallRecovery" in source
    assert "EwmaUpdater" in source


def test_stage2193_progress_cancel_records_typed_cancel_evidence() -> None:
    recovery = _Recovery()
    ewma_state: dict[str, object] = {}
    retry_evidence: list[dict[str, object]] = []
    reporting_failures: list[dict[str, object]] = []

    progress, cancelled = progress_cancel.evaluate_progress_stall_cancellation(
        jid="job-1",
        rec={"attempt": 2, "stage": "running", "file": "sample.bin"},
        now=10.0,
        pid=123,
        progress_age=4.0,
        budget_info={"timeout": 3.0},
        recovery=recovery,
        cancel_grace_sec=1.0,
        update_ewma=_ewma,
        ewma_state=ewma_state,
        timeout_retry_evidence=retry_evidence,
        timeout_reporting_failures=reporting_failures,
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=RECOVERABLE,
    )

    assert (progress, cancelled) == (1, 0)
    assert ewma_state == {"called": True}
    assert recovery.cancelled == [("job-1", "queue_worker_progress_stalled", 123)]
    assert retry_evidence[-1]["action"] == "cancel_only"
    assert reporting_failures == []


def test_stage2193_progress_cancel_escalates_after_grace_without_any_boundary() -> None:
    recovery = _Recovery()
    retry_evidence: list[dict[str, object]] = []

    progress, cancelled = progress_cancel.evaluate_progress_stall_cancellation(
        jid="job-2",
        rec={"attempt": 3, "cancel_requested_at": 1.0},
        now=5.0,
        pid=456,
        progress_age=4.0,
        budget_info={"timeout": 3.0},
        recovery=recovery,
        cancel_grace_sec=1.0,
        update_ewma=_ewma,
        ewma_state={},
        timeout_retry_evidence=retry_evidence,
        timeout_reporting_failures=[],
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=RECOVERABLE,
    )

    assert (progress, cancelled) == (0, 1)
    assert recovery.retried == [("job-2", "queue_worker_killed_after_stall", 456)]
    assert retry_evidence[-1]["action"] == "retry_or_fail"
