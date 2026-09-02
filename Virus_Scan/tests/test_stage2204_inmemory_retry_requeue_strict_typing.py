from __future__ import annotations

from collections import deque
from pathlib import Path

from Virus_Scan.scheduler.queue.inmemory_retry_recovery_requeue import publish_retry_pending


class _RejectingPending(deque[tuple[int, object, int]]):
    def appendleft(self, item: tuple[int, object, int]) -> None:  # pragma: no cover - exercised by RuntimeError path
        raise RuntimeError("pending unavailable")


class _HookBomb:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def _called(self, name: str) -> str:
        self.calls.append(name)
        raise AssertionError("hostile hook called: " + name)

    def __bool__(self) -> bool:
        self._called("__bool__")

    def __format__(self, _spec: str) -> str:
        return self._called("__format__")

    def __repr__(self) -> str:
        return self._called("__repr__")

    def __str__(self) -> str:
        return self._called("__str__")


def _worker_error_result(path: object, error: BaseException | str) -> dict[str, object]:
    return {"file": path, "error": str(error), "scan_integrity": {}}


def test_stage2204_retry_requeue_sources_have_no_any_boundary_annotations() -> None:
    queue_root = Path(__file__).parents[1] / "scheduler" / "queue"
    target_source = (queue_root / "inmemory_retry_recovery_requeue.py").read_text(encoding="utf-8")
    contract_source = (queue_root / "inmemory_retry_requeue_contracts.py").read_text(encoding="utf-8")

    assert "Any" not in target_source
    assert "Any" not in contract_source


def test_stage2204_publish_retry_pending_preserves_success_requeue_behavior() -> None:
    job_records = {7: {"file": "sample.bin", "attempt": 0, "history": ()}}
    pending: deque[tuple[int, object, int]] = deque()
    lifecycle: list[tuple[int, int, str]] = []

    decision = publish_retry_pending(
        job_records=job_records,
        pending=pending,
        results={},
        failed=set(),
        terminal=set(),
        job_id=7,
        reason="retry",
        path="sample.bin",
        rec=job_records[7],
        old_generation=0,
        max_job_retries_int=2,
        pid=123,
        cancel_publication_evidence_records=[],
        lifecycle_recorder=lambda request: lifecycle.append((request.job_id, request.attempt, request.transition)),
        worker_error_result=_worker_error_result,
    )

    assert decision.retried is True
    assert decision.completed_delta == 0
    assert pending[0] == (7, "sample.bin", 1)
    assert lifecycle == [(7, 1, "retry_pending")]
    assert job_records[7]["attempt"] == 1
    assert job_records[7]["state"] == "pending_retry"


def test_stage2204_pending_publication_failure_uses_no_hook_reason_evidence() -> None:
    hostile_reason = _HookBomb()
    job_records = {5: {"file": "sample.bin", "attempt": 0, "history": ()}}
    results: dict[object, object] = {}
    failed: set[int] = set()
    terminal: set[int] = set()

    decision = publish_retry_pending(
        job_records=job_records,
        pending=_RejectingPending(),
        results=results,
        failed=failed,
        terminal=terminal,
        job_id=5,
        reason=hostile_reason,
        path="sample.bin",
        rec=job_records[5],
        old_generation=0,
        max_job_retries_int=1,
        pid=object(),
        cancel_publication_evidence_records=[],
        lifecycle_recorder=lambda _request: None,
        worker_error_result=_worker_error_result,
    )

    assert hostile_reason.calls == []
    assert decision.retried is False
    assert decision.completed_delta == 1
    assert failed == {5}
    assert terminal == {5}
    result = results["sample.bin"]
    assert isinstance(result, dict)
    assert result["retry_pending_publication_failed"] is True
    assert result["retry_pending_publication_evidence"]["reason"] == "<_HookBomb unsupported_retry_reason>"
    assert "<_HookBomb unsupported_retry_reason>" in result["error"]
