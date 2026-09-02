"""Stage2198 strict typing closure for timeout evidence records."""
from __future__ import annotations

import inspect

from Virus_Scan.scheduler.timeout import inmemory_timeout_evidence as timeout_evidence


class Stage2198HostileText:
    touched = 0

    def __str__(self) -> str:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ executed")

    def __format__(self, _spec: str) -> str:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned __format__ executed")


class Stage2198HostileInteger:
    touched = 0

    def __int__(self) -> int:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned __int__ executed")

    def __str__(self) -> str:  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ executed")


class Stage2198HostileMapping:
    touched = 0

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned mapping iteration executed")

    def items(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned mapping items executed")


def _suppressed(_where: str, _exc: BaseException) -> object:
    return None


def test_stage2198_timeout_evidence_source_removes_any_boundary_annotations() -> None:
    source = inspect.getsource(timeout_evidence)
    assert "from typing import Any" not in source
    assert ": Any" not in source
    assert "Mapping[str, Any]" not in source
    assert "Callable[[str, BaseException], Any]" not in source
    assert "TimeoutEvidenceRecord" in source
    assert "TimeoutSuppressionRecorder" in source


def test_stage2198_timeout_retry_evidence_preserves_no_hook_unavailable_records() -> None:
    Stage2198HostileText.touched = 0
    Stage2198HostileInteger.touched = 0
    Stage2198HostileMapping.touched = 0

    record = timeout_evidence.timeout_retry_evidence(
        job_id=Stage2198HostileText(),
        reason=Stage2198HostileText(),
        pid=Stage2198HostileInteger(),
        action=Stage2198HostileText(),
        attempt=Stage2198HostileInteger(),
        timeout_budget=Stage2198HostileMapping(),
        error_category=Stage2198HostileText(),
        error_source=Stage2198HostileText(),
        detail=Stage2198HostileText(),
    )

    assert record["job_id"]["error_category"] == "scheduler_json_materialization_unsupported"
    assert record["job_id"]["field_name"] == "timeout_job_id"
    assert record["pid"]["error_category"] == "scheduler_json_materialization_unsupported"
    assert record["pid"]["field_name"] == "timeout_worker_pid"
    assert record["attempt"]["error_category"] == "scheduler_json_materialization_unsupported"
    assert record["attempt"]["field_name"] == "timeout_attempt"
    assert record["timeout_budget"]["error_category"] == "scheduler_json_materialization_unsupported"
    assert "unsupported_timeout_reason" in record["reason"]
    assert "unsupported_timeout_action" in record["action"]
    assert "unsupported_timeout_error_category" in record["error_category"]
    assert "unsupported_timeout_error_source" in record["error_source"]
    assert "unsupported_timeout_detail" in record["detail"]
    assert Stage2198HostileText.touched == 0
    assert Stage2198HostileInteger.touched == 0
    assert Stage2198HostileMapping.touched == 0


def test_stage2198_record_timeout_recovery_failure_uses_typed_suppression_recorder() -> None:
    failures: list[timeout_evidence.TimeoutEvidenceRecord] = []
    timeout_evidence.record_timeout_recovery_failure(
        failures=failures,
        job_id="job-2198",
        reason="timeout_retry",
        pid=2198,
        action="retry_or_fail",
        attempt="3",
        timeout_budget={"deadline": 10},
        error=RuntimeError("worker timed out"),
        source="stage2198",
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError, AssertionError),
    )

    assert len(failures) == 1
    failure = failures[0]
    assert failure["job_id"] == "job-2198"
    assert failure["pid"] == 2198
    assert failure["attempt"] == 3
    assert failure["error_category"] == "RuntimeError"
    assert failure["error_source"] == "stage2198"
    assert failure["timeout_budget"]["deadline"] == 10
