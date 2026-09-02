from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.evidence.inmemory_result_timeout_support import (
    first_mapping_value,
    timeout_mapping,
    timeout_tags,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_numbers import safe_record_float
from Virus_Scan.scheduler.timeout.inmemory_timeout_retry_evidence import evidence_not_already_present
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import (
    existing_lifecycle_reason,
    safe_parent_worker_message_identity,
    safe_worker_thread_progress_evidence_inputs,
)

_TARGETS = (
    Path("Virus_Scan/scheduler/evidence/inmemory_result_timeout_support.py"),
    Path("Virus_Scan/scheduler/queue/inmemory_retry_publication.py"),
    Path("Virus_Scan/scheduler/timeout/inmemory_timeout_policy_numbers.py"),
    Path("Virus_Scan/scheduler/timeout/inmemory_timeout_retry_evidence.py"),
    Path("Virus_Scan/scheduler/workers/inmemory_worker_lifecycle_boundary.py"),
)


def test_stage2209_scheduler_object_contract_sources_remove_any_surface() -> None:
    for path in _TARGETS:
        source = path.read_text(encoding="utf-8")
        assert "from typing import Any" not in source
        assert "Any" not in source
        assert len(source.splitlines()) <= 200


def test_stage2209_timeout_mapping_and_tags_remain_replayable_without_any() -> None:
    rejections: list[dict[str, object]] = []
    assert first_mapping_value({"missing": None, "timeout": "7"}, ("missing", "timeout")) == "7"
    assert timeout_mapping({"timeout": 3, object(): "ignored"}, field="timeout", rejections=rejections) == {"timeout": 3}
    assert timeout_tags(["retry", 2], rejections=rejections) == ("retry", 2)
    assert rejections == []


def test_stage2209_timeout_policy_records_malformed_numbers_as_evidence() -> None:
    failures: list[dict[str, object]] = []
    suppressed: list[tuple[str, str]] = []

    def record_scheduler_suppressed(source: str, error: BaseException) -> None:
        suppressed.append((source, type(error).__name__))

    result = safe_record_float(
        record={"last_progress": object(), "attempt": 2, "timeout_budget": {"max": 1.5}},
        field="last_progress",
        default=4.0,
        job_id="job-1",
        pid="pid-1",
        failures=failures,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=(Exception,),
    )

    assert result == 4.0
    assert failures
    assert failures[0]["reason"] == "last_progress_malformed"
    assert failures[0]["action"] == "timeout_record_field_malformed"
    assert suppressed == [("suppressed_exception", "ValueError")]


def test_stage2209_retry_and_lifecycle_boundaries_keep_no_hook_identity() -> None:
    existing = ({"job_id": 1, "reason": "done"},)
    candidates = ({"job_id": 1, "reason": "done"}, {"job_id": 2, "reason": "new"})
    assert evidence_not_already_present(candidates=candidates, existing=existing) == ({"job_id": 2, "reason": "new"},)

    assert safe_worker_thread_progress_evidence_inputs(
        job_id="worker-7",
        generation="3",
        stage_name="scan",
        reason="heartbeat",
        progress_counter="9",
    ) == ("worker-7", 3, "scan", 9, "heartbeat")
    assert safe_parent_worker_message_identity(("progress", {"unsafe": object()}))[0] == "progress"


def test_stage2209_existing_lifecycle_reason_empty_string_is_local_optional_reason_sentinel() -> None:
    assert existing_lifecycle_reason("already_recorded") == "already_recorded"
    assert existing_lifecycle_reason(object()) == ""
