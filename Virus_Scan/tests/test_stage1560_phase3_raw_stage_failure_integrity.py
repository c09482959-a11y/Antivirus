"""Stage 1560 Phase 3 raw-stage scheduler failure integrity tests."""
from __future__ import annotations

from Virus_Scan.contracts.result_record import scanner_degraded_tags
from Virus_Scan.scheduler.evidence.final_json_fields import build_final_json_scheduler_fields
from Virus_Scan.scheduler.execution.raw_stage_failure import raw_stage_failure_result
from Virus_Scan.scheduler.replay.replay_projection import replay_result_evidence


def _raw_failure_result():
    return raw_stage_failure_result(
        {"file": "sample.bin", "file_id": "raw-job-1", "tags": []},
        "strings",
        RuntimeError("collector unavailable"),
        stage="raw_stage_strings",
        scanner_degraded_tags=scanner_degraded_tags,
    )


def test_stage1560_raw_stage_failure_is_fail_closed_even_when_not_suspicious() -> None:
    result = _raw_failure_result()

    assert result["suspicious"] is False
    assert result["raw_stage_failed"] is True
    assert result["queue_failure"] is True
    assert result["scheduler_failure"] is True
    assert result["scan_incomplete"] is True
    assert result["had_degraded_stage"] is True
    assert result["file_failed"] is True
    assert result["allow_learning"] is False
    assert result["final_json_must_record"] is True
    assert result["replay_must_record"] is True
    assert result["failure_stage"] == "raw_stage_strings"
    assert result["exception_type"] == "RuntimeError"


def test_stage1560_raw_stage_failure_final_json_includes_scheduler_evidence() -> None:
    result = _raw_failure_result()

    fields = build_final_json_scheduler_fields(result)
    evidence = fields["scheduler_failure_evidence"]

    assert evidence
    assert evidence[0]["error_category"] == "raw_stage_failed"
    assert evidence[0]["final_json_must_record"] is True
    assert evidence[0]["replay_must_record"] is True
    assert fields["scheduler"]["scheduler_status"] == "degraded"
    assert fields["scheduler"]["degraded"] is True


def test_stage1560_raw_stage_failure_replay_includes_published_evidence() -> None:
    result = _raw_failure_result()

    replay_tokens = replay_result_evidence(result)

    assert replay_tokens
    assert any("raw_stage_failed" in token for token in replay_tokens)
    assert any("allow_learning" in token for token in replay_tokens)
