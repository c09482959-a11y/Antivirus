from __future__ import annotations

from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.scheduler.api.final_json import attach_scheduler_final_json_fields
from Virus_Scan.scheduler.evidence.final_json_projection import (
    build_final_json_scheduler_section_decision,
)
from Virus_Scan.scheduler.timeout.timeout_budget import compute_timeout_budget


def _successful_record(tmp_path):
    target = tmp_path / "sample.txt"
    target.write_text("safe sample", encoding="utf-8")
    timeout_evidence = compute_timeout_budget(
        target, configured_timeout_seconds=60, deep_scan=True,
    ).as_evidence()
    timeout_evidence.update({
        "worker_state": "queue_worker_alive_progressing",
        "worker_pid": 321,
        "heartbeat_age": 0.25,
        "progress_age": 0.25,
        "current_stage": "complete",
        "bytes_processed": 11,
        "worker_killed": False,
        "worker_recovered": False,
    })
    return {
        "path": str(target),
        "classification": "benign_clean",
        "score": 0.0,
        "tags": [],
        "timeout_evidence": timeout_evidence,
    }


def test_passive_timeout_budget_does_not_degrade_successful_scheduler_result(tmp_path) -> None:
    record = _successful_record(tmp_path)

    decision = build_final_json_scheduler_section_decision(record)
    compact = compact_result_record(attach_scheduler_final_json_fields(record))

    assert decision.section is None
    assert decision.reason == "scheduler_evidence_not_found"
    assert "scheduler_status" not in compact
    assert "scheduler_failure_evidence" not in compact
    assert compact["timeout_evidence"]["worker_state"] == "queue_worker_alive_progressing"
    assert compact["timeout_evidence"]["timeout_reason"] is None


def test_explicit_timeout_event_still_degrades_and_remains_replayable(tmp_path) -> None:
    record = _successful_record(tmp_path)
    record["timeout_evidence"].update({
        "worker_state": "queue_worker_hard_timeout",
        "timeout_reason": "dynamic_hard_timeout",
        "worker_killed": True,
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_reproduce": True,
    })

    decision = build_final_json_scheduler_section_decision(record)
    compact = compact_result_record(attach_scheduler_final_json_fields(record))

    assert decision.section is not None
    assert decision.evidence_count == 1
    assert compact["scheduler_status"] == "degraded"
    assert compact["scheduler"]["timeout_decisions"][0]["error_category"] == "dynamic_hard_timeout"
