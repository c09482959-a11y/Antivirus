from __future__ import annotations

import pytest

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.contracts.scheduler_result import SchedulerResult
from Virus_Scan.scheduler.evidence.final_json_fields import build_final_json_scheduler_fields
from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section


@pytest.mark.parametrize(
    "record, expected_category",
    (
        ({"scheduler_status": "degraded", "input_file_path": "a.bin"}, "scheduler_root_status_degraded"),
        ({"scheduler_status": "fatal", "input_file_path": "b.bin"}, "scheduler_root_status_fatal"),
        ({"status": "degraded", "input_file_path": "c.bin"}, "scheduler_root_status_degraded"),
        ({"state": "failed", "input_file_path": "d.bin"}, "scheduler_root_status_failed"),
        ({"degraded": True, "input_file_path": "e.bin"}, "scheduler_root_status_degraded"),
        ({"fatal": True, "input_file_path": "f.bin"}, "scheduler_root_status_degraded"),
        ({"scheduler_result": {"status": "degraded", "reason": "phase_output_degraded", "input_file_path": "g.bin"}}, "phase_output_degraded"),
        ({"scheduler_result": {"status": "fatal", "error_category": "scheduler_result_fatal", "input_file_path": "h.bin"}}, "scheduler_result_fatal"),
    ),
)
def test_phase11_root_and_scheduler_result_statuses_are_canonical_evidence(record, expected_category):
    section = build_final_json_scheduler_section(record)

    assert section is not None
    assert section["scheduler_status"] in {"degraded", "fatal"}
    categories = {item["error_category"] for item in section["evidence"]}
    assert expected_category in categories
    for item in section["evidence"]:
        assert item["final_json_must_record"] is True
        assert item["checkpoint_must_record"] is True
        assert item["replay_must_record"] is True


def test_phase11_scheduler_result_contract_object_evidence_is_not_passive_metadata():
    evidence = SchedulerEvidenceRecord(
        stage="replay",
        state="failure",
        error_category="replay_result_mismatch",
        error_source="test",
        message="mismatch",
        final_json_must_record=True,
        checkpoint_must_record=True,
        replay_must_record=True,
    )
    result = SchedulerResult(status="degraded", evidence=(evidence,))

    fields = build_final_json_scheduler_fields({"scheduler_result": result, "input_file_path": "object.bin"})

    assert fields["scheduler_status"] == "degraded"
    assert fields["scheduler_failure_evidence"][0]["error_category"] == "replay_result_mismatch"
    assert fields["scheduler"]["replay_comparison_result"] == {}

@pytest.mark.parametrize(
    "field, value, expected_fragment",
    (
        ("worker_exit_status", {"status": "failed", "reason": "worker_exit_failed"}, "worker_exit_failed"),
        ("timeout_escalation_result", {"state": "error", "error_category": "timeout_escalation_failed"}, "timeout_escalation_failed"),
        ("retry_result_publication", {"failed": True, "reason": "retry_result_publication_failed"}, "retry_result_publication_failed"),
        ("queue_failed", True, "queue_failed_failure"),
        ("suppressed_failures", 2, "suppressed_failures_failure"),
        ("scheduler_runtime_state", "degraded", "scheduler_runtime_state_failure"),
    ),
)
def test_phase11_bounded_passive_status_inventory_backstop(field, value, expected_fragment):
    section = build_final_json_scheduler_section({field: value, "input_file_path": "inventory.bin"})

    assert section is not None
    categories = {item["error_category"] for item in section["evidence"]}
    assert expected_fragment in categories
