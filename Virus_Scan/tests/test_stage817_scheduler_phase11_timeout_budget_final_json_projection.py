from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.scheduler.api.final_json import attach_scheduler_final_json_fields
from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section


def test_stage817_timeout_budget_inspection_error_projects_to_scheduler_final_json():
    record = {
        "path": "timeout-budget.bin",
        "classification": "scan_error",
        "score": 0.0,
        "timeout_evidence": {
            "workload_class": "archive",
            "scan_method": "deep",
            "timeout_budget": 300.0,
            "stall_budget": 45.0,
            "heartbeat_stale_budget": 30.0,
            "inspection_error": "BadZipFile: corrupt archive",
            "timeout_reason": None,
            "stall_reason": None,
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_reproduce": True,
        },
        "checkpoint_reference": "checkpoint-timeout-budget.json",
    }

    section = build_final_json_scheduler_section(record)
    compact = compact_result_record(attach_scheduler_final_json_fields(record))

    assert section is not None
    assert compact["scheduler_status"] == "degraded"
    assert compact["scheduler"]["checkpoint"]["checkpoint_reference"] == "checkpoint-timeout-budget.json"
    assert compact["scheduler"]["timeout_decisions"][0]["error_category"] == "BadZipFile: corrupt archive"
    assert compact["scheduler"]["timeout_decisions"][0]["timeout_state_affected"] is True
    assert compact["scheduler_failure_evidence"][0]["final_json_must_record"] is True
    assert compact["scheduler_failure_evidence"][0]["checkpoint_must_record"] is True
    assert compact["scheduler_failure_evidence"][0]["replay_must_record"] is True
