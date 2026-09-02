from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.scheduler.api.final_json import attach_scheduler_final_json_fields
from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section


def test_stage814_final_json_discovers_new_bounded_scheduler_evidence_keys():
    record = {
        "path": "stale.bin",
        "classification": "scan_error",
        "score": 0.0,
        "stale_recovery_evidence": {
            "stage": "orphan_recovery",
            "state": "failure",
            "error_category": "queue_recovery_failed",
            "message": "stale lock could not be recovered",
            "queue_failure": True,
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
            "queue_id": "queue-17",
        },
        "retry_lifecycle_publication_evidence": [
            {
                "stage": "retry_lifecycle",
                "state": "degraded",
                "error_category": "retry_lifecycle_publication_failed",
                "message": "retry lifecycle publication degraded",
                "retry_failure": True,
                "final_json_must_record": True,
                "checkpoint_must_record": True,
                "replay_must_record": True,
                "job_id": "job-17",
            }
        ],
    }

    compact = compact_result_record(attach_scheduler_final_json_fields(record))
    evidence = compact["scheduler"]["evidence"]
    categories = {item["error_category"] for item in evidence}

    assert compact["scheduler_status"] == "degraded"
    assert "queue_recovery_failed" in categories
    assert "retry_lifecycle_publication_failed" in categories
    assert compact["scheduler"]["orphan_recovery"][0]["queue_id"] == "queue-17"
    assert compact["scheduler"]["retry_decisions"][0]["job_id"] == "job-17"


def test_stage814_nested_scan_integrity_evidence_keys_project_without_clean_default():
    record = {
        "path": "stall.bin",
        "classification": "scan_error",
        "score": 0.0,
        "scan_integrity": {
            "stall_escalation_evidence": {
                "stage": "timeout_escalation",
                "state": "failure",
                "error_category": "timeout_escalation_failed",
                "message": "timeout escalation failed",
                "timeout_failure": True,
                "final_json_must_record": True,
                "checkpoint_must_record": True,
                "replay_must_record": True,
                "worker_id": "worker-11",
            }
        },
    }

    section = build_final_json_scheduler_section(record)

    assert section is not None
    assert section["scheduler_status"] == "degraded"
    assert section["timeout_decisions"][0]["worker_id"] == "worker-11"
    assert section["evidence"][0]["checkpoint_must_record"] is True
    assert section["evidence"][0]["replay_must_record"] is True


def test_stage814_clean_records_with_non_scheduler_evidence_stay_clean():
    compact = compact_result_record(attach_scheduler_final_json_fields(
        {
            "path": "clean.bin",
            "classification": "Benign",
            "score": 0.0,
            "tag_evidence": ["benign-tag-context"],
        }
    ))

    assert "scheduler" not in compact
    assert "scheduler_status" not in compact
