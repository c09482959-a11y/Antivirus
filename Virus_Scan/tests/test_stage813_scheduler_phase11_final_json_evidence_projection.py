from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.scheduler.api.final_json import attach_scheduler_final_json_fields
from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section


def test_stage813_final_json_preserves_explicit_scheduler_evidence_section():
    record = {
        "path": "sample.bin",
        "classification": "scan_error",
        "score": 0.0,
        "scheduler_evidence": [
            SchedulerEvidenceRecord(
                stage="retry_exhaustion",
                state="failure",
                error_category="retry_exhaustion",
                retry_state_affected=True,
                fatal=True,
            ).as_dict()
        ],
        "checkpoint_reference": "scheduler.checkpoint.json",
    }

    compact = compact_result_record(attach_scheduler_final_json_fields(record))

    assert compact["scheduler_status"] == "fatal"
    assert compact["scheduler"]["retry_exhaustion"][0]["retry_state_affected"] is True
    assert compact["scheduler"]["checkpoint"]["checkpoint_reference"] == "scheduler.checkpoint.json"
    assert compact["scheduler_failure_evidence"][0]["stage"] == "retry_exhaustion"


def test_stage813_final_json_projects_visible_scheduler_failure_without_clean_default():
    record = {
        "path": "worker.bin",
        "classification": "scan_error",
        "score": 0.0,
        "queue_failure": True,
        "scheduler_failure_reason": "worker_output_publication_failed",
        "worker_id": "worker-7",
        "scan_integrity": {"worker_output_publication_failed": True},
    }

    section = build_final_json_scheduler_section(record)
    compact = compact_result_record(attach_scheduler_final_json_fields(record))

    assert section is not None
    assert compact["scheduler_status"] == "degraded"
    assert compact["scheduler"]["worker_failures"][0]["worker_id"] == "worker-7"
    assert compact["scheduler"]["evidence"][0]["final_json_must_record"] is True
    assert compact["scheduler"]["evidence"][0]["checkpoint_must_record"] is True
    assert compact["scheduler"]["evidence"][0]["replay_must_record"] is True


def test_stage813_final_json_leaves_clean_records_shape_unchanged():
    clean = compact_result_record(attach_scheduler_final_json_fields({"path": "clean.bin", "classification": "Benign", "score": 0.0}))

    assert "scheduler" not in clean
    assert "scheduler_status" not in clean
    assert "scheduler_failure_evidence" not in clean
