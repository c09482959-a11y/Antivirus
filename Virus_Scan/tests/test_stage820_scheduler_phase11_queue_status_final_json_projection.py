from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.scheduler.api.final_json import attach_scheduler_final_json_fields
from Virus_Scan.scheduler.contracts.queue_snapshot import QueueIntegrityResult, QueueSnapshot
from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section


def test_stage820_queue_integrity_contract_failures_project_to_final_json():
    record = {
        "path": "queue-integrity.bin",
        "classification": "scan_error",
        "score": 0.0,
        "queue_integrity_result": QueueIntegrityResult(
            ok=False,
            snapshot=QueueSnapshot(phase="raw_queue", pending=0, active=1, done=0, failed=0),
            failures=(
                {
                    "stage": "queue_integrity",
                    "state": "failure",
                    "error_category": "queue_json_corrupt",
                    "error_source": "scheduler.queue.integrity",
                    "message": "job json could not be decoded",
                    "queue_claim_id": "claim-820",
                    "file_job_id": "job-820",
                    "input_file_path": "queue-integrity.bin",
                    "final_json_must_record": True,
                    "checkpoint_must_record": True,
                    "replay_must_reproduce": True,
                    "fatal": True,
                },
            ),
        ),
    }

    compact = compact_result_record(attach_scheduler_final_json_fields(record))

    assert compact["scheduler_status"] == "fatal"
    evidence = compact["scheduler_failure_evidence"]
    assert any(item["stage"] == "queue_integrity" and item["error_category"] == "queue_json_corrupt" for item in evidence)
    assert compact["scheduler"]["queue_integrity_result"][0]["queue_id"] == "claim-820"
    assert compact["scheduler"]["queue_integrity_result"][0]["job_id"] == "job-820"
    assert compact["scheduler"]["queue_integrity_result"][0]["final_json_must_record"] is True
    assert compact["scheduler"]["queue_integrity_result"][0]["checkpoint_must_record"] is True
    assert compact["scheduler"]["queue_integrity_result"][0]["replay_must_record"] is True


def test_stage820_orphan_recovery_status_without_evidence_cannot_remain_clean():
    section = build_final_json_scheduler_section(
        {
            "path": "orphan.bin",
            "queue_claim_id": "claim-orphan-820",
            "orphan_recovery_result": {
                "status": "failed",
                "orphaned": 1,
                "recovered": 0,
                "job_id": "job-orphan-820",
                "reason": "orphaned_claim_recovery_failed",
                "message": "active claim could not be moved back to pending",
            },
        }
    )

    assert section is not None
    assert section["scheduler_status"] == "degraded"
    assert section["orphan_recovery"][0]["stage"] == "orphan_recovery"
    assert section["orphan_recovery"][0]["error_category"] == "orphaned_claim_recovery_failed"
    assert section["orphan_recovery"][0]["queue_id"] == "claim-orphan-820"
    assert section["orphan_recovery"][0]["job_id"] == "job-orphan-820"
    assert section["orphan_recovery"][0]["final_json_must_record"] is True
    assert section["orphan_recovery"][0]["checkpoint_must_record"] is True
    assert section["orphan_recovery"][0]["replay_must_record"] is True


def test_stage820_existing_scheduler_queue_failure_status_cannot_stay_ok():
    section = build_final_json_scheduler_section(
        {
            "path": "existing-queue.bin",
            "scheduler": {
                "scheduler_status": "ok",
                "degraded": False,
                "fatal": False,
                "evidence": [],
                "queue_recovery_result": {
                    "status": "failed",
                    "queue_id": "queue-existing-820",
                    "job_id": "job-existing-820",
                    "error": "queue recovery result read failed",
                },
            },
        }
    )

    assert section is not None
    assert section["scheduler_status"] == "degraded"
    assert section["queue_recovery_result"][0]["stage"] == "queue_recovery"
    assert section["queue_recovery_result"][0]["queue_id"] == "queue-existing-820"
    assert section["queue_recovery_result"][0]["job_id"] == "job-existing-820"
    assert section["evidence"][0]["context"]["queue_recovery_result"]["error"] == "queue recovery result read failed"
