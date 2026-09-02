from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.scheduler.api.final_json import attach_scheduler_final_json_fields
from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section


def test_stage823_existing_scheduler_failure_evidence_is_canonicalized():
    section = build_final_json_scheduler_section(
        {
            "path": "existing-mirror-evidence.bin",
            "scheduler": {
                "scheduler_status": "ok",
                "scheduler_failure_evidence": [
                    {
                        "stage": "worker_lifecycle",
                        "state": "failure",
                        "error_category": "worker_died_without_result",
                        "error_source": "scheduler.workers.lifecycle",
                        "message": "worker died before result publication",
                        "queue_claim_id": "claim-17",
                        "file_job_id": "job-17",
                        "input_file_path": "existing-mirror-evidence.bin",
                        "final_json_must_record": True,
                        "checkpoint_must_record": True,
                        "replay_must_reproduce": True,
                    }
                ],
            },
        }
    )

    assert section is not None
    assert section["scheduler_status"] == "degraded"
    assert len(section["evidence"]) == 1
    evidence = section["evidence"][0]
    assert evidence["stage"] == "worker_lifecycle"
    assert evidence["state"] == "failure"
    assert evidence["error_category"] == "worker_died_without_result"
    assert evidence["queue_id"] == "claim-17"
    assert evidence["job_id"] == "job-17"
    assert evidence["path"] == "existing-mirror-evidence.bin"
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_record"] is True


def test_stage823_compact_result_record_canonicalizes_existing_scheduler_failure_evidence():
    compact = compact_result_record(attach_scheduler_final_json_fields(
        {
            "path": "compact-existing-mirror-evidence.bin",
            "scheduler": {
                "scheduler_status": "ok",
                "scheduler_failure_evidence": [
                    {
                        "stage": "timeout",
                        "state": "failure",
                        "error_category": "timeout_exhausted",
                        "error_source": "scheduler.timeouts.enforcement",
                        "message": "timeout exhausted before worker result",
                        "timeout_state_affected": True,
                    }
                ],
            },
        }
    ))

    assert compact["scheduler_status"] == "degraded"
    assert compact["scheduler_failure_evidence"]
    assert compact["scheduler_failure_evidence"][0]["error_category"] == "timeout_exhausted"
    assert compact["scheduler_failure_evidence"][0]["timeout_state_affected"] is True
