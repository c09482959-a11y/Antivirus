from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.scheduler.api.final_json import attach_scheduler_final_json_fields
from Virus_Scan.scheduler.contracts.replay_result import ReplayComparisonResult, ReplaySnapshot
from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section


def test_stage818_replay_mismatch_status_projects_without_clean_default():
    record = {
        "path": "replay-mismatch.bin",
        "classification": "scan_error",
        "score": 0.0,
        "replay_comparison_result": {
            "matched": False,
            "mismatches": [{"job_id": "job-818", "field": "classification"}],
        },
        "checkpoint_status": {"status": "written", "checkpoint_path": "scheduler-818.json"},
    }

    section = build_final_json_scheduler_section(record)
    compact = compact_result_record(attach_scheduler_final_json_fields(record))

    assert section is not None
    assert compact["scheduler_status"] == "degraded"
    assert compact["scheduler"]["replay_comparison_result"]["matched"] is False
    assert compact["scheduler"]["replay_comparison_result"]["mismatches"][0]["job_id"] == "job-818"
    assert compact["scheduler"]["checkpoint"]["checkpoint_path"] == "scheduler-818.json"
    evidence = compact["scheduler_failure_evidence"]
    assert evidence[0]["stage"] == "replay_comparison"
    assert evidence[0]["error_category"] == "replay_mismatch"
    assert evidence[0]["final_json_must_record"] is True
    assert evidence[0]["checkpoint_must_record"] is True
    assert evidence[0]["replay_must_record"] is True


def test_stage818_replay_comparison_contract_object_projects_to_final_json():
    expected = ReplaySnapshot(replay_id="expected", records=({"job_id": "job-1", "classification": "Benign"},))
    actual = ReplaySnapshot(replay_id="actual", records=({"job_id": "job-1", "classification": "scan_error"},))
    record = {
        "path": "replay-contract.bin",
        "classification": "scan_error",
        "score": 0.0,
        "replay_result": ReplayComparisonResult(
            matched=False,
            expected=expected,
            actual=actual,
            mismatches=({"job_id": "job-1", "field": "classification"},),
        ),
    }

    compact = compact_result_record(attach_scheduler_final_json_fields(record))

    assert compact["scheduler_status"] == "degraded"
    assert compact["scheduler"]["replay_comparison_result"]["expected"]["replay_id"] == "expected"
    assert compact["scheduler"]["replay_comparison_result"]["actual"]["replay_id"] == "actual"
    assert compact["scheduler_failure_evidence"][0]["context"]["mismatch_count"] == 1


def test_stage818_scheduler_evidence_mapping_aliases_survive_final_json_projection():
    record = {
        "path": "alias-source.bin",
        "classification": "scan_error",
        "score": 0.0,
        "scheduler_evidence": [
            {
                "stage": "queue_claim",
                "state": "failure",
                "error_category": "queue_claim_failed",
                "queue_claim_id": "claim-alias-818",
                "file_job_id": "job-alias-818",
                "input_file_path": "alias-target.bin",
                "final_json_must_record": True,
                "checkpoint_must_record": True,
                "replay_must_reproduce": True,
            }
        ],
    }

    compact = compact_result_record(attach_scheduler_final_json_fields(record))

    evidence = compact["scheduler_failure_evidence"][0]
    assert evidence["queue_id"] == "claim-alias-818"
    assert evidence["job_id"] == "job-alias-818"
    assert evidence["path"] == "alias-target.bin"
    assert evidence["replay_must_record"] is True
    assert compact["scheduler"]["queue_claims"][0]["queue_id"] == "claim-alias-818"
