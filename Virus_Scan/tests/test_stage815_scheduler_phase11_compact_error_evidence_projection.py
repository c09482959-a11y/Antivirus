from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.scheduler.api.final_json import (
    build_scheduler_final_json_compact_error_fields,
    build_scheduler_final_json_compact_error_section,
)


class _ExplodingEvidence:
    def __iter__(self):
        raise RuntimeError("scheduler evidence payload unavailable")


def test_stage815_publication_preserves_prepublished_scheduler_compact_error_fields():
    scheduler_fields = build_scheduler_final_json_compact_error_fields(
        {
            "path": "boom.bin",
            "checkpoint_reference": "scheduler-checkpoint.json",
            "queue_claim_id": "claim-9",
            "worker_id": "worker-9",
        },
        error_type="RuntimeError",
        message="scheduler evidence payload unavailable",
    )
    compact = compact_result_record(
        {
            "path": "boom.bin",
            "classification": "scan_error",
            "score": 0.0,
            **scheduler_fields,
        }
    )

    assert compact["scheduler_status"] == "degraded"
    assert compact["scheduler"]["checkpoint"]["checkpoint_reference"] == "scheduler-checkpoint.json"
    evidence = compact["scheduler_failure_evidence"]
    assert evidence[0]["stage"] == "final_json_compaction"
    assert evidence[0]["error_category"] == "compact_record_error"
    assert evidence[0]["queue_id"] == "claim-9"
    assert evidence[0]["worker_id"] == "worker-9"
    assert evidence[0]["final_json_must_record"] is True
    assert evidence[0]["checkpoint_must_record"] is True
    assert evidence[0]["replay_must_record"] is True


def test_stage815_compact_error_section_is_public_api_owned():
    section = build_scheduler_final_json_compact_error_section(
        {
            "path": "api.bin",
            "job_id": "job-15",
            "checkpoint_reference": "checkpoint-15.json",
        },
        error_type="RuntimeError",
        message="projection failed",
    )

    assert section["scheduler_status"] == "degraded"
    assert section["checkpoint"]["checkpoint_reference"] == "checkpoint-15.json"
    assert section["evidence"][0]["job_id"] == "job-15"
    assert section["evidence"][0]["error_source"] == "scheduler.evidence.final_json_projection"
