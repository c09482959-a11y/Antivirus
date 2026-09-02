from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.scheduler.api.final_json import (
    attach_scheduler_final_json_fields,
    build_scheduler_final_json_compact_error_fields,
    build_scheduler_final_json_fields,
)
from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord



def test_stage816_scheduler_final_json_fields_are_scheduler_api_owned():
    fields = build_scheduler_final_json_fields(
        {
            "path": "owned-fields.bin",
            "scheduler_evidence": [
                SchedulerEvidenceRecord(
                    stage="queue_integrity",
                    state="failure",
                    error_category="queue_result_missing",
                    queue_id="claim-816",
                    final_json_must_record=True,
                    checkpoint_must_record=True,
                    replay_must_record=True,
                ).as_dict()
            ],
            "checkpoint_reference": "checkpoint-816.json",
        }
    )

    assert sorted(fields) == ["scheduler", "scheduler_failure_evidence", "scheduler_status"]
    assert fields["scheduler_status"] == "degraded"
    assert fields["scheduler"]["checkpoint"]["checkpoint_reference"] == "checkpoint-816.json"
    assert fields["scheduler_failure_evidence"][0]["queue_id"] == "claim-816"


def test_stage816_publication_applies_prepublished_scheduler_fields_without_importing_scheduler():
    record = attach_scheduler_final_json_fields(
        {
            "path": "publication-owned-fields.bin",
            "classification": "scan_error",
            "score": 0.0,
            "scheduler_evidence": [
                SchedulerEvidenceRecord(
                    stage="worker_lifecycle",
                    state="failure",
                    error_category="worker_died",
                    worker_id="worker-816",
                    final_json_must_record=True,
                    checkpoint_must_record=True,
                    replay_must_record=True,
                ).as_dict()
            ],
        }
    )
    compact = compact_result_record(attach_scheduler_final_json_fields(record))

    assert compact["scheduler_status"] == "degraded"
    assert compact["scheduler"]["worker_lifecycle_events"][0]["worker_id"] == "worker-816"
    assert compact["scheduler_failure_evidence"][0]["error_category"] == "worker_died"


def test_stage816_compact_error_fields_are_scheduler_api_owned():
    fields = build_scheduler_final_json_compact_error_fields(
        {"path": "compact-error-fields.bin", "queue_claim_id": "claim-compact-816"},
        error_type="RuntimeError",
        message="compact projection failed",
    )

    assert sorted(fields) == ["scheduler", "scheduler_failure_evidence", "scheduler_status"]
    assert fields["scheduler_status"] == "degraded"
    assert fields["scheduler_failure_evidence"][0]["queue_id"] == "claim-compact-816"
    assert fields["scheduler_failure_evidence"][0]["error_source"] == "scheduler.evidence.final_json_projection"


def test_stage816_publication_has_no_scheduler_import_or_scheduler_projection_builders():
    text = read_python_file(Path("Virus_Scan/publication/json_writer.py"))

    assert "Virus_Scan.scheduler" not in text
    assert "build_scheduler_final_json_fields" not in text
    assert "build_scheduler_final_json_compact_error_fields" not in text
    assert "build_scheduler_final_json_section" not in text
    assert "build_scheduler_final_json_compact_error_section" not in text
    assert "existing_scheduler_final_json_fields" in text
