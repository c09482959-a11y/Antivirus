from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.scheduler.api.final_json import attach_scheduler_final_json_fields
from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section


def test_stage822_existing_degraded_scheduler_section_gets_failure_evidence():
    section = build_final_json_scheduler_section(
        {
            "path": "existing-degraded.bin",
            "scheduler": {
                "scheduler_status": "degraded",
                "degraded": True,
                "fatal": False,
                "reason": "queue_recovery_degraded_without_evidence",
                "queue_recovery_result": {"status": "degraded"},
            },
        }
    )

    assert section is not None
    assert section["scheduler_status"] == "degraded"
    assert section["evidence"]
    assert section["evidence"][0]["stage"] == "scheduler_final_json_section"
    assert section["evidence"][0]["error_category"] == "queue_recovery_degraded_without_evidence"
    assert section["evidence"][0]["final_json_must_record"] is True
    assert section["evidence"][0]["checkpoint_must_record"] is True
    assert section["evidence"][0]["replay_must_record"] is True


def test_stage822_existing_fatal_scheduler_section_gets_fatal_evidence():
    compact = compact_result_record(attach_scheduler_final_json_fields(
        {
            "path": "existing-fatal.bin",
            "scheduler": {
                "scheduler_status": "fatal",
                "fatal": True,
                "message": "checkpoint publication failed before evidence materialized",
            },
        }
    ))

    assert compact["scheduler_status"] == "fatal"
    assert compact["scheduler_failure_evidence"]
    evidence = compact["scheduler_failure_evidence"][0]
    assert evidence["fatal"] is True
    assert evidence["state"] == "failure"
    assert evidence["error_category"] == "checkpoint publication failed before evidence materialized"


def test_stage822_existing_clean_scheduler_section_stays_passive():
    section = build_final_json_scheduler_section(
        {
            "path": "existing-clean.bin",
            "scheduler": {
                "scheduler_status": "ok",
                "degraded": False,
                "fatal": False,
            },
        }
    )

    assert section is not None
    assert section["scheduler_status"] == "ok"
    assert section.get("evidence", []) == []
