from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section


def test_phase11_checkpoint_failure_status_becomes_scheduler_evidence():
    section = build_final_json_scheduler_section(
        {
            "input_file_path": "sample.bin",
            "checkpoint_status": {
                "status": "failed",
                "checkpoint_path": "scheduler-stage819.checkpoint.json",
                "error": "disk write denied",
            },
        }
    )

    assert section is not None
    assert section["scheduler_status"] == "fatal"
    assert section["fatal"] is True
    assert section["checkpoint"]["checkpoint_path"] == "scheduler-stage819.checkpoint.json"
    evidence = section["evidence"]
    assert len(evidence) == 1
    assert evidence[0]["stage"] == "checkpoint_writer"
    assert evidence[0]["error_category"] == "checkpoint_write_failed"
    assert evidence[0]["path"] == "sample.bin"
    assert evidence[0]["final_json_must_record"] is True
    assert evidence[0]["checkpoint_must_record"] is True
    assert evidence[0]["replay_must_record"] is True
    assert section["fatal_vs_recoverable"]["fatal"][0]["stage"] == "checkpoint_writer"


def test_phase11_existing_scheduler_checkpoint_failure_cannot_remain_ok():
    section = build_final_json_scheduler_section(
        {
            "input_file_path": "existing.bin",
            "scheduler": {
                "scheduler_status": "ok",
                "degraded": False,
                "fatal": False,
                "evidence": [],
                "checkpoint": {
                    "status": "failure",
                    "checkpoint_path": "existing.checkpoint.json",
                    "message": "checkpoint verify mismatch",
                },
            },
        }
    )

    assert section is not None
    assert section["scheduler_status"] == "fatal"
    assert section["checkpoint"]["checkpoint_path"] == "existing.checkpoint.json"
    assert section["evidence"][0]["error_source"] == "scheduler.evidence.checkpoint_writer"
    assert section["evidence"][0]["context"]["checkpoint"]["message"] == "checkpoint verify mismatch"


def test_phase11_written_checkpoint_status_remains_passive_metadata_without_failure():
    section = build_final_json_scheduler_section(
        {
            "scheduler": {
                "scheduler_status": "ok",
                "degraded": False,
                "fatal": False,
                "evidence": [],
                "checkpoint": {"status": "written", "checkpoint_path": "ok.checkpoint.json"},
            },
        }
    )

    assert section["scheduler_status"] == "ok"
    assert section["evidence"] == []
    assert section["checkpoint"]["checkpoint_path"] == "ok.checkpoint.json"
