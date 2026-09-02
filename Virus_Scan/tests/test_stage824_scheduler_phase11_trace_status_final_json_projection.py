from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.scheduler.api.final_json import attach_scheduler_final_json_fields
from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section
from Virus_Scan.scheduler.evidence.trace_writer import SchedulerTraceWriteResult


def test_stage824_trace_write_result_failure_cannot_remain_passive_metadata():
    section = build_final_json_scheduler_section(
        {
            "path": "trace-passive.bin",
            "scheduler_trace": SchedulerTraceWriteResult(
                "scheduler.trace.json",
                "failed",
                error="trace writer could not publish trace JSON",
                fatal=False,
            ),
        }
    )

    assert section is not None
    assert section["scheduler_status"] == "degraded"
    evidence = section["evidence"][0]
    assert evidence["stage"] == "trace_writer"
    assert evidence["error_category"] == "trace_write_failed"
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_record"] is True
    assert evidence["context"]["scheduler_trace"]["trace_path"] == "scheduler.trace.json"


def test_stage824_existing_scheduler_trace_failure_is_projected_to_final_json_evidence():
    compact = compact_result_record(attach_scheduler_final_json_fields(
        {
            "path": "existing-trace-status.bin",
            "scheduler": {
                "scheduler_status": "ok",
                "trace_status": {
                    "status": "failed",
                    "trace_path": "existing.trace.json",
                    "error": "trace publication failed",
                },
            },
        }
    ))

    assert compact["scheduler_status"] == "degraded"
    assert compact["scheduler_failure_evidence"]
    evidence = compact["scheduler_failure_evidence"][0]
    assert evidence["stage"] == "trace_writer"
    assert evidence["error_category"] == "trace_write_failed"
    assert evidence["path"] == "existing-trace-status.bin"


def test_stage824_successful_trace_status_remains_passive():
    section = build_final_json_scheduler_section(
        {
            "path": "clean-trace-status.bin",
            "trace_status": {"status": "written", "trace_path": "clean.trace.json"},
        }
    )

    assert section is None
