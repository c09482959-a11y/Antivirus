from Virus_Scan.scheduler.evidence.final_json_fields import (
    build_final_json_scheduler_fields,
    scheduler_fields_from_section,
)


class HostileSchedulerRecord:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("record iter must not execute")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("record str must not execute")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("record repr must not execute")


def test_stage1728_scheduler_fields_rejects_unsupported_record_without_empty_default():
    HostileSchedulerRecord.touched = 0

    fields = build_final_json_scheduler_fields(HostileSchedulerRecord())

    assert HostileSchedulerRecord.touched == 0
    assert fields != {}
    assert fields["scheduler_status"] == "failed"
    evidence = fields["scheduler_failure_evidence"][0]
    assert evidence["scheduler_projection_failed"] is True
    assert evidence["reason"] == "unsupported_scheduler_record"
    assert evidence["unsupported_scheduler_value"] is True
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_must_record"] is True


def test_stage1728_scheduler_fields_from_missing_section_returns_evidence_not_empty_dict():
    fields = scheduler_fields_from_section(None)

    assert fields != {}
    assert fields["scheduler_status"] == "failed"
    evidence = fields["scheduler_failure_evidence"][0]
    assert evidence["scheduler_projection_failed"] is True
    assert evidence["reason"] == "scheduler_section_missing"
    assert evidence["final_json_must_record"] is True


def test_stage1728_absent_scheduler_data_on_exact_record_remains_legitimate_empty_result():
    assert build_final_json_scheduler_fields({}) == {}
