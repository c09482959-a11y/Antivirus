from Virus_Scan.scheduler.evidence.final_json_fields import build_final_json_scheduler_fields
from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section


class HostileSchedulerCarrier:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("scheduler carrier bool hook executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("scheduler carrier iter hook executed")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("scheduler carrier str hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("scheduler carrier repr hook executed")


def _reset() -> None:
    HostileSchedulerCarrier.touched = 0


def test_stage1754_unsupported_scheduler_section_is_explicit_evidence() -> None:
    _reset()

    fields = build_final_json_scheduler_fields({"scheduler": HostileSchedulerCarrier()})

    assert fields != {}
    assert fields["scheduler_status"] == "fatal"
    evidence = fields["scheduler_failure_evidence"][0]
    assert evidence["error_category"] == "scheduler_unsupported"
    assert evidence["context"]["scheduler"]["unsupported_scheduler_value"] is True
    assert HostileSchedulerCarrier.touched == 0


def test_stage1754_unsupported_scheduler_status_is_not_clean_or_absent() -> None:
    _reset()

    section = build_final_json_scheduler_section({"scheduler_status": HostileSchedulerCarrier()})

    assert section is not None
    assert section["scheduler_status"] == "fatal"
    assert section["evidence"][0]["error_category"] == "scheduler_status_unsupported"
    assert HostileSchedulerCarrier.touched == 0


def test_stage1754_unsupported_explicit_evidence_value_is_recorded() -> None:
    _reset()

    fields = build_final_json_scheduler_fields(
        {"scheduler_failure_evidence": HostileSchedulerCarrier()}
    )

    assert fields != {}
    assert fields["scheduler_status"] == "fatal"
    evidence = fields["scheduler_failure_evidence"][0]
    assert evidence["error_category"] == "scheduler_evidence_source_rejected"
    assert evidence["context"]["unsupported_scheduler_evidence_source"]["unsupported_scheduler_value"] is True
    assert HostileSchedulerCarrier.touched == 0


def test_stage1754_absent_scheduler_contract_remains_neutral() -> None:
    assert build_final_json_scheduler_fields({}) == {}
