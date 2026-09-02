from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.orchestration.inmemory_timeout_config_job_evidence import (
    attach_timeout_config_evidence_to_job_records,
    existing_timeout_config_tuple_decision,
    timeout_config_evidence_records_decision,
)


class HostileExistingTuple:
    touched = 0

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("hostile existing tuple iter hook executed")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("hostile existing tuple bool hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("hostile existing tuple repr hook executed")


def test_stage2171_missing_timeout_config_evidence_records_are_replayable_decision() -> None:
    decision = timeout_config_evidence_records_decision(None)

    assert decision.accepted is True
    assert decision.reason == "timeout_config_evidence_records_missing"
    assert decision.value_type == "NoneType"
    assert decision.as_tuple() == ()


def test_stage2171_missing_existing_timeout_config_tuple_is_replayable_decision() -> None:
    decision = existing_timeout_config_tuple_decision(None, field_name="existing_job_history")

    assert decision.accepted is True
    assert decision.reason == "existing_timeout_config_tuple_missing"
    assert decision.field_name == "existing_job_history"
    assert decision.value_type == "NoneType"
    assert decision.as_tuple() == ()


def test_stage2171_hostile_existing_timeout_config_tuple_rejection_keeps_no_hook_evidence() -> None:
    HostileExistingTuple.touched = 0
    hostile = HostileExistingTuple()

    decision = existing_timeout_config_tuple_decision(hostile, field_name="existing_job_history")

    assert HostileExistingTuple.touched == 0
    assert decision.accepted is False
    assert decision.reason == "existing_timeout_config_tuple_rejected"
    assert decision.value_type == "HostileExistingTuple"
    evidence = decision.as_tuple()[0]
    assert evidence["unsupported_scheduler_value"] is True
    assert evidence["field_name"] == "existing_job_history"


def test_stage2171_timeout_config_attachment_preserves_empty_missing_evidence() -> None:
    job_records = {"job-1": {"history": ()}}

    result = attach_timeout_config_evidence_to_job_records(job_records, None)

    assert result is None
    assert job_records == {"job-1": {"history": ()}}


def test_stage2171_timeout_config_job_evidence_source_uses_decisions_not_hidden_empty_tuple() -> None:
    source = Path("Virus_Scan/scheduler/orchestration/inmemory_timeout_config_job_evidence.py").read_text(encoding="utf-8")

    assert "return timeout_config_evidence_records_decision(evidence_records).as_tuple()" in source
    assert "return existing_timeout_config_tuple_decision(value, field_name=field_name).as_tuple()" in source
    assert "if evidence_records is None:\n        return ()" not in source
    assert "if value is None:\n        return ()" not in source
