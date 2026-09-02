from __future__ import annotations

from Virus_Scan.scheduler.evidence.final_json_contract_support import mapping_from_scheduler_value
from Virus_Scan.scheduler.evidence.final_json_queue_projection import failure_records_from_queue_status


class _BrokenStatusContract:
    called = False

    def as_dict(self):
        type(self).called = True
        raise ValueError("status contract cannot materialize")


class _NonMappingStatusContract:
    called = False

    def as_dict(self):
        type(self).called = True
        return ("not", "a", "mapping")


def test_stage1061_scheduler_mapping_materialization_failure_is_not_hidden_as_empty_mapping():
    _BrokenStatusContract.called = False
    status = mapping_from_scheduler_value(_BrokenStatusContract())

    assert status["status"] == "failed"
    assert status["failed"] is True
    assert status["error_category"] == "scheduler_json_materialization_unsupported"
    assert status["unsupported_scheduler_value"] is True
    assert _BrokenStatusContract.called is False
    assert status["final_json_must_record"] is True
    assert status["checkpoint_must_record"] is True
    assert status["replay_must_record"] is True


def test_stage1061_scheduler_non_mapping_materialization_is_not_hidden_as_empty_mapping():
    _NonMappingStatusContract.called = False
    status = mapping_from_scheduler_value(_NonMappingStatusContract())

    assert status["status"] == "failed"
    assert status["failed"] is True
    assert status["error_category"] == "scheduler_json_materialization_unsupported"
    assert status["unsupported_scheduler_value"] is True
    assert _NonMappingStatusContract.called is False


def test_stage1061_queue_status_projection_records_materialization_failure_evidence():
    records = failure_records_from_queue_status(
        {"queue_id": "queue-1", "job_id": "job-1", "queue_integrity_result": _BrokenStatusContract()}
    )

    assert len(records) == 1
    record = records[0]
    assert record.stage == "queue_integrity"
    assert record.state == "failure"
    assert record.error_category == "scheduler_json_materialization_unsupported"
    assert record.queue_id == "queue-1"
    assert record.job_id == "job-1"
    assert record.final_json_must_record is True
    assert record.checkpoint_must_record is True
    assert record.replay_must_record is True
    assert record.context["queue_integrity_result"]["unsupported_scheduler_value"] is True
