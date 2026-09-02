from __future__ import annotations

import inspect

from Virus_Scan.scheduler.evidence import (
    final_json_contract_projection,
    final_json_contract_support,
    final_json_scheduler_result_projection,
)
from Virus_Scan.scheduler.evidence.final_json_contract_projection import failure_records_from_scheduler_contract_status
from Virus_Scan.scheduler.evidence.final_json_contract_projection_decisions import (
    scan_integrity_failure_decision,
    worker_status_failure_decision,
)
from Virus_Scan.scheduler.evidence.final_json_contract_support import mapping_from_scheduler_value
from Virus_Scan.scheduler.evidence.final_json_contract_support_decisions import empty_scheduler_status_decision
from Virus_Scan.scheduler.evidence.final_json_scheduler_result_decisions import root_scheduler_status_decision
from Virus_Scan.scheduler.evidence.final_json_scheduler_result_projection import failure_records_from_scheduler_result_status


class HostileStatusCarrier:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("called __str__")

    def __repr__(self):
        type(self).touched += 1
        raise AssertionError("called __repr__")

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("called __bool__")


def test_stage2120_empty_scheduler_status_is_replayable_decision() -> None:
    missing = empty_scheduler_status_decision(None)
    blank = empty_scheduler_status_decision("")
    present = empty_scheduler_status_decision({"status": "ok"})

    assert missing.is_empty is True
    assert missing.reason == "scheduler_status_missing"
    assert blank.is_empty is True
    assert blank.reason == "scheduler_status_blank_text"
    assert present.is_empty is False
    assert present.reason == "scheduler_status_available"

    mapped = mapping_from_scheduler_value(None)
    assert mapped["status"] == "failed"
    assert mapped["reason"] == "scheduler_status_missing"
    assert mapped["final_json_must_record"] is True


def test_stage2120_worker_scan_integrity_failure_is_replayable_decision() -> None:
    missing_result = worker_status_failure_decision({})
    missing_integrity = worker_status_failure_decision({"result": {}})
    failed_integrity = worker_status_failure_decision({"result": {"scan_integrity": {"queue_failure": True}}})
    empty_integrity = scan_integrity_failure_decision({})

    assert missing_result.failed is False
    assert missing_result.reason == "worker_result_missing"
    assert missing_integrity.failed is False
    assert missing_integrity.reason == "scan_integrity_missing"
    assert empty_integrity.failed is False
    assert empty_integrity.reason == "scan_integrity_empty"
    assert failed_integrity.failed is True
    assert failed_integrity.scan_integrity_present is True
    assert failed_integrity.matched_keys == ("queue_failure",)


def test_stage2120_contract_projection_still_emits_worker_scan_integrity_evidence() -> None:
    records = failure_records_from_scheduler_contract_status(
        {
            "worker_result": {
                "result": {
                    "scan_integrity": {
                        "worker_result_schema_invalid": True,
                        "worker_result_schema_reason": "bad_worker_payload",
                    }
                },
                "job_id": "job-2120",
            }
        }
    )

    assert records
    assert records[0].stage == "worker_result"
    assert records[0].state == "failure"
    assert records[0].error_category == "bad_worker_payload"
    assert records[0].job_id == "job-2120"
    assert records[0].final_json_must_record is True


def test_stage2120_root_scheduler_status_absence_is_replayable_decision() -> None:
    absent = root_scheduler_status_decision({})
    ok = root_scheduler_status_decision({"scheduler_status": "ok"})
    degraded = root_scheduler_status_decision({"scheduler_status": "degraded", "job_id": "job-2120"})

    assert absent.should_record is False
    assert absent.reason == "root_status_absent"
    assert ok.should_record is False
    assert ok.reason == "root_status_ok"
    assert degraded.should_record is True
    assert degraded.status_text == "degraded"

    assert failure_records_from_scheduler_result_status({}) == ()
    records = failure_records_from_scheduler_result_status({"scheduler_status": "degraded", "job_id": "job-2120"})
    assert records
    assert records[0].stage == "scheduler_final_json_root_status"
    assert records[0].state == "degraded"
    assert records[0].job_id == "job-2120"


def test_stage2120_target_modules_removed_hidden_default_return_literals() -> None:
    for module in (
        final_json_contract_projection,
        final_json_contract_support,
        final_json_scheduler_result_projection,
    ):
        source = inspect.getsource(module)
        assert "return False" not in source
        assert "return None" not in source


def test_stage2120_typed_decisions_do_not_invoke_hostile_hooks() -> None:
    HostileStatusCarrier.touched = 0

    empty = empty_scheduler_status_decision(HostileStatusCarrier())
    worker = worker_status_failure_decision({"result": HostileStatusCarrier()})

    assert empty.is_empty is False
    assert worker.failed is False
    assert worker.reason == "scan_integrity_missing"
    assert HostileStatusCarrier.touched == 0
