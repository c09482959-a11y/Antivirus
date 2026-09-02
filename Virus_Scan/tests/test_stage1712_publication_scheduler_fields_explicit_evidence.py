from __future__ import annotations

from Virus_Scan.publication.json_finalization.scheduler_projection import existing_scheduler_final_json_fields


class HostileSchedulerRecord:
    touched = 0

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("scheduler record iter hook executed")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("scheduler record str hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("scheduler record repr hook executed")


class HostileSchedulerValue:
    touched = 0

    def __eq__(self, other):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("scheduler value equality hook executed")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("scheduler value truthiness hook executed")

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("scheduler value iteration hook executed")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("scheduler value string hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("scheduler value repr hook executed")


def test_stage1712_existing_scheduler_fields_rejects_unsupported_record_without_empty_default() -> None:
    HostileSchedulerRecord.touched = 0

    projected = existing_scheduler_final_json_fields(HostileSchedulerRecord())

    assert HostileSchedulerRecord.touched == 0
    evidence = projected["scheduler"]
    assert evidence["scheduler_projection_failed"] is True
    assert evidence["reason"] == "unsupported_scheduler_record"
    assert evidence["value_type"] == "HostileSchedulerRecord"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_must_record"] is True


def test_stage1712_existing_scheduler_fields_absent_scheduler_data_remains_legitimate_empty_result() -> None:
    assert existing_scheduler_final_json_fields({}) == {}


def test_stage1712_existing_scheduler_fields_rejects_hostile_status_without_hooks() -> None:
    HostileSchedulerValue.touched = 0

    projected = existing_scheduler_final_json_fields(
        {
            "scheduler_status": HostileSchedulerValue(),
            "scheduler_failure_evidence": HostileSchedulerValue(),
        }
    )

    assert HostileSchedulerValue.touched == 0
    assert projected["scheduler_status"] == "failed"
    failures = projected["scheduler_failure_evidence"]
    assert any(item.get("reason") == "unsupported_scheduler_status" for item in failures)
    assert any(item.get("reason") == "unsupported_scheduler_evidence" for item in failures)
    assert all(item.get("final_json_must_record") is True for item in failures)


def test_stage1712_existing_scheduler_fields_rejects_hostile_section_without_hooks() -> None:
    HostileSchedulerValue.touched = 0

    projected = existing_scheduler_final_json_fields({"scheduler": HostileSchedulerValue()})

    assert HostileSchedulerValue.touched == 0
    assert projected["scheduler_status"] == "failed"
    assert projected["scheduler"]["reason"] == "unsupported_scheduler_section"
    assert projected["scheduler_failure_evidence"][0]["reason"] == "unsupported_scheduler_section"
