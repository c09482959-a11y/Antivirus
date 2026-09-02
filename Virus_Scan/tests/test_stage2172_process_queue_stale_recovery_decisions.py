from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.process_queue_stale_recovery_decisions import (
    stale_optional_float_decision,
    stale_recovered_record_decision,
)
from Virus_Scan.scheduler.queue.process_queue_stale_recovery_projection import (
    stale_optional_float,
    stale_recovered_record,
)


class HostileRecoveredRecord:
    touched = 0

    def __iter__(self):  # pragma: no cover - touching proves unsafe route
        type(self).touched += 1
        raise AssertionError("stale recovery called __iter__")

    def items(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("stale recovery called items")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("stale recovery called __bool__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("stale recovery called __repr__")


def test_stage2172_missing_stale_optional_float_is_replayable_decision() -> None:
    decision = stale_optional_float_decision(None)

    assert decision.value is None
    assert decision.reason == "stale_optional_float_missing"
    assert decision.value_type == "NoneType"
    assert decision.as_optional_float() is None
    assert stale_optional_float(None) is None


def test_stage2172_missing_stale_recovered_record_is_replayable_decision() -> None:
    decision = stale_recovered_record_decision(None)

    assert decision.accepted is False
    assert decision.reason == "stale_recovered_record_missing"
    assert decision.value_type == "NoneType"
    assert decision.as_record() == {}
    assert stale_recovered_record(None) == {}


def test_stage2172_hostile_stale_recovered_record_evidence_is_replayable_without_hooks() -> None:
    HostileRecoveredRecord.touched = 0
    decision = stale_recovered_record_decision(HostileRecoveredRecord())

    assert HostileRecoveredRecord.touched == 0
    assert decision.accepted is True
    assert decision.reason == "stale_recovered_record_materialized_evidence"
    assert decision.value_type == "HostileRecoveredRecord"
    projected = decision.as_record()
    assert projected["unsupported_scheduler_value"] is True
    assert projected["field_name"] == "scheduler_value"
    assert projected["value_type"] == "HostileRecoveredRecord"


def test_stage2172_process_queue_stale_recovery_projection_source_uses_decisions() -> None:
    source = Path("Virus_Scan/scheduler/queue/process_queue_stale_recovery_projection.py").read_text(encoding="utf-8")

    assert "return stale_optional_float_decision(value).as_optional_float()" in source
    assert "return stale_recovered_record_decision(value).as_record()" in source
    assert "if value is None:\n        return None" not in source
    assert "if value is None:\n        return {}" not in source
