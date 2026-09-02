from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.timeout.process_queue_monitor_decisions import (
    monitor_maximum_evidence_decision,
    monitor_minimum_evidence_decision,
)
from Virus_Scan.scheduler.timeout.process_queue_monitor_values import (
    MonitorClampEvidenceRequest,
    record_monitor_maximum_if_needed,
    record_monitor_minimum_if_needed,
)


class HostileMonitorValue:
    touched = 0

    def __bool__(self) -> bool:
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __float__(self) -> float:
        type(self).touched += 1
        raise RuntimeError("do not float")

    def __int__(self) -> int:
        type(self).touched += 1
        raise RuntimeError("do not int")

    def __str__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("do not str")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("do not repr")


def test_stage2173_monitor_maximum_clean_path_is_replayable_empty_evidence() -> None:
    decision = monitor_maximum_evidence_decision(
        setting="monitor_timeout",
        raw_value=1.0,
        parsed_value=3.0,
        maximum_value=5.0,
        replacement_value=2.0,
    )

    assert decision.accepted is True
    assert decision.reason == "monitor_maximum_within_bounds"
    assert decision.as_evidence() == ()
    assert record_monitor_maximum_if_needed(
        MonitorClampEvidenceRequest(
            evidence=(),
            setting="monitor_timeout",
            raw_value=1.0,
            parsed_value=3.0,
            boundary_value=5.0,
            replacement_value=2.0,
        )
    ) == ()


def test_stage2173_monitor_minimum_clean_path_is_replayable_empty_evidence() -> None:
    decision = monitor_minimum_evidence_decision(
        setting="monitor_timeout",
        raw_value=4.0,
        parsed_value=4.0,
        minimum_value=2.0,
        replacement_value=3.0,
    )

    assert decision.accepted is True
    assert decision.reason == "monitor_minimum_within_bounds"
    assert decision.as_evidence() == ()
    assert record_monitor_minimum_if_needed(
        MonitorClampEvidenceRequest(
            evidence=(),
            setting="monitor_timeout",
            raw_value=4.0,
            parsed_value=4.0,
            boundary_value=2.0,
            replacement_value=3.0,
        )
    ) == ()


def test_stage2173_monitor_clamp_violation_records_replayable_evidence() -> None:
    maximum = monitor_maximum_evidence_decision(
        setting="monitor_timeout",
        raw_value=99.0,
        parsed_value=99.0,
        maximum_value=5.0,
        replacement_value=2.0,
    )
    minimum = monitor_minimum_evidence_decision(
        setting="monitor_timeout",
        raw_value=1.0,
        parsed_value=1.0,
        minimum_value=5.0,
        replacement_value=2.0,
    )

    max_evidence = maximum.as_evidence()
    min_evidence = minimum.as_evidence()
    assert maximum.reason == "monitor_maximum_exceeded"
    assert minimum.reason == "monitor_minimum_below_bounds"
    assert max_evidence[0]["final_json_must_record"] is True
    assert min_evidence[0]["replay_must_reproduce"] is True
    assert "above maximum" in max_evidence[0]["detail"]
    assert "below minimum" in min_evidence[0]["detail"]


def test_stage2173_monitor_unavailable_clamp_rejects_hostile_values_without_hooks() -> None:
    HostileMonitorValue.touched = 0
    hostile = HostileMonitorValue()

    decision = monitor_maximum_evidence_decision(
        setting=hostile,
        raw_value=hostile,
        parsed_value=hostile,
        maximum_value=hostile,
        replacement_value=hostile,
    )

    assert decision.accepted is False
    assert decision.reason == "monitor_maximum_unavailable"
    assert decision.setting == "monitor_setting"
    assert decision.as_evidence() == ()
    assert HostileMonitorValue.touched == 0


def test_stage2173_monitor_values_source_uses_replayable_decisions() -> None:
    source = Path(__file__).resolve().parents[1] / "scheduler" / "timeout" / "process_queue_monitor_values.py"
    text = source.read_text(encoding="utf-8")

    assert "return monitor_maximum_evidence_decision(" in text
    assert "return monitor_minimum_evidence_decision(" in text
    assert "return ()" not in text
