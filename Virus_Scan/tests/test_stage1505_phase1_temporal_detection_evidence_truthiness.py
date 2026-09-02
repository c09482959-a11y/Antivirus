from __future__ import annotations

from pathlib import Path

from Virus_Scan.detection.models.failure_state import _unavailable_failure_record
from Virus_Scan.detection.models.stage_value_utils import detection_unavailable_value
from Virus_Scan.models.temporal.validation_support import temporal_markov_projection


class HostileReason:
    def __init__(self, text: str):
        self.text = text
        self.bool_calls = 0

    def __bool__(self):
        self.bool_calls += 1
        raise AssertionError("caller-owned reason truthiness was probed")

    def __str__(self):
        return self.text


class HostileFlag:
    def __init__(self):
        self.bool_calls = 0

    def __bool__(self):
        self.bool_calls += 1
        raise AssertionError("caller-owned ready flag truthiness was probed")


class HostileCount(int):
    def __new__(cls, value: int):
        return int.__new__(cls, value)

    def __init__(self, value: int):
        self.bool_calls = 0

    def __bool__(self):
        self.bool_calls += 1
        raise AssertionError("caller-owned count truthiness was probed")


def test_stage1505_detection_unavailable_reasons_do_not_probe_truthiness():
    reason = HostileReason("explicit_detection_reason")
    evidence = detection_unavailable_value(reason)

    assert evidence["unavailable_reason"] == "explicit_detection_reason"
    assert reason.bool_calls == 0


def test_stage1505_detection_failure_unavailable_reason_does_not_probe_truthiness():
    reason = HostileReason("explicit_failure_reason")
    record = _unavailable_failure_record(reason)

    assert record["message"] == "explicit_failure_reason"
    assert record["unavailable_reason"] == "explicit_failure_reason"
    assert reason.bool_calls == 0


def test_stage1505_temporal_markov_projection_does_not_probe_hostile_truthiness():
    ready = HostileFlag()
    support = HostileCount(7)
    reason = HostileReason("temporal_support_unavailable")
    result = temporal_markov_projection(
        {
            "ready": ready,
            "support": support,
            "reason": reason,
            "transition": 0.25,
            "rarity": 0.0,
            "pair_anomaly": 0.0,
            "sequence_anomaly": 0.0,
        },
        "extract", ("download", "exec"), "scan",
    )

    assert result["ready"] is False
    assert result["degraded"] is False
    assert result["anomaly"] == 0.25
    assert result["unavailable_reason"] is reason
    assert ready.bool_calls == 0
    assert support.bool_calls == 0
    assert reason.bool_calls == 0


def test_stage1505_temporal_markov_projection_rejects_hostile_numeric_subclass_without_hooks():
    value = HostileCount(1)
    result = temporal_markov_projection(
        {"transition": value, "ready": True},
        "extract", ("download",), "scan",
    )

    assert result["ready"] is False
    assert result["degraded"] is True
    assert result["unavailable_reason"] == "markov_features_invalid"
    assert value.bool_calls == 0


def test_stage1505_repaired_sources_do_not_contain_removed_private_or_truthiness_paths():
    source = Path("Virus_Scan/models/temporal/overlay.py").read_text(encoding="utf-8")
    validation_source = Path(
        "Virus_Scan/models/temporal/validation_support.py"
    ).read_text(encoding="utf-8")

    assert "_temporal_pair_probability_details" not in source
    assert "_temporal_sequence_probability" not in source
    assert "bool(_mapping(record).get(\"ready\"))" not in source
    assert "declared_ready is True" in validation_source
