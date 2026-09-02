from pathlib import Path

from Virus_Scan.models.temporal import overlay
from Virus_Scan.tests.support.static_inventory import read_python_file
from Virus_Scan.utils.probability import safe_probability_score


class HostileNumeric:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned truthiness hook was invoked")

    def __float__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned float hook was invoked")


def test_stage2023_temporal_overlay_numeric_boundary_rejects_hostile_hooks() -> None:
    HostileNumeric.touched = 0

    assert safe_probability_score(HostileNumeric()) == 0.0
    result = overlay.transition_probability_overlay(
        prev_stage="asset", tags=("download", "exec"), curr_stage="runtime",
        ordered_events=(
            {"tag": "download", "timestamp": HostileNumeric(), "stage": "asset"},
            {"tag": "exec", "timestamp": 2.0, "stage": "runtime"},
        ),
    )

    assert result["degraded"] is True
    assert result["unavailable_reason"] == "temporal_timestamp_non_numeric"
    assert result["events"][0]["timestamp_value"] is None
    assert HostileNumeric.touched == 0


def test_stage2023_temporal_overlay_source_removed_backlog_and_legacy_helpers() -> None:
    source = read_python_file(Path("Virus_Scan/models/temporal/overlay.py"))

    forbidden = (
        "safe_clamp(sum(pair_probabilities)",
        "_temporal_overlay_positive_probability",
        "_temporal_overlay_clamp",
        "event_times",
        "time.time()",
    )
    for snippet in forbidden:
        assert snippet not in source
