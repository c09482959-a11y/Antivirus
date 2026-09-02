from pathlib import Path

from Virus_Scan.models.temporal import validation
from Virus_Scan.tests.support.static_inventory import read_python_file
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


class HostileNumeric:
    touched = 0

    def __float__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned float hook was invoked")

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("caller-owned truthiness hook was invoked")


def test_stage2023_temporal_validation_rejects_hostile_markov_metric_hooks() -> None:
    HostileNumeric.touched = 0

    result = validation.compute_temporal_validation(
        "stage2023-temporal-validation-markov",
        tags=physical_tag_evidence(("certutil_exec", "network_download")),
        prev_stage="asset", curr_stage="runtime",
        markov={
            "transition": HostileNumeric(), "rarity": 0.0,
            "pair_anomaly": 0.0, "sequence_anomaly": 0.0,
        },
    )

    assert result["degraded"] is True
    assert result["unavailable_reason"] == "markov_features_invalid"
    assert "temporal_markov_feature_failure_evidence" in result["hits"]
    assert HostileNumeric.touched == 0


def test_stage2023_temporal_validation_rejects_hostile_event_time_hooks_without_rebinding() -> None:
    HostileNumeric.touched = 0
    result = validation.compute_temporal_validation(
        "stage2023-temporal-validation-timeline",
        tags=("certutil_exec", "network_download"),
        prev_stage="asset", curr_stage="runtime",
        ordered_events=(
            {"tag": "certutil_exec", "timestamp": HostileNumeric(), "stage": "asset"},
            {"tag": "network_download", "timestamp": 2.0, "stage": "runtime"},
        ),
        markov={
            "transition": 0.0, "rarity": 0.0,
            "pair_anomaly": 0.0, "sequence_anomaly": 0.0,
        },
    )

    assert result["evidence_type"] == "temporal_validation"
    assert result["events"]
    assert result["events"][0]["timestamp_value"] is None
    assert "temporal_timestamp_non_numeric" in result["ordered_sequence_evidence"]["validations"][0]["reasons"]
    assert HostileNumeric.touched == 0


def test_stage2023_temporal_validation_source_removed_backlog_snippets() -> None:
    combined = "".join((
        read_python_file(Path("Virus_Scan/models/temporal/validation.py")),
        read_python_file(Path("Virus_Scan/models/temporal/validation_support.py")),
        read_python_file(Path("Virus_Scan/models/temporal/text_boundary.py")),
        read_python_file(Path("Virus_Scan/models/temporal/evidence.py")),
    ))

    forbidden = (
        "protocol fallback.",
        "Markov support behind an empty clean fallback.",
        "markov_values.append(safe_clamp(metric))",
        "float(timeline[-1].get('time'",
        "numeric = float(value)",
    )
    for snippet in forbidden:
        assert snippet not in combined
