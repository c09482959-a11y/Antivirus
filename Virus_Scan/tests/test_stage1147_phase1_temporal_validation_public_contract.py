from __future__ import annotations

from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
import ast
from pathlib import Path

from Virus_Scan.models import temporal
from Virus_Scan.models.temporal.validation import TEMPORAL_VALIDATION_VERSION
from Virus_Scan.tests.support.static_inventory import read_python_file


def _function_source(path: str, name: str) -> str:
    source = read_python_file(Path(path))
    tree = ast.parse(source)
    function = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    return ast.get_source_segment(source, function) or ""


def test_stage1147_temporal_validation_public_output_is_deterministic_and_replay_safe() -> None:
    kwargs = dict(
        node="stage1147-temporal-validation-public-contract",
        tags=physical_tag_evidence(("certutil_exec", "network_download"), source_detector="temporal-test"),
        prev_stage="asset",
        curr_stage="runtime",
        markov={
            "transition": 0.0, "rarity": 0.0,
            "pair_anomaly": 0.0, "sequence_anomaly": 0.0,
        },
    )

    first = temporal.compute_temporal_validation(**kwargs)
    second = temporal.compute_temporal_validation(**kwargs)

    assert first == second
    assert first["ready"] is True
    assert first["degraded"] is False
    assert first["evidence_type"] == "temporal_validation"
    assert first["temporal_model_version"] == TEMPORAL_VALIDATION_VERSION
    assert "execution.certutil_download" in first["chain_identities"]
    assert first["chain_score_contribution"] == 0.0
    assert "ordered_certutil_download" not in first["hits"]
    assert [event["behavior_id"] for event in first["events"]] == [
        "certutil_exec", "network_download",
    ]
    assert all(event["schema_version"] == "temporal_event_v5" for event in first["events"])
    assert all(event["timestamp_kind"] == "ordinal_only" for event in first["events"])
    assert all(event["timestamp_value"] is None for event in first["events"])


def test_stage1147_temporal_validation_invalid_markov_is_degraded_evidence_not_crash_or_clean_default() -> None:
    result = temporal.compute_temporal_validation(
        "stage1147-invalid-markov-contract",
        tags=physical_tag_evidence(("certutil_exec", "network_download"), source_detector="temporal-test"),
        prev_stage="asset",
        curr_stage="runtime",
        markov={"transition": object()},
    )

    assert result["degraded"] is True
    assert result["unavailable_reason"] == "markov_features_invalid"
    assert "temporal_markov_feature_failure_evidence" in result["hits"]
    assert result["evidence_type"] == "temporal_validation"
    assert result["markov_transition_evidence"]["ready"] is False
    assert result["markov_transition_evidence"]["anomaly"] == 0.0


def test_stage1147_temporal_validation_source_has_no_live_time_or_empty_markov_fallback() -> None:
    validation_source = _function_source(
        "Virus_Scan/models/temporal/validation.py", "compute_temporal_validation",
    )
    support_source = _function_source(
        "Virus_Scan/models/temporal/validation_support.py",
        "temporal_markov_projection",
    )

    assert "time.time()" not in validation_source + support_source
    assert "markov = {}" not in validation_source
    assert "temporal_markov_projection" in validation_source
    assert "markov_features_unavailable" in support_source
