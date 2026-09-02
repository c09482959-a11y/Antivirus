from __future__ import annotations

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1268_direct_probability_mapping_type_is_result_boundary_invalid() -> None:
    record = {
        "file": "direct-temporal-overlay-map-type.exe",
        "path": "direct-temporal-overlay-map-type.exe",
        "classification": "suspicious",
        "score": 84.0,
        "temporal_overlay_record": {
            "ready": True,
            "stage_probability": 0.4,
            "pair_probabilities": "not-a-probability-map",
        },
    }

    with pytest.raises(ValueError, match=r"temporal_overlay_record\.pair_probabilities.*probability mapping"):
        validate_evidence_object_invariants(record, context="stage1268")


def test_stage1268_direct_probability_mapping_type_becomes_model_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "direct-temporal-overlay-map-type.exe",
            "path": "direct-temporal-overlay-map-type.exe",
            "classification": "suspicious",
            "score": 84.0,
            "tags": ["temporal_overlay_model_signal"],
            "explanation": {"reasons": ["direct temporal overlay pair probabilities affected model evidence"]},
            "temporal_overlay_record": {
                "ready": True,
                "stage_probability": 0.4,
                "pair_probabilities": [0.2, 0.4],
                "model_version": "temporal_overlay_v1",
            },
        }
    )

    evidence = compact["model_evidence"]
    overlay = evidence["temporal_overlay_record"]
    assert "pair_probabilities" not in overlay
    assert overlay["pair_probabilities_unavailable_reason"] == "non_mapping_probability_container"
    assert evidence["unavailable_reasons"]["temporal_overlay_record.pair_probabilities"] == "non_mapping_probability_container"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert any(
        failure["failure_type"] == "invalid_model_probability"
        and failure["model_name"] == "temporal_overlay_record.pair_probabilities"
        and failure["affected_fields"] == ("temporal_overlay_record", "pair_probabilities")
        and failure["reason"] == "non_mapping_probability_container"
        for failure in evidence["model_failures"]
    )
    assert compact["temporal_overlay_record_summary"]["pair_probabilities"] == {
        "model_signal_projection_failed": True,
        "reason": "non_mapping_probability_container",
    }


def test_stage1268_upstream_probability_mapping_type_is_sanitized() -> None:
    compact = compact_result_record(
        {
            "file": "upstream-temporal-overlay-map-type.exe",
            "path": "upstream-temporal-overlay-map-type.exe",
            "classification": "suspicious",
            "score": 79.0,
            "tags": ["upstream_temporal_overlay_model_signal"],
            "explanation": {"reasons": ["upstream temporal overlay affected model evidence"]},
            "model_evidence": {
                "temporal_overlay_record": {
                    "ready": True,
                    "stage_probability": 0.6,
                    "pair_probabilities": "not-a-probability-map",
                }
            },
        }
    )

    evidence = compact["model_evidence"]
    overlay = evidence["temporal_overlay_record"]
    assert overlay["stage_probability"] == 0.6
    assert "pair_probabilities" not in overlay
    assert overlay["pair_probabilities_unavailable_reason"] == "non_mapping_probability_container"
    assert evidence["unavailable_reasons"]["temporal_overlay_record.pair_probabilities"] == "non_mapping_probability_container"
    assert any(
        failure["failure_type"] == "invalid_model_probability"
        and failure["model_name"] == "temporal_overlay_record.pair_probabilities"
        and failure["reason"] == "non_mapping_probability_container"
        for failure in evidence["model_failures"]
    )
