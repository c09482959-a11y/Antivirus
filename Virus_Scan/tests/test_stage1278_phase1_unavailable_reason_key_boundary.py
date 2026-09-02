from __future__ import annotations

import json

import pytest

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1278_blank_feature_unavailable_reason_model_key_is_result_boundary_invalid() -> None:
    record = {
        "file": "blank-feature-unavailable-key.exe",
        "path": "blank-feature-unavailable-key.exe",
        "classification": "suspicious",
        "score": 82.0,
        "feature_probabilities": {
            "markov": 0.2,
            "_unavailable_reason": "cold_start",
        },
    }

    with pytest.raises(ValueError, match=r"feature_probabilities\._unavailable_reason.*model key missing"):
        validate_evidence_object_invariants(record, context="stage1278")


def test_stage1278_blank_model_evidence_unavailable_reason_key_is_result_boundary_invalid() -> None:
    record = {
        "file": "blank-model-evidence-unavailable-key.exe",
        "path": "blank-model-evidence-unavailable-key.exe",
        "classification": "suspicious",
        "score": 82.0,
        "model_evidence": {
            "unavailable_reasons": {
                "": "cold_start",
                "markov": "missing_snapshot",
            }
        },
    }

    with pytest.raises(ValueError, match=r"model_evidence\.unavailable_reasons.*blank key"):
        validate_evidence_object_invariants(record, context="stage1278")


def test_stage1278_publication_projects_blank_feature_unavailable_reason_key_as_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "publication-blank-feature-unavailable-key.exe",
            "path": "publication-blank-feature-unavailable-key.exe",
            "classification": "suspicious",
            "score": 83.0,
            "tags": ["blank_feature_unavailable_reason_key"],
            "explanation": {"reasons": ["blank unavailable-reason model key affected model evidence"]},
            "feature_probabilities": {
                "markov": 0.3,
                "_unavailable_reason": "cold_start",
                "profile_unavailable_reason": "missing_profile",
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["feature_probabilities"] == {"markov": 0.3}
    assert evidence["unavailable_reasons"] == {
        "feature_probabilities._unavailable_reason": "blank_model_unavailable_reason_key",
        "profile": "missing_profile",
    }
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert {failure["model_name"] for failure in evidence["model_failures"]} == {
        "feature_probabilities._unavailable_reason",
    }
    assert {failure["reason"] for failure in evidence["model_failures"]} == {
        "blank_model_unavailable_reason_key",
    }
    assert "" not in evidence["unavailable_reasons"]
    json.dumps(evidence, sort_keys=True, allow_nan=False)


def test_stage1278_publication_projects_blank_existing_model_unavailable_reason_key_as_failure_evidence() -> None:
    compact = compact_result_record(
        {
            "file": "publication-blank-existing-unavailable-key.exe",
            "path": "publication-blank-existing-unavailable-key.exe",
            "classification": "suspicious",
            "score": 84.0,
            "tags": ["blank_existing_model_unavailable_reason_key"],
            "model_evidence": {
                "unavailable_reasons": {
                    "": "cold_start",
                    "temporal": "missing_snapshot",
                }
            },
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["unavailable_reasons"] == {
        "model_evidence.unavailable_reasons": "blank_model_unavailable_reason_key",
        "temporal": "missing_snapshot",
    }
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert {failure["model_name"] for failure in evidence["model_failures"]} == {
        "model_evidence.unavailable_reasons",
    }
    assert {failure["reason"] for failure in evidence["model_failures"]} == {
        "blank_model_unavailable_reason_key",
    }
    assert "" not in evidence["unavailable_reasons"]
    json.dumps(evidence, sort_keys=True, allow_nan=False)
