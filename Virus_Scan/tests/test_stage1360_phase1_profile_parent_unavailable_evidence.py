from __future__ import annotations

import pytest

import json

from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles
from Virus_Scan.tests.support.sqlite_profile_state import bind_profile_database
from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.models.profiles import (
    adaptive_profile_signal,
    coordinated_model_validation_signal,
    extension_profile_anomaly,
)
from Virus_Scan.publication.json_writer import compact_result_record



@pytest.fixture(autouse=True)
def _canonical_profile_bootstrap(tmp_path):
    bind_profile_database(tmp_path)
    ensure_authoritative_engine_profiles()


def _failure_types(record):
    return {failure["failure_type"] for failure in record.get("model_failures", ())}


def test_stage1360_extension_profile_cold_start_is_explicit_unavailable_evidence() -> None:
    signal = extension_profile_anomaly("other", "sample.txt", ["alpha"], 0.0)

    assert signal["ready"] is False
    assert signal["anomaly"] == 0.0
    assert signal["reason"] == "insufficient_trusted_profile_support"
    assert signal["unavailable_reason"] == "insufficient_trusted_profile_support"
    assert signal["degraded"] is True
    assert signal["evidence_type"] == "profile_extension_anomaly"
    assert signal["final_json_must_record"] is True
    assert signal["replay_record_required"] is True
    assert "extension_profile_unavailable" in _failure_types(signal)
    json.dumps(signal, allow_nan=False)


def test_stage1360_adaptive_profile_cold_start_is_explicit_unavailable_evidence() -> None:
    signal = adaptive_profile_signal("sample.txt", ["alpha"])

    assert signal["profile_ready"] is False
    assert signal["profile_anomaly"] == 0.0
    assert signal["reason"] == "insufficient_trusted_profile_support"
    assert signal["unavailable_reason"] == "insufficient_trusted_profile_support"
    assert signal["degraded"] is True
    assert signal["evidence_type"] == "profile_adaptive_signal"
    assert signal["final_json_must_record"] is True
    assert signal["replay_record_required"] is True
    assert "adaptive_profile_unavailable" in _failure_types(signal)
    json.dumps(signal, allow_nan=False)


def test_stage1360_coordinated_profile_parent_propagates_nested_unavailable_evidence() -> None:
    signal = coordinated_model_validation_signal("other", "sample.txt", ["alpha"])

    assert signal["degraded"] is True
    assert signal["final_json_must_record"] is True
    assert signal["replay_record_required"] is True
    assert signal["unavailable_reasons"]["vector_validation"] == "insufficient_trusted_profile_support"
    assert signal["unavailable_reasons"]["timeline_validation"] == "insufficient_timeline_history"
    assert signal["vector_validation"]["final_json_must_record"] is True
    assert signal["timeline_validation"]["replay_record_required"] is True
    assert {"vector_baseline_unavailable", "timeline_baseline_unavailable"}.issubset(_failure_types(signal))
    json.dumps(signal, allow_nan=False)


def test_stage1360_profile_unavailable_model_failures_reach_final_json() -> None:
    extension = extension_profile_anomaly("other", "sample.txt", ["alpha"], 0.0)
    adaptive = adaptive_profile_signal("sample.txt", ["alpha"])
    coordinated = coordinated_model_validation_signal("other", "sample.txt", ["alpha"])
    record = {
        "file": "stage1360-profile-parent-unavailable.txt",
        "path": "stage1360-profile-parent-unavailable.txt",
        "classification": "medium",
        "score": 44.0,
        "tags": ["stage1360_profile_unavailable_evidence"],
        "adaptive_learning": {
            "profile_extension": extension,
            "profile_adaptive": adaptive,
            "profile_coordinated": coordinated,
        },
    }

    assert validate_evidence_object_invariants(record, context="stage1360-source") is True
    compact = compact_result_record(record)
    evidence = compact["model_evidence"]
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    projected = _failure_types(evidence)
    assert "extension_profile_unavailable" in projected
    assert "adaptive_profile_unavailable" in projected
    assert "vector_baseline_unavailable" in projected
    assert "timeline_baseline_unavailable" in projected
    assert validate_evidence_object_invariants(compact, context="stage1360-compact") is True
