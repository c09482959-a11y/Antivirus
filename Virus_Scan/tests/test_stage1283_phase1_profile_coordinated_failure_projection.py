from __future__ import annotations

import pytest

from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles
from Virus_Scan.tests.support.sqlite_profile_state import bind_profile_database
from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.models.profiles import coordinated_model_validation_signal
from Virus_Scan.publication.json_writer import compact_result_record



@pytest.fixture(autouse=True)
def _canonical_profile_bootstrap(tmp_path):
    bind_profile_database(tmp_path)
    ensure_authoritative_engine_profiles()


class _BadOrderedEvents:
    def __iter__(self):
        raise ValueError("malformed ordered profile events")


def test_stage1283_profile_coordinated_validation_failure_is_explicit_model_evidence() -> None:
    signal = coordinated_model_validation_signal(
        "other",
        "sample.txt",
        ["alpha"],
        ordered_events=_BadOrderedEvents(),
    )

    assert signal["degraded"] is True
    assert signal["final_json_must_record"] is True
    assert signal["replay_record_required"] is True
    assert signal["vector_validation"]["reason"] == "profile_vector_validation_failed"
    assert signal["timeline_validation"]["reason"] == "profile_timeline_validation_failed"
    assert signal["unavailable_reasons"]["markov_support"] == "profile_markov_support_failed"
    failure_types = {failure["failure_type"] for failure in signal["model_failures"]}
    assert "vector_validation_failed" in failure_types
    assert "markov_support_failed" in failure_types
    assert "timeline_validation_failed" in failure_types


def test_stage1283_nested_adaptive_learning_model_failures_reach_final_json() -> None:
    signal = coordinated_model_validation_signal(
        "other",
        "sample.txt",
        ["alpha"],
        ordered_events=_BadOrderedEvents(),
    )
    record = {
        "file": "profile-coordinated-failure.txt",
        "path": "profile-coordinated-failure.txt",
        "classification": "medium",
        "score": 44.0,
        "tags": ["profile_coordinated_failure_evidence"],
        "adaptive_learning": {"bucket_vector": signal},
    }

    assert validate_evidence_object_invariants(record, context="stage1283-source") is True
    compact = compact_result_record(record)
    evidence = compact["model_evidence"]
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    projected = {
        (failure["model_name"], failure["failure_type"], failure["reason"])
        for failure in evidence["model_failures"]
    }
    assert ("profiles", "vector_validation_failed", "profile_vector_validation_failed") in projected
    assert ("profiles", "markov_support_failed", "profile_markov_support_failed") in projected
    assert ("profiles", "timeline_validation_failed", "profile_timeline_validation_failed") in projected
    assert validate_evidence_object_invariants(compact, context="stage1283-compact") is True
