from __future__ import annotations

import pytest

from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles
from Virus_Scan.tests.support.sqlite_profile_state import bind_profile_database
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
import json
from collections import Counter, defaultdict

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.models.profiles import coordinated_model_validation_signal, extension_profile_anomaly
from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.runtime.model_state import configure_runtime_model_state



@pytest.fixture(autouse=True)
def _canonical_profile_bootstrap(tmp_path):
    bind_profile_database(tmp_path)
    ensure_authoritative_engine_profiles()


def _reset_markov_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def _failure_types(record):
    return {failure["failure_type"] for failure in record.get("model_failures", ())}


def test_stage1361_coordinated_profile_parent_records_markov_and_temporal_cold_start_support() -> None:
    _reset_markov_state()
    signal = coordinated_model_validation_signal(
        "other",
        "stage1361-profile-cold-start.txt",
        physical_tag_evidence(("download", "exec"), source_detector="profile-temporal"),
    )

    assert signal["degraded"] is True
    assert signal["final_json_must_record"] is True
    assert signal["replay_record_required"] is True
    assert signal["unavailable_reasons"]["temporal_support"] == "insufficient_temporal_history"
    assert signal["unavailable_reasons"]["markov_support"] == "markov_stage_identity_unavailable"
    failures = _failure_types(signal)
    assert "temporal_support_unavailable" in failures
    assert "markov_support_unavailable" in failures
    json.dumps(signal, allow_nan=False, sort_keys=True)


def test_stage1361_profile_markov_temporal_unavailable_support_reaches_final_json() -> None:
    _reset_markov_state()
    coordinated = coordinated_model_validation_signal(
        "other",
        "stage1361-profile-final-json.txt",
        physical_tag_evidence(("download", "exec"), source_detector="profile-temporal"),
    )
    extension = extension_profile_anomaly(
        "other",
        "stage1361-profile-final-json.txt",
        physical_tag_evidence(("download", "exec"), source_detector="profile-temporal"),
        0.0,
    )
    record = {
        "file": "stage1361-profile-final-json.txt",
        "path": "stage1361-profile-final-json.txt",
        "classification": "medium",
        "score": 42.0,
        "tags": ["stage1361_profile_markov_temporal_unavailable"],
        "adaptive_learning": {
            "profile_coordinated": coordinated,
            "profile_extension": extension,
        },
    }

    assert validate_evidence_object_invariants(record, context="stage1361-source") is True
    compact = compact_result_record(record)
    evidence = compact["model_evidence"]
    failures = _failure_types(evidence)

    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert "temporal_support_unavailable" in failures
    assert "markov_support_unavailable" in failures
    assert validate_evidence_object_invariants(compact, context="stage1361-compact") is True
    json.dumps(compact, allow_nan=False, sort_keys=True)
