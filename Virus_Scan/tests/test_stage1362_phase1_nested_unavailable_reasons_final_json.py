from __future__ import annotations

import pytest

from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles
from Virus_Scan.tests.support.sqlite_profile_state import bind_profile_database
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
import json
from collections import Counter, defaultdict

from Virus_Scan.contracts.result_record import validate_evidence_object_invariants
from Virus_Scan.models.profiles import coordinated_model_validation_signal
from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields
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


def test_stage1362_nested_profile_unavailable_reasons_reach_final_json_field_map() -> None:
    _reset_markov_state()
    coordinated = coordinated_model_validation_signal(
        "other",
        "stage1362-profile-final-json.txt",
        physical_tag_evidence(("download", "exec"), source_detector="profile-temporal"),
    )
    record = {
        "file": "stage1362-profile-final-json.txt",
        "path": "stage1362-profile-final-json.txt",
        "classification": "medium",
        "score": 42.0,
        "tags": ["stage1362_nested_unavailable_reasons"],
        "adaptive_learning": {
            "profile_coordinated": coordinated,
        },
    }

    projected = build_model_evidence_final_json_fields(record)["model_evidence"]
    unavailable = projected["unavailable_reasons"]

    assert unavailable["adaptive_learning.profile_coordinated.temporal_support"] == "insufficient_temporal_history"
    assert (
        unavailable["adaptive_learning.profile_coordinated.markov_support"]
        == "markov_stage_identity_unavailable"
    )
    assert projected["final_json_must_record"] is True
    assert projected["replay_record_required"] is True
    json.dumps(projected, allow_nan=False, sort_keys=True)


def test_stage1362_nested_unavailable_reasons_survive_compact_result_record() -> None:
    _reset_markov_state()
    coordinated = coordinated_model_validation_signal(
        "other",
        "stage1362-profile-compact.txt",
        physical_tag_evidence(("download", "exec"), source_detector="profile-temporal"),
    )
    record = {
        "file": "stage1362-profile-compact.txt",
        "path": "stage1362-profile-compact.txt",
        "classification": "medium",
        "score": 43.0,
        "tags": ["stage1362_nested_unavailable_reasons_compact"],
        "adaptive_learning": {
            "profile_coordinated": coordinated,
        },
    }

    assert validate_evidence_object_invariants(record, context="stage1362-source") is True
    compact = compact_result_record(record)
    evidence = compact["model_evidence"]
    unavailable = evidence["unavailable_reasons"]

    assert unavailable["adaptive_learning.profile_coordinated.temporal_support"] == "insufficient_temporal_history"
    assert (
        unavailable["adaptive_learning.profile_coordinated.markov_support"]
        == "markov_stage_identity_unavailable"
    )
    assert validate_evidence_object_invariants(compact, context="stage1362-compact") is True
    json.dumps(compact, allow_nan=False, sort_keys=True)


def test_stage1362_invalid_nested_unavailable_reason_shape_becomes_publication_failure() -> None:
    record = {
        "file": "stage1362-invalid-unavailable-reasons.txt",
        "classification": "medium",
        "score": 40.0,
        "tags": ["stage1362_invalid_nested_unavailable_reasons"],
        "adaptive_learning": {
            "profile_coordinated": {
                "unavailable_reasons": {"temporal_support": ["not", "text"]},
            },
        },
    }

    projected = build_model_evidence_final_json_fields(record)["model_evidence"]
    assert projected["unavailable_reasons"][
        "adaptive_learning.profile_coordinated.unavailable_reasons.temporal_support"
    ] == "non_text_model_unavailable_reason"
    assert any(
        failure["failure_type"] == "invalid_model_unavailable_reasons_record"
        for failure in projected["model_failures"]
    )
    assert projected["final_json_must_record"] is True
    assert projected["replay_record_required"] is True
    json.dumps(projected, allow_nan=False, sort_keys=True)
