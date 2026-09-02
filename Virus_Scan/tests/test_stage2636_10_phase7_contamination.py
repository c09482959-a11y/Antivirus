from __future__ import annotations
from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles

from pathlib import Path
from Virus_Scan.models.profiles.contamination import preflight_learning_contamination
from Virus_Scan.models.profiles.context import contextual_profile_learning_policy
from Virus_Scan.models.profiles.learning_decision import build_learning_decision
from Virus_Scan.models.profiles.replay_learning import get_benign_candidate_store
from Virus_Scan.models.profiles.learning_transaction import execute_learning_transaction
from Virus_Scan.models.profiles.maturity import profile_maturity_evidence
from Virus_Scan.models.profiles.persistence import load_engine_profile, save_engine_profile
from Virus_Scan.models.profiles.request_contracts import ProfileLearningGateRequest
from Virus_Scan.models.profiles.snapshots import default_extension_baseline
from Virus_Scan.models.profiles.transaction_contracts import LearningCommitRequest
from Virus_Scan.models.profiles.learning_decision import content_sha256_for_path
from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_NAMES
from Virus_Scan.models.profiles.vector_statistics import (
    PROFILE_MAX_OBSERVATION_INFLUENCE,
    default_profile_vector_statistics,
    update_profile_vector_statistics,
)
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def _isolate(tmp_path: Path) -> Path:
    profiles = tmp_path / "profiles"
    configure_profiles_dir(str(profiles))
    state = profile_persistence_state()
    state.bind_profiles_dir(str(profiles))
    configure_runtime_cluster_state(RuntimeClusterState())
    ensure_authoritative_engine_profiles()
    return profiles


def _request(sample: Path, *, forged_context: bool = False, unsafe: bool = False) -> LearningCommitRequest:
    sample.parent.mkdir(parents=True, exist_ok=True)
    sample.write_text("label start:\n    return\n", encoding="utf-8")
    fields = contextual_profile_learning_policy(
        str(sample), trusted_benign=True, degraded=False,
    ).as_record_fields()
    if forged_context:
        fields = dict(fields)
        fields["learning_baseline_key"] = "unity/.dll"
    validation: dict[str, object] = {"contextual_engine_identity": fields}
    if unsafe:
        validation["mixed_evidence"] = True
    evidence = physical_tag_evidence(
        ("benign_asset",), source_detector="phase7_contamination_fixture",
    )
    gate = ProfileLearningGateRequest(
        "renpy", str(sample), evidence, 0.0, "", "clean", (), (),
        scan_integrity={},
    )
    decision = build_learning_decision(
        gate, observation_id="phase7:" + ("forged" if forged_context else "accepted") + (":unsafe" if unsafe else ""),
        yara_hits=(), behavior_flow=(), previous_stage="asset",
        current_stage="runtime", learning_allowed=True,
        reason="test_authorized", validation=validation,
        gate_version="test_gate_v1",
    )
    return LearningCommitRequest(
        decision=decision, engine="renpy", content_sha256=content_sha256_for_path(sample), file_path=str(sample),
        tag_evidence=evidence, yara_hits=(), risk=0.0,
        strings_blob="", verdict="clean", api_calls=(), ordered_events=(),
        behavior_flow=(), previous_stage="asset", current_stage="runtime",
        validation=validation, scan_integrity={},
    )



def test_phase7_context_collision_quarantines_before_every_target(tmp_path: Path) -> None:
    _isolate(tmp_path)
    request = _request(tmp_path / "game" / "script.rpy", forged_context=True)
    result = execute_learning_transaction(request, get_benign_candidate_store())
    profile = load_engine_profile("renpy")
    contamination = profile["model_state"]["contamination"]

    assert result["learned"] is False
    assert result["reason"] == "profile_context_identity_collision"
    assert result["disposition"] == "quarantined"
    assert contamination["context_collision_count"] == 1
    assert profile["model_state"]["learning_transactions"] == {}


def test_phase7_unsafe_evidence_quarantines_before_every_target(tmp_path: Path) -> None:
    _isolate(tmp_path)
    request = _request(tmp_path / "game" / "script.rpy", unsafe=True)
    result = execute_learning_transaction(request, get_benign_candidate_store())
    profile = load_engine_profile("renpy")

    assert result["learned"] is False
    assert result["reason"] == "profile_unsafe_evidence_mixed_evidence"
    assert profile["model_state"]["contamination"]["unsafe_evidence_count"] == 1
    assert profile["model_state"]["learning_transactions"] == {}


def test_phase7_drift_quarantine_does_not_mutate_benign_statistics(tmp_path: Path) -> None:
    _isolate(tmp_path)
    sample = tmp_path / "game" / "script.rpy"
    request = _request(sample)
    profile = load_engine_profile("renpy")
    key = dict(request.decision.context_identity)["learning_baseline_key"]
    baseline = default_extension_baseline(key)
    statistics = default_profile_vector_statistics()
    for ordinal in range(12):
        statistics = update_profile_vector_statistics(
            statistics, [0.0] * len(PROFILE_RAW_FEATURE_NAMES), diversity_key=f"clean:{ordinal % 3}",
        )
    baseline["vector_baseline"] = statistics
    profile["extension_baselines"][key] = baseline
    plan = preflight_learning_contamination(profile, request, [1.0] * len(PROFILE_RAW_FEATURE_NAMES))
    current = profile["extension_baselines"][key]["vector_baseline"]

    assert plan.reason == "profile_drift_quarantined"
    assert len(plan.drift_dimensions) == len(PROFILE_RAW_FEATURE_NAMES)
    assert current["trusted_count"] == 12
    assert current["count"] == 13
    assert current["quarantine_count"] == 1
    assert current["mean"] == statistics["mean"]


def test_phase7_per_observation_influence_is_bounded() -> None:
    baseline = update_profile_vector_statistics(
        default_profile_vector_statistics(), [0.0] * len(PROFILE_RAW_FEATURE_NAMES),
        diversity_key="vendor:a",
    )
    updated = update_profile_vector_statistics(
        baseline, [1.0] * len(PROFILE_RAW_FEATURE_NAMES), diversity_key="vendor:b",
    )

    assert updated["outlier_count"] == 1
    assert all(value <= PROFILE_MAX_OBSERVATION_INFLUENCE for value in updated["mean"])


def test_phase7_maturity_requires_clean_diversity() -> None:
    baseline = default_profile_vector_statistics()
    for _ordinal in range(12):
        baseline = update_profile_vector_statistics(
            baseline, [0.1] * len(PROFILE_RAW_FEATURE_NAMES), diversity_key="vendor:one",
        )
    evidence = profile_maturity_evidence(baseline)
    assert evidence["maturity"] == "cold"
    assert evidence["reason"] == "insufficient_clean_profile_diversity"

    for key in ("vendor:two", "vendor:three"):
        baseline = update_profile_vector_statistics(
            baseline, [0.1] * len(PROFILE_RAW_FEATURE_NAMES), diversity_key=key,
        )
    assert profile_maturity_evidence(baseline)["maturity"] == "mature"


def test_phase7_malformed_contamination_state_fails_closed(tmp_path: Path) -> None:
    _isolate(tmp_path)
    request = _request(tmp_path / "game" / "script.rpy")
    profile = load_engine_profile("renpy")
    profile["model_state"]["contamination"] = []
    result = execute_learning_transaction(request, get_benign_candidate_store())

    assert result == {
        "learned": False,
        "reason": "profile_contamination_state_invalid",
        "promoted": True,
    }
