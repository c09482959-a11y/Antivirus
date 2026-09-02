from __future__ import annotations
from Virus_Scan.models.profiles.staged_store_schema import default_staged_benign_store
from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles

import json
from pathlib import Path

import pytest

from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.models.api.clustering_contracts import assign_cluster_with_context_tags
from Virus_Scan.models.api.markov_contracts import update_markov_model
from Virus_Scan.models.api.temporal_contracts import update_temporal
from Virus_Scan.models.profiles.context import contextual_profile_learning_policy
from Virus_Scan.models.profiles.extension_learning import apply_extension_learning_decision
from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_NAMES
from Virus_Scan.models.profiles.replay_learning import get_benign_candidate_store
from Virus_Scan.models.profiles.learning_transaction import (
    execute_learning_transaction,
)
from Virus_Scan.models.profiles.transaction_state import TRANSACTION_TARGET_ORDER
from Virus_Scan.models.profiles.learning_decision import build_learning_decision
from Virus_Scan.models.profiles.persistence import load_engine_profile, save_engine_profile
from Virus_Scan.models.profiles.schema import validate_engine_profile_schema
from Virus_Scan.models.profiles.request_contracts import ProfileLearningGateRequest
from Virus_Scan.models.profiles.transaction_contracts import LearningCommitRequest
from Virus_Scan.models.profiles.learning_decision import content_sha256_for_path
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision


def _isolate(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    configure_profiles_dir(str(profiles))
    state = profile_persistence_state()
    state.bind_profiles_dir(str(profiles))
    configure_runtime_cluster_state(RuntimeClusterState())
    state.set_staged_cache(
        default_staged_benign_store(),
        dirty=False,
    )

    ensure_authoritative_engine_profiles()

def _request(tmp_path: Path, flow: tuple[str, ...]) -> LearningCommitRequest:
    sample = tmp_path / "game" / "script.rpy"
    sample.parent.mkdir(parents=True, exist_ok=True)
    sample.write_text("label start:\n    return\n", encoding="utf-8")
    tag_evidence = physical_tag_evidence(("benign_asset",), source_detector="phase3_learning_fixture")
    validation = {
        "contextual_engine_identity": contextual_profile_learning_policy(
            str(sample), trusted_benign=True, degraded=False,
        ).as_record_fields(),
    }
    gate = ProfileLearningGateRequest(
        "renpy", str(sample), tag_evidence, 0.0, "", "clean", (), (),
        scan_integrity={},
    )
    decision = build_learning_decision(
        gate, observation_id="phase3:" + "-".join(flow or ("profile",)),
        yara_hits=(), behavior_flow=flow, previous_stage="asset",
        current_stage="runtime", learning_allowed=True, reason="test_authorized",
        validation=validation, gate_version="test_gate_v1",
    )
    return LearningCommitRequest(
        decision=decision, engine="renpy", content_sha256=content_sha256_for_path(sample), file_path=str(sample),
        tag_evidence=tag_evidence, yara_hits=(), risk=0.0, strings_blob="",
        verdict="clean", api_calls=(), ordered_events=(), behavior_flow=flow,
        previous_stage="asset", current_stage="runtime",
        validation=validation, scan_integrity={},
    )


def test_phase3_missing_decisions_fail_closed_for_every_public_model_target(tmp_path: Path) -> None:
    _isolate(tmp_path)
    request = _request(tmp_path, ())
    profile = load_engine_profile("renpy")

    assert apply_extension_learning_decision(
        profile, object(), [0.0] * len(PROFILE_RAW_FEATURE_NAMES), diversity_key="test-invalid",
    )["reason"] == "learning_decision_required"
    assert update_markov_model("a", ("x", "y"), "b")["reason"] == "learning_decision_required"
    assert update_temporal("node", "stage", ("x",))["reason"] == "learning_decision_required"
    cluster = assign_cluster_with_context_tags("node", (0.1,), tags=("x",))
    assert cluster["reason"] == "learning_decision_required"


def test_phase3_complete_transaction_is_idempotent(tmp_path: Path) -> None:
    _isolate(tmp_path)
    request = _request(tmp_path, ())

    first = execute_learning_transaction(request, get_benign_candidate_store())
    second = execute_learning_transaction(request, get_benign_candidate_store())
    profile = load_engine_profile("renpy")
    baseline = profile["extension_baselines"]["renpy/.rpy"]

    assert first["learned"] is True
    assert first["target_status"] == {"profile": "succeeded", "clustering": "succeeded"}
    assert second["learned"] is True
    assert second["idempotent_replay"] is True
    assert baseline["files"] == 1


def test_phase3_transaction_schema_survives_canonical_json_key_sorting(tmp_path: Path) -> None:
    _isolate(tmp_path)
    request = _request(tmp_path, ())

    assert execute_learning_transaction(request, get_benign_candidate_store())["learned"] is True
    profile = load_engine_profile("renpy")
    canonical = json.loads(json.dumps(profile, sort_keys=True))

    assert validate_engine_profile_schema(canonical, expected_engine="renpy") is True
    transaction = canonical["model_state"]["learning_transactions"][
        request.decision.replay_key
    ]
    assert transaction["target_order"] == ["profile", "clustering"]
    assert set(transaction["targets"]) == {"profile", "clustering"}


def test_phase3_incomplete_persisted_transaction_fails_closed_without_reapplication(tmp_path: Path) -> None:
    _isolate(tmp_path)
    request = _request(tmp_path, ())

    first = execute_learning_transaction(request, get_benign_candidate_store())
    profile = load_engine_profile("renpy")
    before_files = profile["extension_baselines"]["renpy/.rpy"]["files"]
    transaction = profile["model_state"]["learning_transactions"][request.decision.replay_key]
    transaction["targets"]["profile"]["status"] = "in_progress"
    transaction["targets"]["profile"]["reason"] = ""
    transaction["targets"]["profile"]["output"] = {}
    transaction["status"] = "pending"
    transaction.pop("authoritative_transaction_id", None)
    transaction["completed_targets"] = 1
    with pytest.raises(
        ValueError, match="learning_transaction_incomplete_persistence_rejected",
    ):
        save_engine_profile("renpy", profile, force=True)

    persisted = load_engine_profile("renpy")
    second = execute_learning_transaction(request, get_benign_candidate_store())

    assert first["learned"] is True
    assert second["learned"] is True
    assert second["idempotent_replay"] is True
    assert persisted["extension_baselines"]["renpy/.rpy"]["files"] == before_files


def test_phase3_replay_has_no_model_execution_owner_and_graph_is_not_a_learning_target() -> None:
    deleted_owner = Path("Virus_Scan/models/replay/runtime_observation.py")
    replay_source = Path("Virus_Scan/models/replay/learning.py").read_text(encoding="utf-8")
    transaction_source = Path("Virus_Scan/models/profiles/learning_transaction.py").read_text(encoding="utf-8")

    assert not deleted_owner.exists()
    assert "graph" not in TRANSACTION_TARGET_ORDER
    assert "graph" not in accepted_learning_decision(target_names=("profile",)).permitted_model_targets
    for forbidden in (
        "update_markov_model", "apply_temporal_learning_target", "update_temporal",
        "update_filetype", "assign_cluster_with_context_tags",
        "link_temporal_to_graph", "mark_runtime_models_dirty",
    ):
        assert forbidden not in replay_source
    assert "update_markov_model" in transaction_source
    assert "apply_temporal_learning_target" in transaction_source
