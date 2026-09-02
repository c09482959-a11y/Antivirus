from __future__ import annotations
from Virus_Scan.models.profiles.staged_store_schema import default_staged_benign_store
from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles

from dataclasses import replace
from pathlib import Path
from collections import Counter, defaultdict
import pytest

from Virus_Scan.contracts.temporal_accumulator import initial_temporal_accumulator_state
from Virus_Scan.models import markov, temporal
from Virus_Scan.models.profiles.commit import commit_promoted_learning
from Virus_Scan.models.profiles.learning_transaction import execute_learning_transaction
from Virus_Scan.models.profiles.persistence import load_engine_profile, save_engine_profile
from Virus_Scan.models.profiles.replay_learning import get_benign_candidate_store
from Virus_Scan.models.profiles.schema import ProfileSchemaInvariantError
from Virus_Scan.runtime.cluster_state import (
    RuntimeClusterState,
    configure_runtime_cluster_state,
    runtime_cluster_state_to_json,
)
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.orchestration.model_state_loader import load_runtime_model_state
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    load_runtime_model_baselines,
    runtime_model_mapping_snapshot,
    runtime_model_snapshot,
    runtime_transition_key_to_json,
    runtime_markov_observation_total,
)
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state
from Virus_Scan.runtime.temporal_state import (
    TEMPORAL_RUNTIME_STATE_SCHEMA,
    load_temporal_runtime_state,
    temporal_history_snapshot,
    temporal_runtime_state_to_json,
)
from Virus_Scan.tests.support.profile_learning import accepted_learning_request
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.storage import authoritative_model_state


def _isolate(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    configure_profiles_dir(str(profiles))
    owner = profile_persistence_state()
    owner.bind_profiles_dir(str(profiles))
    owner.set_staged_cache(
        default_staged_benign_store(),
        dirty=False,
    )
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )
    configure_runtime_cluster_state(RuntimeClusterState())
    assert load_temporal_runtime_state({
        "schema_version": TEMPORAL_RUNTIME_STATE_SCHEMA,
        "nodes": {},
        "applied_learning_keys": [],
    })["loaded"] is True

    ensure_authoritative_engine_profiles()

def _sample(tmp_path: Path) -> Path:
    path = tmp_path / "game" / "script.rpy"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("label start:\n    return\n", encoding="utf-8")
    return path


def test_phase4_transaction_request_rejects_altered_evidence(tmp_path: Path) -> None:
    request = accepted_learning_request(_sample(tmp_path), flow=("decode", "execute"))
    with pytest.raises(ValueError, match="observation mismatch"):
        replace(request, behavior_flow=("execute", "decode")).validate()
    with pytest.raises(ValueError, match="context mismatch"):
        replace(request, validation={"contextual_engine_identity": {"baseline_key": "other/.rpy"}}).validate()


def test_phase4_duplicate_observation_stages_once_and_collision_fails_closed(tmp_path: Path) -> None:
    _isolate(tmp_path)
    sample = _sample(tmp_path)
    first = commit_promoted_learning(
        "renpy", sample, physical_tag_evidence(
            ("benign_asset",), source_detector="phase4_commit_fixture",
        ), verdict="clean", observation_id="worker-parent-observation",
    )
    duplicate = commit_promoted_learning(
        "renpy", sample, physical_tag_evidence(
            ("benign_asset",), source_detector="phase4_commit_fixture",
        ), verdict="clean", observation_id="worker-parent-observation",
    )
    collision = commit_promoted_learning(
        "renpy", sample, physical_tag_evidence(
            ("benign_asset", "text_file"), source_detector="phase4_commit_fixture",
        ), verdict="clean", observation_id="worker-parent-observation",
    )
    store = get_benign_candidate_store()
    candidate = next(iter(store["candidates"].values()))

    assert first["reason"] == "staged_pending_more_clean_observations"
    assert duplicate["reason"] == "staged_pending_more_clean_observations"
    assert collision["reason"] == "learning_observation_identity_collision"
    assert candidate["clean_observations"] == 1
    assert store["observation_ledger"]["entries"]["worker-parent-observation"]["status"] == "staged"


def test_phase4_distinct_observations_promote_after_three_unique_commits(tmp_path: Path) -> None:
    _isolate(tmp_path)
    sample = _sample(tmp_path)
    results = [
        commit_promoted_learning(
            "renpy", sample, physical_tag_evidence(
                ("benign_asset",), source_detector="phase4_commit_fixture",
                source_stage="unique-" + str(index),
            ), verdict="clean", observation_id=f"unique-{index}",
        )
        for index in range(3)
    ]
    assert [result["promoted"] for result in results] == [False, False, True]
    assert results[-1]["learned"] is True


def test_phase4_incomplete_committed_record_is_not_resumed_or_reapplied(tmp_path: Path) -> None:
    _isolate(tmp_path)
    sample = _sample(tmp_path)
    request = accepted_learning_request(
        sample, flow=("decode", "execute"), observation_id="all-target-recovery",
    )
    first = execute_learning_transaction(request, get_benign_candidate_store())
    assert first["learned"] is True

    profile = load_engine_profile("renpy")
    transaction = profile["model_state"]["learning_transactions"][request.decision.replay_key]
    before_files = profile["extension_baselines"]["renpy/.rpy"]["files"]
    before_markov = runtime_markov_observation_total()
    before_temporal = len(temporal_history_snapshot(str(sample)))
    before_filetype = dict(runtime_model_mapping_snapshot("FILETYPE_BASELINE"))
    for target_state in transaction["targets"].values():
        target_state["status"] = "in_progress"
        target_state["reason"] = ""
        target_state["output"] = {}
    transaction["status"] = "pending"
    transaction.pop("authoritative_transaction_id", None)
    transaction["completed_targets"] = 0
    with pytest.raises(
        ValueError, match="learning_transaction_incomplete_persistence_rejected",
    ):
        save_engine_profile("renpy", profile, force=True)

    second = execute_learning_transaction(request, get_benign_candidate_store())
    profile = load_engine_profile("renpy")

    assert second["learned"] is True
    assert second["idempotent_replay"] is True
    assert profile["extension_baselines"]["renpy/.rpy"]["files"] == before_files
    assert runtime_markov_observation_total() == before_markov
    assert len(temporal_history_snapshot(str(sample))) == before_temporal
    assert dict(runtime_model_mapping_snapshot("FILETYPE_BASELINE")) == before_filetype


def test_phase4_stale_or_tampered_transaction_fails_closed(tmp_path: Path) -> None:
    _isolate(tmp_path)
    request = accepted_learning_request(_sample(tmp_path), observation_id="tamper")
    assert execute_learning_transaction(request, get_benign_candidate_store())["learned"] is True
    profile = load_engine_profile("renpy")
    transaction = profile["model_state"]["learning_transactions"][request.decision.replay_key]
    transaction["status"] = "pending"
    transaction["decision"]["schema_version"] = "profiles_learning_decision_v0"
    with pytest.raises(
        ProfileSchemaInvariantError, match="learning transaction decision invalid",
    ):
        save_engine_profile("renpy", profile, force=True)

    result = execute_learning_transaction(request, get_benign_candidate_store())
    assert result["learned"] is True
    assert result["idempotent_replay"] is True


def test_phase4_temporal_state_and_replay_key_survive_runtime_snapshot_reload(tmp_path: Path) -> None:
    _isolate(tmp_path)
    sample = _sample(tmp_path)
    decision = accepted_learning_request(
        sample, flow=("decode", "execute"), observation_id="temporal-restart",
    ).decision
    first = temporal.update_temporal(
        str(sample), "asset", ("decode", "execute"),
        learning_decision=decision,
    )
    assert first["updated"] is True
    snapshot = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )
    assert snapshot["schema_version"] == 4
    assert snapshot["temporal_state"]["schema_version"] == TEMPORAL_RUNTIME_STATE_SCHEMA

    assert load_temporal_runtime_state({
        "schema_version": TEMPORAL_RUNTIME_STATE_SCHEMA,
        "nodes": {},
        "applied_learning_keys": [],
    })["loaded"] is True
    assert temporal_history_snapshot(str(sample)) == ()

    loaded = load_runtime_model_baselines(snapshot)
    assert loaded["loaded"] is True
    assert len(temporal_history_snapshot(str(sample))) == 2
    replay = temporal.update_temporal(
        str(sample), "asset", ("decode", "execute"),
        learning_decision=decision,
    )
    assert replay["updated"] is True
    assert replay["idempotent_replay"] is True
    assert len(temporal_history_snapshot(str(sample))) == 2


def test_phase4_malformed_temporal_reload_is_atomic() -> None:
    before = temporal_runtime_state_to_json()
    malformed = dict(before)
    malformed["nodes"] = {
        "node": {
            "history": [[float("nan"), "asset", []]],
            "belief": 0.0,
            "hidden_state": initial_temporal_accumulator_state().to_record(),
            "last_snapshot": None,
            "last_learning_ordinal": -1,
        }
    }

    result = load_temporal_runtime_state(malformed)

    assert result == {"loaded": False, "reason": "temporal_event_record_invalid"}
    assert temporal_runtime_state_to_json() == before


def test_phase4_lifecycle_loader_restores_every_runtime_learning_owner(tmp_path: Path) -> None:

    _isolate(tmp_path)
    sample = _sample(tmp_path)
    request = accepted_learning_request(
        sample, flow=("decode", "execute"), observation_id="lifecycle-restart",
    )
    assert execute_learning_transaction(request, get_benign_candidate_store())["learned"] is True
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )
    configure_runtime_cluster_state(RuntimeClusterState())
    assert load_temporal_runtime_state({
        "schema_version": TEMPORAL_RUNTIME_STATE_SCHEMA,
        "nodes": {},
        "applied_learning_keys": [],
    })["loaded"] is True

    assert load_runtime_model_state() is True
    assert runtime_markov_observation_total() == 1
    assert len(temporal_history_snapshot(str(sample))) == 2
    markov_replay = markov.update_markov_model(
        "asset", ("decode", "execute"), "runtime",
        learning_decision=request.decision,
    )
    temporal_replay = temporal.update_temporal(
        str(sample), "runtime", ("decode", "execute"),
        learning_decision=request.decision,
    )
    assert markov_replay["idempotent_replay"] is True
    assert temporal_replay["idempotent_replay"] is True
    assert runtime_markov_observation_total() == 1
    assert len(temporal_history_snapshot(str(sample))) == 2


def test_phase4_same_content_at_distinct_paths_has_one_learning_contribution(tmp_path: Path) -> None:
    _isolate(tmp_path)
    first_path = tmp_path / "first" / "script.rpy"
    second_path = tmp_path / "second" / "script.rpy"
    for path in (first_path, second_path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("label start:\n    return\n", encoding="utf-8")
    first_request = accepted_learning_request(
        first_path, flow=("decode", "execute"), observation_id="content-first",
    )
    second_request = accepted_learning_request(
        second_path, flow=("decode", "execute"), observation_id="content-second",
    )

    first = execute_learning_transaction(first_request, get_benign_candidate_store())
    before_profile = load_engine_profile("renpy")["extension_baselines"]["renpy/.rpy"]["files"]
    before_markov = runtime_markov_observation_total()
    before_temporal = len(temporal_history_snapshot(str(first_path)))
    second = execute_learning_transaction(second_request, get_benign_candidate_store())
    profile = load_engine_profile("renpy")

    assert first["learned"] is True
    assert first_request.content_sha256 == second_request.content_sha256
    assert first_request.decision.observation_digest == second_request.decision.observation_digest
    assert first_request.decision.replay_key != second_request.decision.replay_key
    assert second["learned"] is True
    assert second["idempotent_replay"] is True
    assert second["content_deduplicated"] is True
    assert second["source_replay_key"] == first_request.decision.replay_key
    assert profile["extension_baselines"]["renpy/.rpy"]["files"] == before_profile
    assert runtime_markov_observation_total() == before_markov
    assert len(temporal_history_snapshot(str(first_path))) == before_temporal
    occurrences = authoritative_model_state().read_content_occurrences(
        engine="renpy", content_sha256=first_request.content_sha256,
    )
    assert {row["artifact_instance"] for row in occurrences} == {
        str(first_path), str(second_path),
    }
    assert all(row["occurrence_count"] == 1 for row in occurrences)
    assert len(profile["model_state"]["learning_transactions"]) == 1
