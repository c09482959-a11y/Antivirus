"""Stage 1372 Phase 1 runtime model mutation-boundary identity validation."""
from __future__ import annotations
from Virus_Scan.detection.scoring.adaptive.log_odds_probabilities import LogOddsFeatureProbabilitiesRequest

import json
from collections import Counter, defaultdict


from Virus_Scan.models import markov
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision
from Virus_Scan.contracts.markov_learning import (
    markov_context_support_key,
    markov_event_transition_key,
    markov_global_context_key,
)
from Virus_Scan.detection.scoring.adaptive.model_score import (
    log_odds_feature_probabilities,
    adaptive_learned_model_confidence,
)
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    runtime_markov_observation_total,
    runtime_model_mapping_snapshot,
    runtime_model_snapshot,
    runtime_transition_counter_snapshot,
    runtime_transition_key_to_json,
    set_global_tag_count,
    update_filetype_baseline,
)


def _reset_runtime_model_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def _event_key() -> tuple[str, tuple[str, str, str]]:
    return markov_event_transition_key(
        context_key=markov_global_context_key(),
        previous_stage="asset",
        source_event="download",
    )



def test_stage1372_snapshot_omits_empty_transition_targets_and_emits_evidence() -> None:
    transitions: defaultdict[object, Counter[str]] = defaultdict(Counter)
    key = _event_key()
    transitions[key][""] = 5
    transitions[key]["exec"] = 3
    configure_runtime_model_state(
        transition_counts=transitions,
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )

    snapshot = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )

    assert any(item["reason"] == "invalid_runtime_transition_target" for item in snapshot["model_state_unavailable_reasons"])
    assert snapshot["transition_counts"] == [{
        "type": "markov_event_v2",
        "context": markov_global_context_key(),
        "previous_stage": "asset",
        "source_event": "download",
        "target": "exec",
        "count": 3,
    }]
    json.dumps(snapshot, allow_nan=False, sort_keys=True)


def test_stage1372_empty_transition_targets_do_not_inflate_context_support_or_counter_snapshot() -> None:
    transitions: defaultdict[object, Counter[str]] = defaultdict(Counter)
    event_key = _event_key()
    support_key = markov_context_support_key(markov_global_context_key())
    transitions[event_key][""] = 99
    transitions[event_key]["exec"] = 2
    transitions[support_key][""] = 7
    transitions[support_key]["observations"] = 1
    configure_runtime_model_state(
        transition_counts=transitions,
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )

    assert runtime_markov_observation_total() == 1
    assert runtime_transition_counter_snapshot(event_key) == {"exec": 2}
    transition_snapshot = runtime_model_mapping_snapshot("TRANSITION_COUNTS")
    assert transition_snapshot[event_key] == {"exec": 2}
    assert transition_snapshot[support_key] == {"observations": 1}


def test_stage1372_markov_probability_rejects_snapshot_with_only_empty_targets() -> None:
    record = markov.markov_pair_probability(
        "download",
        "exec",
        prev_stage="asset",
        snapshot={_event_key(): {"": 5}},
    )

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["reason"] == "invalid_markov_target"
    assert record["support"] == 0


def test_stage1372_public_markov_owner_is_the_only_global_rarity_mutator() -> None:
    _reset_runtime_model_state()

    result = markov.update_markov_model(
        "asset", ["download", " ", "exec", ""], "runtime",
        learning_decision=accepted_learning_decision(
            target_names=("markov",), observation_id="stage1372-authorized",
        ),
    )
    update_filetype_baseline("  .bin  ", ["download", " ", "exec"])
    update_filetype_baseline(".empty", [" ", ""])
    set_global_tag_count("   ", 12)
    set_global_tag_count(" normalized ", 4)

    assert result["learned"] is True
    assert runtime_model_mapping_snapshot("GLOBAL_TAG_BASELINE") == {"download": 1, "exec": 1, "normalized": 4}
    assert runtime_model_mapping_snapshot("GLOBAL_TAG_PAIR_BASELINE") == {("download", "exec"): 1}
    assert runtime_model_mapping_snapshot("FILETYPE_BASELINE") == {".bin": {"download": 1, "exec": 1}}


def test_stage1372_public_markov_owner_rejects_blank_stage_identity_atomically() -> None:
    _reset_runtime_model_state()

    result = markov.update_markov_model(
        " ", ("download", "exec"), "runtime",
        learning_decision=accepted_learning_decision(
            target_names=("markov",), observation_id="stage1372-blank-stage",
        ),
    )

    assert result["learned"] is False
    assert result["reason"] == "markov_stage_unavailable"
    assert runtime_markov_observation_total() == 0
    assert runtime_model_mapping_snapshot("TRANSITION_COUNTS") == {}


def test_stage1372_adaptive_unavailable_model_metadata_cannot_inflate_log_odds_probabilities() -> None:
    probs = log_odds_feature_probabilities(LogOddsFeatureProbabilitiesRequest(
        {
            "p_yara": 0.0,
            "p_mitre": 0.0,
            "p_exec": 0.0,
            "p_behavior": 0.0,
            "p_evasion": 0.0,
            "p_entropy": 0.0,
            "p_profile": 0.0,
            "p_markov": 0.0,
            "p_temporal": 0.0,
            "p_cluster": 0.0,
            "p_bucket": 0.0,
            "p_vector": 0.0,
            "p_graph_chain": 0.0,
            "p_attention": 0.0,
            "p_graph": 0.0,
        },
        {"profile_anomaly": 0.95, "reason": "profile_unavailable"},
        {"markov_anomaly": 0.95, "markov_unavailable_reason": "cold_start"},
        {"cluster_signal": 0.95, "cluster_unavailable_reason": "cluster_not_assigned"},
        {"bucket_anomaly": 0.95, "unavailable_reason": "bucket_unavailable"},
        {"anomaly": 0.95, "failure_reason": "vector_unavailable"},
        {},
        {},
    ))

    assert probs["p_profile"] == 0.0
    assert probs["p_markov"] == 0.0
    assert probs["p_cluster"] == 0.0
    assert probs["p_bucket"] == 0.0
    assert probs["p_vector"] == 0.0
    assert probs["p_profile_unavailable_reason"] == "profile_unavailable"
    assert probs["p_markov_unavailable_reason"] == "cold_start"
    assert probs["p_cluster_unavailable_reason"] == "cluster_not_assigned"


def test_stage1372_adaptive_confidence_ignores_unavailable_model_signals() -> None:
    confidence = adaptive_learned_model_confidence(
        profile_signal={"profile_ready": True, "profile_anomaly": 1.0, "reason": "profile_unavailable"},
        markov_signal={"markov_anomaly": 1.0, "markov_unavailable_reason": "cold_start"},
        cluster_signal={"cluster_signal": 1.0, "cluster_unavailable_reason": "cluster_not_assigned"},
        vector_signal=0.0,
        bucket_signal=0.0,
    )

    assert confidence == 0.0
