"""Stage 1383 Phase 1 runtime transition counter boundary repairs."""
from __future__ import annotations

from collections import Counter, defaultdict

from Virus_Scan.runtime import model_state
from Virus_Scan.models import markov
from Virus_Scan.contracts.markov_learning import (
    markov_event_transition_key,
    markov_global_context_key,
    markov_stage_transition_key,
)


def _event_key(source: str = "download"):
    return markov_event_transition_key(context_key=markov_global_context_key(), previous_stage="asset", source_event=source)


def _stage_key(flow=("download", "exec")):
    return markov_stage_transition_key(context_key=markov_global_context_key(), previous_stage="asset", behavior_flow=tuple(flow))


def _configure_runtime_maps():
    transitions = defaultdict(Counter)
    model_state.configure_runtime_model_state(
        transition_counts=transitions,
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )
    return transitions


def test_stage1383_runtime_model_snapshot_rejects_non_mapping_transition_counter() -> None:
    transitions = _configure_runtime_maps()
    transitions[_stage_key()] = 99
    transitions[_event_key()]["exec"] = 3

    snapshot = model_state.runtime_model_snapshot(
        markov_key_to_json=model_state.runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )

    assert {row["type"] for row in snapshot["transition_counts"]} == {"markov_event_v2"}
    assert snapshot["transition_counts"] == [
        {"type": "markov_event_v2", "context": "global:trusted_benign", "previous_stage": "asset", "source_event": "download", "target": "exec", "count": 3}
    ]
    reasons = snapshot["model_state_unavailable_reasons"]
    assert any(item["reason"] == "non_mapping_runtime_transition_counter" for item in reasons)


def test_stage1383_retention_drops_non_mapping_transition_counters_before_ranking() -> None:
    transitions = _configure_runtime_maps()
    transitions[_stage_key(("bad", "counter"))] = 999999
    transitions[_stage_key(("good", "counter"))]["runtime"] = 1

    model_state.prune_runtime_model_mappings_for_retention(
        max_transition_keys=1,
        max_transition_next_keys=10,
        max_tag_counter_keys=10,
        max_pair_counter_keys=10,
        max_filetype_baselines=10,
    )

    snapshot = model_state.runtime_model_mapping_snapshot("TRANSITION_COUNTS")
    assert list(snapshot) == [_stage_key(("good", "counter"))]
    assert dict(snapshot[_stage_key(("good", "counter"))]) == {"runtime": 1}


def test_stage1383_zero_count_markov_targets_do_not_inflate_probability_vocab() -> None:
    record = markov.markov_pair_probability(
        "download",
        "exec",
        snapshot={_event_key(): {"exec": 0}},
        prev_stage="asset",
    )

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["support"] == 0
    assert record["count"] == 0
    assert record["vocab"] == 2
    assert record["reason"] == "insufficient_markov_pair_support"
