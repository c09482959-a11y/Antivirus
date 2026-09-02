from __future__ import annotations
from Virus_Scan.tests.support.runtime_model_state import current_runtime_model_record
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision

import json
import math
import pytest
from collections import Counter, defaultdict
from pathlib import Path


from Virus_Scan.models import markov, temporal
from Virus_Scan.contracts.markov_learning import (
    markov_event_transition_key,
    markov_global_context_key,
    markov_stage_transition_key,
)
from Virus_Scan.models.api.clustering_contracts import load_cluster_runtime_model_record
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    load_runtime_model_baselines,
    runtime_model_mapping_snapshot,
    runtime_model_snapshot,
    runtime_transition_counter_snapshot,
    runtime_transition_key_to_json,
)


def _reset_runtime_model_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def _event_key(source: str = "download"):
    return markov_event_transition_key(
        context_key=markov_global_context_key(),
        previous_stage="asset",
        source_event=source,
    )


def _stage_key(flow=("download", "exec")):
    return markov_stage_transition_key(
        context_key=markov_global_context_key(),
        previous_stage="asset",
        behavior_flow=tuple(flow),
    )


def test_stage1368_temporal_pair_probabilities_use_each_markov_pair_record() -> None:
    _reset_runtime_model_state()

    for _ in range(3):
        markov.update_markov_model("asset", ["download", "exec", "network"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",), observation_id=f"stage1368-network-{_}"))
        markov.update_markov_model("asset", ["download", "exec", "persist"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",), observation_id=f"stage1368-persist-{_}"))

    overlay = temporal.transition_probability_overlay(
        prev_stage="asset",
        tags=["download", "exec", "network"],
        curr_stage="runtime",
    )

    pairs = overlay["pair_probabilities"]
    assert [pair["probability"] for pair in pairs] == pytest.approx([
        0.7647058823529411, 0.4117647058823529,
    ])
    assert [pair["support"] for pair in pairs] == [6, 6]
    assert all(pair["ready"] is True for pair in pairs)
    assert {pair["model_version"] for pair in pairs} == {"markov_contextual_dirichlet_v2"}


def test_stage1368_runtime_model_snapshot_records_sanitized_count_failures() -> None:
    transition_counts = defaultdict(Counter)
    transition_counts[_stage_key()]["runtime"] = math.inf
    transition_counts[_event_key()]["exec"] = -2

    configure_runtime_model_state(
        transition_counts=transition_counts,
        global_tag_baseline={"download": math.nan},
        global_tag_pair_baseline={("download", "exec"): -math.inf},
        filetype_baseline={".bin": Counter({"download": math.nan})},
    )

    snapshot = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )

    reasons = snapshot["model_state_unavailable_reasons"]
    assert any(item["reason"] == "non_finite_runtime_model_count" for item in reasons)
    assert any(item["reason"] == "negative_runtime_model_count" for item in reasons)
    assert snapshot["transition_counts"] == []
    assert snapshot["global_tag_baseline"] == {}
    assert snapshot["global_tag_pair_baseline"] == []
    assert snapshot["filetype_baseline"] == {}
    json.dumps(snapshot, allow_nan=False, sort_keys=True)


def test_stage1368_malformed_runtime_model_load_does_not_clear_existing_state() -> None:
    _reset_runtime_model_state()
    markov.update_markov_model("asset", ["download", "exec"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",)))
    before = runtime_transition_counter_snapshot(_event_key())
    assert before["exec"] == 1

    result = load_runtime_model_baselines(["not", "a", "mapping"])

    after = runtime_transition_counter_snapshot(_event_key())
    assert result["loaded"] is False
    assert result["reason"] == "runtime_model_snapshot_record_invalid"
    assert after["exec"] == 1


def test_stage1368_runtime_model_loader_reports_malformed_sections() -> None:
    _reset_runtime_model_state()

    result = load_runtime_model_baselines(
        current_runtime_model_record({
            "transition_counts": [{"type": "markov_stage_v2", "context": "global:trusted_benign", "previous_stage": "asset", "flow_class": "flow:test", "target": "runtime", "count": math.inf}],
            "global_tag_baseline": ["not", "mapping"],
            "global_tag_pair_baseline": ["not-a-row"],
            "filetype_baseline": {".bin": "not-a-counter"},
        })
    )

    assert result["loaded"] is False
    assert result["reason"] == "runtime_model_tag_section_invalid"
    assert runtime_model_mapping_snapshot("TRANSITION_COUNTS") == {}
    assert runtime_model_mapping_snapshot("GLOBAL_TAG_BASELINE") == {}
    assert runtime_model_mapping_snapshot("GLOBAL_TAG_PAIR_BASELINE") == {}
    assert runtime_model_mapping_snapshot("FILETYPE_BASELINE") == {}


def test_stage1368_malformed_cluster_current_record_does_not_clear_existing_state() -> None:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    state.node_cluster_map["node-a"] = "cluster-a"
    state.cluster_signatures["cluster-a"] = [1.0, 0.0]
    state.cluster_metadata["cluster-a"] = {"members": {"node-a"}, "kind": "mixed"}

    assert load_cluster_runtime_model_record({"cluster_signatures": ["not", "mapping"]}) is False
    assert state.node_cluster_map["node-a"] == "cluster-a"
    assert state.cluster_signatures["cluster-a"] == [1.0, 0.0]
    assert state.cluster_metadata["cluster-a"]["members"] == {"node-a"}

def test_stage1368_malformed_runtime_model_sections_do_not_clear_existing_state() -> None:
    transition_counts = defaultdict(Counter)
    transition_counts[_event_key()]["exec"] = 2
    configure_runtime_model_state(
        transition_counts=transition_counts,
        global_tag_baseline={"download": 7},
        global_tag_pair_baseline={("download", "exec"): 3},
        filetype_baseline={".bin": Counter({"download": 5})},
    )

    result = load_runtime_model_baselines(
        current_runtime_model_record({
            "transition_counts": "not-a-transition-row-list",
            "global_tag_baseline": ["not", "a", "mapping"],
            "global_tag_pair_baseline": {"not": "a-row-list"},
            "filetype_baseline": ["not", "a", "mapping"],
        })
    )

    assert result["loaded"] is False
    assert result["reason"] == "runtime_model_transition_section_invalid"
    assert runtime_transition_counter_snapshot(_event_key())["exec"] == 2
    assert runtime_model_mapping_snapshot("GLOBAL_TAG_BASELINE")["download"] == 7
    assert runtime_model_mapping_snapshot("GLOBAL_TAG_PAIR_BASELINE")[("download", "exec")] == 3
    assert runtime_model_mapping_snapshot("FILETYPE_BASELINE")[".bin"]["download"] == 5



def test_stage1368_runtime_model_snapshot_records_malformed_pair_key_evidence() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline={"download->exec": 4},
        filetype_baseline=defaultdict(Counter),
    )

    snapshot = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )

    reasons = snapshot["model_state_unavailable_reasons"]
    assert any(item["reason"] == "invalid_runtime_pair_key" for item in reasons)
    assert snapshot["global_tag_pair_baseline"] == []
    json.dumps(snapshot, allow_nan=False, sort_keys=True)



def test_stage1368_runtime_model_loader_rejects_pair_rows_without_pair_identity() -> None:
    _reset_runtime_model_state()

    result = load_runtime_model_baselines(
        current_runtime_model_record({
            "global_tag_pair_baseline": [
                {"a": "download", "count": 3},
                {"a": "download", "b": "exec", "count": 2},
            ]
        })
    )

    reasons = result["model_state_unavailable_reasons"]
    assert any(item["reason"] == "invalid_runtime_pair_row_key" for item in reasons)
    pair_snapshot = runtime_model_mapping_snapshot("GLOBAL_TAG_PAIR_BASELINE")
    assert ("", "") not in pair_snapshot
    assert pair_snapshot == {}
    assert result["loaded"] is False



def test_stage1368_runtime_model_loader_rejects_transition_rows_without_identity() -> None:
    _reset_runtime_model_state()

    result = load_runtime_model_baselines(
        current_runtime_model_record({
            "transition_counts": [
                {"type": "markov_event_v2", "context": "", "previous_stage": "asset", "source_event": "download", "target": "exec", "count": 2},
                {"type": "markov_stage_v2", "context": "global:trusted_benign", "previous_stage": "asset", "flow_class": "flow:test", "target": "runtime", "count": 3},
            ]
        })
    )

    reasons = result["model_state_unavailable_reasons"]
    assert any(item["reason"] == "invalid_runtime_transition_key" for item in reasons)
    assert runtime_transition_counter_snapshot(("markov_event_v2", ("", "asset", "download"))) == {}
    assert runtime_transition_counter_snapshot(("markov_stage_v2", ("global:trusted_benign", "asset", "flow:test"))) == {}
    assert result["loaded"] is False



def test_stage1368_model_contracts_do_not_expose_placeholder_named_failure_paths() -> None:
    contract_paths = (
        Path("Virus_Scan/models/contracts/model_evidence.py"),
        Path("Virus_Scan/models/contracts/model_failure.py"),
        Path("Virus_Scan/models/contracts/model_feature_bundle.py"),
    )

    for contract_path in contract_paths:
        source = contract_path.read_text(encoding="utf-8").lower()
        assert "placeholder" not in source


def test_stage1370_runtime_model_snapshot_omits_empty_pair_key_evidence() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline={("download", ""): 4, ("download", "exec"): 2},
        filetype_baseline=defaultdict(Counter),
    )

    snapshot = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )

    assert any(item["reason"] == "invalid_runtime_pair_key" for item in snapshot["model_state_unavailable_reasons"])
    assert snapshot["global_tag_pair_baseline"] == [
        {"a": "download", "b": "exec", "count": 2}
    ]
    json.dumps(snapshot, allow_nan=False, sort_keys=True)


def test_stage1370_runtime_model_snapshot_omits_invalid_transition_key_evidence() -> None:
    transition_counts = defaultdict(Counter)
    transition_counts[("markov_event_v2", ("", "asset", "download"))]["exec"] = 2
    transition_counts[_stage_key()]["runtime"] = 3
    configure_runtime_model_state(
        transition_counts=transition_counts,
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )

    snapshot = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )

    assert any(item["reason"] == "invalid_runtime_transition_key" for item in snapshot["model_state_unavailable_reasons"])
    assert snapshot["transition_counts"] == [
        {**runtime_transition_key_to_json(_stage_key()), "target": "runtime", "count": 3}
    ]
    json.dumps(snapshot, allow_nan=False, sort_keys=True)
