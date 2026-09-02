"""Stage 1380 Phase 1 runtime model retention identity boundaries."""
from __future__ import annotations

from collections import Counter, defaultdict

from Virus_Scan.contracts.markov_learning import (
    markov_context_support_key,
    markov_global_context_key,
    markov_stage_transition_key,
)
from Virus_Scan.runtime import model_state


def _configure_runtime_maps():
    transitions = defaultdict(Counter)
    tags = defaultdict(int)
    pairs = defaultdict(int)
    filetypes = defaultdict(Counter)
    model_state.configure_runtime_model_state(
        transition_counts=transitions,
        global_tag_baseline=tags,
        global_tag_pair_baseline=pairs,
        filetype_baseline=filetypes,
    )
    return transitions, tags, pairs, filetypes


def test_stage1380_retention_discards_invalid_transition_keys_before_ranking() -> None:
    transitions, _tags, _pairs, _filetypes = _configure_runtime_maps()
    valid_key = markov_stage_transition_key(context_key=markov_global_context_key(), previous_stage="asset", behavior_flow=("download", "exec"))
    transitions[("", frozenset())]["malformed"] = 999
    transitions[valid_key]["runtime"] = 1

    model_state.prune_runtime_model_mappings_for_retention(
        max_transition_keys=1,
        max_transition_next_keys=4,
        max_tag_counter_keys=4,
        max_pair_counter_keys=4,
        max_filetype_baselines=4,
    )

    assert list(transitions.keys()) == [valid_key]
    assert dict(model_state.runtime_model_mapping_snapshot("TRANSITION_COUNTS")) == {
        valid_key: {"runtime": 1}
    }


def test_stage1380_retention_discards_invalid_global_pair_keys_before_ranking() -> None:
    _transitions, _tags, pairs, _filetypes = _configure_runtime_maps()
    pairs[("", "bad")] = 999
    pairs[("download", "exec")] = 1

    model_state.prune_runtime_model_mappings_for_retention(
        max_transition_keys=4,
        max_transition_next_keys=4,
        max_tag_counter_keys=4,
        max_pair_counter_keys=1,
        max_filetype_baselines=4,
    )

    assert dict(pairs) == {("download", "exec"): 1}
    assert dict(model_state.runtime_model_mapping_snapshot("GLOBAL_TAG_PAIR_BASELINE")) == {
        ("download", "exec"): 1
    }


def test_stage1380_retention_discards_invalid_filetype_and_tag_identities_before_ranking() -> None:
    _transitions, tags, _pairs, filetypes = _configure_runtime_maps()
    tags[""] = 999
    tags["network_download"] = 1
    filetypes[""]["bad"] = 999
    filetypes[".py"][""] = 999
    filetypes[".py"]["script_exec"] = 1

    model_state.prune_runtime_model_mappings_for_retention(
        max_transition_keys=4,
        max_transition_next_keys=4,
        max_tag_counter_keys=1,
        max_pair_counter_keys=4,
        max_filetype_baselines=1,
    )

    assert dict(tags) == {"network_download": 1}
    assert list(filetypes.keys()) == [".py"]
    assert dict(filetypes[".py"]) == {"script_exec": 1}
    assert dict(model_state.runtime_model_mapping_snapshot("GLOBAL_TAG_BASELINE")) == {
        "network_download": 1
    }
    assert dict(model_state.runtime_model_mapping_snapshot("FILETYPE_BASELINE")) == {
        ".py": {"script_exec": 1}
    }


def test_stage1380_retention_preserves_canonical_context_support_key() -> None:
    transitions, _tags, _pairs, _filetypes = _configure_runtime_maps()
    alpha_key = markov_context_support_key("alpha")
    zeta_key = markov_context_support_key("zeta")
    transitions[alpha_key]["observations"] = 1
    transitions[zeta_key]["observations"] = 1

    model_state.prune_runtime_model_mappings_for_retention(
        max_transition_keys=1,
        max_transition_next_keys=1,
        max_tag_counter_keys=1,
        max_pair_counter_keys=1,
        max_filetype_baselines=1,
    )

    assert list(transitions.keys()) == [alpha_key]
    snapshot = model_state.runtime_model_snapshot(
        markov_key_to_json=model_state.runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )
    assert snapshot["transition_counts"] == [
        {
            "type": "markov_context_support_v2",
            "context": "alpha",
            "target": "observations",
            "count": 1,
        }
    ]
