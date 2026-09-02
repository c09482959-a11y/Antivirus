"""Stage 1385 Phase 1 runtime non-positive count boundary repairs."""
from __future__ import annotations
from Virus_Scan.tests.support.runtime_model_state import current_runtime_model_record

from collections import Counter, defaultdict

from Virus_Scan.contracts.markov_learning import (
    markov_event_transition_key,
    markov_global_context_key,
)
from Virus_Scan.runtime import model_state


def _event_key(source: str):
    return markov_event_transition_key(
        context_key=markov_global_context_key(), previous_stage="asset", source_event=source,
    )


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


def test_stage1385_runtime_mapping_snapshots_omit_nonpositive_learned_counts() -> None:
    transitions, tags, pairs, filetypes = _configure_runtime_maps()
    transitions[_event_key("download")]["zero"] = 0
    transitions[_event_key("download")]["negative"] = -7
    transitions[_event_key("download")]["exec"] = 2
    tags["empty"] = 0
    tags["download"] = 3
    pairs[("download", "zero")] = 0
    pairs[("download", "exec")] = 4
    filetypes[".bad"]["zero"] = 0
    filetypes[".good"]["exec"] = 1

    transition_snapshot = model_state.runtime_model_mapping_snapshot("TRANSITION_COUNTS")

    assert dict(transition_snapshot[_event_key("download")]) == {"exec": 2}
    assert dict(model_state.runtime_model_mapping_snapshot("GLOBAL_TAG_BASELINE")) == {"download": 3}
    assert dict(model_state.runtime_model_mapping_snapshot("GLOBAL_TAG_PAIR_BASELINE")) == {("download", "exec"): 4}
    assert set(model_state.runtime_model_mapping_snapshot("FILETYPE_BASELINE")) == {".good"}


def test_stage1385_runtime_model_snapshot_omits_nonpositive_clean_rows_but_reports_corrupt_counts() -> None:
    transitions, tags, pairs, filetypes = _configure_runtime_maps()
    transitions[_event_key("download")]["zero"] = 0
    transitions[_event_key("download")]["nan"] = float("nan")
    transitions[_event_key("download")]["exec"] = 2
    tags["zero"] = 0
    tags["bad"] = float("inf")
    tags["download"] = 3
    pairs[("download", "zero")] = 0
    pairs[("download", "bad")] = float("nan")
    pairs[("download", "exec")] = 4
    filetypes[".bad"]["zero"] = 0
    filetypes[".bad"]["nan"] = float("nan")
    filetypes[".good"]["exec"] = 1

    snapshot = model_state.runtime_model_snapshot(
        markov_key_to_json=model_state.runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )

    assert snapshot["transition_counts"] == [
        {"type": "markov_event_v2", "context": "global:trusted_benign", "previous_stage": "asset", "source_event": "download", "target": "exec", "count": 2}
    ]
    assert snapshot["global_tag_baseline"] == {"download": 3}
    assert snapshot["global_tag_pair_baseline"] == [{"a": "download", "b": "exec", "count": 4}]
    assert snapshot["filetype_baseline"] == {".good": {"exec": 1}}
    reasons = snapshot["model_state_unavailable_reasons"]
    assert any(item["path"].endswith(".nan") and item["reason"] == "non_finite_runtime_model_count" for item in reasons)


def test_stage1385_loader_skips_nonpositive_baseline_counts_without_materializing_empty_models() -> None:
    _configure_runtime_maps()

    result = model_state.load_runtime_model_baselines(
        current_runtime_model_record({
            "global_tag_baseline": {"zero": 0, "download": 2},
            "global_tag_pair_baseline": [
                {"a": "download", "b": "zero", "count": 0},
                {"a": "download", "b": "exec", "count": 3},
            ],
            "filetype_baseline": {".bad": {"zero": 0}, ".good": {"exec": 4}},
        })
    )

    assert result["loaded"] is True
    assert dict(model_state.runtime_model_mapping_snapshot("GLOBAL_TAG_BASELINE")) == {"download": 2}
    assert dict(model_state.runtime_model_mapping_snapshot("GLOBAL_TAG_PAIR_BASELINE")) == {("download", "exec"): 3}
    assert set(model_state.runtime_model_mapping_snapshot("FILETYPE_BASELINE")) == {".good"}


def test_stage1385_retention_drops_invalid_or_zero_nested_counters_before_parent_ranking() -> None:
    transitions, _tags, pairs, filetypes = _configure_runtime_maps()
    transitions[_event_key("bad")][""] = 999999
    transitions[_event_key("zero")]["target"] = 0
    transitions[_event_key("good")]["exec"] = 1
    pairs[("bad", "zero")] = 0
    pairs[("good", "exec")] = 1
    filetypes[".bad"][""] = 999999
    filetypes[".zero"]["tag"] = 0
    filetypes[".good"]["tag"] = 1

    model_state.prune_runtime_model_mappings_for_retention(
        max_transition_keys=1,
        max_transition_next_keys=10,
        max_tag_counter_keys=10,
        max_pair_counter_keys=1,
        max_filetype_baselines=1,
    )

    transition_snapshot = model_state.runtime_model_mapping_snapshot("TRANSITION_COUNTS")
    assert list(transition_snapshot) == [_event_key("good")]
    assert dict(model_state.runtime_model_mapping_snapshot("GLOBAL_TAG_PAIR_BASELINE")) == {("good", "exec"): 1}
    filetype_snapshot = model_state.runtime_model_mapping_snapshot("FILETYPE_BASELINE")
    assert list(filetype_snapshot) == [".good"]
    assert dict(filetype_snapshot[".good"]) == {"tag": 1}
