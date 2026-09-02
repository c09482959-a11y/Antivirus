"""Stage 1384 Phase 1 runtime filetype counter boundary repairs."""
from __future__ import annotations

from collections import Counter, defaultdict

from Virus_Scan.runtime import model_state


def _configure_runtime_maps():
    filetypes = defaultdict(Counter)
    model_state.configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=filetypes,
    )
    return filetypes


def test_stage1384_runtime_model_snapshot_rejects_non_mapping_filetype_counter() -> None:
    filetypes = _configure_runtime_maps()
    filetypes["bad"] = 999999
    filetypes["good"]["tag"] = 2

    snapshot = model_state.runtime_model_snapshot(
        markov_key_to_json=model_state.runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )

    assert snapshot["filetype_baseline"] == {"good": {"tag": 2}}
    reasons = snapshot["model_state_unavailable_reasons"]
    assert any(
        item["path"] == "filetype_baseline.bad"
        and item["reason"] == "non_mapping_runtime_filetype_counter"
        for item in reasons
    )


def test_stage1384_runtime_model_mapping_snapshot_omits_non_mapping_filetype_counter() -> None:
    filetypes = _configure_runtime_maps()
    filetypes["bad"] = 999999
    filetypes["good"]["tag"] = 2

    snapshot = model_state.runtime_model_mapping_snapshot("FILETYPE_BASELINE")

    assert list(snapshot) == ["good"]
    assert dict(snapshot["good"]) == {"tag": 2}


def test_stage1384_runtime_retention_drops_non_mapping_filetype_counters_before_ranking() -> None:
    filetypes = _configure_runtime_maps()
    filetypes["bad"] = 999999
    filetypes["good"]["tag"] = 1

    model_state.prune_runtime_model_mappings_for_retention(
        max_transition_keys=10,
        max_transition_next_keys=10,
        max_tag_counter_keys=10,
        max_pair_counter_keys=10,
        max_filetype_baselines=1,
    )

    snapshot = model_state.runtime_model_mapping_snapshot("FILETYPE_BASELINE")
    assert list(snapshot) == ["good"]
    assert dict(snapshot["good"]) == {"tag": 1}
