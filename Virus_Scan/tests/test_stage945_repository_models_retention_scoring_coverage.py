from __future__ import annotations

from Virus_Scan.models import retention as retention_module

from dataclasses import FrozenInstanceError

import pytest

from Virus_Scan.core.ilspy_runtime import resolve_ilspy_path
from Virus_Scan.models.retention import (
    prune_counter_map,
    prune_extension_baseline_for_retention,
    prune_staged_benign_store,
)
from Virus_Scan.detection.scoring.adaptive.calibration_state import FusionScoreHistory
from Virus_Scan.runtime.config_state import configure_ilspy_path


def test_fusion_score_history_is_bounded_and_snapshot_is_tuple_contract():
    history = FusionScoreHistory(maxlen=2)

    assert history.add(1.25) == (1.25,)
    assert history.add("2.5") == (1.25, 2.5)
    assert history.add(3) == (2.5, 3.0)
    assert history.snapshot() == (2.5, 3.0)
    assert isinstance(history.snapshot(), tuple)


def test_retention_counter_pruning_preserves_ranked_entries_in_place():
    counter = {
        "low": 1,
        "nested-high": {"a": 3, "b": 4},
        "ignored": "not numeric",
        "mid": 5,
    }

    returned = prune_counter_map(counter, 2)

    assert returned is counter
    assert counter == {"nested-high": {"a": 3, "b": 4}, "mid": 5}

    low_counter = {"high": 10, "low": 1, "mid": 5}
    prune_counter_map(low_counter, 2, prefer_high=False)
    assert low_counter == {"low": 1, "mid": 5}


def test_staged_benign_retention_keeps_promoted_recent_high_observation_candidates():

    original_limit = retention_module.MAX_STAGED_BENIGN_CANDIDATES
    retention_module.MAX_STAGED_BENIGN_CANDIDATES = 2
    try:
        store = {
            "candidates": {
                "weak": {"clean_observations": 1, "last_seen": 10.0},
                "recent": {"clean_observations": 3, "last_seen": 30.0},
                "promoted": {"promoted": True, "clean_observations": 0, "last_seen": 1.0},
            }
        }

        returned = prune_staged_benign_store(store)

        assert returned is store
        assert set(store["candidates"]) == {"promoted", "recent"}
        assert store["retention"]["max_staged_benign_candidates"] == 2
        assert "staged_candidates_pruned_at" in store["retention"]
    finally:
        retention_module.MAX_STAGED_BENIGN_CANDIDATES = original_limit


def test_extension_baseline_retention_removes_raw_vectors_and_records_policy_metadata():
    baseline = {
        "vector_baseline": {
            "vectors": [1],
            "samples": [2],
            "raw_vectors": [3],
            "centroid": [0.1, 0.2],
        }
    }

    returned = prune_extension_baseline_for_retention(baseline)

    assert returned is baseline
    assert baseline["vector_baseline"] == {"centroid": [0.1, 0.2]}
    assert "last_pruned" in baseline["retention"]


def test_ilspy_runtime_resolves_through_canonical_runtime_config_owner(tmp_path):
    configure_ilspy_path(None)
    assert resolve_ilspy_path("fallback-ilspy") == "fallback-ilspy"

    configured = configure_ilspy_path(tmp_path / "ilspycmd")
    try:
        assert resolve_ilspy_path("fallback-ilspy") == configured
    finally:
        configure_ilspy_path(None)
