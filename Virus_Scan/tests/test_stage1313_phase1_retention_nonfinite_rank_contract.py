from __future__ import annotations

import math

from Virus_Scan.models import retention as retention_module
from Virus_Scan.models.retention import (
    prune_counter_map,
    prune_engine_profile_for_retention,
    prune_staged_benign_store,
)


def test_stage1313_retention_counter_pruning_ignores_nonfinite_model_counts():
    counter = {
        "valid-high": 7,
        "valid-mid": {"a": 3, "b": 2},
        "infinite": math.inf,
        "nan-nested": {"a": math.nan, "b": 1},
    }

    returned = prune_counter_map(counter, 2)

    assert returned is counter
    assert counter == {"valid-high": 7, "valid-mid": {"a": 3, "b": 2}}


def test_stage1313_staged_benign_retention_does_not_rank_nonfinite_timestamps_as_recent():
    original_limit = retention_module.MAX_STAGED_BENIGN_CANDIDATES
    retention_module.MAX_STAGED_BENIGN_CANDIDATES = 1
    try:
        store = {
            "candidates": {
                "corrupt": {"clean_observations": math.inf, "last_seen": math.inf},
                "valid": {"clean_observations": 2, "last_seen": 50.0},
            }
        }

        returned = prune_staged_benign_store(store)

        assert returned is store
        assert set(store["candidates"]) == {"valid"}
    finally:
        retention_module.MAX_STAGED_BENIGN_CANDIDATES = original_limit


def test_stage1313_engine_profile_retention_does_not_keep_nonfinite_extension_rank():
    original_limit = retention_module.MAX_EXTENSION_BASELINES_PER_ENGINE
    retention_module.MAX_EXTENSION_BASELINES_PER_ENGINE = 1
    try:
        profile = {
            "extension_baselines": {
                ".corrupt": {"files": math.inf, "updated": math.inf},
                ".valid": {"files": 3, "updated": 20.0},
            }
        }

        returned = prune_engine_profile_for_retention(profile)

        assert returned is profile
        assert set(profile["extension_baselines"]) == {".valid"}
    finally:
        retention_module.MAX_EXTENSION_BASELINES_PER_ENGINE = original_limit
