from __future__ import annotations

from Virus_Scan.models import retention as retention_module
from Virus_Scan.models.retention import (
    prune_counter_map,
    prune_engine_profile_for_retention,
    prune_staged_benign_store,
)


class HostileRetentionKey:
    def __str__(self) -> str:  # pragma: no cover - must not be reached
        raise RuntimeError("raw retention __str__ should not be invoked")

    def __repr__(self) -> str:  # pragma: no cover - must not be reached
        raise RuntimeError("raw retention __repr__ should not be invoked")


class HostileRetentionPath:
    def __init__(self, value: str) -> None:
        self._value = value

    def __fspath__(self) -> str:
        return self._value

    def __str__(self) -> str:  # pragma: no cover - must not be reached
        raise RuntimeError("raw retention path __str__ should not be invoked")

    def __repr__(self) -> str:  # pragma: no cover - must not be reached
        raise RuntimeError("raw retention path __repr__ should not be invoked")


def test_stage1545_counter_retention_prunes_hostile_key_without_raw_stringification() -> None:
    hostile = HostileRetentionKey()
    counter = {"low": 1, hostile: 9}

    returned = prune_counter_map(counter, 1, prefer_high=True)

    assert returned is counter
    assert list(counter) == [hostile]
    assert counter[hostile] == 9


def test_stage1545_staged_benign_retention_ranks_hostile_candidate_keys_without_raw_repr() -> None:
    original_limit = retention_module.MAX_STAGED_BENIGN_CANDIDATES
    retention_module.MAX_STAGED_BENIGN_CANDIDATES = 1
    hostile = HostileRetentionKey()
    try:
        store = {
            "candidates": {
                "older": {"clean_observations": 1, "last_seen": 10.0},
                hostile: {"clean_observations": 5, "last_seen": 20.0},
            }
        }

        returned = prune_staged_benign_store(store)

        assert returned is store
        assert list(store["candidates"]) == [hostile]
        assert store["retention"]["max_staged_benign_candidates"] == 1
    finally:
        retention_module.MAX_STAGED_BENIGN_CANDIDATES = original_limit


def test_stage1545_engine_profile_retention_ranks_hostile_extension_keys_without_raw_repr() -> None:
    original_limit = retention_module.MAX_EXTENSION_BASELINES_PER_ENGINE
    retention_module.MAX_EXTENSION_BASELINES_PER_ENGINE = 1
    hostile = HostileRetentionPath(".hostile")
    try:
        profile = {
            "extension_baselines": {
                ".low": {"files": 1, "updated": 1.0, "tags": {}},
                hostile: {"files": 7, "updated": 7.0, "tags": {}},
            }
        }

        returned = prune_engine_profile_for_retention(profile)

        assert returned is profile
        assert list(profile["extension_baselines"]) == [hostile]
        assert profile["retention"]["max_extension_baselines_per_engine"] == 1
    finally:
        retention_module.MAX_EXTENSION_BASELINES_PER_ENGINE = original_limit
