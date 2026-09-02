from __future__ import annotations

from Virus_Scan.runtime.profile_scoring_state import ProfileScoringState


def test_stage1353_profile_scoring_snapshot_orders_nested_mapping_keys_deterministically() -> None:
    first = ProfileScoringState()
    second = ProfileScoringState()

    first_snapshot = {
        "renpy": {
            "weights": {"z_tag": 0.3, "a_tag": 0.9, "m_tag": 0.5},
            "thresholds": {"high": 0.8, "low": 0.2},
        },
        "unity": {"weights": {"b_tag": 0.4}},
    }
    second_snapshot = {
        "unity": {"weights": {"b_tag": 0.4}},
        "renpy": {
            "thresholds": {"low": 0.2, "high": 0.8},
            "weights": {"m_tag": 0.5, "a_tag": 0.9, "z_tag": 0.3},
        },
    }

    first.freeze(first_snapshot)
    second.freeze(second_snapshot)

    first_materialized = first.snapshot()
    second_materialized = second.snapshot()

    assert list(first_materialized) == ["renpy", "unity"]
    assert list(second_materialized) == ["renpy", "unity"]
    assert list(first_materialized["renpy"]) == ["thresholds", "weights"]
    assert list(second_materialized["renpy"]) == ["thresholds", "weights"]
    assert list(first_materialized["renpy"]["weights"]) == ["a_tag", "m_tag", "z_tag"]
    assert list(second_materialized["renpy"]["weights"]) == ["a_tag", "m_tag", "z_tag"]
    assert first_materialized == second_materialized


def test_stage1353_profile_scoring_get_profile_returns_canonical_nested_order() -> None:
    state = ProfileScoringState()
    state.freeze(
        {
            "renpy": {
                "weights": {"z": 3, "a": 1, "b": 2},
                "sets_are_not_semantic_sequences": {"z", "a", "m"},
                "lists_are_semantic_sequences": ["z", "a", "m"],
            }
        }
    )

    profile = state.get_profile("renpy")

    assert list(profile) == ["lists_are_semantic_sequences", "sets_are_not_semantic_sequences", "weights"]
    assert list(profile["weights"]) == ["a", "b", "z"]
    assert profile["sets_are_not_semantic_sequences"] == ["a", "m", "z"]
    assert profile["lists_are_semantic_sequences"] == ["z", "a", "m"]
