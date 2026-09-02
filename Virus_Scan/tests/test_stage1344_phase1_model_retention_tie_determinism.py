from collections import Counter

from Virus_Scan.contracts.markov_learning import (
    markov_event_transition_key,
    markov_global_context_key,
)
from Virus_Scan.models.retention import prune_counter_map, prune_engine_profile_for_retention
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    prune_runtime_model_mappings_for_retention,
)


def test_stage1344_runtime_transition_retention_ties_are_key_deterministic() -> None:
    context = markov_global_context_key()
    alpha_key = markov_event_transition_key(
        context_key=context, previous_stage="asset", source_event="alpha",
    )
    zeta_key = markov_event_transition_key(
        context_key=context, previous_stage="asset", source_event="zeta",
    )
    first_order = {
        zeta_key: Counter({"next": 1}),
        alpha_key: Counter({"next": 1}),
    }
    second_order = {
        alpha_key: Counter({"next": 1}),
        zeta_key: Counter({"next": 1}),
    }

    configure_runtime_model_state(
        transition_counts=first_order,
        global_tag_baseline={},
        global_tag_pair_baseline={},
        filetype_baseline={},
    )
    prune_runtime_model_mappings_for_retention(
        max_transition_keys=1,
        max_transition_next_keys=1,
        max_tag_counter_keys=1,
        max_pair_counter_keys=1,
        max_filetype_baselines=1,
    )
    first_kept = tuple(first_order)

    configure_runtime_model_state(
        transition_counts=second_order,
        global_tag_baseline={},
        global_tag_pair_baseline={},
        filetype_baseline={},
    )
    prune_runtime_model_mappings_for_retention(
        max_transition_keys=1,
        max_transition_next_keys=1,
        max_tag_counter_keys=1,
        max_pair_counter_keys=1,
        max_filetype_baselines=1,
    )
    second_kept = tuple(second_order)

    assert first_kept == second_kept == (alpha_key,)


def test_stage1344_runtime_nested_transition_retention_ties_are_key_deterministic() -> None:
    key = markov_event_transition_key(
        context_key=markov_global_context_key(),
        previous_stage="asset",
        source_event="same",
    )
    transitions = {
        key: Counter({"zeta": 1, "alpha": 1}),
    }
    configure_runtime_model_state(
        transition_counts=transitions,
        global_tag_baseline={},
        global_tag_pair_baseline={},
        filetype_baseline={},
    )

    prune_runtime_model_mappings_for_retention(
        max_transition_keys=4,
        max_transition_next_keys=1,
        max_tag_counter_keys=1,
        max_pair_counter_keys=1,
        max_filetype_baselines=1,
    )

    assert list(transitions[key]) == ["alpha"]


def test_stage1344_profile_counter_retention_ties_are_key_deterministic_for_high_and_low() -> None:
    high_first = {"zeta": 2, "alpha": 2, "middle": 1}
    high_second = {"middle": 1, "alpha": 2, "zeta": 2}
    prune_counter_map(high_first, 1, prefer_high=True)
    prune_counter_map(high_second, 1, prefer_high=True)
    assert high_first == high_second == {"alpha": 2}

    low_first = {"zeta": 1, "alpha": 1, "middle": 2}
    low_second = {"middle": 2, "alpha": 1, "zeta": 1}
    prune_counter_map(low_first, 1, prefer_high=False)
    prune_counter_map(low_second, 1, prefer_high=False)
    assert low_first == low_second == {"alpha": 1}


def test_stage1344_engine_extension_retention_ties_do_not_follow_insertion_order() -> None:
    def build_profile(order):
        return {
            "extension_baselines": {
                ext: {"files": 1, "updated": 1.0, "tags": {}}
                for ext in order
            }
        }

    # The production limit is intentionally used here so the regression proves
    # the real retention path, not a test-only patched constant.
    extension_names = [f"ext_{index:04d}" for index in range(513)]
    forward = build_profile(reversed(extension_names))
    reverse = build_profile(extension_names)

    prune_engine_profile_for_retention(forward)
    prune_engine_profile_for_retention(reverse)

    assert tuple(forward["extension_baselines"]) == tuple(reverse["extension_baselines"])
    assert "ext_0000" in forward["extension_baselines"]
    assert "ext_0512" not in forward["extension_baselines"]
