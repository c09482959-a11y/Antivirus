"""Stage 1376 Phase 1 runtime transition-key identity boundary repairs."""
from __future__ import annotations

from collections import Counter, defaultdict

from Virus_Scan.models import markov
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision
from Virus_Scan.runtime import model_state


def _configure_runtime_maps():
    transitions = defaultdict(Counter)
    model_state.configure_runtime_model_state(
        transition_counts=transitions,
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )
    return transitions


def test_stage1376_invalid_runtime_transition_counter_snapshot_omits_bad_key() -> None:
    transitions = _configure_runtime_maps()
    transitions[("", frozenset())]["runtime"] = 7

    snapshot = model_state.runtime_transition_counter_snapshot(("", frozenset()))

    assert dict(snapshot) == {}
    assert dict(model_state.runtime_model_mapping_snapshot("TRANSITION_COUNTS")) == {}


def test_stage1376_contextual_markov_owner_rejects_invalid_request_atomically() -> None:
    transitions = _configure_runtime_maps()
    result = markov.update_markov_model(
        "", ("download", "exec"), "runtime",
        learning_decision=accepted_learning_decision(
            target_names=("markov",), observation_id="stage1376",
        ),
    )

    assert result["learned"] is False
    assert result["reason"] == "markov_stage_unavailable"
    assert dict(transitions) == {}
