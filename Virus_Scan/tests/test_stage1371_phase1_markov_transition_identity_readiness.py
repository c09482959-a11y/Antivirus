"""Stage 1371 Phase 1 Markov transition identity readiness validation."""
from __future__ import annotations

from collections import Counter, defaultdict

from Virus_Scan.models import markov
from Virus_Scan.contracts.markov_learning import (
    markov_context_support_key,
    markov_event_transition_key,
    markov_global_context_key,
)
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    runtime_markov_observation_total,
    runtime_model_mapping_snapshot,
)


def _configure(transitions: defaultdict[object, Counter[str]]) -> None:
    configure_runtime_model_state(
        transition_counts=transitions,
        global_tag_baseline={},
        global_tag_pair_baseline={},
        filetype_baseline={},
    )


def test_stage1371_invalid_transition_namespace_does_not_inflate_markov_readiness() -> None:
    transitions: defaultdict[object, Counter[str]] = defaultdict(Counter)
    transitions[("invalid_transition_namespace", ())]["runtime"] = 5
    _configure(transitions)

    features = markov.compute_markov_features("asset", ["download", "exec"], "runtime")

    assert runtime_markov_observation_total() == 0
    assert features["ready"] is False
    assert features["reason"] == "insufficient_markov_stage_support"
    assert features["supported_transitions"] == 0
    assert features["support"] == 0


def test_stage1371_transition_mapping_snapshot_omits_noncanonical_transition_keys() -> None:
    transitions: defaultdict[object, Counter[str]] = defaultdict(Counter)
    context = markov_global_context_key()
    event_key = markov_event_transition_key(
        context_key=context,
        previous_stage="asset",
        source_event="download",
    )
    support_key = markov_context_support_key(context)
    transitions[("invalid_transition_namespace", frozenset())]["exec"] = 3
    transitions[event_key]["exec"] = 2
    transitions[support_key]["observations"] = 4
    _configure(transitions)

    snapshot = runtime_model_mapping_snapshot("TRANSITION_COUNTS")

    assert ("invalid_transition_namespace", frozenset()) not in snapshot
    assert snapshot[event_key]["exec"] == 2
    assert snapshot[support_key]["observations"] == 4
    assert runtime_markov_observation_total() == 4
