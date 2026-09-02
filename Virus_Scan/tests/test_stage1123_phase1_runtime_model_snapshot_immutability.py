from Virus_Scan.tests.support.profile_learning import accepted_learning_decision
from collections import Counter, defaultdict
from types import MappingProxyType

import pytest

from Virus_Scan.models import markov
from Virus_Scan.contracts.markov_learning import (
    markov_event_transition_key,
    markov_global_context_key,
    markov_stage_transition_key,
)
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    runtime_model_mapping_snapshot,
    runtime_transition_counter_snapshot,
)


def _reset_state():
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_stage1123_runtime_model_snapshots_are_deeply_immutable():
    _reset_state()
    for _ in range(3):
        assert markov.update_markov_model("asset", ["download", "exec"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",), observation_id=f"stage1123-markov-{_}"))["learned"] is True

    snapshot = runtime_model_mapping_snapshot("TRANSITION_COUNTS")
    context = markov_global_context_key()
    sequence_key = markov_stage_transition_key(
        context_key=context, previous_stage="asset", behavior_flow=("download", "exec"),
    )
    pair_key = markov_event_transition_key(
        context_key=context, previous_stage="asset", source_event="download",
    )

    assert isinstance(snapshot, MappingProxyType)
    assert isinstance(snapshot[sequence_key], MappingProxyType)
    assert snapshot[sequence_key]["runtime"] == 3
    assert snapshot[pair_key]["exec"] == 3

    with pytest.raises(TypeError):
        snapshot[sequence_key] = {"runtime": 99}
    with pytest.raises(TypeError):
        snapshot[sequence_key]["runtime"] = 99

    fresh = runtime_model_mapping_snapshot("TRANSITION_COUNTS")
    assert fresh[sequence_key]["runtime"] == 3


def test_stage1123_runtime_transition_counter_snapshot_is_immutable_and_detached():
    _reset_state()
    markov.update_markov_model("asset", ["download", "exec"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",)))

    pair_key = markov_event_transition_key(
        context_key=markov_global_context_key(),
        previous_stage="asset",
        source_event="download",
    )
    counter = runtime_transition_counter_snapshot(pair_key)

    assert isinstance(counter, MappingProxyType)
    assert counter["exec"] == 1
    with pytest.raises(TypeError):
        counter["exec"] = 99

    markov.update_markov_model("asset", ["download", "exec"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",)))
    assert counter["exec"] == 1
    assert runtime_transition_counter_snapshot(pair_key)["exec"] == 2
