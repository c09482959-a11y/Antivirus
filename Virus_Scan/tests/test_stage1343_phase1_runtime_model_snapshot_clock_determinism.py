from __future__ import annotations
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision

import inspect
from collections import Counter, defaultdict

from Virus_Scan.runtime.model_state import runtime_model_state_to_json
from Virus_Scan.models import markov
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    runtime_model_snapshot,
    runtime_transition_key_to_json,
)


def _reset_runtime_model_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )
    configure_runtime_cluster_state(RuntimeClusterState())


def test_stage1343_runtime_model_snapshot_default_updated_is_state_derived_and_repeatable() -> None:
    _reset_runtime_model_state()
    markov.update_markov_model("asset", ["download", "exec"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",)))

    first = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )
    second = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )

    assert first == second
    assert isinstance(first["updated"], int)
    assert first["updated"] > 0


def test_stage1343_runtime_model_snapshot_revision_changes_when_learned_state_changes() -> None:
    _reset_runtime_model_state()

    cold = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )
    markov.update_markov_model("asset", ["download", "exec"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",)))
    trained = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )

    assert trained["updated"] != cold["updated"]
    assert trained["transition_counts"]


def test_stage1343_runtime_model_state_to_json_no_longer_injects_live_clock() -> None:
    source = inspect.getsource(runtime_model_state_to_json)
    snapshot_signature = inspect.signature(runtime_model_snapshot)

    assert "time.time" not in source
    assert "now_func" not in source
    assert "now_func" not in snapshot_signature.parameters


def test_stage1343_core_runtime_model_state_to_json_is_repeatable_for_same_state() -> None:
    _reset_runtime_model_state()
    markov.update_markov_model("asset", ["download", "exec"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",)))

    first = runtime_model_state_to_json()
    second = runtime_model_state_to_json()

    assert first == second
    assert isinstance(first["updated"], int)
