from __future__ import annotations
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision

from collections import Counter, defaultdict

import pytest

from Virus_Scan.models import markov
from Virus_Scan.models.contracts.model_feature_bundle import materialize_model_feature_bundle
from Virus_Scan.runtime.model_state import configure_runtime_model_state


def _reset_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_markov_feature_bundle_is_immutable_and_detaches_flow() -> None:
    _reset_state()

    features = markov.compute_markov_features("asset", ["download", "exec"], "runtime")

    assert features["ready"] is False
    assert features["support"] == 0
    assert features["flow"] == ("download", "exec")
    assert features["model_version"] == "markov_feature_bundle_v3_contextual_dirichlet"
    with pytest.raises(TypeError):
        features["ready"] = True  # type: ignore[index]


def test_markov_feature_bundle_materialization_is_deterministic_and_detached() -> None:
    _reset_state()
    for _ in range(3):
        assert markov.update_markov_model("asset", ["download", "exec"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",), observation_id=f"stage1238-markov-{_}"))["learned"] is True

    features = markov.compute_markov_features("asset", ["download", "exec"], "runtime")
    first = materialize_model_feature_bundle(features)
    second = materialize_model_feature_bundle(features)

    assert first == second
    assert first["flow"] == ("download", "exec")
    assert first["model_version"] == "markov_feature_bundle_v3_contextual_dirichlet"
    first["ready"] = False
    assert features["ready"] is True


def test_markov_features_do_not_expose_mutable_caller_lists() -> None:
    _reset_state()
    events = ["download", "exec"]
    features = markov.compute_markov_features("asset", events, "runtime")
    events.append("mutated_after_call")

    assert features["flow"] == ("download", "exec")
