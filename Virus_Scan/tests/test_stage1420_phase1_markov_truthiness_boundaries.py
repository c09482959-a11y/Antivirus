from __future__ import annotations
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision

from collections.abc import Iterable, Mapping

from Virus_Scan.models.api import markov_contracts


class HostileIterable(Iterable):
    touched = 0

    def __iter__(self):  # pragma: no cover - validates no iteration probe
        type(self).touched += 1
        raise AssertionError("hostile iterable iteration")

    def __bool__(self):  # pragma: no cover - validates no truthiness probe
        type(self).touched += 1
        raise AssertionError("hostile iterable truthiness")


class HostileText:
    def __bool__(self):  # pragma: no cover - validates no truthiness probe
        raise RuntimeError("hostile text truthiness")

    def __str__(self):
        return "runtime"


def test_stage1420_markov_public_feature_api_does_not_probe_flow_truthiness() -> None:
    HostileIterable.touched = 0
    features = markov_contracts.compute_markov_features("asset", HostileIterable(), "runtime")

    assert isinstance(features, Mapping)
    assert tuple(features["flow"]) == ()
    assert features["ready"] is False
    assert features["reason"] == "insufficient_behavior_flow"
    assert HostileIterable.touched == 0


def test_stage1420_markov_probability_api_does_not_probe_flow_truthiness() -> None:
    HostileIterable.touched = 0
    probability = markov_contracts.markov_stage_probability("asset", HostileIterable(), "runtime")

    assert probability["probability"] is None
    assert tuple(probability["flow"]) == ()
    assert probability["reason"] == "insufficient_behavior_flow"
    assert HostileIterable.touched == 0


def test_stage1420_markov_update_api_does_not_probe_flow_or_stage_truthiness() -> None:
    HostileIterable.touched = 0
    record = markov_contracts.update_markov_model(HostileText(), HostileIterable(), HostileText(), learning_decision=accepted_learning_decision(target_names=("markov",)))

    assert record["learned"] is False
    assert tuple(record["flow"]) == ()
    assert record["model_name"] == "markov"
    assert record["reason"] == "insufficient_behavior_flow"
    assert HostileIterable.touched == 0
