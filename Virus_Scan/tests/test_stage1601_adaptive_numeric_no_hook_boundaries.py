"""Stage1601 continuation: adaptive numeric probability boundaries are no-hook."""
from __future__ import annotations
from Virus_Scan.detection.scoring.adaptive.log_odds_probabilities import LogOddsFeatureProbabilitiesRequest

from Virus_Scan.detection.scoring.adaptive.confidence import (
    coerce_model_probability,
    coerce_scaled_model_probability,
    finite_engine_context,
    max_model_probability,
)
from Virus_Scan.detection.scoring.adaptive.log_odds_probabilities import (
    log_odds_feature_probabilities,
    log_odds_static_model_probabilities,
)
from Virus_Scan.detection.scoring.adaptive.model_inputs import graph_chain_probability_from_layer


class HostileNumber:
    touched = 0

    def __float__(self):  # pragma: no cover - failure proves unsafe numeric hook ran
        type(self).touched += 1
        raise AssertionError("caller-owned __float__ invoked")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __repr__ invoked")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ invoked")


class HostileEngineKey:
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned engine key __str__ invoked")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned engine key __repr__ invoked")


class HostileDict(dict):
    touched = 0

    def get(self, key, default=None):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned mapping get invoked")

    def items(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned mapping items invoked")

    def keys(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned mapping keys invoked")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned mapping iter invoked")


def _reset() -> None:
    HostileNumber.touched = 0
    HostileEngineKey.touched = 0
    HostileDict.touched = 0


def test_adaptive_probability_numeric_helpers_reject_hostile_float_without_hooks() -> None:
    _reset()
    value = HostileNumber()

    assert coerce_model_probability(value, "unsafe_probability") == (0.0, "unsafe_probability")
    assert coerce_scaled_model_probability(value, 10.0, "unsafe_scaled_probability") == (
        0.0,
        "unsafe_scaled_probability",
    )
    assert max_model_probability((0.25, value), "unsafe_max_probability") == (
        0.25,
        "unsafe_max_probability",
    )
    assert HostileNumber.touched == 0


def test_finite_engine_context_rejects_hostile_numeric_and_key_without_hooks() -> None:
    _reset()
    result, reason = finite_engine_context({HostileEngineKey(): HostileNumber(), "safe": 0.5})

    assert result == {"safe": 0.5}
    assert reason == "nonfinite_engine_context_probability"
    assert HostileNumber.touched == 0
    assert HostileEngineKey.touched == 0


def test_graph_chain_probability_rejects_hostile_score_without_float_hook() -> None:
    _reset()
    probability, reason = graph_chain_probability_from_layer(
        {
            "score": HostileNumber(),
            "hits": ("graph_hit",),
            "propagated_chains": (),
            "graph_unavailable_reason": None,
        }
    )

    assert probability == 0.0
    assert reason == "non_numeric_graph_chain_score"
    assert HostileNumber.touched == 0


def test_log_odds_probabilities_reject_hostile_mapping_get_and_numeric_hooks() -> None:
    _reset()
    hostile_mapping = HostileDict({"p_yara": 0.95, "graph_probability": 0.8})
    feature_result = log_odds_feature_probabilities(LogOddsFeatureProbabilitiesRequest(
        hostile_mapping,
        hostile_mapping,
        hostile_mapping,
        hostile_mapping,
        hostile_mapping,
        hostile_mapping,
        hostile_mapping,
        hostile_mapping,
    ))
    static_result = log_odds_static_model_probabilities(
        HostileNumber(),
        {"quick_static_probability": HostileNumber()},
        {"p_yara": HostileNumber(), "p_behavior": HostileNumber()},
    )

    assert feature_result["p_yara"] == 0.0
    assert feature_result["p_graph"] == 0.0
    assert static_result == (0.0, 0.0, 0.0)
    assert HostileDict.touched == 0
    assert HostileNumber.touched == 0
