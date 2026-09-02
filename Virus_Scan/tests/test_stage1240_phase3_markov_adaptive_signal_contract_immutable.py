from __future__ import annotations
from Virus_Scan.detection.scoring.adaptive.log_odds_probabilities import LogOddsFeatureProbabilitiesRequest

from collections import Counter, defaultdict
from types import MappingProxyType

import pytest

from Virus_Scan.detection.scoring.adaptive.model_score import log_odds_feature_probabilities
from Virus_Scan.models import markov
from Virus_Scan.models.contracts.model_feature_bundle import materialize_model_feature_bundle
from Virus_Scan.runtime.model_state import configure_runtime_model_state


def _reset_markov_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_stage1240_adaptive_markov_signal_is_immutable_and_deterministic() -> None:
    _reset_markov_state()

    signal = markov.adaptive_markov_signal("asset", "runtime", ["download", "exec"])

    assert signal["model_version"] == "markov_adaptive_signal_v2_contextual_dirichlet"
    assert signal["source_model_version"] == "markov_feature_bundle_v3_contextual_dirichlet"
    assert signal["markov_ready"] is False
    assert signal["markov_unavailable_reason"] == "insufficient_markov_stage_support"
    assert signal["markov_anomaly"] == 0.0
    with pytest.raises(TypeError):
        signal["markov_anomaly"] = 1.0

    assert materialize_model_feature_bundle(signal) == materialize_model_feature_bundle(signal)


def test_stage1240_adaptive_markov_signal_detaches_caller_owned_flow() -> None:
    _reset_markov_state()
    events = ["download", "exec"]

    signal = markov.adaptive_markov_signal("asset", "runtime", events)
    events.append("network")

    assert signal["markov_unavailable_reason"] == "insufficient_markov_stage_support"
    assert signal["markov_support"] == 0
    assert signal["markov_anomaly"] == 0.0


def test_stage1240_log_odds_model_probability_consumes_immutable_markov_meta() -> None:
    probs = log_odds_feature_probabilities(LogOddsFeatureProbabilitiesRequest(
        {"p_markov": 0.05},
        profile_meta={},
        markov_meta=MappingProxyType(
            {
                "markov_anomaly": 0.62,
                "markov_ready": True,
                "markov_unavailable_reason": None,
            }
        ),
        cluster_meta={},
        bv_bucket={},
        bv_vector={},
        bv_timeline={},
        layer_probs={},
    ))

    assert probs["p_markov"] == 0.62


def test_stage1240_log_odds_unavailable_reason_accepts_immutable_markov_meta() -> None:
    probs = log_odds_feature_probabilities(LogOddsFeatureProbabilitiesRequest(
        {},
        profile_meta={},
        markov_meta=MappingProxyType(
            {
                "markov_anomaly": 0.0,
                "markov_ready": False,
                "markov_unavailable_reason": "markov_signal_failed",
            }
        ),
        cluster_meta={},
        bv_bucket={},
        bv_vector={},
        bv_timeline={},
        layer_probs={},
    ))

    assert probs["p_markov"] == 0.0
    assert probs["p_markov_unavailable_reason"] == "markov_signal_failed"
