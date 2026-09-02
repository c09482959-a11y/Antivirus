from __future__ import annotations
from Virus_Scan.detection.scoring.adaptive.log_odds_probabilities import LogOddsFeatureProbabilitiesRequest
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.detection.scoring.adaptive.confidence import adaptive_learned_model_confidence
from Virus_Scan.detection.scoring.adaptive.log_odds_probabilities import log_odds_feature_probabilities


class HostileReason:
    def __init__(self, text: str):
        self.text = text
        self.bool_calls = 0
        self.str_calls = 0

    def __bool__(self):  # pragma: no cover - must not be invoked
        self.bool_calls += 1
        raise AssertionError("caller-owned adaptive reason truthiness was probed")

    def __str__(self):  # pragma: no cover - must not be invoked
        self.str_calls += 1
        raise AssertionError("caller-owned adaptive reason __str__ was probed")


class HostileFlag:
    def __init__(self):
        self.bool_calls = 0

    def __bool__(self):  # pragma: no cover - must not be invoked
        self.bool_calls += 1
        raise AssertionError("caller-owned readiness truthiness was probed")



def test_stage1506_adaptive_graph_reason_fallback_does_not_probe_truthiness():
    feature_reason = HostileReason("")
    layer_reason = HostileReason("graph_layer_unavailable")

    probs = log_odds_feature_probabilities(LogOddsFeatureProbabilitiesRequest(
        {
            "p_graph": 0.91,
            "p_graph_unavailable_reason": feature_reason,
        },
        profile_meta={},
        markov_meta={},
        cluster_meta={},
        bv_bucket={},
        bv_vector={},
        bv_timeline={},
        layer_probs={"graph_probability": 0.93, "graph_unavailable_reason": layer_reason},
    ))

    assert probs["p_graph"] == 0.0
    assert probs["p_graph_unavailable_reason"] == "unreadable_model_signal_reason"
    assert feature_reason.bool_calls == 0
    assert feature_reason.str_calls == 0
    assert layer_reason.bool_calls == 0
    assert layer_reason.str_calls == 0



def test_stage1506_adaptive_graph_chain_reason_does_not_probe_truthiness():
    chain_reason = HostileReason("")
    graph_reason = HostileReason("graph_probability_unavailable")

    probs = log_odds_feature_probabilities(LogOddsFeatureProbabilitiesRequest(
        {
            "p_graph_chain": 0.88,
            "p_chain_unavailable_reason": chain_reason,
            "p_graph_unavailable_reason": graph_reason,
        },
        profile_meta={},
        markov_meta={},
        cluster_meta={},
        bv_bucket={},
        bv_vector={},
        bv_timeline={},
        layer_probs={},
    ))

    assert probs["p_graph_chain"] == 0.0
    assert probs["p_graph_unavailable_reason"] == "unreadable_model_signal_reason"
    assert chain_reason.bool_calls == 0
    assert chain_reason.str_calls == 0
    assert graph_reason.bool_calls == 0
    assert graph_reason.str_calls == 0



def test_stage1506_adaptive_profile_ready_flag_is_strict_not_truthy():
    ready = HostileFlag()

    confidence = adaptive_learned_model_confidence(
        profile_signal={"profile_ready": ready, "profile_anomaly": 0.99},
        markov_signal={},
        cluster_signal={},
        vector_signal=0.0,
        bucket_signal=0.0,
    )

    assert confidence == 0.0
    assert ready.bool_calls == 0



def test_stage1506_repaired_adaptive_sources_do_not_contain_targeted_truthiness_chains():
    log_odds_source = read_python_file(Path("Virus_Scan/detection/scoring/adaptive/log_odds_probabilities.py"))
    confidence_source = read_python_file(Path("Virus_Scan/detection/scoring/adaptive/confidence.py"))

    forbidden_log_odds = (
        "feature_probs.get('p_graph_unavailable_reason') or layer_probs.get('graph_unavailable_reason')",
        "feature_probs.get('p_chain_unavailable_reason') or graph_unavailable_reason",
    )
    for snippet in forbidden_log_odds:
        assert snippet not in log_odds_source

    assert "profile_signal.get('profile_ready') and" not in confidence_source
