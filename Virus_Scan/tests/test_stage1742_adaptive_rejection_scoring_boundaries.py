from __future__ import annotations
from Virus_Scan.tests.support.adaptive_chain_fixtures import adaptive_chain_evidence_fixture
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.detection.scoring.adaptive.availability import (
    availability_aware_layer_probability_summary,
)
from Virus_Scan.detection.scoring.adaptive.confidence import (
    adaptive_learned_model_confidence,
    adaptive_normalized_weights,
)
from Virus_Scan.detection.scoring.adaptive.layer_weights import (
    distribute_static_learned_model_weights,
    learn_adaptive_layer_weights,
)
from Virus_Scan.detection.scoring.adaptive.log_odds_weights import (
    apply_log_odds_concrete_caps,
    derive_log_odds_weights,
    log_odds_active_layer_bonus,
    normalize_log_odds_weights,
)
from Virus_Scan.detection.scoring.adaptive.log_odds_probabilities import (
    log_odds_static_model_probabilities,
)
from Virus_Scan.detection.scoring.adaptive.log_odds_fusion import (
    calibrated_log_odds_score_100,
)
from Virus_Scan.detection.scoring.adaptive.model_caps import (
    hybrid_static_model_evidence_fusion,
)
from Virus_Scan.detection.scoring.adaptive.model_inputs import (
    graph_chain_probability_from_layer,
)


class HostileAdaptiveMapping(Mapping):
    touched = 0

    def __getitem__(self, key):  # pragma: no cover - failure proves hook use
        type(self).touched += 1
        raise AssertionError("caller-owned __getitem__ invoked")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __iter__ invoked")

    def __len__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __len__ invoked")

    def get(self, key, default=None):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned get invoked")


class HostileActiveLayerCount:
    touched = 0

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        return 3

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        return True


class HostileWeight:
    touched = 0

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned weight __float__ invoked")

    def __int__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned weight __int__ invoked")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned weight __bool__ invoked")


def _hostile() -> HostileAdaptiveMapping:
    HostileAdaptiveMapping.touched = 0
    return HostileAdaptiveMapping()


def test_stage1742_rejected_weights_remain_evidence_instead_of_normalizing() -> None:
    weights = adaptive_normalized_weights(_hostile())

    assert HostileAdaptiveMapping.touched == 0
    assert weights["adaptive_input_rejected"] is True
    assert weights["adaptive_input_reason"] == "adaptive_input_mapping_rejected"
    assert "quick_static" not in weights


def test_stage1742_rejected_base_weights_do_not_create_default_weight_distribution() -> None:
    weights = distribute_static_learned_model_weights(_hostile(), 0.7, 0.3)

    assert HostileAdaptiveMapping.touched == 0
    assert weights["adaptive_input_rejected"] is True
    assert "graph_relationships" not in weights


def test_stage1742_rejected_layers_have_zero_probability_and_explicit_evidence() -> None:
    summary = availability_aware_layer_probability_summary(_hostile())

    assert HostileAdaptiveMapping.touched == 0
    assert summary["quick_static_probability"] == 0.0
    assert summary["stage_probability"] == 0.0
    assert summary["graph_probability"] == 0.0
    assert summary["threat_intel_probability"] == 0.0
    assert summary["graph_unavailable_reason"] == "adaptive_input_mapping_rejected"
    assert summary["adaptive_input_failure"]["adaptive_input_rejected"] is True


def test_stage1742_layer_weight_learning_rejects_hostile_layer_without_hooks() -> None:
    weights, metadata = learn_adaptive_layer_weights(
        node=None,
        tags=(),
        
        quick=_hostile(),
        stage={},
        graph={},
        intel={},
    )

    assert HostileAdaptiveMapping.touched == 0
    assert abs(sum(weights.values()) - 1.0) < 1e-9
    assert metadata["layer_unavailable_reasons"]["quick_static"] == (
        "adaptive_input_mapping_rejected"
    )


def test_stage1742_rejected_adaptive_inputs_cannot_inflate_confidence_or_fusion() -> None:
    hostile = _hostile()

    confidence = adaptive_learned_model_confidence(
        profile_signal=hostile,
        markov_signal=hostile,
        cluster_signal=hostile,
    )
    fused = hybrid_static_model_evidence_fusion(hostile)

    assert HostileAdaptiveMapping.touched == 0
    assert confidence == 0.0
    assert fused == 0.0


def test_stage1742_graph_chain_rejects_hostile_mapping_before_get_hooks() -> None:
    probability, reason = graph_chain_probability_from_layer(_hostile())

    assert HostileAdaptiveMapping.touched == 0
    assert probability == 0.0
    assert reason == "adaptive_input_mapping_rejected"


def test_stage1742_hostile_active_layer_count_cannot_add_score_bonus() -> None:
    HostileActiveLayerCount.touched = 0
    hostile = HostileActiveLayerCount()

    assert log_odds_active_layer_bonus(hostile) == 0.0
    hostile_score, hostile_meta = calibrated_log_odds_score_100(
        0.0,
        chain_evidence=adaptive_chain_evidence_fixture(tags=None, api_calls=None, ordered_events=None),
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        active_layers=hostile,
    )
    baseline_score, baseline_meta = calibrated_log_odds_score_100(
        0.0,
        chain_evidence=adaptive_chain_evidence_fixture(tags=None, api_calls=None, ordered_events=None),
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        active_layers=0,
    )

    assert HostileActiveLayerCount.touched == 0
    assert hostile_score == baseline_score
    assert hostile_meta["layer_bonus"] == baseline_meta["layer_bonus"] == 0.0


def test_stage1742_rejected_weight_metadata_does_not_invoke_mapping_hooks() -> None:
    hostile = _hostile()

    static_weight, model_weight = derive_log_odds_weights(
        hostile,
        hostile,
        hostile,
        concrete_count=0,
        raw=0.0,
        layer_probs=hostile,
    )
    static_probability, model_probability, chain_probability = (
        log_odds_static_model_probabilities(0.0, hostile, hostile)
    )

    assert HostileAdaptiveMapping.touched == 0
    assert static_weight >= model_weight
    assert model_probability == 0.0
    assert static_probability == 0.0
    assert chain_probability == 0.0


def test_stage1742_log_odds_weight_helpers_reject_hostile_numeric_hooks() -> None:
    HostileWeight.touched = 0

    static_weight, model_weight = normalize_log_odds_weights(HostileWeight(), HostileWeight())
    capped_static, capped_model, caps = apply_log_odds_concrete_caps(
        HostileWeight(),
        HostileWeight(),
        concrete_count=0,
    )

    assert HostileWeight.touched == 0
    assert static_weight >= model_weight
    assert capped_static >= capped_model
    assert caps == ["model_weight_capped_no_concrete_evidence"]


def test_stage1742_log_odds_weight_source_removes_raw_safe_clamp_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/detection/scoring/adaptive/log_odds_weights.py"))
    tree = ast.parse(source)
    forbidden = (
        "static_weight = safe_clamp(static_weight, 0.2, 0.85)",
        "model_weight = safe_clamp(model_weight, 0.15, 0.8)",
        "static_weight = safe_clamp(1.0 - model_weight, 0.2, 0.85)",
    )
    assert [snippet for snippet in forbidden if snippet in source] == []
    assert [node for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []
