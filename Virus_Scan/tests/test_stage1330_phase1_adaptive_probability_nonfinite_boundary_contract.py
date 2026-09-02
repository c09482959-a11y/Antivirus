from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from contextlib import ExitStack
from unittest.mock import patch
import json
import math

from Virus_Scan.detection.scoring.adaptive import model_score
from Virus_Scan.detection.scoring.adaptive import evidence_projection


def test_stage1330_adaptive_probability_features_reject_nonfinite_upstream_model_values():
    with ExitStack() as stack:
        stack.enter_context(patch.object(evidence_projection, "model_graph_risk_enhanced", lambda node: float("inf")))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_graph_relationship_layer",
            lambda node, tags=None: {
                "score": 0.0,
                "hits": (),
                "propagated_chains": (),
                "graph_unavailable_reason": None,
            },
        ))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_temporal_snapshot",
            lambda node: {"ready": True, "belief": float("nan")},
        ))
        stack.enter_context(patch.object(evidence_projection, "model_behavior_flow", lambda events: tuple(events or ())))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_markov_features",
            lambda prev_stage, behavior_flow, curr_stage: {
                "ready": True,
                "transition": float("nan"),
                "rarity": float("inf"),
                "pair_anomaly": "not-a-number",
            },
        ))
        stack.enter_context(patch.object(
            evidence_projection,
            "infer_engine_context",
            lambda tags, *, file_structure=None, strings_blob="": {
                "unity": float("inf"),
                "renpy": 0.8,
                "rpgm": float("nan"),
            },
        ))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_extension_profile_anomaly",
            lambda *args, **kwargs: {"anomaly": float("inf"), "reason": None},
        ))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_coordinated_validation_signal",
            lambda *args, **kwargs: {
                "bucket_validation": {"bucket_anomaly": float("nan")},
                "vector_validation": {"anomaly": float("inf")},
            },
        ))

        features = model_score.build_probability_features(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
            tags=["process_exec"],
            yara_hits=[],
            node="stage1330-node.exe",
            prev_stage="archive",
            curr_stage="runtime",
            ordered_events=["process_exec"],
        )

        assert features["p_graph"] == 0.0
        assert features["p_graph_unavailable_reason"] == "non_finite_graph_probability"
        assert features["p_temporal"] == 0.0
        assert features["p_temporal_unavailable_reason"] == "non_finite_temporal_probability"
        assert features["p_markov"] == 0.0
        assert features["p_markov_unavailable_reason"] == "non_finite_markov_probability"
        assert features["p_engine"] == 0.0
        assert features["p_engine_unavailable_reason"] == "nonfinite_engine_context_probability"
        assert features["p_profile"] == 0.0
        assert features["p_profile_unavailable_reason"] == "non_finite_profile_probability"
        assert features["p_bucket"] == 0.0
        assert features["p_bucket_unavailable_reason"] == "non_finite_bucket_probability"
        assert features["p_vector"] == 0.0
        assert features["p_vector_unavailable_reason"] == "non_finite_vector_probability"
        assert all(
            math.isfinite(float(value))
            for key, value in dict(features).items()
            if key.startswith("p_") and not key.endswith("_reason")
        )
        json.dumps(dict(features), allow_nan=False, sort_keys=True)


def test_stage1330_adaptive_probability_features_preserve_finite_upstream_model_values():
    with ExitStack() as stack:
        stack.enter_context(patch.object(evidence_projection, "model_graph_risk_enhanced", lambda node: 5.0))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_graph_relationship_layer",
            lambda node, tags=None: {
                "score": 50.0,
                "hits": ("graph_hit",),
                "propagated_chains": (),
                "graph_unavailable_reason": None,
            },
        ))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_temporal_snapshot",
            lambda node: {"ready": True, "belief": 0.4},
        ))
        stack.enter_context(patch.object(evidence_projection, "model_behavior_flow", lambda events: tuple(events or ())))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_markov_features",
            lambda prev_stage, behavior_flow, curr_stage: {
                "ready": True,
                "transition": 0.2,
                "rarity": 0.3,
                "pair_anomaly": 0.1,
            },
        ))
        stack.enter_context(patch.object(
            evidence_projection,
            "infer_engine_context",
            lambda tags, *, file_structure=None, strings_blob="": {"unity": 0.7, "renpy": 0.2},
        ))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_extension_profile_anomaly",
            lambda *args, **kwargs: {"anomaly": 0.25, "reason": None},
        ))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_coordinated_validation_signal",
            lambda *args, **kwargs: {
                "bucket_validation": {"bucket_anomaly": 0.35},
                "vector_validation": {"anomaly": 0.45},
            },
        ))

        features = model_score.build_probability_features(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
            tags=["process_exec"],
            yara_hits=[],
            node="stage1330-finite.exe",
            prev_stage="archive",
            curr_stage="runtime",
            ordered_events=["process_exec"],
        )

        assert features["p_graph"] == 0.5
        assert features["p_temporal"] == 0.4
        assert features["p_markov"] == 0.3
        assert features["p_engine"] == 0.7
        assert features["p_profile"] == 0.25
        assert features["p_bucket"] == 0.35
        assert features["p_vector"] == 0.45
        assert features["p_graph_unavailable_reason"] is None
        assert features["p_temporal_unavailable_reason"] is None
        assert features["p_markov_unavailable_reason"] is None
        json.dumps(dict(features), allow_nan=False, sort_keys=True)
