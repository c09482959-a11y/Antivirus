from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from contextlib import ExitStack, contextmanager
from unittest.mock import patch
import json
import math

from Virus_Scan.detection.scoring.adaptive import model_score
from Virus_Scan.detection.scoring.adaptive import evidence_projection


@contextmanager
def _patch_low_noise_dependencies():
    with ExitStack() as stack:
        stack.enter_context(patch.object(evidence_projection, "model_graph_risk_enhanced", lambda node: 0.0))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_temporal_snapshot",
            lambda node: {"ready": False, "belief": 0.0, "unavailable_reason": "temporal_not_ready"},
        ))
        stack.enter_context(patch.object(evidence_projection, "model_behavior_flow", lambda events: tuple(events or ())))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_markov_features",
            lambda prev_stage, behavior_flow, curr_stage: {
                "ready": False,
                "reason": "insufficient_markov_support",
                "transition": 0.0,
                "rarity": 0.0,
                "pair_anomaly": 0.0,
            },
        ))
        stack.enter_context(patch.object(
            evidence_projection,
            "infer_engine_context",
            lambda tags, *, file_structure=None, strings_blob="": {"other": 0.0},
        ))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_extension_profile_anomaly",
            lambda *args, **kwargs: {"anomaly": 0.0, "reason": "profile_not_ready"},
        ))
        stack.enter_context(patch.object(
            evidence_projection,
            "model_coordinated_validation_signal",
            lambda *args, **kwargs: {
                "bucket_validation": {"bucket_anomaly": 0.0, "reason": "bucket_not_ready"},
                "vector_validation": {"anomaly": 0.0, "reason": "vector_not_ready"},
            },
        ))
        yield


def test_stage1333_graph_chain_rejects_nonfinite_layer_score_even_with_hits():
    with _patch_low_noise_dependencies(), ExitStack() as stack:
        stack.enter_context(patch.object(
            evidence_projection,
            "model_graph_relationship_layer",
            lambda node, tags=None: {
                "score": float("nan"),
                "hits": ("graph_hit",),
                "propagated_chains": ("chain_hit",),
                "graph_unavailable_reason": None,
            },
        ))

        features = model_score.build_probability_features(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
            tags=["process_exec", "network_download"],
            yara_hits=[],
            node="stage1333-corrupt-graph-chain.exe",
            prev_stage="archive",
            curr_stage="runtime",
            ordered_events=["process_exec", "network_download"],
        )

        assert features["p_graph_chain"] == 0.0
        assert features["p_attention"] == 0.0
        assert features["p_graph_unavailable_reason"] == "non_finite_graph_chain_score"
        assert all(
            math.isfinite(float(value))
            for key, value in dict(features).items()
            if key.startswith("p_") and not key.endswith("_reason")
        )
        json.dumps(dict(features), allow_nan=False, sort_keys=True)


def test_stage1333_graph_chain_preserves_finite_relationship_score():
    with _patch_low_noise_dependencies(), ExitStack() as stack:
        stack.enter_context(patch.object(
            evidence_projection,
            "model_graph_relationship_layer",
            lambda node, tags=None: {
                "score": 40.0,
                "hits": ("graph_hit",),
                "propagated_chains": (),
                "graph_unavailable_reason": None,
            },
        ))

        features = model_score.build_probability_features(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
            tags=["process_exec", "network_download"],
            yara_hits=[],
            node="stage1333-ready-graph-chain.exe",
            prev_stage="archive",
            curr_stage="runtime",
            ordered_events=["process_exec", "network_download"],
        )

        assert features["p_graph_chain"] == 0.4
        assert features["p_attention"] == features["p_graph_chain"]
        assert features["p_graph_unavailable_reason"] is None
