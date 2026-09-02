from __future__ import annotations
from contextlib import ExitStack
from unittest.mock import patch


from collections.abc import Mapping
import json
import math

import Virus_Scan.models.graph as graph_model
from Virus_Scan.models.graph import relationships as graph_relationships


from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
def _materialize(value):
    if isinstance(value, Mapping):
        return {str(k): _materialize(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset, tuple, list)):
        return [_materialize(v) for v in value]
    return value


def test_stage1332_graph_relationship_layer_projects_nonfinite_feature_scores() -> None:
    node_evidence = physical_tag_evidence(("execution",), source_detector="stage1332-node-corrupt")
    with ExitStack() as stack:
        stack.enter_context(patch.object(
            graph_relationships,
            "get_graph_node",
            lambda node: {"edges": {"edge:one"}, "tags": {"execution"}, "tag_evidence_records": node_evidence.records, "weights": {}, "types": {}},
        ))
        stack.enter_context(patch.object(
            graph_relationships,
            "get_graph_features",
            lambda node: {
                "risk": math.nan,
                "base_risk": math.inf,
                "anomaly": -math.inf,
                "graph_features_ready": True,
                "graph_unavailable_reason": None,
            },
        ))
        stack.enter_context(patch.object(
            graph_relationships,
            "propagate_behavior_chains_from_node",
            lambda node, max_depth=3: (
                math.inf,
                [{"chain": "execution", "score": math.nan, "nested": {"weight": math.inf}}],
            ),
        ))

        evidence = graph_model.compute_graph_relationship_layer(
            "node:corrupt-graph-score",
            tags=physical_tag_evidence(("execution", "credential_access")),
        )

        assert evidence["score"] == 0.5
        assert evidence["graph_relationship_ready"] is False
        assert evidence["graph_unavailable_reason"] == "non_finite_graph_relationship_metric"
        assert evidence["graph_features"]["risk"] == 0.0
        assert evidence["graph_features"]["base_risk"] == 0.0
        assert evidence["graph_features"]["anomaly"] == 0.0
        assert evidence["propagated_chains"][0]["score"] is None
        assert evidence["propagated_chains"][0]["score_unavailable_reason"] == "non_finite_graph_relationship_metric"
        assert evidence["propagated_chains"][0]["nested"]["weight"] is None
        json.dumps(_materialize(evidence), allow_nan=False, sort_keys=True)


def test_stage1332_graph_relationship_layer_preserves_valid_finite_feature_scores() -> None:
    node_evidence = physical_tag_evidence(("execution",), source_detector="stage1332-node-finite")
    with ExitStack() as stack:
        stack.enter_context(patch.object(
            graph_relationships,
            "get_graph_node",
            lambda node: {"edges": {"edge:one", "edge:two"}, "tags": {"execution"}, "tag_evidence_records": node_evidence.records, "weights": {}, "types": {}},
        ))
        stack.enter_context(patch.object(
            graph_relationships,
            "get_graph_features",
            lambda node: {
                "risk": 0.5,
                "base_risk": 0.25,
                "anomaly": 0.125,
                "graph_features_ready": True,
                "graph_unavailable_reason": None,
            },
        ))
        stack.enter_context(patch.object(
            graph_relationships,
            "propagate_behavior_chains_from_node",
            lambda node, max_depth=3: (4.0, [{"chain": "execution", "score": 4.0}]),
        ))

        evidence = graph_model.compute_graph_relationship_layer(
            "node:finite-graph-score",
            tags=physical_tag_evidence(("execution", "credential_access")),
        )

        assert evidence["graph_relationship_ready"] is True
        assert evidence["graph_unavailable_reason"] is None
        assert evidence["score"] > 0.0
        assert evidence["propagated_chains"][0]["score"] == 4.0
        json.dumps(_materialize(evidence), allow_nan=False, sort_keys=True)
