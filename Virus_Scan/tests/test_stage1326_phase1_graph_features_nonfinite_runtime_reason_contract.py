from __future__ import annotations

from collections.abc import Mapping
import json
import math

from Virus_Scan.models.graph import compute_graph_relationship_layer, get_graph_features
from Virus_Scan.runtime.graph_state import (
    add_graph_edge_owned,
    reset_graph_state,
    update_graph_node_owned,
)
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def _materialize(value):
    if isinstance(value, Mapping):
        return {str(k): _materialize(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset, tuple, list)):
        return [_materialize(v) for v in value]
    return value


def test_stage1326_graph_features_preserve_nonfinite_risk_unavailable_reason() -> None:
    reset_graph_state()
    update_graph_node_owned("node:graph-risk", risk=math.inf)

    features = get_graph_features("node:graph-risk")

    assert features["graph_features_ready"] is False
    assert features["graph_unavailable_reason"] == "non_finite_graph_risk"
    assert features["risk"] == 0.0
    json.dumps(_materialize(features), allow_nan=False, sort_keys=True)


def test_stage1326_graph_features_preserve_nonfinite_attention_unavailable_reason() -> None:
    reset_graph_state()
    update_graph_node_owned("node:graph-attention", attention=math.nan)

    features = get_graph_features("node:graph-attention")

    assert features["graph_features_ready"] is False
    assert features["graph_unavailable_reason"] == "non_finite_graph_attention"
    assert features["risk"] == 0.0
    json.dumps(_materialize(features), allow_nan=False, sort_keys=True)


def test_stage1326_graph_relationship_layer_preserves_nonfinite_weight_unavailable_reason() -> None:
    reset_graph_state()
    add_graph_edge_owned("node:graph-weight", "tag:execution", edge_type="tag", weight=math.inf)

    evidence = compute_graph_relationship_layer("node:graph-weight", tags=physical_tag_evidence(("execution", "credential_access")))

    assert evidence["graph_relationship_ready"] is False
    assert evidence["graph_unavailable_reason"] == "non_finite_graph_weight"
    assert evidence["graph_features"]["graph_features_ready"] is False
    assert evidence["graph_features"]["risk"] == 0.0
    json.dumps(_materialize(evidence), allow_nan=False, sort_keys=True)
