from __future__ import annotations

from collections.abc import Mapping
import json
import math

from Virus_Scan.runtime.graph_state import (
    add_graph_edge_owned,
    graph_node_snapshot,
    graph_snapshot,
    prune_graph_owned,
    reset_graph_state,
    update_graph_node_owned,
)


def _materialize(value):
    if isinstance(value, Mapping):
        return {str(k): _materialize(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset, tuple, list)):
        return [_materialize(v) for v in value]
    return value


def test_stage1315_graph_node_snapshot_sanitizes_nonfinite_public_model_scalars() -> None:
    reset_graph_state()
    add_graph_edge_owned("node:nonfinite", "tag:execution", edge_type="tag", weight=math.inf)
    update_graph_node_owned("node:nonfinite", risk=math.nan, attention=-math.inf)

    snapshot = graph_node_snapshot("node:nonfinite")

    assert snapshot is not None
    assert snapshot["risk"] == 0.0
    assert snapshot["attention"] == 0.0
    assert snapshot["weights"]["tag:execution"] == 1.0
    assert snapshot["risk_unavailable_reason"] == "non_finite_graph_risk"
    assert snapshot["attention_unavailable_reason"] == "non_finite_graph_attention"
    assert snapshot["weight_unavailable_reasons"]["tag:execution"] == "non_finite_graph_weight"
    json.dumps(_materialize(snapshot), allow_nan=False, sort_keys=True)


def test_stage1315_graph_pruning_does_not_rank_nonfinite_weight_above_valid_weight() -> None:
    reset_graph_state()
    add_graph_edge_owned("node:rank", "tag:corrupt", edge_type="tag", weight=math.inf)
    add_graph_edge_owned("node:rank", "tag:valid", edge_type="tag", weight=2.0)

    prune_graph_owned(max_nodes=10, max_edges_per_node=1)

    snapshot = graph_node_snapshot("node:rank")
    assert snapshot is not None
    assert snapshot["edges"] == frozenset({"tag:valid"})
    assert snapshot["weights"]["tag:valid"] == 2.0


def test_stage1315_graph_full_snapshot_materializes_nested_nonfinite_metadata_as_evidence() -> None:
    reset_graph_state()
    update_graph_node_owned(
        "node:metadata",
        metadata={"nested": [math.nan, {"score": math.inf}]},
    )

    snapshot = graph_snapshot()["node:metadata"]
    materialized = _materialize(snapshot)

    assert materialized["metadata"]["nested"][0]["non_finite_float"] == "nan"
    assert materialized["metadata"]["nested"][1]["score"]["non_finite_float"] == "inf"
    json.dumps(materialized, allow_nan=False, sort_keys=True)
