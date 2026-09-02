from __future__ import annotations

import pytest

from Virus_Scan.models import graph
from Virus_Scan.models.api import graph_contracts


def test_stage1394_graph_public_contract_exposes_relationship_evidence_owner() -> None:
    assert "compute_graph_relationship_layer" in graph_contracts.__all__
    assert "get_graph_risk_enhanced" in graph_contracts.__all__
    assert graph_contracts.get_graph_risk_enhanced("stage1394-missing-node") == graph.get_graph_risk_enhanced("stage1394-missing-node")


def test_stage1394_graph_relationship_public_contract_is_immutable_and_deterministic() -> None:
    first = graph_contracts.compute_graph_relationship_layer(
        "stage1394-node",
        tags={"network_download", "process_exec"},
    )
    second = graph_contracts.compute_graph_relationship_layer(
        "stage1394-node",
        tags={"process_exec", "network_download"},
    )

    assert first == second
    assert first["summary"] == "relationships"
    with pytest.raises(TypeError):
        first["score"] = 99.0

    graph_features = first["graph_features"]
    with pytest.raises(TypeError):
        graph_features["risk"] = 99.0
