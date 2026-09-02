from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from types import MappingProxyType

from Virus_Scan.detection.scoring.adaptive.evidence_projection import build_probability_features
from Virus_Scan.models.api import adaptive_signals, graph_contracts
from Virus_Scan.models.clustering import api as clustering_api
from Virus_Scan.models.graph import api as graph_api
from Virus_Scan.models import temporal


def test_graph_risk_contract_exposes_unavailable_evidence_not_clean_zero():
    evidence = graph_contracts.get_graph_risk_enhanced_evidence("stage1455-missing-graph-node")

    assert isinstance(evidence, MappingProxyType)
    assert evidence["risk"] == 0.0
    assert evidence["ready"] is False
    assert evidence["degraded"] is True
    assert evidence["unavailable_reason"] == "graph_node_snapshot_unavailable"
    assert evidence["final_json_must_record"] is True
    assert "get_graph_risk_enhanced_evidence" in graph_contracts.__all__
    assert "get_graph_risk_enhanced_evidence" in graph_api.__all__


def test_adaptive_probability_features_record_graph_unavailable_reason():
    features = build_probability_features(
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
        tags=("stage1455_tag",),
        yara_hits=(),
        node="stage1455-missing-graph-node",
    )

    assert features["p_graph"] == 0.0
    assert features["p_graph_unavailable_reason"] is not None
    assert features["model_failure"] is None


def test_cluster_risk_contract_exposes_unavailable_evidence_not_clean_zero():
    evidence = adaptive_signals.cluster_risk_score_evidence("stage1455-unconfigured-cluster-node")

    assert isinstance(evidence, MappingProxyType)
    assert evidence["risk"] == 0.0
    assert evidence["ready"] is False
    assert evidence["degraded"] is True
    assert evidence["unavailable_reason"] in {"runtime_cluster_state_not_configured", "cluster_not_assigned"}
    assert evidence["final_json_must_record"] is True
    assert "cluster_risk_score_evidence" in adaptive_signals.__all__
    assert "cluster_risk_score_evidence" in clustering_api.__all__


def test_temporal_package_root_does_not_leak_cache_helper():
    assert "cache_key" not in temporal.__all__
    assert not hasattr(temporal, "cache_key")
