"""Stage1986 clustering numeric/evidence boundary regressions."""
from __future__ import annotations

from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from pathlib import Path

from Virus_Scan.models import clustering
from Virus_Scan.tests.support.clustering_v2 import seed_canonical_microcluster
from Virus_Scan.models.clustering.anomaly import (
    cluster_anomaly_boost_evidence,
    cluster_detection_boost_evidence,
)
from Virus_Scan.models.clustering.assignment_decision import deterministic_cluster_id
from Virus_Scan.models.clustering.feature_registry import RAW_FEATURE_COUNT
from Virus_Scan.models.clustering.normalization import normalize_cluster_vector
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.graph_state import graph_vector_node_key, reset_graph_state, update_graph_node_owned


def _source(relative: str) -> str:
    return Path(relative).read_text(encoding="utf-8")


def _bind_cluster_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    return state


def _seed_anomaly_cluster(state: RuntimeClusterState, raw_node: str) -> tuple[str, str]:
    node_key = graph_vector_node_key(raw_node)
    peer_key = "stage1986_peer.exe"
    cluster_id = "stage1986_cluster"
    snapshot = seed_canonical_microcluster(
        state, cluster_id, members=(node_key, peer_key), kind="malicious",
        confidence=0.8, malicious_ratio=1.0, tags=("process_injection",),
        trusted_sample_count=3, influence_enabled=True,
    )
    vector = list(snapshot["centroid_vector"])
    vector[3] = 0.0 if vector[3] > 0.0 else 1.0
    state.node_feature_vectors[node_key] = vector
    update_graph_node_owned(node_key, risk=80.0, tags={"process_injection"})
    update_graph_node_owned(peer_key, risk=70.0, tags={"network_exfiltration"})
    return node_key, cluster_id


def test_stage1986_cluster_anomaly_unavailable_path_is_explicit_evidence() -> None:
    _bind_cluster_state()

    evidence = cluster_anomaly_boost_evidence("stage1986_unassigned.exe")
    detection = cluster_detection_boost_evidence("stage1986_unassigned.exe")

    assert evidence["cluster_anomaly_boost"] == 0.0
    assert evidence["cluster_anomaly_ready"] is False
    assert evidence["cluster_unavailable_reason"] == "cluster_not_assigned"
    assert detection["cluster_detection_boost"] == 0.0
    assert detection["cluster_unavailable_reason"] == "cluster_not_assigned"


def test_stage1986_cluster_anomaly_ready_path_preserves_primitive_boosts() -> None:
    reset_graph_state()
    try:
        state = _bind_cluster_state()
        raw_node = "  stage1986_sample.exe  "
        _node_key, cluster_id = _seed_anomaly_cluster(state, raw_node)

        evidence = cluster_anomaly_boost_evidence(raw_node)
        detection = cluster_detection_boost_evidence(raw_node)

        assert evidence["cluster_id"] == cluster_id
        assert evidence["cluster_anomaly_ready"] is True
        assert evidence["cluster_anomaly_boost"] > 0.0
        assert clustering.cluster_anomaly_boost(raw_node) == evidence["cluster_anomaly_boost"]
        assert detection["cluster_detection_boost"] > 0.0
        assert clustering.cluster_detection_boost(raw_node) == detection["cluster_detection_boost"]
    finally:
        reset_graph_state()


def test_stage1986_cluster_assignment_ids_are_content_derived_and_collision_bounded() -> None:
    state = _bind_cluster_state()
    normalized = normalize_cluster_vector([0.0] * RAW_FEATURE_COUNT)
    assert normalized.available is True

    first = deterministic_cluster_id("unity_exe_cluster_", normalized, "benign")
    assert first == deterministic_cluster_id("unity_exe_cluster_", normalized, "benign")
    assert first.startswith("unity_exe_cluster_")
    assert first.endswith("_1")

    state.cluster_metadata[first] = object()
    second = deterministic_cluster_id("unity_exe_cluster_", normalized, "benign")
    assert second.endswith("_2")


def test_stage1986_repaired_clustering_sources_do_not_restore_numeric_hazards() -> None:
    anomaly_source = _source("Virus_Scan/models/clustering/anomaly.py")
    assignment_source = _source("Virus_Scan/models/clustering/assignment.py")
    centroid_source = _source("Virus_Scan/models/clustering/centroid.py")

    assert "log_error(f'adaptive cluster signal failed:" not in anomaly_source
    assert "except RECOVERABLE_RUNTIME_ERRORS:\n        return 0.0" not in anomaly_source
    assert "return safe_clamp(cluster_risk_score(node) * 0.75 + cluster_anomaly_boost(node) * 0.25)" not in anomaly_source
    assert "list(cluster_signatures().items())" not in assignment_source
    assert "cid = f'{prefix}{count + 1}'" not in assignment_source
    assert "safe_clamp(1.0 / min(10.0, samples + 1.0), 0.1, 0.35)" not in centroid_source


def test_stage1986_context_quality_explain_and_prefix_preserve_owned_outputs() -> None:
    reset_graph_state()
    try:
        state = _bind_cluster_state()
        raw_node = "  stage1986_context.exe  "
        _node_key, cluster_id = _seed_anomaly_cluster(state, raw_node)
        adaptive_learning = {"cluster": {"cluster_id": cluster_id, "cluster_members": 3}}

        quality = clustering.context_cluster_quality(raw_node, physical_tag_evidence(("process_injection",)), adaptive_learning)
        explanation = clustering.explain_cluster(raw_node)

        assert quality["eligible"] is True
        assert quality["cluster_quality"] > 0.0
        assert quality["cluster_tag_overlap"] > 0.0
        assert explanation["confidence"] == 0.8
        assert explanation["malicious_ratio"] == 1.0
    finally:
        reset_graph_state()


def test_stage1986_repaired_followup_sources_do_not_restore_text_numeric_hazards() -> None:
    common_source = _source("Virus_Scan/models/clustering/common.py")
    context_source = _source("Virus_Scan/models/clustering/context.py")
    explain_source = _source("Virus_Scan/models/clustering/explain.py")
    graph_context_source = _source("Virus_Scan/models/clustering/graph_context.py")
    metadata_source = _source("Virus_Scan/models/clustering/metadata.py")

    assert "context.items()" not in common_source
    assert "safe_clamp(member_count / max" not in context_source
    assert "quality = safe_clamp(overlap * 0.7 + maturity * 0.3)" not in context_source
    assert "bool(eligible)" not in context_source
    assert "log_error(f'context cluster quality failed:" not in context_source
    assert "safe_clamp(finite_cluster_metric(meta.get('confidence'" not in explain_source
    assert "safe_clamp(finite_cluster_metric(meta.get('malicious_ratio'" not in explain_source
    assert "key_text = f'cluster_graph_mapping_key_{index}'" not in graph_context_source
    assert "key_text = f'{key_text}#{index}'" not in graph_context_source
    assert "for key, value in materialized.items()" not in graph_context_source
    assert "return f'{engine}_{ext}_cluster_'" not in metadata_source
