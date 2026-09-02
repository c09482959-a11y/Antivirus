from __future__ import annotations

import inspect

from Virus_Scan.models import clustering
from Virus_Scan.tests.support.clustering_v2 import seed_canonical_microcluster
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.graph_state import graph_vector_node_key, reset_graph_state, update_graph_node_owned
from Virus_Scan.tests.support.graph_corruption import remove_graph_node_fields_for_test


def _bind_cluster_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    return state


def _seed_cluster_with_missing_member_clock() -> str:
    state = _bind_cluster_state()
    node_key = graph_vector_node_key("stage1338_sample.exe")
    peer_key = graph_vector_node_key("stage1338_peer.exe")
    cid = "stage1338_cluster"
    seed_canonical_microcluster(
        state, cid, members=(node_key, peer_key), kind="malicious",
        tags=("process_injection",), malicious_ratio=1.0, confidence=0.75,
        trusted_sample_count=3, updated_ordinal=10, influence_enabled=True,
    )
    update_graph_node_owned(node_key, risk=80.0, tags={"process_injection"}, last_seen=10.0)
    update_graph_node_owned(peer_key, risk=65.0, tags={"network_exfiltration"}, last_seen=5.0)
    # Simulate an older/corrupt runtime graph snapshot where one member has no
    # timestamp.  Cluster readers must use recorded model state, not a fresh clock.
    remove_graph_node_fields_for_test(peer_key, "last_seen")
    return "stage1338_sample.exe"


def test_stage1338_cluster_risk_missing_member_clock_is_replay_stable() -> None:
    reset_graph_state()
    try:
        node = _seed_cluster_with_missing_member_clock()
        first = clustering.cluster_risk_score(node)
        second = clustering.cluster_risk_score(node)

        assert 0.0 < first <= 1.0
        assert second == first
    finally:
        reset_graph_state()


def test_stage1338_cluster_risk_score_does_not_call_live_clock() -> None:
    source = inspect.getsource(clustering.cluster_risk_score)
    module_source = inspect.getsource(clustering)

    assert "_cluster_now" not in source
    assert "time.time" not in source
    assert "time.time" not in module_source
    assert "import time" not in module_source
