from Virus_Scan.models.clustering import adaptive_cluster_signal
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.tests.support.clustering_v2 import seed_canonical_microcluster


from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
def test_stage1140_adaptive_cluster_unassigned_node_is_explicit_cold_state():
    configure_runtime_cluster_state(RuntimeClusterState())

    signal = adaptive_cluster_signal("stage1140_unassigned_node", physical_tag_evidence(("process_exec",)))

    assert signal["cluster_signal"] == 0.0
    assert signal["cluster_signal_ready"] is False
    assert signal["cluster_unavailable_reason"] == "cluster_not_assigned"


def test_stage1140_adaptive_cluster_assigned_node_records_ready_signal():
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    seed_canonical_microcluster(
        state,
        "cluster_a",
        members=("stage1140_assigned_node", "peer"),
        tags=("process_exec", "network_download"),
        influence_enabled=True,
    )

    signal = adaptive_cluster_signal("stage1140_assigned_node", physical_tag_evidence(("process_exec", "network_download")))

    assert signal["cluster_signal"] > 0.0
    assert signal["cluster_signal_ready"] is True
    assert signal["cluster_unavailable_reason"] is None
