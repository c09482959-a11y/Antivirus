from __future__ import annotations

from Virus_Scan.models import clustering
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.graph_state import graph_vector_node_key
from Virus_Scan.tests.support.clustering_v2 import seed_canonical_microcluster


from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
def _bind_cluster_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    return state


def test_stage1334_feature_vector_cluster_size_uses_all_kind_stores_and_runtime_key() -> None:
    state = _bind_cluster_state()
    raw_node = " node.exe "
    node_key = graph_vector_node_key(raw_node)
    state.node_cluster_map[node_key] = "cluster_all_kinds"
    state.malicious_clusters["cluster_all_kinds"].add("malicious.exe")
    state.benign_clusters["cluster_all_kinds"].add("benign.png")
    state.mixed_clusters["cluster_all_kinds"].add("mixed.asset")
    state.cluster_metadata["cluster_all_kinds"] = {
        "kind": "mixed",
        "members": {"metadata.bin"},
        "tag_signature": {"process_exec"},
    }

    vector = clustering.build_feature_vector(
        raw_node,
        tags=physical_tag_evidence(("process_exec",)),
        graph_features={},
        temporal_features={},
        markov_features={},
        engine_context={"unknown": 1.0},
    )

    cluster_size_index = clustering.VECTOR_FEATURE_NAMES.index("cluster_size")
    assert vector[cluster_size_index] == 4.0 / 20.0


def test_stage1334_adaptive_cluster_signal_reads_runtime_vector_key() -> None:
    state = _bind_cluster_state()
    raw_node = " assigned.node "
    node_key = graph_vector_node_key(raw_node)
    seed_canonical_microcluster(
        state,
        "cluster_runtime_key",
        members=(node_key, "peer"),
        tags=("process_exec", "network_download"),
        influence_enabled=True,
    )

    signal = clustering.adaptive_cluster_signal(raw_node, physical_tag_evidence(("process_exec", "network_download")))

    assert signal["cluster_signal_ready"] is True
    assert signal["cluster_unavailable_reason"] is None
    assert signal["cluster_members"] == 2
    assert signal["cluster_signal"] > 0.0
