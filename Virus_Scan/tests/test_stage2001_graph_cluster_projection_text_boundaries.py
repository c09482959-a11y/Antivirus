from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.models.graph.cluster_projection import (
    propagate_cluster_influence,
    reinforce_graph_with_cluster,
)
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.graph_state import graph_node_snapshot, graph_vector_node_key, reset_graph_state, update_graph_node_owned


class HostileText:
    touched = 0

    def __hash__(self) -> int:
        return 2401

    def __eq__(self, other):  # pragma: no cover - failure proves caller-owned equality ran
        type(self).touched += 1
        raise AssertionError("caller-owned equality hook executed")

    def __str__(self):  # pragma: no cover - failure proves caller-owned text hook ran
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ executed")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __repr__ executed")

    def __format__(self, spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __format__ executed")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __bool__ executed")


def _bind_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    return state


def test_stage2001_cluster_projection_filters_hostile_members_without_text_hooks() -> None:
    HostileText.touched = 0
    reset_graph_state()
    try:
        state = _bind_state()
        node = "stage2001_cluster_node.exe"
        node_key = graph_vector_node_key(node)
        cid = "stage2001_cluster"
        state.node_cluster_map[node_key] = cid
        state.benign_clusters[cid].update({node_key, "stage2001_peer_a", HostileText()})
        state.cluster_metadata[cid] = {"members": ("stage2001_peer_a", "stage2001_peer_b", HostileText())}
        update_graph_node_owned(node, tags={"benign_asset"})

        result = reinforce_graph_with_cluster(node)
        propagate_cluster_influence(node, tags=("benign_asset", HostileText()))

        snapshot = graph_node_snapshot(node)
        assert result["reinforced"] is True
        assert result["cluster"] == cid
        assert snapshot is not None
        assert f"cluster:{cid}" in snapshot["edges"]
        assert any(str(edge).startswith("cluster_peer:") for edge in snapshot["edges"])
        assert all("unsupported_graph_text_type" not in edge for edge in snapshot["edges"])
        assert all("HostileText" not in edge for edge in snapshot["edges"])
        assert HostileText.touched == 0
    finally:
        reset_graph_state()


def test_stage2001_cluster_projection_rejects_hostile_cluster_id_without_hooks() -> None:
    HostileText.touched = 0
    reset_graph_state()
    try:
        state = _bind_state()
        node = "stage2001_hostile_cluster_id.exe"
        state.node_cluster_map[graph_vector_node_key(node)] = HostileText()
        update_graph_node_owned(node, tags={"benign_asset"})

        result = reinforce_graph_with_cluster(node)

        assert result == {"reinforced": False, "reason": "cluster_unavailable"}
        assert HostileText.touched == 0
    finally:
        reset_graph_state()


def test_stage2001_cluster_projection_source_uses_reasoned_projection_boundaries() -> None:
    source = read_python_file(Path("Virus_Scan/models/graph/cluster_projection.py"))

    assert "safe_graph_sequence" not in source
    assert "safe_graph_text(" not in source
    assert "graph_first_reason(graph_vector_node_key(node)" not in source
    assert "frozenset(safe_graph_text(member)" not in source
    assert "peer_digest = hashlib.md5(safe_graph_text(m).encode())" not in source
