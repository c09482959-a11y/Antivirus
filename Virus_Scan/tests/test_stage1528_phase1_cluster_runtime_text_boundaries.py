"""Stage 1528 Phase 1 clustering/runtime exact-text boundary regressions."""
from __future__ import annotations

from Virus_Scan.models.clustering.retention import prune_cluster_state_for_retention
from Virus_Scan.tests.support.clustering_v2 import seed_canonical_microcluster
from Virus_Scan.models.clustering.storage import prune_node_feature_vectors
from Virus_Scan.runtime.cluster_state import (
    RuntimeClusterState,
    configure_runtime_cluster_state,
    runtime_cluster_state_to_json,
)


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.str_calls = 0
        obj.strip_calls = 0
        obj.bool_calls = 0
        return obj

    def __str__(self):  # pragma: no cover - failure proves raw str() was used
        self.str_calls += 1
        raise AssertionError("caller-owned __str__ was invoked")

    def strip(self, *args, **kwargs):  # pragma: no cover - failure proves raw strip() was used
        self.strip_calls += 1
        raise AssertionError("caller-owned strip() was invoked")

    def __bool__(self):  # pragma: no cover - failure proves truthiness was probed
        self.bool_calls += 1
        raise AssertionError("caller-owned truthiness was invoked")


def _bind_cluster_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    return state


def test_stage1528_cluster_retention_detaches_hostile_cluster_ids_and_nodes() -> None:
    state = _bind_cluster_state()
    cid = HostileText("renpy_rpy_cluster_1")
    node = HostileText("game/scripts/start.rpy")
    kind = HostileText("malicious")
    tag = HostileText("pickle_exec")

    seed_canonical_microcluster(
        state, "renpy_rpy_cluster_1", members=("game/scripts/start.rpy",),
        kind="malicious", tags=("pickle_exec",), confidence=0.9,
        malicious_ratio=1.0, trusted_sample_count=3,
    )
    # Replace derived-index keys with exact str subclasses to prove retention
    # detaches them without invoking caller hooks.
    state.node_cluster_map.clear(); state.node_cluster_map[node] = cid
    state.malicious_clusters.clear(); state.malicious_clusters[cid].add(node)

    prune_cluster_state_for_retention(
        max_cluster_members=10, max_cluster_count=10, max_node_cluster_map=10,
    )

    assert "renpy_rpy_cluster_1" in state.cluster_metadata
    assert "game/scripts/start.rpy" in state.cluster_metadata["renpy_rpy_cluster_1"]["members"]
    assert "pickle_exec" in state.cluster_tag_signatures["renpy_rpy_cluster_1"]
    for value in (cid, node, kind, tag):
        assert value.str_calls == 0
        assert value.strip_calls == 0
        assert value.bool_calls == 0


def test_stage1528_cluster_vector_pruning_detaches_hostile_node_keys() -> None:
    state = _bind_cluster_state()
    live_node = HostileText("live-node")
    stale_node = HostileText("stale-node")
    cid = HostileText("cluster-live")

    state.node_cluster_map[live_node] = cid
    state.node_feature_vectors[live_node] = [1.0, 0.0]
    state.node_feature_vectors[stale_node] = [0.0, 1.0]

    prune_node_feature_vectors(max_items=10)

    assert list(state.node_feature_vectors) == [live_node]
    assert live_node.str_calls == 0
    assert stale_node.str_calls == 0
    assert cid.str_calls == 0
    assert live_node.strip_calls == 0
    assert stale_node.strip_calls == 0
    assert live_node.bool_calls == 0
    assert stale_node.bool_calls == 0


def test_stage1528_runtime_cluster_json_detaches_hostile_metadata_text() -> None:
    state = _bind_cluster_state()
    cid = HostileText("cluster-json")
    key = HostileText("tag_signature")
    tag = HostileText("credential_access")
    kind_key = HostileText("kind")
    kind_value = HostileText("mixed")

    state.cluster_signatures[cid] = [0.4, 0.6]
    state.cluster_metadata[cid] = {
        key: {tag},
        kind_key: kind_value,
        "samples": 2,
        "last_updated": 2.0,
        "confidence": 0.5,
    }

    snapshot = runtime_cluster_state_to_json()

    assert "cluster_signatures" not in snapshot
    assert snapshot["microclusters"]["cluster-json"]["tag_signature"] == ["credential_access"]
    assert snapshot["microclusters"]["cluster-json"]["kind"] == "mixed"
    assert cid.str_calls == 0
    assert key.str_calls == 0
    assert tag.str_calls == 0
    assert kind_key.str_calls == 0
    assert kind_value.str_calls == 0
    assert cid.strip_calls == 0
    assert key.strip_calls == 0
    assert tag.strip_calls == 0
    assert kind_value.strip_calls == 0
    assert cid.bool_calls == 0
    assert key.bool_calls == 0
    assert tag.bool_calls == 0
    assert kind_value.bool_calls == 0
