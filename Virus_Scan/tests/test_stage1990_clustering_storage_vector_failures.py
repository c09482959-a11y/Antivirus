from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.models import clustering
from Virus_Scan.models.clustering.state import cluster_lock, node_cluster_map, node_feature_vectors
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.models.clustering.storage import prune_node_feature_vectors, store_node_vector
from Virus_Scan.models.clustering.vectors import build_feature_vector, cosine_similarity, json_cluster_prior
from Virus_Scan.tests.support.clustering_v2 import assignment_cluster_vector



class HostileKeysDict(dict):
    def keys(self):  # pragma: no cover - must never be invoked
        raise AssertionError("caller-owned keys hook executed")


class HostileText:
    def __str__(self):  # pragma: no cover - must never be invoked
        raise AssertionError("caller-owned str hook executed")


def test_stage1990_storage_prune_and_store_use_clustering_boundaries():
    configure_runtime_cluster_state(RuntimeClusterState())
    with cluster_lock():
        node_cluster_map().clear()
        node_feature_vectors().clear()
        node_cluster_map()["kept-node"] = "cluster-a"
        node_feature_vectors()["kept-node"] = [1.0, 0.0]
        node_feature_vectors()["dropped-node"] = [0.0, 1.0]

    prune_node_feature_vectors(max_items=10)

    with cluster_lock():
        assert "kept-node" in node_feature_vectors()
        assert "dropped-node" not in node_feature_vectors()

    vector = assignment_cluster_vector()
    assert store_node_vector(None, vector) == []
    assert store_node_vector(HostileText(), vector) == vector
    assert store_node_vector("new-node", vector) == vector


def test_stage1990_vector_math_preserves_exact_primitive_behavior():
    configure_runtime_cluster_state(RuntimeClusterState())
    assert cosine_similarity([1.0, 0.0], [1.0, 0.0]) == 1.0
    assert cosine_similarity([], [1.0, 0.0]) == 0.0
    assert json_cluster_prior([], "unknown") == 0.0
    vector = build_feature_vector(
        "node-a",
        ["archive"],
        {"risk": 0.5, "anomaly": 0.25},
        {"belief": 0.75},
        {"transition": 0.4, "rarity": 0.3, "pair_anomaly": 0.2},
        {"other": 0.6},
    )
    assert len(vector) == len(clustering.VECTOR_FEATURE_NAMES)
    assert all(type(value) is float for value in vector)


def test_stage1990_clustering_sources_close_storage_vector_sentinel_rows():
    snapshots = read_python_file(Path("Virus_Scan/models/clustering/snapshots.py"))
    storage = read_python_file(Path("Virus_Scan/models/clustering/storage.py"))
    vectors = read_python_file(Path("Virus_Scan/models/clustering/vectors.py"))

    assert "return cluster_snapshot_load_failure(error)" in snapshots
    assert "log_error(f'runtime_cluster_state_load_failed" not in snapshots

    assert "node_feature_vectors().keys()" not in storage
    assert "node_cluster_map().keys()" not in storage
    assert "log_error(f'node feature vector prune failed: {e}')" not in storage
    assert "log_error(f'store_node_vector failed for {node}: {e}')" not in storage
    assert "return []" not in storage

    assert "return safe_clamp(dot / (na * nb))" not in vectors
    assert "return 0.0" not in vectors
    assert "return safe_clamp(risky / max(1, len(tagset)))" not in vectors
    assert "safe_clamp(float(len(yara_hits)) / 20.0)" not in vectors
