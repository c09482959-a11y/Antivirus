from __future__ import annotations

from Virus_Scan.models import clustering
from Virus_Scan.tests.support.clustering_v2 import seed_canonical_microcluster
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state


def _bind_cluster_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    return state


def test_stage1122_online_vector_update_does_not_mutate_caller_baseline_or_vector() -> None:
    baseline = {
        "count": 1,
        "mean": [2.0, 4.0],
        "m2": [0.0, 0.0],
        "variance": [0.0, 0.0],
        "feature_names": ["a", "b"],
        "updated": 1.0,
    }
    vector = [4.0, "bad"]
    baseline_before = {key: (list(value) if isinstance(value, list) else value) for key, value in baseline.items()}
    vector_before = list(vector)

    updated = clustering.online_vector_update(baseline, vector, ["a", "b"])

    assert baseline == baseline_before
    assert vector == vector_before
    assert updated is not baseline
    assert updated["count"] == 2
    assert updated["mean"] == (3.0, 2.0)
    assert updated["feature_names"] == ("a", "b")
    assert isinstance(updated["variance"], tuple)


def test_stage1122_cluster_members_read_each_kind_store_once() -> None:
    state = _bind_cluster_state()
    state.malicious_clusters["c1"].add("malicious.exe")
    state.benign_clusters["c1"].add("benign.png")
    state.mixed_clusters["c1"].add("mixed.asset")
    state.cluster_metadata["c1"] = {"members": {"metadata.bin"}, "kind": "mixed"}

    assert clustering.cluster_members_for("c1") == {
        "malicious.exe",
        "benign.png",
        "mixed.asset",
        "metadata.bin",
    }


def test_stage1122_cluster_retention_preserves_benign_and_mixed_cluster_stores() -> None:
    state = _bind_cluster_state()
    seed_canonical_microcluster(
        state, "malicious_cluster", members=("malicious.exe",), kind="malicious",
        tags=("process_injection",), confidence=0.9, malicious_ratio=1.0,
    )
    seed_canonical_microcluster(
        state, "benign_cluster", members=("benign.png",), kind="benign",
        tags=("image_asset",), confidence=0.9, malicious_ratio=0.0,
    )
    seed_canonical_microcluster(
        state, "mixed_cluster", members=("mixed.asset",), kind="mixed",
        tags=("asset_bundle",), confidence=0.9, malicious_ratio=0.5,
    )

    clustering.prune_cluster_state_for_retention(
        max_cluster_members=10,
        max_cluster_count=10,
        max_node_cluster_map=10,
    )

    assert state.malicious_clusters == {"malicious_cluster": {"malicious.exe"}}
    assert state.benign_clusters == {"benign_cluster": {"benign.png"}}
    assert state.mixed_clusters == {"mixed_cluster": {"mixed.asset"}}
    assert set(state.cluster_signatures) == {"malicious_cluster", "benign_cluster", "mixed_cluster"}
    assert state.cluster_tag_signatures["benign_cluster"] == {"image_asset"}
