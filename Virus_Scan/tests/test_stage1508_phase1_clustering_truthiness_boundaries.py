from __future__ import annotations

from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.models import clustering
from Virus_Scan.tests.support.clustering_v2 import seed_canonical_microcluster
from Virus_Scan.models.clustering.evidence import cluster_signal_unavailable_reason
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.graph_state import graph_vector_node_key, reset_graph_state, update_graph_node_owned
from Virus_Scan.tests.support.graph_corruption import corrupt_graph_node_for_test


class BoolBomb:
    def __init__(self, text: str = "stage1508_reason") -> None:
        self.text = text

    def __bool__(self) -> bool:  # pragma: no cover - failure sentinel
        raise RuntimeError("caller-owned truthiness must not be evaluated")

    def __str__(self) -> str:
        return self.text


class BoolFloatBomb(BoolBomb):
    def __float__(self) -> float:
        return 65.0


class HostileIterable:
    def __init__(self, values) -> None:
        self.values = tuple(values)

    def __bool__(self) -> bool:  # pragma: no cover - failure sentinel
        raise RuntimeError("caller-owned iterable truthiness must not be evaluated")

    def __iter__(self):
        return iter(self.values)


class HostileLenIterable(HostileIterable):
    def __len__(self):  # pragma: no cover - failure sentinel for direct len()
        raise RuntimeError("caller-owned iterable length must not be evaluated directly")


class HostileList(list):
    def __bool__(self) -> bool:  # pragma: no cover - failure sentinel
        raise RuntimeError("caller-owned list truthiness must not be evaluated")


class ClusterIdBomb(BoolBomb):
    pass


def _bind_cluster_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    return state


def _seed_cluster(state: RuntimeClusterState, raw_node: str = "stage1508_sample.exe") -> tuple[str, str]:
    node_key = graph_vector_node_key(raw_node)
    peers = ("stage1508_peer.exe", "stage1508_peer_two.exe")
    cid = "stage1508_cluster"
    snapshot = seed_canonical_microcluster(
        state, cid, members=(node_key, *peers), kind="malicious",
        malicious_ratio=1.0, confidence=0.75,
        tags=("process_injection", "network_exfiltration"),
        chains=("download_execute_chain",), trusted_sample_count=3,
        influence_enabled=True,
    )
    state.node_feature_vectors[node_key] = list(snapshot["centroid_vector"])
    update_graph_node_owned(node_key, risk=80.0, tags={"process_injection"})
    update_graph_node_owned(peers[0], risk=60.0, tags={"network_exfiltration"})
    update_graph_node_owned(peers[1], risk=55.0, tags={"process_injection"})
    return node_key, cid


def test_stage1508_cluster_signal_reason_avoids_truthiness_on_reason_flags() -> None:
    reason = cluster_signal_unavailable_reason(
        {
            "reason": BoolBomb("cluster_stage1508_unavailable"),
            "degraded": BoolBomb("not_a_bool"),
            "confidence_degraded": BoolBomb("not_a_bool"),
        }
    )

    assert reason == "cluster_stage1508_unavailable"


def test_stage1508_cluster_risk_reader_avoids_graph_field_truthiness() -> None:
    reset_graph_state()
    try:
        state = _bind_cluster_state()
        node_key, cid = _seed_cluster(state)
        corrupt_graph_node_for_test(
            node_key,
            risk=BoolFloatBomb("risk"),
            tags=HostileIterable(["process_injection"]),
            edges=HostileLenIterable(["peer"]),
        )
        corrupt_graph_node_for_test(
            "stage1508_peer.exe",
            risk=BoolFloatBomb("risk"),
            tags=HostileIterable(["network_exfiltration"]),
        )

        evidence = clustering.cluster_risk_score_evidence("stage1508_sample.exe")

        assert evidence["ready"] is True
        assert evidence["degraded"] is False
        assert evidence["cluster_id"] == cid
        assert evidence["risk"] > 0.0
        assert clustering.cluster_risk_score("stage1508_sample.exe") == evidence["risk"]
    finally:
        reset_graph_state()


def test_stage1508_cluster_context_and_signal_avoid_cluster_id_truthiness() -> None:
    reset_graph_state()
    try:
        state = _bind_cluster_state()
        node_key, cid = _seed_cluster(state, "stage1508_context.exe")
        state.node_cluster_map[node_key] = ClusterIdBomb(cid)

        quality = clustering.context_cluster_quality(
            "stage1508_context.exe",
            physical_tag_evidence(("process_injection", "network_exfiltration")),
            adaptive_learning={"cluster": {"cluster_members": 3}},
        )
        signal = clustering.adaptive_cluster_signal(
            "stage1508_context.exe",
            physical_tag_evidence(("process_injection",)),
        )
        explanation = clustering.explain_cluster("stage1508_context.exe")

        assert quality["cluster_id"] == cid
        assert quality["eligible"] is True
        assert signal["cluster_id"] == cid
        assert signal["cluster_signal_ready"] is True
        assert explanation["cluster"] == cid
    finally:
        reset_graph_state()
