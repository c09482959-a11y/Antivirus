from __future__ import annotations
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision
from Virus_Scan.tests.support.clustering_v2 import clustering_learning_decision, raw_cluster_vector, seed_canonical_microcluster

from Virus_Scan.models import clustering
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state, runtime_cluster_state_to_json
from Virus_Scan.runtime.graph_state import reset_graph_state, update_graph_node_owned
from Virus_Scan.tests.support.clustering_v2 import assignment_cluster_vector
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def _bind_cluster_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    return state


def test_stage949_feature_vector_schema_matches_declared_feature_names() -> None:
    _bind_cluster_state()

    vector = clustering.build_feature_vector(
        "Game_Data/Managed/Assembly-CSharp.dll",
        tags=physical_tag_evidence(("process_exec", "network_exfiltration", "process_exec"), source_detector="stage949"),
        graph_features={"risk": 0.25, "anomaly": 0.5},
        temporal_features={"belief": 0.75},
        markov_features={"transition": 0.4, "rarity": 0.3, "pair_anomaly": 0.2},
        engine_context={"unity": 0.9, "renpy": 0.05, "rpgm": 0.0, "media": 0.0, "unknown": 0.05},
    )

    assert clustering.build_feature_vector is clustering.build_feature_vector
    assert len(vector) == len(clustering.VECTOR_FEATURE_NAMES)


def test_stage949_feature_vector_is_finite_and_preserves_model_inputs() -> None:
    _bind_cluster_state()

    vector = clustering.build_feature_vector(
        "Game_Data/Managed/Assembly-CSharp.dll",
        tags=physical_tag_evidence(("process_exec", "network_exfiltration", "process_exec"), source_detector="stage949"),
        graph_features={"risk": 0.25, "anomaly": 0.5},
        temporal_features={"belief": 0.75},
        markov_features={"transition": 0.4, "rarity": 0.3, "pair_anomaly": 0.2},
        engine_context={"unity": 0.9, "renpy": 0.05, "rpgm": 0.0, "media": 0.0, "unknown": 0.05},
    )

    assert clustering.build_feature_vector is clustering.build_feature_vector
    assert len(vector) == 17
    assert vector[0] == 3.0
    assert vector[2] == 2.0
    assert vector[3:9] == [0.25, 0.5, 0.75, 0.4, 0.3, 0.2]
    assert vector[9:14] == [0.9, 0.05, 0.0, 0.0, 0.05]
    assert all(isinstance(value, float) for value in vector)
    assert all(value == value and value not in (float("inf"), float("-inf")) for value in vector)


def test_stage949_assign_cluster_reuses_matching_engine_cluster_and_preserves_metadata() -> None:
    state = _bind_cluster_state()

    first = clustering.assign_cluster_with_context_tags(
        "sample_one.exe",
        raw_cluster_vector(),
        tags=physical_tag_evidence(("process_injection", "powershell_exec", "network_download"), source_detector="stage949-one"),
        engine_context={"unity": 1.0},
     learning_decision=clustering_learning_decision("stage949-sample-one", ordinal=1))
    second = clustering.assign_cluster_with_context_tags(
        "sample_two.exe",
        raw_cluster_vector(),
        tags=physical_tag_evidence(("network_download", "powershell_exec", "process_injection"), source_detector="stage949-two"),
        engine_context={"unity": 1.0},
     learning_decision=clustering_learning_decision("stage949-sample-two", ordinal=2))

    assert first == second
    assert isinstance(first, str)
    assert first.startswith("unity_exe_cluster_")
    assert state.node_cluster_map == {"sample_one.exe": first, "sample_two.exe": first}
    metadata = state.cluster_metadata[first]
    assert metadata["kind"] == "mixed"
    assert metadata["samples"] == 2
    assert metadata["trusted_sample_count"] == 0
    assert metadata["quarantined_sample_count"] == 2
    assert metadata["malicious_samples"] == 0
    assert metadata["malicious_ratio"] == 0.0
    assert metadata["influence_enabled"] is False
    assert set(metadata["members"]) == {"sample_one.exe", "sample_two.exe"}
    assert {"process_injection", "powershell_exec", "network_download"} <= set(
        metadata["tag_signature"]
    )
    assert set(metadata["chain_signature"]) == {
        "candidate:download_execute:anchor:download_execute_chain:stage2636_11020_chain_registry_v5"
    }

    snapshot = runtime_cluster_state_to_json()
    assert snapshot["schema"] == "online_microcluster_state_v2"
    assert len(snapshot["microclusters"][first]["centroid_vector"]) == 14
    assert snapshot["microclusters"][first]["members"] == ["sample_one.exe", "sample_two.exe"]


def test_stage949_cluster_scores_require_membership_and_remain_bounded() -> None:
    reset_graph_state()
    state = _bind_cluster_state()

    assert clustering.cluster_risk_score("missing.exe") == 0.0
    cluster_id = "unity_exe_cluster_fixture"
    members = ("risk_one.exe", "risk_two.exe")
    seed_canonical_microcluster(
        state,
        cluster_id,
        members=members,
        kind="malicious",
        tags=("process_injection", "credential_access", "network_exfiltration"),
        confidence=0.8,
        malicious_ratio=1.0,
        trusted_sample_count=3,
        influence_enabled=True,
    )
    update_graph_node_owned("risk_one.exe", risk=80.0, tags={"process_injection"}, metadata={"last_seen": 3.0})
    update_graph_node_owned("risk_two.exe", risk=60.0, tags={"network_exfiltration"}, metadata={"last_seen": 2.0})

    risk = clustering.cluster_risk_score("risk_one.exe")
    anomaly = clustering.cluster_anomaly_boost("risk_one.exe")
    detection = clustering.cluster_detection_boost("risk_one.exe")
    assert 0.0 < risk <= 1.0
    assert 0.0 <= anomaly <= 1.0
    assert 0.0 < detection <= 1.0

    explanation = clustering.explain_cluster("risk_one.exe")
    assert explanation["cluster"] == cluster_id
    assert explanation["kind"] == "malicious"
    assert explanation["size"] == 2
    assert set(explanation["sample_nodes"]) == set(members)
    assert "credential_access" in explanation["tags"]
    reset_graph_state()


def test_stage949_vector_storage_sanitizes_without_creating_split_aliases() -> None:
    state = _bind_cluster_state()

    assert clustering.store_node_vector("", [1, 2, 3]) == []
    assert state.node_feature_vectors == {}

    assert clustering.store_node_vector(
        "nested/../payload.bin", [1, "bad", float("nan"), float("inf"), -2],
    ) == []
    assert state.node_feature_vectors == {}

    stored = clustering.store_node_vector(
        "nested/../payload.bin", assignment_cluster_vector(),
    )
    assert state.node_feature_vectors == {"nested/../payload.bin": stored}

    assert not hasattr(clustering, "update_cluster_centroid")
    assert state.cluster_signatures == {}
    assert state.cluster_metadata == {}
