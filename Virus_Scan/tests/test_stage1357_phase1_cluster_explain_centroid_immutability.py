from __future__ import annotations

import math

import pytest

from Virus_Scan.models import clustering
from Virus_Scan.tests.support.clustering_v2 import seed_canonical_microcluster
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.graph_state import reset_graph_state


def _bind_cluster_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    return state


def test_stage1357_explain_cluster_does_not_leak_runtime_centroid_list() -> None:
    reset_graph_state()
    state = _bind_cluster_state()
    cid = "stage1357_cluster"
    node = "stage1357_sample.exe"
    snapshot = seed_canonical_microcluster(
        state, cid, members=(node,), kind="mixed", confidence=0.4,
        malicious_ratio=0.25, tags=("zeta_tag", "alpha_tag"),
        chains=("chain_b", "chain_a"), trusted_sample_count=3,
    )

    explanation = clustering.explain_cluster(node)

    assert explanation["centroid"] == tuple(snapshot["centroid_vector"])
    assert explanation["tags"] == ("alpha_tag", "zeta_tag")
    assert explanation["chains"] == ("chain_a", "chain_b")
    assert explanation["sample_nodes"] == (node,)
    with pytest.raises(AttributeError):
        explanation["centroid"].append(9.0)  # type: ignore[attr-defined]
    stored_centroid = state.cluster_signatures[cid]
    assert stored_centroid == list(snapshot["centroid_vector"])


def test_stage1357_explain_cluster_result_sequences_are_immutable() -> None:
    reset_graph_state()
    state = _bind_cluster_state()
    cid = "stage1357_sequence_cluster"
    node = "stage1357_sequence_sample.exe"
    seed_canonical_microcluster(
        state, cid, members=(node, "stage1357_other.exe"), kind="benign",
        confidence=0.8, malicious_ratio=0.0, tags=("media_asset",),
        chains=("safe_chain",), trusted_sample_count=3,
    )

    explanation = clustering.explain_cluster(node)

    for field in ("chains", "tags", "sample_nodes", "centroid"):
        assert isinstance(explanation[field], tuple)
        with pytest.raises(AttributeError):
            explanation[field].append("mutate")  # type: ignore[attr-defined]
