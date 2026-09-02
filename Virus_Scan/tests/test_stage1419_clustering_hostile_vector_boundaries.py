from __future__ import annotations

import math

from Virus_Scan.models import clustering
from Virus_Scan.models.clustering.similarity import cluster_jaccard_similarity
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state


class _HostileBool:
    def __bool__(self):
        raise RuntimeError("hostile bool")

    def __str__(self):
        raise RuntimeError("hostile str")


class _HostileIterable:
    def __iter__(self):
        raise RuntimeError("hostile iterator")


class _HostileFloat:
    def __float__(self):
        raise RuntimeError("hostile float")

    def __bool__(self):
        raise RuntimeError("hostile bool")


def _bind_cluster_state() -> RuntimeClusterState:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    return state


def test_stage1419_clustering_cosine_and_jaccard_detach_hostile_sequences() -> None:
    similarity = clustering.cosine_similarity([1.0, _HostileFloat()], [1.0, 1.0])
    assert similarity == 0.0
    assert cluster_jaccard_similarity(_HostileIterable(), ["process_injection"]) == 0.0


def test_stage1419_clustering_feature_vector_handles_hostile_public_inputs() -> None:
    _bind_cluster_state()

    vector = clustering.build_feature_vector(
        _HostileBool(),
        tags=_HostileIterable(),
        graph_features=_HostileIterable(),
        temporal_features=_HostileIterable(),
        markov_features=_HostileIterable(),
        engine_context=_HostileIterable(),
    )

    assert len(vector) == 17
    assert all(isinstance(value, float) for value in vector)
    assert all(math.isfinite(value) for value in vector)


def test_stage1419_online_vector_update_and_retention_ignore_hostile_truthiness() -> None:
    _bind_cluster_state()

    baseline = clustering.online_vector_update(
        vector_baseline=_HostileIterable(),
        vector=[_HostileFloat(), 2.0],
        feature_names=_HostileIterable(),
    )
    clustering.prune_cluster_state_for_retention(
        max_cluster_members=_HostileBool(),
        max_cluster_count=_HostileBool(),
        max_node_cluster_map=_HostileBool(),
    )

    assert baseline["count"] == 1
    assert baseline["mean"] == (0.0, 2.0)
    assert baseline["feature_names"] == clustering.VECTOR_FEATURE_NAMES
