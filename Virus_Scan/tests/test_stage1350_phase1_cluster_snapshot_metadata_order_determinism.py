from __future__ import annotations

from Virus_Scan.models.clustering.microcluster import microcluster_with_fields
from Virus_Scan.runtime.cluster_state import (
    RuntimeClusterState,
    configure_runtime_cluster_state,
    runtime_cluster_state_to_json,
)
from Virus_Scan.tests.support.clustering_v2 import canonical_microcluster_snapshot


def _snapshot_for_record(record: dict[str, object]) -> dict[str, object]:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    state.cluster_metadata["cluster-a"] = record
    return runtime_cluster_state_to_json()["microclusters"]["cluster-a"]


def _canonical_record() -> dict[str, object]:
    return dict(canonical_microcluster_snapshot(
        "cluster-a",
        members=("node-z", "node-a", "node-m"),
        tags=("zeta", "alpha", "middle"),
    ))


def test_runtime_cluster_snapshot_metadata_keys_are_sorted_before_materialization() -> None:
    record = _canonical_record()
    left = _snapshot_for_record(dict(record.items()))
    right = _snapshot_for_record(dict(reversed(tuple(record.items()))))

    assert left == right
    assert tuple(left) == tuple(sorted(left))


def test_runtime_cluster_snapshot_retains_complete_canonical_record_independent_of_insertion_order() -> None:
    record = _canonical_record()
    left = _snapshot_for_record(record)
    right = _snapshot_for_record(dict(reversed(tuple(record.items()))))

    assert left == right
    assert set(left) == set(record)
    assert "schema_version" in left
    assert "normalization_vector_digest" in left


def test_runtime_cluster_snapshot_unordered_canonical_collections_are_sorted() -> None:
    record = _canonical_record()
    record = dict(microcluster_with_fields(
        record,
        members=frozenset(("node-z", "node-a", "node-m")),
        tag_signature=frozenset(("zeta", "alpha", "middle")),
    ))
    snapshot = _snapshot_for_record(record)

    assert snapshot["members"] == ["node-a", "node-m", "node-z"]
    assert snapshot["tag_signature"] == ["alpha", "middle", "zeta"]
