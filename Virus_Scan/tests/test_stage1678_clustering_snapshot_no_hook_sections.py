from __future__ import annotations

import pytest

from Virus_Scan.models.api.clustering_contracts import load_cluster_runtime_model_record
from Virus_Scan.models.clustering import snapshots as cluster_snapshots
from Virus_Scan.models.clustering.microcluster_record import microcluster_from_record
from Virus_Scan.runtime.cluster_state import (
    CLUSTER_STATE_SCHEMA_VERSION,
    RuntimeClusterState,
    configure_runtime_cluster_state,
)
from Virus_Scan.models.clustering.state import cluster_signatures, node_cluster_map
from Virus_Scan.tests.support.clustering_v2 import seed_canonical_microcluster


class HostileItemsObject:
    touched = 0

    def __getattribute__(self, name):
        if name in {"items", "get"}:
            type(self).touched += 1
            raise AssertionError("cluster snapshot loader must not inspect caller-owned mapping hooks")
        return object.__getattribute__(self, name)


class HostileIterableObject:
    touched = 0

    def __iter__(self):  # pragma: no cover - failure proves hook execution
        type(self).touched += 1
        raise AssertionError("cluster snapshot loader must not iterate caller-owned objects")


class HostileFloatObject:
    touched = 0

    def __float__(self):  # pragma: no cover - failure proves hook execution
        type(self).touched += 1
        raise AssertionError("cluster snapshot loader must not coerce caller-owned numeric hooks")


class HostileVectorList(list):
    touched = 0

    def __iter__(self):  # pragma: no cover - failure proves hook execution
        type(self).touched += 1
        raise AssertionError("cluster snapshot loader must not invoke caller-owned list-subclass iteration")


def _empty_current_state(**overrides: object) -> dict[str, object]:
    state: dict[str, object] = {
        "schema": CLUSTER_STATE_SCHEMA_VERSION,
        "microclusters": {},
        "node_cluster_map": {},
        "node_feature_vectors": {},
        "applied_learning_keys": {},
    }
    state.update(overrides)
    return state


def test_stage1678_cluster_snapshot_section_rejects_hostile_items_without_hook() -> None:
    HostileItemsObject.touched = 0

    with pytest.raises(ValueError, match="cluster_microclusters_not_object"):
        cluster_snapshots._snapshot_sections(  # type: ignore[attr-defined]
            _empty_current_state(microclusters=HostileItemsObject()),
        )

    assert HostileItemsObject.touched == 0


def test_stage1678_cluster_snapshot_metadata_rejects_hostile_items_without_hook() -> None:
    HostileItemsObject.touched = 0

    with pytest.raises(ValueError, match="microcluster_record_not_object"):
        microcluster_from_record(HostileItemsObject(), "cluster")

    assert HostileItemsObject.touched == 0


def test_stage1678_cluster_snapshot_iterable_rejects_hostile_iter_without_hook() -> None:
    HostileIterableObject.touched = 0

    with pytest.raises(ValueError, match="invalidcluster_metadata_members"):
        cluster_snapshots._strict_assignment_vector(  # type: ignore[attr-defined]
            HostileIterableObject(),
            "invalidcluster_metadata_members",
        )

    assert HostileIterableObject.touched == 0


def test_stage1678_cluster_snapshot_vector_rejects_subclass_and_float_hooks_without_hook() -> None:
    HostileVectorList.touched = 0
    HostileFloatObject.touched = 0

    with pytest.raises(ValueError, match="invalid_cluster_signature_vector"):
        cluster_snapshots._strict_assignment_vector(  # type: ignore[attr-defined]
            HostileVectorList([1.0] * 16),
            "invalid_cluster_signature_vector",
        )
    with pytest.raises(ValueError, match="invalid_cluster_signature_vector"):
        cluster_snapshots._strict_assignment_vector(  # type: ignore[attr-defined]
            [HostileFloatObject()] * 16,
            "invalid_cluster_signature_vector",
        )

    assert HostileVectorList.touched == 0
    assert HostileFloatObject.touched == 0


def test_stage1678_cluster_record_load_rejects_invalid_metadata_without_clearing_state(capsys) -> None:
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    seed_canonical_microcluster(
        state, "existing-cluster", members=("existing-node",), kind="mixed", trusted_sample_count=3,
    )
    invalid = _empty_current_state(
        microclusters={"loaded": {"members": {}}},
        node_cluster_map={"loaded-node": "loaded"},
        node_feature_vectors={"loaded-node": [0.0] * 16},
    )
    assert load_cluster_runtime_model_record(invalid) is False
    assert "existing-cluster" in cluster_signatures()
    assert node_cluster_map()["existing-node"] == "existing-cluster"
    captured = capsys.readouterr()
    assert "runtime_cluster_state_load_rejected" in captured.err
