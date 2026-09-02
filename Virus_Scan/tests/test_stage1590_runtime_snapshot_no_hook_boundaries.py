from __future__ import annotations

import json

from Virus_Scan.runtime.cluster_state import (
    RuntimeClusterState,
    configure_runtime_cluster_state,
    runtime_cluster_state_to_json,
)
from Virus_Scan.runtime.profile_scoring_state import ProfileScoringState


class HostileBoundaryObject:
    touched = 0

    def __str__(self):  # pragma: no cover - production path must not call this
        type(self).touched += 1
        raise RuntimeError("hostile __str__ invoked")

    def __repr__(self):  # pragma: no cover - production path must not call this
        type(self).touched += 1
        raise RuntimeError("hostile __repr__ invoked")

    def __iter__(self):  # pragma: no cover - production path must not call this
        type(self).touched += 1
        raise RuntimeError("hostile __iter__ invoked")

    def __float__(self):  # pragma: no cover - production path must not call this
        type(self).touched += 1
        raise RuntimeError("hostile __float__ invoked")

    def __bool__(self):  # pragma: no cover - production path must not call this
        type(self).touched += 1
        raise RuntimeError("hostile __bool__ invoked")


def test_stage1590_runtime_cluster_snapshot_rejects_hostile_metadata_without_hooks() -> None:
    HostileBoundaryObject.touched = 0
    state = RuntimeClusterState()
    configure_runtime_cluster_state(state)
    hostile_cluster_id = HostileBoundaryObject()
    hostile_key = HostileBoundaryObject()
    hostile_value = HostileBoundaryObject()

    state.cluster_signatures[hostile_cluster_id] = [hostile_value]
    state.cluster_metadata[hostile_cluster_id] = {
        hostile_key: hostile_value,
        "confidence": hostile_value,
        "centroid_vector": [hostile_value],
        "members": {hostile_value},
    }

    snapshot = runtime_cluster_state_to_json()

    assert HostileBoundaryObject.touched == 0
    cluster_key = next(iter(snapshot["microclusters"]))
    assert cluster_key.startswith("cluster_state_text_unavailable:HostileBoundaryObject")
    metadata = snapshot["microclusters"][cluster_key]
    assert metadata["confidence"].startswith("cluster_state_value_unavailable:unsafe_cluster_metadata_value_rejected")
    assert metadata["confidence_unavailable_reason"] == "unsafe_cluster_metadata_value_rejected"
    assert metadata["centroid_vector"] == [0.0]
    assert metadata["members"] == ["cluster_state_text_unavailable:HostileBoundaryObject"]
    assert any(name.startswith("cluster_state_text_unavailable:HostileBoundaryObject") for name in metadata)
    json.dumps(snapshot, allow_nan=False, sort_keys=True)


def test_stage1590_profile_scoring_snapshot_rejects_hostile_keys_values_without_hooks() -> None:
    HostileBoundaryObject.touched = 0
    state = ProfileScoringState()
    hostile_engine = HostileBoundaryObject()
    hostile_key = HostileBoundaryObject()
    hostile_value = HostileBoundaryObject()

    materialized = state.freeze({hostile_engine: {hostile_key: hostile_value}, "renpy": {"tags": {hostile_value}}})

    assert HostileBoundaryObject.touched == 0
    assert "profile_key_0" in materialized
    assert materialized["profile_key_0"]["unavailable_reason"] == "invalid_key_type"
    assert materialized["renpy"]["tags"][0]["unavailable_reason"] == "non_materializable_profile_value"
    assert state.get_profile(hostile_engine) is None
    assert HostileBoundaryObject.touched == 0
    json.dumps(state.snapshot(), allow_nan=False, sort_keys=True)
