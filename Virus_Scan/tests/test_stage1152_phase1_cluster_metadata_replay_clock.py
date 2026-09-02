from __future__ import annotations
from Virus_Scan.tests.support.clustering_v2 import clustering_learning_decision, raw_cluster_vector

import inspect
import time

from Virus_Scan.models import clustering
from Virus_Scan.models.clustering.microcluster import empty_microcluster_snapshot
from Virus_Scan.models.clustering.microcluster_update import update_microcluster_snapshot
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state, runtime_cluster_state_to_json
from Virus_Scan.runtime.graph_state import reset_graph_state


from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
def _materialize_cluster_snapshot_after_equivalent_updates():
    reset_graph_state()
    configure_runtime_cluster_state(RuntimeClusterState())
    first = clustering.assign_cluster_with_context_tags(
        "sample_one.png", raw_cluster_vector(), tags=physical_tag_evidence(("image_asset",)),
        engine_context={"unity": 1.0},
        learning_decision=clustering_learning_decision("stage1152-one", ordinal=1),
    )
    time.sleep(0.01)
    second = clustering.assign_cluster_with_context_tags(
        "sample_two.png", raw_cluster_vector(), tags=physical_tag_evidence(("image_asset",)),
        engine_context={"unity": 1.0},
        learning_decision=clustering_learning_decision("stage1152-two", ordinal=2),
    )
    assert first == second
    assert isinstance(first, str)
    return first, runtime_cluster_state_to_json()


def test_stage1152_cluster_metadata_json_is_replay_deterministic_without_wall_clock() -> None:
    first_id, first = _materialize_cluster_snapshot_after_equivalent_updates()
    time.sleep(0.02)
    second_id, second = _materialize_cluster_snapshot_after_equivalent_updates()

    assert first_id == second_id
    assert first == second
    metadata = first["microclusters"][first_id]
    assert metadata["created"] == 1.0
    assert metadata["last_updated"] == 2.0
    assert metadata["created_source"] == "deterministic_learning_decision_ordinal"
    assert metadata["last_updated_source"] == "deterministic_learning_decision_ordinal"


def test_stage1152_cluster_metadata_update_path_does_not_publish_time_time() -> None:
    update_source = inspect.getsource(clustering.cluster_update_metadata)
    meta_source = inspect.getsource(clustering.cluster_meta_for)

    assert "time.time" not in update_source
    assert "_cluster_now" not in update_source
    assert "time.time" not in meta_source
    assert "_cluster_now" not in meta_source
    snapshot_source = inspect.getsource(empty_microcluster_snapshot) + inspect.getsource(update_microcluster_snapshot)
    assert "deterministic_learning_decision_ordinal" in snapshot_source
    assert "time.time" not in snapshot_source
