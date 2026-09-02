import pytest

import Virus_Scan.detection.scoring.adaptive.confidence as confidence
import Virus_Scan.detection.scoring.adaptive.feature_bundle as feature_bundle
import Virus_Scan.models.clustering.state as clustering_state
import Virus_Scan.runtime.cache_state as cache_state
import Virus_Scan.runtime.config_state as config_state
import Virus_Scan.runtime.detector_state as detector_state
import Virus_Scan.runtime.init_state as init_state
import Virus_Scan.runtime.runtime_flags as runtime_flags
import Virus_Scan.runtime.scheduler_state as scheduler_state
from Virus_Scan.runtime.cache_state import CacheStateOwner
from Virus_Scan.scheduler.queue.authority import acquire_identity_lock_decision, release_identity_lock_decision


def test_runtime_cache_owner_rejects_rebinding_drift():
    owner = CacheStateOwner()
    first = {}
    owner.register("stage347", first)
    assert owner.register("stage347", first) is first
    with pytest.raises(RuntimeError, match="runtime cache registration drift"):
        owner.register("stage347", {})


def test_stage1794_runtime_cache_dead_public_wrappers_stay_deleted():
    removed = {"cache_owner", "register_runtime_cache", "runtime_cache_snapshot"}
    assert removed.isdisjoint(cache_state.__all__)
    for name in removed:
        assert not hasattr(cache_state, name)


def test_stage1794_runtime_dead_public_wrappers_stay_deleted():
    removed_by_module = {
        config_state: {"runtime_config_owner"},
        detector_state: {"detector_state_owner", "configure_detector_state"},
        init_state: {"init_state_owner"},
        runtime_flags: {"runtime_flag_owner", "runtime_flag_set", "runtime_flag_snapshot"},
        scheduler_state: {"scheduler_state_owner", "get_workload_queue_plan", "scheduler_state_snapshot"},
    }
    for module, removed in removed_by_module.items():
        assert removed.isdisjoint(module.__all__)
        for name in removed:
            assert not hasattr(module, name)


def test_stage1794_adaptive_dead_scalar_cluster_risk_wrapper_stays_deleted():
    assert "model_cluster_risk_score" not in feature_bundle.__all__
    assert not hasattr(feature_bundle, "model_cluster_risk_score")
    assert "model_cluster_risk_score_evidence" in feature_bundle.__all__


def test_stage1794_adaptive_dead_weight_bundle_wrapper_stays_deleted():
    assert "adaptive_learned_weight_bundle" not in confidence.__all__
    assert not hasattr(confidence, "adaptive_learned_weight_bundle")
    assert "adaptive_learned_model_weight_from_confidence" in confidence.__all__


def test_stage1794_clustering_dead_runtime_state_alias_stays_deleted():
    assert "cluster_runtime_state" not in clustering_state.__all__
    assert not hasattr(clustering_state, "cluster_runtime_state")
    assert "node_cluster_map" in clustering_state.__all__


def test_process_queue_identity_lock_is_reusable_after_release(tmp_path):
    first = acquire_identity_lock_decision(tmp_path, "file-A")
    assert first.acquired is True
    assert first.lock_path is not None
    assert acquire_identity_lock_decision(tmp_path, "file-A").reason == "process_queue_identity_lock_already_locked"
    assert release_identity_lock_decision(first.lock_path).released is True
    second = acquire_identity_lock_decision(tmp_path, "file-A")
    assert second.acquired is True
    assert second.lock_path is not None
    assert release_identity_lock_decision(second.lock_path).released is True
