from __future__ import annotations

from Virus_Scan.models import profiles
from Virus_Scan.models.profiles import api as profile_api

_FOREIGN_MODEL_OWNER_NAMES = (
    "canonical_behavior_flow",
    "compute_markov_features",
    "update_markov_model",
    "assign_cluster_with_context_tags",
    "online_vector_update",
    "update_temporal",
    "snapshot_temporal",
    "link_temporal_to_graph",
)


def test_stage1453_profiles_root_does_not_reexport_foreign_model_owner_apis():
    assert sorted(set(_FOREIGN_MODEL_OWNER_NAMES) & set(profiles.__all__)) == []
    for name in _FOREIGN_MODEL_OWNER_NAMES:
        assert not hasattr(profiles, name)


def test_stage1453_profile_api_all_does_not_advertise_foreign_model_owner_apis():
    assert sorted(set(_FOREIGN_MODEL_OWNER_NAMES) & set(profile_api.__all__)) == []
    assert "canonical_behavior_flow_from_sources" in profile_api.__all__
    assert "canonical_profile_learning_flow" in profile_api.__all__
