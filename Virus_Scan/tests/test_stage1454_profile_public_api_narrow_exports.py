from __future__ import annotations

from Virus_Scan.models import profiles
from Virus_Scan.models.profiles import api as profile_api

_FOREIGN_PROFILE_API_NAMES = (
    "CLUSTER_VECTOR_FEATURE_NAMES",
    "IO_CONFIGURATION_ERRORS",
    "TELEMETRY_FAILURE_ERRORS",
    "configure_profile_corruption_policy",
    "contextual_dangerous_anchor_hits",
    "effective_stage_for_path",
    "evidence_level_for_tag",
    "get_init_value",
    "get_profile_corruption_policy",
    "get_profiles_dir",
    "get_scan_extension",
    "increment_counter",
    "is_passive_fast_asset_result",
    "library_baseline_has_hard_proof",
    "library_behavior_baseline_profile",
    "log_error",
    "make_model_failure_record",
    "materialize_model_failure_record",
    "normalize_profile_extension",
    "normalize_stage",
    "normalize_tags",
    "ordered_unique_tags",
    "profile_persistence_state",
    "profile_scoring_state",
    "record_suppressed_failure",
    "safe_clamp",
    "update_filetype_baseline",
    "write_profile_json",
)

_PROFILE_MODEL_OWNER_NAMES = (
    "adaptive_profile_signal",
    "canonical_profile_learning_flow",
    "commit_promoted_learning",
    "default_engine_profile",
    "default_extension_baseline",
    "extension_profile_anomaly",
    "load_engine_profile",
    "profile_corruption_events_snapshot",
    "validate_engine_profile_schema",
)


def test_stage1454_profile_api_does_not_advertise_foreign_runtime_utility_or_publication_names():
    leaked = sorted(set(_FOREIGN_PROFILE_API_NAMES) & set(profile_api.__all__))
    assert leaked == []


def test_stage1454_profile_root_does_not_reexport_foreign_runtime_utility_or_publication_names():
    leaked = sorted(set(_FOREIGN_PROFILE_API_NAMES) & set(profiles.__all__))
    assert leaked == []
    for name in _FOREIGN_PROFILE_API_NAMES:
        assert not hasattr(profiles, name)


def test_stage1454_profile_root_preserves_profile_owned_public_names():
    missing = [name for name in _PROFILE_MODEL_OWNER_NAMES if name not in profiles.__all__]
    assert missing == []
    for name in _PROFILE_MODEL_OWNER_NAMES:
        assert hasattr(profiles, name)
