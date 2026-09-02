from __future__ import annotations
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence

from pathlib import Path
from Virus_Scan.detection.profiles import baseline_snapshot
from Virus_Scan.models.contracts.empirical_frequency import empirical_frequency_record
from Virus_Scan.models.profiles import api as profile_api
from Virus_Scan.models.profiles.baseline import profile_behavior_bucket_validation
from Virus_Scan.models.profiles.request_contracts import ProfileBucketValidationRequest
from Virus_Scan.models.profiles.context import contextual_profile_learning_policy
from Virus_Scan.models.profiles.maturity import profile_maturity_evidence
from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_NAMES
from Virus_Scan.models.profiles.snapshots import (
    default_engine_profile,
    default_extension_baseline,
)
from Virus_Scan.models.profiles.vector_statistics import (
    PROFILE_VECTOR_HISTOGRAM_BINS,
    default_profile_vector_statistics,
    update_profile_vector_statistics,
)
from Virus_Scan.runtime.config_state import (
    configure_profiles_dir,
)
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state


def _isolate_profile_state(tmp_path: Path) -> Path:
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)
    configure_profiles_dir(str(profiles_dir))
    state = profile_persistence_state()
    state.bind_profiles_dir(str(profiles_dir))
    state.clear_all_profiles()
    return profiles_dir


def _statistics(count: int, value: float = 0.2) -> dict[str, object]:
    baseline = default_profile_vector_statistics()
    for ordinal in range(count):
        current = min(1.0, value + (ordinal % 3) * 0.05)
        baseline = update_profile_vector_statistics(
            baseline, [current] * len(PROFILE_RAW_FEATURE_NAMES), diversity_key=f"phase6:{ordinal}",
        )
    return baseline


def test_phase6_robust_statistics_publish_versioned_quantiles_and_support() -> None:
    baseline = _statistics(12)
    assert baseline["count"] == 12
    assert baseline["trusted_count"] == 12
    assert baseline["update_ordinal"] == 12
    assert baseline["maturity"] == "mature"
    assert baseline["suppression_authority"] == 1.0
    assert len(baseline["histograms"]) == len(PROFILE_RAW_FEATURE_NAMES)
    assert all(len(histogram) == PROFILE_VECTOR_HISTOGRAM_BINS for histogram in baseline["histograms"])
    assert all(sum(histogram) == 12 for histogram in baseline["histograms"])
    for field in ("q25", "median", "q75", "p95"):
        assert len(baseline[field]) == len(PROFILE_RAW_FEATURE_NAMES)
        assert all(0.0 <= value <= 1.0 for value in baseline[field])
    assert baseline["outlier_count"] == 0
    assert baseline["quarantine_count"] == 0


def test_phase6_maturity_uses_trusted_support_not_legacy_file_count() -> None:
    extension = default_extension_baseline(".rpy")
    extension["files"] = 1000
    cold = profile_maturity_evidence(extension["vector_baseline"])
    assert cold["maturity"] == "cold"
    assert cold["trusted_count"] == 0
    assert cold["suppression_authority"] == 0.0

    extension["vector_baseline"] = _statistics(3)
    warming = profile_maturity_evidence(extension["vector_baseline"])
    assert warming["maturity"] == "warming"
    assert warming["suppression_authority"] == 0.35

    extension["vector_baseline"] = _statistics(12)
    mature = profile_maturity_evidence(extension["vector_baseline"])
    assert mature["maturity"] == "mature"
    assert mature["suppression_authority"] == 1.0


def test_phase6_empirical_probability_is_smoothed_and_provenanced() -> None:
    record = empirical_frequency_record(
        3, 4, minimum_support=3,
        maturity="warming", suppression_authority=0.35,
    )
    assert record["ready"] is True
    assert record["probability"] == 4 / 6
    assert record["successes"] == 3
    assert record["support"] == 4
    assert record["estimator"] == "laplace_beta_binomial_v1"
    assert record["prior"]["source"] == "fixed_smoothing_prior_not_learned"

    cold = empirical_frequency_record(
        1, 2, minimum_support=3,
        maturity="cold", suppression_authority=0.0,
    )
    assert cold["ready"] is False
    assert cold["probability"] == 0.0
    assert cold["reason"] == "insufficient_trusted_profile_support"


def test_phase6_fixed_bucket_heuristics_are_explicit_policy_priors() -> None:
    validation = profile_behavior_bucket_validation(
        ProfileBucketValidationRequest(
            "unity", "sample.dll",
            physical_tag_evidence(("network_activity", "credential_access")),
        )
    )
    assert validation["records"]
    for record in validation["records"]:
        assert "probability" not in record
        assert 0.0 <= record["policy_prior"] <= 1.0
        assert record["policy_prior_source"] == "profile_bucket_validation_policy_v1_not_learned"


def test_phase6_bucket_snapshot_uses_trusted_support_and_single_estimator(
    tmp_path: Path,
) -> None:
    _isolate_profile_state(tmp_path)
    sample = tmp_path / "sample.dll"
    sample.write_bytes(b"managed fixture")
    key = contextual_profile_learning_policy(
        str(sample), trusted_benign=True, degraded=False,
    ).as_record_fields()["learning_baseline_key"]
    baseline = default_extension_baseline(key)
    baseline["files"] = 999
    baseline["vector_baseline"] = _statistics(4)
    baseline["behavior_buckets"] = {"network": {"files": 3}}
    profile = default_engine_profile("unity")
    profile["extension_baselines"][key] = baseline
    profile_persistence_state().cache_engine_profile("unity", profile)
    record = baseline_snapshot.behavior_bucket_probability_record(
        "unity", str(sample), "network",
    )
    assert record["ready"] is True
    assert record["support"] == 4
    assert record["successes"] == 3
    assert record["probability"] == 4 / 6
    assert record["estimator"] == "laplace_beta_binomial_v1"


def test_phase6_cold_profile_cannot_publish_ready_adaptive_signal(tmp_path: Path) -> None:
    _isolate_profile_state(tmp_path)
    sample = tmp_path / "script.rpy"
    sample.write_text("label start:\n    return\n", encoding="utf-8")
    profile = default_engine_profile("renpy")
    baseline = default_extension_baseline(".rpy")
    baseline["files"] = 500
    profile["extension_baselines"][".rpy"] = baseline
    profile_persistence_state().cache_engine_profile("renpy", profile)
    signal = profile_api.adaptive_profile_signal(sample, ("benign_asset",))
    assert signal["ready"] is False
    assert signal["profile_ready"] is False
    assert signal["unavailable_reason"] == "insufficient_trusted_profile_support"


def test_phase6_robust_statistics_survive_atomic_profile_round_trip(tmp_path: Path) -> None:
    profiles_dir = _isolate_profile_state(tmp_path)
    profile = default_engine_profile("renpy")
    baseline = default_extension_baseline(".rpy")
    baseline["vector_baseline"] = _statistics(12)
    baseline["files"] = 12
    profile["extension_baselines"][".rpy"] = baseline
    profile_api.save_engine_profile("renpy", profile, force=True)
    assert (profiles_dir / "model_state.sqlite3").exists()
    assert not tuple(profiles_dir.glob("*.json*"))
    profile_persistence_state().clear_all_profiles()
    loaded = profile_api.load_engine_profile("renpy")
    statistics = loaded["extension_baselines"][".rpy"]["vector_baseline"]
    assert statistics["trusted_count"] == 12
    assert statistics["maturity"] == "mature"
    assert statistics["median"] == baseline["vector_baseline"]["median"]


def test_phase6_profile_public_surface_has_no_scalar_frequency_aliases() -> None:
    assert not hasattr(profile_api, "behavior_bucket_probability")
    assert not hasattr(profile_api, "extension_tag_probability")
    assert not hasattr(profile_api, "extension_chain_probability")
    assert hasattr(profile_api, "behavior_bucket_frequency_evidence")
    assert hasattr(profile_api, "extension_tag_frequency_evidence")
    assert hasattr(profile_api, "extension_chain_frequency_evidence")
