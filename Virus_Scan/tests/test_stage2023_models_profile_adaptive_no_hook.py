from __future__ import annotations

from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from pathlib import Path
from unittest.mock import patch

from Virus_Scan.models.profiles import api as profile_api
from Virus_Scan.models.profiles import adaptive_signal
from Virus_Scan.models.profiles.context import contextual_profile_bucket_key
from Virus_Scan.models.profiles.snapshots import default_extension_baseline
from Virus_Scan.models.profiles.extension_learning import learn_extension_tags
from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_NAMES
from Virus_Scan.models.profiles.vector_statistics import (
    default_profile_vector_statistics,
    update_profile_vector_statistics,
)
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state


class HostileKey:
    touched = 0

    def __eq__(self, other):  # pragma: no cover - any call is the regression
        type(self).touched += 1
        raise AssertionError("caller-owned key equality hook executed")

    def __hash__(self) -> int:
        return 23

    def __str__(self):  # pragma: no cover - any call is the regression
        type(self).touched += 1
        raise AssertionError("caller-owned key text hook executed")

    def __repr__(self):  # pragma: no cover - any call is the regression
        type(self).touched += 1
        raise AssertionError("caller-owned key repr hook executed")


class HostileNumeric:
    touched = 0

    def __float__(self):  # pragma: no cover - any call is the regression
        type(self).touched += 1
        raise AssertionError("caller-owned float hook executed")

    def __int__(self):  # pragma: no cover - any call is the regression
        type(self).touched += 1
        raise AssertionError("caller-owned int hook executed")


class HostileConfigError(OSError):
    def __str__(self):  # pragma: no cover - any call is the regression
        raise AssertionError("caller-owned exception text hook executed")


def _reset_hostile_counters() -> None:
    HostileKey.touched = 0
    HostileNumeric.touched = 0


def _isolate_profile_state(tmp_path: Path) -> None:
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)
    configure_profiles_dir(str(profiles_dir))
    state = profile_persistence_state()
    state.bind_profiles_dir(str(profiles_dir))
    state.clear_all_profiles()
    state.set_staged_cache({"schema_version": 3, "candidates": {}, "promotions": 0, "rejections": {}}, dirty=False)


def _store_baseline(tmp_path: Path, baseline: dict) -> Path:
    _isolate_profile_state(tmp_path)
    sample = tmp_path / "game" / "script.rpy"
    sample.parent.mkdir(parents=True, exist_ok=True)
    sample.write_text("label start:\n    return\n", encoding="utf-8")
    key, _context = contextual_profile_bucket_key(sample, trusted_benign=True)
    profile = profile_api.default_engine_profile("renpy")
    profile["extension_baselines"][key] = baseline
    profile_persistence_state().cache_engine_profile("renpy", profile)
    return sample



def _mature_vector_baseline() -> dict[str, object]:
    baseline = default_profile_vector_statistics()
    for _ordinal in range(12):
        baseline = update_profile_vector_statistics(
            baseline, [0.1] * len(PROFILE_RAW_FEATURE_NAMES), diversity_key=f"adaptive:{_ordinal}",
        )
    return baseline

def test_stage2023_extension_frequency_ignores_hostile_keys_without_equality_hooks(tmp_path: Path) -> None:
    _reset_hostile_counters()
    baseline = default_extension_baseline(".rpy")
    baseline["files"] = 12
    baseline["vector_baseline"] = _mature_vector_baseline()
    for _ordinal in range(3):
        learn_extension_tags(baseline, physical_tag_evidence(("benign_asset",)))
    baseline["chains"]["suspicious_audit"] = {HostileKey(): 4, "network_exec": 2}
    sample = _store_baseline(tmp_path, baseline)

    tag_probability = profile_api.extension_tag_frequency_evidence("renpy", sample, "benign_asset")
    chain_probability = profile_api.extension_chain_frequency_evidence("renpy", sample, "network_exec")

    assert tag_probability["probability"] == 4 / 14
    assert chain_probability["probability"] == 3 / 14
    assert tag_probability["support"] == 12
    assert chain_probability["support"] == 12
    assert HostileKey.touched == 0


def test_stage2023_adaptive_profile_rejects_hostile_support_without_numeric_hooks(tmp_path: Path) -> None:
    _reset_hostile_counters()
    baseline = default_extension_baseline(".rpy")
    baseline["files"] = HostileNumeric()
    sample = _store_baseline(tmp_path, baseline)

    result = adaptive_signal.adaptive_profile_signal(sample, ("benign_asset",))

    assert result["ready"] is False
    assert result["degraded"] is True
    assert result["unavailable_reason"] == "invalid_profile_history_support"
    assert HostileNumeric.touched == 0


def test_stage2023_extension_profile_uses_no_hook_nested_model_metrics(tmp_path: Path) -> None:
    _reset_hostile_counters()
    baseline = default_extension_baseline(".rpy")
    baseline["files"] = 12
    baseline["vector_baseline"] = _mature_vector_baseline()
    baseline["risk"] = {"avg": 0.1, "max_seen": 1.0}
    sample = _store_baseline(tmp_path, baseline)
    coordinated = {
        "ready": True,
        "bucket_validation": {HostileKey(): 1.0, "bucket_anomaly": HostileNumeric()},
        "vector_validation": {HostileKey(): 1.0, "anomaly": 0.25},
        "timeline_validation": {HostileKey(): 1.0, "anomaly": 0.5},
    }

    with patch.object(adaptive_signal, "coordinated_model_validation_signal", return_value=coordinated):
        result = adaptive_signal.extension_profile_anomaly("renpy", sample, (), risk=0.4)

    assert result["files_seen"] == 12
    assert result["trusted_support"] == 12
    assert result["bucket_anomaly"] == 0.0
    assert result["vector_anomaly"] == 0.25
    assert result["timeline_anomaly"] == 0.5
    assert HostileKey.touched == 0
    assert HostileNumeric.touched == 0


def test_stage2023_profile_prior_failure_uses_unavailable_projection() -> None:
    seen = []

    def raise_hostile(*_args, **_kwargs):
        raise HostileConfigError()

    def record_unavailable(extension, reason, *, files_seen=0):
        seen.append((extension, reason, files_seen))
        return {"ready": False, "degraded": True, "anomaly": 0.0, "unavailable_reason": reason}

    with (
        patch.object(adaptive_signal, "get_extension_baseline", raise_hostile),
        patch.object(adaptive_signal, "extension_profile_unavailable", record_unavailable),
    ):
        assert adaptive_signal.profile_prior_for_scoring("renpy", "game.rpy", ("renpy_script",)) == 0.0

    assert seen == [(".rpy", "profile_prior_baseline_load_failed", 0)]
