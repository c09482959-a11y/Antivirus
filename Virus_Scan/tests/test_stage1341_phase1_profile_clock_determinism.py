from __future__ import annotations

import inspect
from pathlib import Path

from Virus_Scan.models.profiles import api as profile_api
from Virus_Scan.models.profiles.extension_state_learning import update_extension_timeline_baseline
from Virus_Scan.models.profiles.promotion import prepare_benign_observation
from Virus_Scan.models.profiles.staged_store_schema import (
    default_staged_benign_store,
)
from Virus_Scan.tests.support.profile_learning import accepted_learning_request
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state


def _isolate_profile_state(tmp_path: Path) -> None:
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)
    configure_profiles_dir(str(profiles_dir))
    state = profile_persistence_state()
    state.bind_profiles_dir(str(profiles_dir))
    state.set_staged_cache(default_staged_benign_store(), dirty=False)


def test_stage1341_profile_model_has_no_live_wall_clock_source() -> None:
    source = inspect.getsource(profile_api)

    assert "import time" not in source
    assert "time.time" not in source


def test_stage1341_default_engine_profile_metadata_is_deterministic() -> None:
    first = profile_api.default_engine_profile("renpy")
    second = profile_api.default_engine_profile("renpy")

    assert first == second
    assert first["created"] == 0.0
    assert first["updated"] == 0.0


def test_stage1341_timeline_baseline_uses_sample_count_marker() -> None:
    baseline = profile_api.default_extension_baseline(".rpy")

    first = update_extension_timeline_baseline(baseline, ["load", "execute"])
    second = update_extension_timeline_baseline(baseline, ["load", "execute"])

    assert first is second
    assert second["sample_count"] == 2
    assert second["last_updated"] == 2.0


def test_stage1341_staged_benign_timestamps_are_observation_deterministic(tmp_path: Path) -> None:
    _isolate_profile_state(tmp_path)
    path = tmp_path / "game" / "script.rpy"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("label start:\n    return\n", encoding="utf-8")

    state = profile_persistence_state()
    first = prepare_benign_observation(accepted_learning_request(
        path, observation_id="stage1341-observation-1",
    ))
    assert first.candidate is not None
    first_seen = first.candidate["first_seen"]
    first_last_seen = first.candidate["last_seen"]
    state.set_staged_cache(first.staged_store, dirty=False)
    second = prepare_benign_observation(accepted_learning_request(
        path, observation_id="stage1341-observation-2",
    ))
    assert second.candidate is not None
    second_last_seen = second.candidate["last_seen"]
    state.set_staged_cache(second.staged_store, dirty=False)
    third = prepare_benign_observation(accepted_learning_request(
        path, observation_id="stage1341-observation-3",
    ))

    assert first_seen == 0.0
    assert first_last_seen == 0.0
    assert second_last_seen == 86400.0
    assert third.promoted is True
    assert third.candidate is not None
    assert third.candidate["last_seen"] == 172800.0
    assert third.candidate["promoted_at"] == 172800.0
