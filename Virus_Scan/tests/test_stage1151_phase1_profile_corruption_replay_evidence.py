from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.models.profiles import (
    PROFILE_SCHEMA_VERSION,
    ProfileSchemaInvariantError,
    configure_engine_profile_corruption_policy,
    load_engine_profile,
    profile_corruption_events_snapshot,
)
from Virus_Scan.models.profiles.snapshots import default_engine_profile
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state
from Virus_Scan.storage import authoritative_model_state, sqlite_lifecycle


def _bind_profiles(root: Path) -> Path:
    profiles_dir = root / "profiles"
    profiles_dir.mkdir(parents=True)
    sqlite_lifecycle().close()
    configure_profiles_dir(str(profiles_dir))
    profile_persistence_state().bind_profiles_dir(str(profiles_dir))
    profile_persistence_state().clear_all_profiles()
    authoritative_model_state().configure(profiles_dir)
    return profiles_dir


def _seed_invalid_profile(engine: str = "renpy") -> None:
    authoritative_model_state().commit(
        profiles=(default_engine_profile(engine),),
        transaction_kind="test_profile_seed",
    )
    with sqlite_lifecycle().transaction("model") as connection:
        connection.execute(
            "UPDATE profile_engines SET profile_schema_version=? "
            "WHERE engine_id=? AND profile_scope='default'",
            (PROFILE_SCHEMA_VERSION + 1, engine),
        )
    profile_persistence_state().clear_all_profiles()


def _quarantine_once(root: Path) -> dict[str, object]:
    configure_engine_profile_corruption_policy("quarantine")
    profiles_dir = _bind_profiles(root)
    _seed_invalid_profile()
    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        load_engine_profile("renpy")
    event = dict(profile_corruption_events_snapshot()[-1])
    return {"event": event, "profiles_dir": profiles_dir}


def test_stage1151_profile_corruption_evidence_uses_deterministic_timestamp_source(tmp_path: Path) -> None:
    result = _quarantine_once(tmp_path / "run")
    event = result["event"]

    assert event["timestamp"] == 0.0
    assert event["timestamp_source"] == "deterministic_profile_corruption_event"
    assert event["profile_corruption_policy"] == "quarantine"
    assert event["profile_quarantined"] is True
    assert event["scan_continued"] is False


def test_stage1151_profile_corruption_content_identity_is_path_independent(tmp_path: Path) -> None:
    first = _quarantine_once(tmp_path / "first")
    second = _quarantine_once(tmp_path / "second")

    first_event = first["event"]
    second_event = second["event"]
    assert first_event["profile_corruption_event_key"] != second_event["profile_corruption_event_key"]
    assert first_event["profile_corruption_content_key"] == second_event["profile_corruption_content_key"]
    assert first_event["actual_schema_version"] == second_event["actual_schema_version"]
    assert not tuple(first["profiles_dir"].glob("*.json"))
    assert not tuple(second["profiles_dir"].glob("*.json"))
