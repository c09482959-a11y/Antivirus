from __future__ import annotations

import json
from pathlib import Path

import pytest

from Virus_Scan.contracts.worker_record import make_json_safe
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


def _bind_profiles(tmp_path: Path) -> Path:
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()
    sqlite_lifecycle().close()
    configure_profiles_dir(str(profiles_dir))
    profile_persistence_state().bind_profiles_dir(str(profiles_dir))
    profile_persistence_state().clear_all_profiles()
    authoritative_model_state().configure(profiles_dir)
    return profiles_dir


def _seed_invalid_schema(engine: str, schema_version: int) -> None:
    authority = authoritative_model_state()
    authority.commit(
        profiles=(default_engine_profile(engine),),
        transaction_kind="test_profile_seed",
    )
    with sqlite_lifecycle().transaction("model") as connection:
        connection.execute(
            "UPDATE profile_engines SET profile_schema_version=? "
            "WHERE engine_id=? AND profile_scope='default'",
            (schema_version, engine),
        )
    profile_persistence_state().clear_all_profiles()


def test_stage1131_profile_corruption_snapshot_is_immutable_and_json_safe(tmp_path: Path) -> None:
    configure_engine_profile_corruption_policy("quarantine")
    profiles_dir = _bind_profiles(tmp_path)
    _seed_invalid_schema("renpy", PROFILE_SCHEMA_VERSION + 1)

    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        load_engine_profile("renpy")

    assert (profiles_dir / "model_state.sqlite3").exists()
    assert not tuple(profiles_dir.glob("*.json"))
    snapshot = profile_corruption_events_snapshot()
    assert isinstance(snapshot, tuple)
    assert snapshot
    event = snapshot[-1]
    assert event["profile_corruption_policy"] == "quarantine"
    assert event["actual_schema_version"] == PROFILE_SCHEMA_VERSION + 1

    with pytest.raises(TypeError):
        event["profile_corruption_policy"] = "clean"  # type: ignore[index]

    json_safe = make_json_safe({"profile_events": snapshot})
    assert json_safe["profile_events"][-1]["profile_corruption_policy"] == "quarantine"
    json.dumps(json_safe, sort_keys=True, allow_nan=False)


def test_stage1131_profile_corruption_snapshot_is_detached_from_runtime_state(tmp_path: Path) -> None:
    configure_engine_profile_corruption_policy("quarantine")
    _bind_profiles(tmp_path)
    authority = authoritative_model_state()
    authority.commit(
        profiles=(default_engine_profile("renpy"), default_engine_profile("unity")),
        transaction_kind="test_profile_seed_pair_before_corruption",
    )
    with sqlite_lifecycle().transaction("model") as connection:
        connection.execute(
            "UPDATE profile_engines SET profile_schema_version=? "
            "WHERE engine_id IN (?,?) AND profile_scope='default'",
            (PROFILE_SCHEMA_VERSION + 1, "renpy", "unity"),
        )
    profile_persistence_state().clear_all_profiles()

    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        load_engine_profile("renpy")
    first_snapshot = profile_corruption_events_snapshot()

    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        load_engine_profile("unity")

    assert len(first_snapshot) == 1
    assert len(profile_corruption_events_snapshot()) == 2
