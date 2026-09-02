"""Test-only SQLite profile-state construction and corruption helpers."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.models.profiles.persistence import (
    load_engine_profile,
    resolved_profiles_dir,
    save_engine_profile,
)
from Virus_Scan.models.profiles.snapshots import default_engine_profile
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state
from Virus_Scan.storage import authoritative_model_state, sqlite_lifecycle


def bind_profile_database(tmp_path: Path) -> Path:
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)
    configure_profiles_dir(profiles_dir)
    state = profile_persistence_state()
    state.bind_profiles_dir(str(profiles_dir))
    state.clear_all_profiles()
    state.set_staged_cache(None, dirty=False)
    authoritative_model_state().configure(profiles_dir)
    return profiles_dir


def persist_profile(engine: str, profile: dict[str, object] | None = None) -> dict[str, object]:
    value = default_engine_profile(engine) if profile is None else profile
    save_engine_profile(engine, value, force=True)
    profile_persistence_state().clear_all_profiles()
    loaded = load_engine_profile(engine)
    if type(loaded) is not dict:
        raise AssertionError("profile did not round-trip")
    return loaded


def tamper_profile_schema_version(engine: str, schema_version: int) -> None:
    if type(schema_version) is not int or schema_version <= 0:
        raise ValueError("test schema version must satisfy SQLite storage constraint")
    resolved_profiles_dir()
    with sqlite_lifecycle().transaction("model") as connection:
        connection.execute(
            "UPDATE profile_engines SET profile_schema_version=? "
            "WHERE engine_id=? AND profile_scope='default'",
            (schema_version, engine),
        )
    profile_persistence_state().clear_all_profiles()


def delete_profile_singleton(engine: str, table: str) -> None:
    allowed = {
        "profile_contamination_state",
        "profile_decision_history_state",
    }
    if table not in allowed:
        raise ValueError("unsupported test singleton table")
    resolved_profiles_dir()
    with sqlite_lifecycle().transaction("model") as connection:
        connection.execute(
            f"DELETE FROM {table} WHERE engine_id=? AND profile_scope='default'",
            (engine,),
        )
    profile_persistence_state().clear_all_profiles()


__all__ = (
    "bind_profile_database",
    "delete_profile_singleton",
    "persist_profile",
    "tamper_profile_schema_version",
)
