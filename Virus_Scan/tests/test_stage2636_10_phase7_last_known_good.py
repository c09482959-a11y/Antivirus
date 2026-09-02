from __future__ import annotations
from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles

from pathlib import Path

import pytest

from Virus_Scan.models.profiles.persistence import load_engine_profile, save_engine_profile
from Virus_Scan.models.profiles.persistence_snapshot import persisted_engine_profile_snapshot
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state
from Virus_Scan.storage import SQLiteLifecycleError, sqlite_lifecycle


def _isolate(tmp_path: Path) -> Path:
    profiles = tmp_path / "profiles"
    profiles.mkdir(parents=True, exist_ok=True)
    configure_profiles_dir(profiles)
    state = profile_persistence_state()
    state.bind_profiles_dir(str(profiles))
    state.clear_all_profiles()
    ensure_authoritative_engine_profiles()
    return profiles


def test_phase7_sqlite_transaction_rollback_restores_exact_prior_snapshot(tmp_path: Path) -> None:
    profiles = _isolate(tmp_path)
    profile = load_engine_profile("renpy")
    profile["model_state"]["learning_rejections"]["proof"] = 3
    save_engine_profile("renpy", profile, force=True)
    state = profile_persistence_state()
    state.clear_all_profiles()
    expected = persisted_engine_profile_snapshot(
        load_engine_profile("renpy"), expected_engine="renpy",
    )

    with pytest.raises(RuntimeError, match="forced_profile_rollback"):
        with sqlite_lifecycle().transaction("model") as connection:
            connection.execute(
                "UPDATE profile_engines SET updated_value=999 "
                "WHERE engine_id='renpy' AND profile_scope='default'"
            )
            raise RuntimeError("forced_profile_rollback")

    state.clear_all_profiles()
    restored = persisted_engine_profile_snapshot(
        load_engine_profile("renpy"), expected_engine="renpy",
    )
    assert restored == expected
    assert (profiles / "model_state.sqlite3").exists()
    assert not tuple(profiles.glob("*.json*"))
    assert sqlite_lifecycle().integrity_check("model").ok is True


@pytest.mark.parametrize("remove_digest", [False, True])
def test_phase7_tampered_or_missing_sqlite_schema_digest_is_rejected(
    tmp_path: Path, remove_digest: bool,
) -> None:
    profiles = _isolate(tmp_path)
    save_engine_profile("renpy", load_engine_profile("renpy"), force=True)
    database = profiles / "model_state.sqlite3"
    with sqlite_lifecycle().transaction("model") as connection:
        if remove_digest:
            connection.execute("DELETE FROM database_metadata WHERE key='schema_digest'")
        else:
            connection.execute(
                "UPDATE database_metadata SET value=? WHERE key='schema_digest'",
                ("0" * 64,),
            )
    sqlite_lifecycle().close()
    profile_persistence_state().clear_all_profiles()

    with pytest.raises(SQLiteLifecycleError, match="sqlite_open_failed:model:sqlite_schema_"):
        load_engine_profile("renpy")
