from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.models.profiles import (
    ProfileSchemaInvariantError,
    configure_engine_profile_corruption_policy,
    load_engine_profile,
    profile_corruption_events_snapshot,
)
from Virus_Scan.storage import authoritative_model_state
from Virus_Scan.tests.support.sqlite_profile_state import (
    bind_profile_database,
    delete_profile_singleton,
    persist_profile,
    tamper_profile_schema_version,
)


def test_stage354_corrupt_profile_schema_version_hard_fails(tmp_path: Path) -> None:
    configure_engine_profile_corruption_policy("hard-fail")
    profiles_dir = bind_profile_database(tmp_path)
    persist_profile("renpy")
    tamper_profile_schema_version("renpy", 1004)

    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        load_engine_profile("renpy")

    stored = authoritative_model_state().read_profile("renpy")
    assert stored is not None and stored["schema_version"] == 1004
    assert profile_corruption_events_snapshot()[-1]["profile_corruption_policy"] == "hard-fail"
    assert not list(profiles_dir.glob("*.json"))


def test_stage354_missing_relational_profile_state_hard_fails(tmp_path: Path) -> None:
    configure_engine_profile_corruption_policy("hard-fail")
    profiles_dir = bind_profile_database(tmp_path)
    persist_profile("unity")
    delete_profile_singleton("unity", "profile_contamination_state")

    with pytest.raises(ProfileSchemaInvariantError, match="model_singleton_state_missing"):
        load_engine_profile("unity")

    assert profile_corruption_events_snapshot()[-1]["profile_corruption_type"] == "schema_contract"
    assert not list(profiles_dir.glob("*.json"))
