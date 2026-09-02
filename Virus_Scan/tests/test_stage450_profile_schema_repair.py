from pathlib import Path

import pytest

from Virus_Scan.models.profiles import (
    PROFILE_SCHEMA_VERSION,
    ProfileSchemaInvariantError,
    configure_engine_profile_corruption_policy,
    load_engine_profile,
    profile_corruption_events_snapshot,
)
from Virus_Scan.storage import authoritative_model_state
from Virus_Scan.tests.support.sqlite_profile_state import (
    bind_profile_database,
    persist_profile,
    tamper_profile_schema_version,
)


def test_invalid_profile_schema_quarantine_fails_closed_and_preserves_authority(
    tmp_path: Path,
) -> None:
    configure_engine_profile_corruption_policy("quarantine")
    profiles_dir = bind_profile_database(tmp_path)
    persist_profile("renpy")
    tamper_profile_schema_version("renpy", 1)

    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        load_engine_profile("renpy")

    stored = authoritative_model_state().read_profile("renpy")
    assert stored is not None and stored["schema_version"] == 1
    event = profile_corruption_events_snapshot()[-1]
    assert event["profile_quarantined"] is True
    assert event["actual_schema_version"] == 1
    assert event["scan_continued"] is False
    assert not list(profiles_dir.glob("*.json"))


def test_invalid_profile_schema_hard_fails_and_preserves_database_row(tmp_path: Path) -> None:
    configure_engine_profile_corruption_policy("hard-fail")
    profiles_dir = bind_profile_database(tmp_path)
    persist_profile("renpy")
    tamper_profile_schema_version("renpy", 1)

    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        load_engine_profile("renpy")

    stored = authoritative_model_state().read_profile("renpy")
    assert stored is not None and stored["schema_version"] == 1
    event = profile_corruption_events_snapshot()[-1]
    assert event["profile_quarantined"] is False
    assert event["scan_continued"] is False
    assert not list(profiles_dir.glob("*.json"))
