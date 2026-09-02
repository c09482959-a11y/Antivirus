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
from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles
from Virus_Scan.storage import authoritative_model_state
from Virus_Scan.tests.support.sqlite_profile_state import (
    bind_profile_database,
    persist_profile,
    tamper_profile_schema_version,
)


def test_rev15_missing_profile_requires_explicit_persisted_bootstrap(tmp_path: Path) -> None:
    configure_engine_profile_corruption_policy("hard-fail")
    bind_profile_database(tmp_path)

    with pytest.raises(ProfileSchemaInvariantError, match="canonical bootstrap required"):
        load_engine_profile("renpy")

    assert authoritative_model_state().read_profile("renpy") is None

    result = ensure_authoritative_engine_profiles()
    assert "renpy" in result["created"]
    persisted = authoritative_model_state().read_profile("renpy")
    assert persisted is not None
    assert persisted["schema_version"] == PROFILE_SCHEMA_VERSION
    assert load_engine_profile("renpy")["schema_version"] == PROFILE_SCHEMA_VERSION


def test_rev15_quarantine_policy_never_replaces_invalid_authority_with_default(tmp_path: Path) -> None:
    configure_engine_profile_corruption_policy("quarantine")
    bind_profile_database(tmp_path)
    persist_profile("renpy")
    tamper_profile_schema_version("renpy", PROFILE_SCHEMA_VERSION + 1)

    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        load_engine_profile("renpy")

    persisted = authoritative_model_state().read_profile("renpy")
    assert persisted is not None
    assert persisted["schema_version"] == PROFILE_SCHEMA_VERSION + 1
    event = profile_corruption_events_snapshot()[-1]
    assert event["profile_corruption_policy"] == "quarantine"
    assert event["profile_quarantined"] is True
    assert event["scan_continued"] is False
