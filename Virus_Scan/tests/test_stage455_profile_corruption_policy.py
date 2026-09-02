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
from Virus_Scan.models.profiles.quarantine import handle_invalid_engine_profile
from Virus_Scan.storage import authoritative_model_state
from Virus_Scan.tests.support.sqlite_profile_state import (
    bind_profile_database,
    persist_profile,
    tamper_profile_schema_version,
)


def test_policy_c_hard_fail_is_default_and_preserves_corrupt_profile(tmp_path: Path) -> None:
    configure_engine_profile_corruption_policy("hard-fail")
    profiles_dir = bind_profile_database(tmp_path)
    persist_profile("renpy")
    tamper_profile_schema_version("renpy", PROFILE_SCHEMA_VERSION + 1)

    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        load_engine_profile("renpy")

    stored = authoritative_model_state().read_profile("renpy")
    assert stored is not None
    assert stored["schema_version"] == PROFILE_SCHEMA_VERSION + 1
    assert profile_corruption_events_snapshot()[-1]["profile_quarantined"] is False
    assert not list(profiles_dir.glob("*.json"))


def test_policy_c_quarantine_is_explicit_and_records_durable_evidence(tmp_path: Path) -> None:
    configure_engine_profile_corruption_policy("quarantine")
    profiles_dir = bind_profile_database(tmp_path)
    persist_profile("renpy")
    tamper_profile_schema_version("renpy", PROFILE_SCHEMA_VERSION + 1)

    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        load_engine_profile("renpy")

    event = profile_corruption_events_snapshot()[-1]
    assert event["profile_corruption_policy"] == "quarantine"
    assert event["profile_quarantined"] is True
    assert event["actual_schema_version"] == PROFILE_SCHEMA_VERSION + 1
    assert event["profile_corruption_reason"].endswith("invalid profile schema_version")
    assert event["scan_continued"] is False
    stored = authoritative_model_state().read_profile("renpy")
    assert stored is not None and stored["schema_version"] == PROFILE_SCHEMA_VERSION + 1
    assert not list(profiles_dir.glob("*.json"))


@pytest.mark.parametrize(
    ("engine", "payload", "reason", "corruption_type"),
    [
        ("renpy", None, "malformed or unreadable profile JSON", "malformed_json"),
        ("rpgm", {"engine": "rpgm"}, "malformed or unreadable profile JSON", "malformed_json"),
        ("unity", {"engine": "unity", "schema_version": PROFILE_SCHEMA_VERSION, "model_state": {}}, "missing extension_baselines", "extension_baselines"),
        ("media", {"engine": "media", "schema_version": PROFILE_SCHEMA_VERSION, "extension_baselines": [], "model_state": {}}, "extension_baselines must be an object", "extension_baselines"),
        ("other", {"engine": "other", "schema_version": PROFILE_SCHEMA_VERSION, "extension_baselines": {}, "model_state": []}, "model_state must be an object", "model_state"),
    ],
)
def test_policy_c_fixture_classes_record_relational_quarantine_evidence(
    tmp_path: Path, engine: str, payload: object, reason: str, corruption_type: str,
) -> None:
    configure_engine_profile_corruption_policy("quarantine")
    profiles_dir = bind_profile_database(tmp_path)

    with pytest.raises(ProfileSchemaInvariantError, match=reason):
        handle_invalid_engine_profile(engine, reason, profile=payload)

    stored = authoritative_model_state().read_profile(engine)
    assert stored is None
    event = profile_corruption_events_snapshot()[-1]
    assert reason in event["profile_corruption_reason"]
    assert event["profile_corruption_type"] == corruption_type
    assert event["profile_quarantined"] is True
    assert event["scan_continued"] is False
    assert not list(profiles_dir.glob("*.json"))
