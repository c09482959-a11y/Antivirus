from __future__ import annotations

import json
from pathlib import Path

import pytest

from Virus_Scan.contracts.worker_record import make_json_safe
from Virus_Scan.models.profiles import (
    PROFILE_SCHEMA_VERSION,
    ProfileSchemaInvariantError,
    configure_engine_profile_corruption_policy,
    profile_corruption_events_snapshot,
)
from Virus_Scan.models.profiles.quarantine import handle_invalid_engine_profile
from Virus_Scan.tests.support.sqlite_profile_state import bind_profile_database


def test_stage1317_profile_corruption_nonfinite_schema_is_explicit_json_safe_evidence(
    tmp_path: Path,
) -> None:
    configure_engine_profile_corruption_policy("quarantine")
    profiles_dir = bind_profile_database(tmp_path)

    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        handle_invalid_engine_profile(
            "renpy", "invalid profile schema_version",
            profile={"schema_version": float("nan")},
        )

    evidence = profile_corruption_events_snapshot()[-1]
    assert evidence["profile_corruption_type"] == "schema_version"
    assert evidence["actual_schema_version"] == {
        "profile_value_unavailable": True,
        "reason": "non_finite_profile_corruption_value",
        "value": "nan",
    }
    json.dumps(make_json_safe(evidence), sort_keys=True, allow_nan=False)

    safe_snapshot = make_json_safe({"profile_events": profile_corruption_events_snapshot()})
    assert safe_snapshot["profile_events"][-1]["actual_schema_version"] == evidence[
        "actual_schema_version"
    ]
    json.dumps(safe_snapshot, sort_keys=True, allow_nan=False)
    assert not list(profiles_dir.glob("*.json"))


def test_stage1317_profile_corruption_content_key_is_root_independent(
    tmp_path: Path,
) -> None:
    configure_engine_profile_corruption_policy("quarantine")
    bind_profile_database(tmp_path / "first")
    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        handle_invalid_engine_profile(
            "renpy", "invalid profile schema_version",
            profile={"schema_version": float("inf")},
        )
    first = profile_corruption_events_snapshot()[-1]

    bind_profile_database(tmp_path / "second")
    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        handle_invalid_engine_profile(
            "renpy", "invalid profile schema_version",
            profile={"schema_version": float("inf")},
        )
    second = profile_corruption_events_snapshot()[-1]

    assert first["profile_corruption_event_key"] != second["profile_corruption_event_key"]
    assert first["profile_corruption_content_key"] == second["profile_corruption_content_key"]
    assert first["actual_schema_version"] == second["actual_schema_version"]
    json.dumps(make_json_safe(first), sort_keys=True, allow_nan=False)
    json.dumps(make_json_safe(second), sort_keys=True, allow_nan=False)
