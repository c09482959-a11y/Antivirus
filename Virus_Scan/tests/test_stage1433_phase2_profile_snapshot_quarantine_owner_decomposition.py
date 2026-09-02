from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

import pytest

from Virus_Scan.models import profiles
from Virus_Scan.models.profiles import quarantine as profile_quarantine
from Virus_Scan.models.profiles.schema import ProfileSchemaInvariantError
from Virus_Scan.models.profiles import snapshots as profile_snapshots
from Virus_Scan.tests.support.sqlite_profile_state import bind_profile_database


def test_stage1433_profile_snapshot_and_quarantine_owners_are_explicit_modules():
    assert Path("Virus_Scan/models/profiles/snapshots.py").exists()
    assert Path("Virus_Scan/models/profiles/quarantine.py").exists()
    assert profiles.default_engine_profile.__module__ == "Virus_Scan.models.profiles.snapshots"
    assert profiles.default_extension_baseline.__module__ == "Virus_Scan.models.profiles.snapshots"
    assert profiles.profile_corruption_events_snapshot.__module__ == "Virus_Scan.models.profiles.quarantine"


def test_stage1433_profile_api_no_longer_owns_snapshot_or_quarantine_functions():
    api_source = read_python_file(Path("Virus_Scan/models/profiles/api.py"))
    snapshots_source = read_python_file(Path("Virus_Scan/models/profiles/snapshots.py"))
    quarantine_source = read_python_file(Path("Virus_Scan/models/profiles/quarantine.py"))
    assert "from Virus_Scan.models.profiles.snapshots import" in api_source
    assert "from Virus_Scan.models.profiles.quarantine import" in api_source
    assert "def default_engine_profile" not in api_source
    assert "def default_extension_baseline" not in api_source
    assert "def handle_invalid_engine_profile" not in api_source
    assert "def default_engine_profile" in snapshots_source
    assert "def handle_invalid_engine_profile" in quarantine_source
    assert "authoritative_model_state().replace_corrupt_profile" not in quarantine_source
    assert "authoritative_model_state().record_profile_corruption_event" in quarantine_source
    assert "def _profile_quarantine_path" not in quarantine_source
    assert ".invalid_schema" not in quarantine_source
    assert "from Virus_Scan.models.profiles.api" not in snapshots_source
    assert "from Virus_Scan.models.profiles.api" not in quarantine_source


def test_stage1433_snapshot_defaults_are_fresh_mutable_containers_without_shared_state():
    first = profile_snapshots.default_engine_profile("renpy")
    second = profile_snapshots.default_engine_profile("renpy")
    first["extension_baselines"][".rpy"] = {"files": 1}
    assert second["extension_baselines"] == {}
    baseline_one = profile_snapshots.default_extension_baseline(".rpy")
    baseline_two = profile_snapshots.default_extension_baseline(".rpy")
    baseline_one["tags"]["example"] = 1
    assert baseline_two["tags"] == {}


def test_stage1433_quarantine_evidence_is_database_owned_without_api_cycle(tmp_path):
    bind_profile_database(tmp_path)
    profiles.configure_engine_profile_corruption_policy("quarantine")

    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        profile_quarantine.handle_invalid_engine_profile(
            "renpy", "invalid profile schema_version", profile={"schema_version": "bad"},
        )
    events = profile_quarantine.profile_corruption_events_snapshot()

    assert events[-1]["profile_path"].endswith("model_state.sqlite3#profile/renpy")
    assert "profile_quarantine_path" not in events[-1]
    assert events[-1]["profile_quarantined"] is True
    assert events[-1]["scan_continued"] is False
