from __future__ import annotations

import pytest

from Virus_Scan.models import profiles
from Virus_Scan.models.api import profile_contracts
from Virus_Scan.tests.support.sqlite_profile_state import bind_profile_database


def test_stage1392_profile_public_contract_validates_schema_through_profile_owner() -> None:
    profile = profiles.default_engine_profile("renpy")

    assert "validate_engine_profile_schema" in profile_contracts.__all__
    assert profile_contracts.validate_engine_profile_schema(profile, expected_engine="renpy") is True

    invalid = dict(profile)
    invalid["schema_version"] = profiles.PROFILE_SCHEMA_VERSION + 1
    with pytest.raises(profile_contracts.ProfileSchemaInvariantError):
        profile_contracts.validate_engine_profile_schema(invalid, expected_engine="renpy")


def test_stage1392_profile_public_reads_do_not_leak_mutable_model_state() -> None:
    public_profile = profile_contracts.default_engine_profile("renpy")

    with pytest.raises(TypeError):
        public_profile["schema_version"] = 0
    with pytest.raises(TypeError):
        public_profile["model_state"]["vector_baselines"] = {}

    fresh_profile = profiles.default_engine_profile("renpy")
    assert fresh_profile["schema_version"] == profiles.PROFILE_SCHEMA_VERSION
    assert fresh_profile["model_state"]["vector_baselines"] == {}


def test_stage1392_profile_corruption_snapshot_public_contract_is_immutable(tmp_path) -> None:
    assert "profile_corruption_events_snapshot" in profile_contracts.__all__

    bind_profile_database(tmp_path)
    snapshot = profile_contracts.profile_corruption_events_snapshot()
    assert isinstance(snapshot, tuple)
    if snapshot:
        with pytest.raises(TypeError):
            snapshot[0]["profile_schema_error"] = False
