from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from Virus_Scan.models.profiles.persistence import load_engine_profile
from Virus_Scan.models.profiles.persistence_snapshot import (
    persisted_engine_profile_snapshot,
)
from Virus_Scan.models.profiles.replay_learning import (
    save_benign_candidate_store,
)
from Virus_Scan.models.profiles.schema import (
    ProfileSchemaInvariantError,
    validate_engine_profile_schema,
)
from Virus_Scan.models.profiles.schema_versions import (
    PROFILE_SCHEMA_VERSION,
    PROFILE_STAGED_STORE_SCHEMA_VERSION,
)
from Virus_Scan.models.profiles.snapshots import (
    default_engine_profile,
    default_extension_baseline,
)
from Virus_Scan.models.profiles.staged_store_schema import (
    default_staged_benign_store,
)
from Virus_Scan.runtime.config_state import (
    configure_profile_corruption_policy,
)
from Virus_Scan.storage import authoritative_model_state, learning_candidate_store
from Virus_Scan.tests.support.sqlite_profile_state import (
    bind_profile_database,
    persist_profile,
    tamper_profile_schema_version,
)


class _HostileProfile(dict):
    def get(self, *_args: object, **_kwargs: object) -> object:
        raise AssertionError("hostile profile hook executed")


def _isolate(tmp_path: Path) -> Path:
    profiles = bind_profile_database(tmp_path)
    configure_profile_corruption_policy("hard-fail")
    return profiles


def test_phase8_current_schema_rejects_mapping_subclasses_without_hooks() -> None:
    hostile = _HostileProfile(default_engine_profile("renpy"))
    with pytest.raises(ProfileSchemaInvariantError, match="profile must be an object"):
        validate_engine_profile_schema(hostile, expected_engine="renpy")


def test_phase8_non_v5_profile_is_rejected_without_mutation() -> None:
    profile = default_engine_profile("renpy")
    profile["schema_version"] = 4
    before = deepcopy(profile)
    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        validate_engine_profile_schema(profile, expected_engine="renpy")
    assert profile == before


def test_phase8_malformed_current_schema_is_not_repaired() -> None:
    profile = default_engine_profile("renpy")
    baseline = default_extension_baseline(".rpy")
    baseline.pop("timeline_baseline")
    profile["extension_baselines"][".rpy"] = baseline
    with pytest.raises(ProfileSchemaInvariantError, match="timeline_baseline"):
        validate_engine_profile_schema(profile, expected_engine="renpy")
    assert "timeline_baseline" not in baseline


def test_phase8_persistence_snapshot_is_detached_and_projection_free() -> None:
    profile = default_engine_profile("renpy")
    baseline = default_extension_baseline(".rpy")
    baseline["tags"] = {"benign_asset": 0}
    profile["extension_baselines"][".rpy"] = baseline
    snapshot = persisted_engine_profile_snapshot(profile, expected_engine="renpy")
    assert snapshot["schema_version"] == PROFILE_SCHEMA_VERSION
    assert "tags" not in snapshot["extension_baselines"][".rpy"]
    assert profile["extension_baselines"][".rpy"]["tags"] == {"benign_asset": 0}
    assert snapshot is not profile


def test_phase8_malformed_staged_store_rolls_back_without_replacement(
    tmp_path: Path,
) -> None:
    _isolate(tmp_path)
    current = default_staged_benign_store()
    assert save_benign_candidate_store(current) is True
    before = learning_candidate_store().read_staged_store()
    malformed = {
        "schema_version": PROFILE_STAGED_STORE_SCHEMA_VERSION,
        "candidates": [],
    }

    with pytest.raises(ValueError, match="staged benign store"):
        save_benign_candidate_store(malformed)

    assert learning_candidate_store().read_staged_store() == before


def test_phase8_noncurrent_staged_store_is_rejected_without_rewrite(
    tmp_path: Path,
) -> None:
    _isolate(tmp_path)
    current = default_staged_benign_store()
    assert save_benign_candidate_store(current) is True
    before = learning_candidate_store().read_staged_store()
    noncurrent = {
        "schema_version": "profile_staged_benign_store_v0",
        "candidates": {},
        "promotions": 0,
        "rejections": {},
        "observation_ledger": current["observation_ledger"],
    }

    with pytest.raises(ValueError, match="staged benign store schema invalid"):
        save_benign_candidate_store(noncurrent)

    assert learning_candidate_store().read_staged_store() == before


def test_phase8_non_v5_engine_profile_is_not_converted_on_load(
    tmp_path: Path,
) -> None:
    profiles = _isolate(tmp_path)
    persist_profile("renpy")
    tamper_profile_schema_version("renpy", 4)

    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        load_engine_profile("renpy")

    stored = authoritative_model_state().read_profile("renpy")
    assert stored is not None
    assert stored["schema_version"] == 4
    assert not list(profiles.glob("*.json"))


def test_phase8_current_staged_schema_has_no_conversion_state() -> None:
    assert PROFILE_STAGED_STORE_SCHEMA_VERSION == "profile_staged_benign_store_v1"
    assert not Path("Virus_Scan/models/profiles/schema_migration.py").exists()
    assert not Path("Virus_Scan/models/profiles/legacy_schema.py").exists()
    assert not Path("Virus_Scan/models/profiles/feature_migration.py").exists()
