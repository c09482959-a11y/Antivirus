from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.tag_evidence_persistence import persisted_tag_frequency_projection
from Virus_Scan.models.profiles.extension_learning import update_behavior_bucket_learning
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.models.profiles.persistence import (
    load_engine_profile,
    save_engine_profile,
)
from Virus_Scan.models.profiles.persistence_snapshot import (
    persisted_engine_profile_snapshot,
)
from Virus_Scan.models.profiles.snapshots import (
    PROFILE_TAG_EVIDENCE_SCHEMA_VERSION,
    default_engine_profile,
    default_extension_baseline,
)
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state


def _isolate_profiles(tmp_path: Path) -> Path:
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)
    configure_profiles_dir(str(profiles_dir))
    state = profile_persistence_state()
    state.bind_profiles_dir(str(profiles_dir))
    state.clear_all_profiles()
    return profiles_dir


def test_stage2636_07_profile_defaults_have_one_versioned_tag_state() -> None:
    baseline = default_extension_baseline(".rpy")

    assert "raw_tags" not in baseline
    assert "tag_aliases" not in baseline
    assert baseline["tag_evidence"]["schema_version"] == PROFILE_TAG_EVIDENCE_SCHEMA_VERSION
    assert baseline["tag_evidence"]["records"] == {}


def test_stage2636_07_profile_learning_counts_aliases_as_one_root() -> None:
    baseline = default_extension_baseline(".rpy")

    result = update_behavior_bucket_learning(
        baseline, physical_tag_evidence(("browser_xhr_fetch",), one_root=True),
    )

    records = tuple(baseline["tag_evidence"]["records"].values())
    roots = {record["root_observation_id"] for record in records}
    publications = {record["publication_name"] for record in records}
    assert result["updated"] is True
    assert roots and len(roots) == 1
    assert {"browser_xhr_fetch", "asset_resource_fetch"} <= publications
    assert baseline["tag_evidence"]["summary"]["raw_observation_count"] == 1
    assert sum(baseline["tags"].values()) == 0


def test_stage2636_07_profile_load_materializes_current_v5_tag_projection(
    tmp_path: Path,
) -> None:
    profiles_dir = _isolate_profiles(tmp_path)
    profile = default_engine_profile("renpy")
    baseline = default_extension_baseline(".rpy")
    update_behavior_bucket_learning(
        baseline, physical_tag_evidence(("browser_xhr_fetch",), one_root=True),
    )
    profile["extension_baselines"] = {".rpy": baseline}
    persisted = persisted_engine_profile_snapshot(
        profile, expected_engine="renpy",
    )
    save_engine_profile("renpy", persisted, force=True)

    profile_persistence_state().clear_all_profiles()
    loaded = load_engine_profile("renpy")
    loaded_baseline = loaded["extension_baselines"][".rpy"]
    expected_tags = {
        tag: 0
        for tag in sorted(
            persisted_tag_frequency_projection(loaded_baseline["tag_evidence"]),
        )
    }
    assert loaded_baseline["tags"] == expected_tags
    assert "migration" not in loaded_baseline["tag_evidence"]
    assert (profiles_dir / "model_state.sqlite3").exists()
    assert not tuple(profiles_dir.glob("*.json*"))

    profile_persistence_state().clear_all_profiles()
    reloaded = load_engine_profile("renpy")
    assert reloaded["extension_baselines"][".rpy"]["tags"] == expected_tags

