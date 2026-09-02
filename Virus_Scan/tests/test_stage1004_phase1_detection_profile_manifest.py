"""Stage 1004 Phase 1 regression coverage for detection profile manifests."""

from __future__ import annotations

import pytest

from Virus_Scan.detection.profiles import engine_context, selection
from Virus_Scan.detection.profiles.contracts import DetectionProfileSnapshot


def test_detection_profile_selection_exports_names_not_snapshot_manifest() -> None:
    assert "DETECTION_PROFILE_NAMES" in selection.__all__
    assert "DETECTION_PROFILE_SNAPSHOTS" not in selection.__all__
    assert not hasattr(selection, "DETECTION_PROFILE_SNAPSHOTS")
    assert selection.DETECTION_PROFILE_NAMES == ("renpy", "rpgm", "unity", "media", "other")
    assert all(isinstance(name, str) for name in selection.DETECTION_PROFILE_NAMES)


def test_detection_profile_registry_is_private_mappingproxy_and_behaviour_preserved() -> None:
    registry = selection._DETECTION_PROFILE_BY_NAME
    with pytest.raises(TypeError):
        registry["renpy"] = registry["renpy"]

    renpy = selection.profile_for_engine("renpy_engine")
    assert isinstance(renpy, DetectionProfileSnapshot)
    assert renpy.name == "renpy"
    assert selection.canonical_profile_name("unknown-engine") == "other"


def test_engine_context_uses_private_profile_names_not_profile_object_tuple() -> None:
    assert not hasattr(engine_context, "_ENGINE_PROFILES")
    assert engine_context._ENGINE_PROFILE_NAMES == ("renpy", "rpgm", "unity", "media")
    assert all(isinstance(name, str) for name in engine_context._ENGINE_PROFILE_NAMES)

    context = engine_context.infer_engine_context(("renpy_script",), file_structure="game/script.rpy")
    assert context["renpy"] > context["unity"]
    assert engine_context.select_active_profile_engine({"unity": 1.0}) == "unity"
