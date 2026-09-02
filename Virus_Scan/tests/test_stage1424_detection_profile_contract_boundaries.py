
"""Stage 1424: detection profile contracts must not truthiness-probe caller values."""

from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.detection.models.stage_value_utils import thaw_detection_value
from Virus_Scan.detection.profiles.contracts import DetectionProfileContext, DetectionProfileSnapshot


class HostileBoolIterable:
    def __bool__(self):  # pragma: no cover - exercised by contract normalization
        raise RuntimeError("iterable truthiness unavailable")

    def __iter__(self):  # pragma: no cover - exercised by contract normalization
        raise RuntimeError("iterable unavailable")


class HostileText:
    def __bool__(self):  # pragma: no cover - old value-or-default code probed this
        raise RuntimeError("text truthiness unavailable")

    def __str__(self):  # pragma: no cover - safe text should convert to evidence
        raise RuntimeError("text unavailable")


class UnreadableMapping(Mapping):
    def __bool__(self):  # pragma: no cover - old value-or-default code probed this
        raise RuntimeError("mapping truthiness unavailable")

    def __iter__(self):
        raise RuntimeError("mapping iteration unavailable")

    def __len__(self):
        raise RuntimeError("mapping length unavailable")

    def __getitem__(self, key):
        raise RuntimeError("mapping item unavailable")

    def keys(self):
        raise RuntimeError("mapping keys unavailable")


class HostileValue:
    def __str__(self):  # pragma: no cover - exercised by tuple normalization
        raise RuntimeError("value text unavailable")


class HostileSelectedProfile:
    touched = 0

    def __getattr__(self, _name):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("selected profile getattr unavailable")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise RuntimeError("selected profile truthiness unavailable")


def _reasons(records) -> set[str]:
    thawed = thaw_detection_value(records)
    return {item.get("unavailable_reason") for item in thawed if isinstance(item, dict)}


def test_stage1424_profile_snapshot_records_hostile_constructor_values() -> None:
    snapshot = DetectionProfileSnapshot(
        name=HostileText(),
        aliases=HostileBoolIterable(),
        tag_markers=(HostileValue(),),
        file_extensions=HostileBoolIterable(),
        baseline_suppression_profile=HostileText(),
        selected_engine_context_key=HostileText(),
    )

    assert snapshot.name == "other"
    assert snapshot.aliases == ()
    assert snapshot.file_extensions == frozenset()
    assert snapshot.baseline_suppression_profile == "other"
    assert snapshot.selected_engine_context_key == "unknown"
    assert {
        "profile_snapshot_name_unavailable",
        "profile_snapshot_aliases_unavailable",
        "profile_snapshot_tag_markers_unavailable",
        "profile_snapshot_file_extensions_unavailable",
        "profile_snapshot_baseline_suppression_profile_unavailable",
        "profile_snapshot_selected_engine_context_key_unavailable",
    } <= _reasons(snapshot.failure_evidence)
    assert _reasons(snapshot.to_record()["failure_evidence"]) == _reasons(snapshot.failure_evidence)


def test_stage1424_profile_context_records_hostile_mappings_and_selection_reasons() -> None:
    snapshot = DetectionProfileSnapshot(
        name="renpy",
        aliases=("renpy",),
        tag_markers=("renpy_script",),
        file_extensions=(".rpy",),
        baseline_suppression_profile="renpy",
        selected_engine_context_key="renpy",
    )
    context = DetectionProfileContext(
        active_profile=HostileText(),
        selected_profile=snapshot,
        engine_context=UnreadableMapping(),
        engine_confidence=UnreadableMapping(),
        selection_reasons=HostileBoolIterable(),
    )

    assert context.active_profile == "other"
    assert thaw_detection_value(context.engine_context)["unavailable_reason"] == "detection_mapping_keys_unavailable"
    assert thaw_detection_value(context.engine_confidence)["unavailable_reason"] == "detection_mapping_keys_unavailable"
    assert context.selection_reasons == ()
    assert {
        "profile_context_active_profile_unavailable",
        "profile_context_engine_context_unavailable",
        "profile_context_engine_confidence_unavailable",
        "profile_context_selection_reasons_unavailable",
    } <= _reasons(context.failure_evidence)
    assert _reasons(context.to_record()["failure_evidence"]) == _reasons(context.failure_evidence)


def test_stage1424_profile_context_rejects_hostile_selected_profile_without_getattr() -> None:
    HostileSelectedProfile.touched = 0

    context = DetectionProfileContext(
        active_profile="other",
        selected_profile=HostileSelectedProfile(),
        engine_context={},
        engine_confidence={},
        selection_reasons=(),
    )

    assert context.selected_profile.name == "other"
    assert "profile_context_selected_profile_unavailable" in _reasons(context.failure_evidence)
    assert context.to_record()["selected_profile"]["name"] == "other"
    assert HostileSelectedProfile.touched == 0


def test_stage1424_profile_match_name_is_bounded_and_valid_behavior_preserved() -> None:
    snapshot = DetectionProfileSnapshot(
        name="RenPy",
        aliases=("Ren'Py",),
        tag_markers=("rpy",),
        file_extensions=(".RPY",),
        baseline_suppression_profile="renpy",
        selected_engine_context_key="renpy",
    )

    assert snapshot.name == "renpy"
    assert snapshot.file_extensions == frozenset({".rpy"})
    assert snapshot.matches_name("REN'PY") is True
    assert snapshot.matches_name(HostileText()) is False


def test_stage1424_profile_contract_source_removes_hookable_text_and_getattr_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/detection/profiles/contracts.py"))
    tree = ast.parse(source)
    forbidden = (
        "fallback",
        "text, evidence = safe_detection_text(value, fallback, reason)",
        'getattr(self.selected_profile, "failure_evidence", ())',
    )
    assert [snippet for snippet in forbidden if snippet in source] == []
    assert [node for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []
