from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
from pathlib import Path

from Virus_Scan.detection.profiles.engine_context import (
    engine_confidence_report,
    infer_engine_context,
    select_active_profile_engine,
)



class HostileText:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")


class HostileIterable:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")


class HostileFloat:
    touched = 0

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not float")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")


class HostileMapping(dict):
    touched = 0

    def keys(self):
        type(self).touched += 1
        raise RuntimeError("do not call keys")

    def __getitem__(self, key):
        type(self).touched += 1
        raise RuntimeError("do not getitem")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not call items")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")


def test_stage1601_engine_context_rejects_hostile_text_and_iterables_without_hooks():
    HostileText.touched = 0
    HostileIterable.touched = 0

    context = infer_engine_context(
        HostileIterable(),
        file_structure=HostileText(),
        strings_blob=HostileText(),
    )
    report = engine_confidence_report(
        context,
        tags=HostileIterable(),
        path=HostileText(),
        strings_blob=HostileText(),
    )

    assert HostileText.touched == 0
    assert HostileIterable.touched == 0
    assert context["unknown"] > 0.0
    assert report["active_profile"] in {"other", "renpy", "rpgm", "unity", "media"}


def test_stage1601_engine_context_rejects_hostile_mapping_and_threshold_without_hooks():
    HostileMapping.touched = 0
    HostileFloat.touched = 0

    selected = select_active_profile_engine(HostileMapping({"renpy": 1.0}), threshold=HostileFloat())
    report = engine_confidence_report(HostileMapping({"renpy": 1.0}))

    assert HostileMapping.touched == 0
    assert HostileFloat.touched == 0
    assert selected == "other"
    assert report["active_profile"] == "other"
    assert report["raw_context"] == {}


def test_stage1601_engine_context_preserves_exact_builtin_evidence():
    context = infer_engine_context(
        ["renpy", "media_asset"],
        file_structure="game/scripts/main.rpy",
        strings_blob="init python renpy.exports",
    )
    assert context["renpy"] > context["unknown"]
    assert select_active_profile_engine({"renpy": 0.95}, threshold=0.8) == "renpy"
    report = engine_confidence_report({"renpy": 0.95}, path="game/scripts/main.rpy", tags=("renpy",))
    assert report["active_profile"] == "renpy"
    assert report["baseline_suppression_allowed"] is True


def test_stage1601_engine_context_source_removes_hookable_mapping_snippets():
    source = read_python_file(Path("Virus_Scan/detection/profiles/engine_context.py"))
    tree = ast.parse(source)
    forbidden = (
        'key_text = f"engine_context_key_{index}"',
        "total = sum(scores.values()) + 1e-6",
        "return freeze_registry_value({key: _clamp(value / total) for key, value in scores.items()})",
        "for key, value in ctx.items()",
    )
    assert [snippet for snippet in forbidden if snippet in source] == []
    assert [node for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []
