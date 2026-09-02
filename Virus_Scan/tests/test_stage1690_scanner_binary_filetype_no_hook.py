"""Stage 1690: scanner binary filetype/path identity no-hook boundaries."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners.binary_filetype import (
    _actual_filetype_category,
    _filetype_claim_matches_actual,
    _filetype_misclassification_severity,
    engine_extension_key,
    filetype_validation_context,
    get_engine_filetype_info,
    get_global_filetype_info,
    update_filetype,
)
from Virus_Scan.scanners.binary_path_identity import get_binary_scan_extension, normalize_binary_profile_extension


class HostilePath:
    touched = 0

    def __bool__(self):
        HostilePath.touched += 1
        raise RuntimeError("do not call bool")

    def __str__(self):
        HostilePath.touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        HostilePath.touched += 1
        raise RuntimeError("do not call repr")

    def __fspath__(self):
        HostilePath.touched += 1
        raise RuntimeError("do not call fspath")


class HostileText:
    touched = 0

    def __bool__(self):
        HostileText.touched += 1
        raise RuntimeError("do not call bool")

    def __str__(self):
        HostileText.touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        HostileText.touched += 1
        raise RuntimeError("do not call repr")

    def __eq__(self, other):
        HostileText.touched += 1
        raise RuntimeError("do not compare")


class HostileIterable:
    touched = 0

    def __bool__(self):
        HostileIterable.touched += 1
        raise RuntimeError("do not call bool")

    def __iter__(self):
        HostileIterable.touched += 1
        raise RuntimeError("do not iterate")

    def __str__(self):
        HostileIterable.touched += 1
        raise RuntimeError("do not call str")


class HostileTag:
    touched = 0

    def __str__(self):
        HostileTag.touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        HostileTag.touched += 1
        raise RuntimeError("do not call repr")

    def __bool__(self):
        HostileTag.touched += 1
        raise RuntimeError("do not call bool")


def _reset() -> None:
    HostilePath.touched = 0
    HostileText.touched = 0
    HostileIterable.touched = 0
    HostileTag.touched = 0


def test_binary_path_identity_rejects_hostile_path_without_str_repr_fspath_or_bool() -> None:
    _reset()
    path = HostilePath()
    assert get_binary_scan_extension(path) == ""
    assert normalize_binary_profile_extension(path) == "<no_ext>"
    assert HostilePath.touched == 0


def test_engine_and_filetype_info_reject_hostile_engine_and_path_without_hooks() -> None:
    _reset()
    engine = HostileText()
    path = HostilePath()
    assert engine_extension_key(engine, path) == "other:<no_ext>"
    assert get_engine_filetype_info(engine, path)["extension"] == "<no_ext>"
    assert get_global_filetype_info(path)["extension"] == "<no_ext>"
    ctx = filetype_validation_context(engine, path)
    assert ctx["extension"] == "<no_ext>"
    assert HostileText.touched == 0
    assert HostilePath.touched == 0


def test_magic_and_claim_classification_reject_hostile_text_without_comparison_hooks() -> None:
    _reset()
    hostile = HostileText()
    assert _actual_filetype_category(hostile, hostile) == "unknown"
    assert _filetype_claim_matches_actual(hostile, hostile, hostile) is False
    assert _filetype_misclassification_severity(hostile, hostile, hostile) == (0, "none")
    assert HostileText.touched == 0


def test_update_filetype_rejects_hostile_iterables_and_tag_objects_without_hooks() -> None:
    _reset()
    assert update_filetype("DLL", HostileIterable()) == {
        "updated": False,
        "reason": "no_behavior_flow",
        "publication_request": None,
    }
    assert HostileIterable.touched == 0

    result = update_filetype("DLL", [HostileTag(), " Network "])
    assert result["updated"] is True
    assert result["extension"] == "dll"
    assert result["flow"] == ("network",)
    assert HostileTag.touched == 0


def test_binary_filetype_modules_do_not_use_raw_str_repr_fspath_or_truthiness_boundaries() -> None:
    for file_name in ("binary_path_identity.py", "binary_filetype.py"):
        tree = ast.parse(Path("Virus_Scan/scanners", file_name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"str", "repr", "format"}
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr != "__fspath__"
