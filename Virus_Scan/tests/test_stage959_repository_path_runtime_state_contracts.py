from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path
from typing import Mapping

import pytest

from Virus_Scan.runtime.path_runtime_state import PathRuntimeStateOwner, path_runtime_owner


def test_stage959_path_runtime_engine_snapshot_normalizes_and_detaches_context() -> None:
    owner = PathRuntimeStateOwner()
    context = {"Unity": 0.9, "unknown": 0.1}

    owner.configure_engine("  AUTO  ", "  UNITY  ", context)
    snapshot = owner.snapshot()
    context["Unity"] = 0.0

    assert snapshot.cli_engine_hint == "auto"
    assert snapshot.scan_engine_hint == "unity"
    assert snapshot.scan_engine_hint_context == {"Unity": 0.9, "unknown": 0.1}

    followup = owner.snapshot()
    assert followup.scan_engine_hint_context == {"Unity": 0.9, "unknown": 0.1}
    with pytest.raises(TypeError):
        snapshot.scan_engine_hint_context["Unity"] = 0.2


def test_stage959_path_runtime_ilspy_configuration_clears_cache_and_bounds_timeout() -> None:
    owner = PathRuntimeStateOwner()

    assert owner.ilspy_cache_set("Assembly-CSharp.dll", "cached.il") == "cached.il"
    assert owner.ilspy_cache_contains("Assembly-CSharp.dll") is True

    owner.configure_ilspy(path="tool/ilspycmd", use_ilspy=True, timeout_sec=0, dump_root="Dump/IL")
    snapshot = owner.snapshot()

    assert snapshot.ilspy_path == "tool/ilspycmd"
    assert snapshot.use_ilspy is True
    assert snapshot.ilspy_timeout_sec == 60
    assert snapshot.ilspy_dump_root == "Dump/IL"
    assert owner.ilspy_cache_contains("Assembly-CSharp.dll") is False
    assert owner.ilspy_cache_get("Assembly-CSharp.dll") is None

    owner.configure_ilspy(path=None, use_ilspy=False, timeout_sec=-5, dump_root=None)
    assert owner.snapshot().ilspy_timeout_sec == 1

    assert owner.set_ilspy_dump_root(None) is None
    assert owner.ilspy_dump_root() is None


def test_stage959_path_runtime_public_owner_is_singleton_and_has_default_snapshot() -> None:
    first = path_runtime_owner()
    second = path_runtime_owner()
    snapshot = first.snapshot()

    assert first is second
    assert snapshot.cli_engine_hint
    assert snapshot.scan_engine_hint
    assert isinstance(snapshot.scan_engine_hint_context, Mapping)
    with pytest.raises(TypeError):
        snapshot.scan_engine_hint_context["new"] = 1
    assert isinstance(snapshot.use_ilspy, bool)
    assert snapshot.ilspy_timeout_sec >= 1


def test_stage959_path_runtime_state_static_import_boundary() -> None:
    source = read_python_file(Path("Virus_Scan/runtime/path_runtime_state.py"))
    tree = ast.parse(source)

    function_imports = []
    for parent in ast.walk(tree):
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            function_imports.extend(
                node for node in ast.walk(parent) if isinstance(node, (ast.Import, ast.ImportFrom))
            )
    dynamic_imports = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__"]
    forbidden_cross_domain_imports = [
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module
        and node.module.startswith((
            "Virus_Scan.scheduler",
            "Virus_Scan.detection",
            "Virus_Scan.scanners",
            "Virus_Scan.reporting",
        ))
    ]

    assert function_imports == []
    assert dynamic_imports == []
    assert forbidden_cross_domain_imports == []
