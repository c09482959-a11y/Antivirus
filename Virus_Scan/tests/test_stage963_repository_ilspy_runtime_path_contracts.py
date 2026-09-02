from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path
from types import SimpleNamespace

from Virus_Scan.core.ilspy_runtime import resolve_ilspy_path
from Virus_Scan.core.paths import configure_runtime_engine_and_ilspy, get_ilspy_dump_root
from Virus_Scan.runtime.config_state import configure_ilspy_path
from Virus_Scan.runtime.path_runtime_state import path_runtime_owner


def _args(scan_dir: Path, **overrides):
    values = {
        "dir": str(scan_dir),
        "engine": "auto",
        "ilspy": None,
        "ilspy_path": None,
        "ilspy_dump": None,
        "ilspy_timeout": 60,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_stage963_missing_ilspy_request_records_canonical_path_but_keeps_static_metadata_mode(tmp_path: Path) -> None:
    scan_dir = tmp_path / "UnityGame"
    managed_dir = scan_dir / "Game_Data" / "Managed"
    managed_dir.mkdir(parents=True)
    (managed_dir / "Assembly-CSharp.dll").write_bytes(b"not-a-real-pe")
    missing_ilspy = tmp_path / "tools" / "ilspycmd.exe"

    configure_ilspy_path(None)
    path_runtime_owner().configure_ilspy(path=None, use_ilspy=False, timeout_sec=60, dump_root=None)

    configure_runtime_engine_and_ilspy(
        _args(scan_dir, ilspy_path=str(missing_ilspy), ilspy_timeout="15")
    )
    snapshot = path_runtime_owner().snapshot()

    assert snapshot.cli_engine_hint == "auto"
    assert snapshot.scan_engine_hint in {"unity", "unknown"}
    assert snapshot.ilspy_path == str(missing_ilspy.resolve())
    assert resolve_ilspy_path("fallback-ilspy") == str(missing_ilspy.resolve())
    assert snapshot.use_ilspy is False
    assert snapshot.ilspy_timeout_sec == 15

    configure_ilspy_path(None)
    path_runtime_owner().configure_ilspy(path=None, use_ilspy=False, timeout_sec=60, dump_root=None)


def test_stage963_existing_ilspy_path_enables_runtime_snapshot_and_resolved_dump_root(tmp_path: Path) -> None:
    scan_dir = tmp_path / "Game"
    scan_dir.mkdir()
    ilspy = tmp_path / "bin" / "ilspycmd.exe"
    ilspy.parent.mkdir()
    ilspy.write_text("placeholder", encoding="utf-8")
    dump_root = tmp_path / "custom-dump"

    configure_ilspy_path(None)
    path_runtime_owner().configure_ilspy(path=None, use_ilspy=False, timeout_sec=60, dump_root=None)

    configure_runtime_engine_and_ilspy(
        _args(scan_dir, engine="UNITY", ilspy="auto", ilspy_path=str(ilspy), ilspy_dump=str(dump_root), ilspy_timeout="0")
    )
    snapshot = path_runtime_owner().snapshot()

    assert snapshot.cli_engine_hint == "unity"
    assert snapshot.ilspy_path == str(ilspy.resolve())
    assert resolve_ilspy_path("fallback-ilspy") == str(ilspy.resolve())
    assert snapshot.use_ilspy is True
    assert snapshot.ilspy_timeout_sec == 1
    assert snapshot.ilspy_dump_root == str(dump_root.resolve())
    assert dump_root.is_dir()

    configure_ilspy_path(None)
    path_runtime_owner().configure_ilspy(path=None, use_ilspy=False, timeout_sec=60, dump_root=None)


def test_stage963_ilspy_dump_root_is_derived_once_from_scan_parent_when_not_configured(tmp_path: Path) -> None:
    scan_dir = tmp_path / "Stage" / "ExtractedGame"
    scan_dir.mkdir(parents=True)
    target = scan_dir / "GameAssembly.dll"
    target.write_bytes(b"MZ")

    path_runtime_owner().configure_ilspy(path=None, use_ilspy=False, timeout_sec=60, dump_root=None)

    first = get_ilspy_dump_root(str(target))
    second = get_ilspy_dump_root(str(target))

    assert first == second
    assert Path(first) == tmp_path / "Stage" / "dump"
    assert Path(first).is_dir()

    path_runtime_owner().configure_ilspy(path=None, use_ilspy=False, timeout_sec=60, dump_root=None)


def test_stage963_ilspy_runtime_seam_has_static_config_owner_import_only() -> None:
    source = read_python_file(Path("Virus_Scan/core/ilspy_runtime.py"))
    tree = ast.parse(source)

    function_imports = [
        node
        for parent in ast.walk(tree)
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
        for node in getattr(parent, "body", [])
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    dynamic_import_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id == "__import__")
            or (isinstance(node.func, ast.Attribute) and node.func.attr in {"import_module"})
        )
    ]
    imported_modules = sorted(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )

    assert function_imports == []
    assert dynamic_import_calls == []
    assert imported_modules == sorted(["__future__", "typing", "Virus_Scan.runtime.config_state"])
