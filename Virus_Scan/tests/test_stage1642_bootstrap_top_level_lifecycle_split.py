from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path


def _imported_symbols(path: str) -> set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imported.update(f"{module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    return imported


def test_stage1642_bootstrap_no_longer_owns_full_top_level_initialization() -> None:
    bootstrap_source = read_python_file(Path("Virus_Scan/orchestration/bootstrap_initialization.py"))
    bootstrap_imports = _imported_symbols("Virus_Scan/orchestration/bootstrap_initialization.py")

    assert "Virus_Scan.init_runtime.top_level.run_top_level_init" not in bootstrap_imports
    assert "run_top_level_init()" not in bootstrap_source


def test_stage1642_lifecycle_owns_full_top_level_initialization_after_bootstrap() -> None:
    lifecycle_source = read_python_file(Path("Virus_Scan/orchestration/lifecycle.py"))
    lifecycle_imports = _imported_symbols("Virus_Scan/orchestration/lifecycle.py")

    assert "Virus_Scan.init_runtime.top_level.run_top_level_init" in lifecycle_imports
    assert "runtime.initialize(initialize_runtime)" in lifecycle_source
    assert "runtime.owner.refresh(run_top_level_init())" in lifecycle_source
