"""Phase 2 regression tests for orchestration publication API ownership."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.publication.api import finalize_scan_results, recover_results_from_partial


def test_orchestration_lifecycle_uses_public_publication_api_only():
    path = Path("Virus_Scan/orchestration/lifecycle.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    publication_imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("Virus_Scan.publication"):
            publication_imports.append(node.module)
        elif isinstance(node, ast.Import):
            publication_imports.extend(
                alias.name for alias in node.names if alias.name.startswith("Virus_Scan.publication")
            )
    assert publication_imports == ["Virus_Scan.publication.api"]


def test_publication_api_exports_final_json_ownership_surface():
    assert callable(finalize_scan_results)
    assert callable(recover_results_from_partial)
