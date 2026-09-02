from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.publication.api import (
    clear_profile_scoring_snapshot,
    flush_all_persistent_models,
    persist_parent_learning_from_results,
    write_partial_scan_results,
)


def _module_imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
        elif isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
    return imports


def test_scheduler_runner_uses_publication_dependency_contract_not_model_internals():
    root = Path(__file__).resolve().parents[1]
    scheduler_root = root / "scheduler" / "orchestration"
    runner_imports = _module_imports(scheduler_root / "scheduler_runner.py")
    dependency_imports = _module_imports(scheduler_root / "scheduler_pipeline_dependencies.py")

    assert "Virus_Scan.models.profiles" not in runner_imports
    assert "Virus_Scan.core.jsonio" not in runner_imports
    assert "Virus_Scan.publication.api" not in runner_imports
    assert "Virus_Scan.scheduler.orchestration.scheduler_pipeline_dependencies" in runner_imports
    assert "Virus_Scan.publication.api" in dependency_imports
    assert "Virus_Scan.publication.api.pipeline_finalization" not in dependency_imports
    assert "Virus_Scan.publication.json_writer" not in dependency_imports


def test_publication_api_exports_canonical_scheduler_publication_callables():
    assert callable(persist_parent_learning_from_results)
    assert callable(flush_all_persistent_models)
    assert callable(clear_profile_scoring_snapshot)
    assert callable(write_partial_scan_results)
