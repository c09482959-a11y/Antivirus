from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.publication import json_writer

ROOT = Path(__file__).resolve().parents[1]


def _imports_for(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
    return imports


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def test_stage1442_publication_json_writer_is_bounded_entrypoint() -> None:
    writer = ROOT / "publication" / "json_writer.py"

    assert _line_count(writer) <= 80
    imports = _imports_for(writer)
    assert "Virus_Scan.publication.json_finalization.streaming" in imports
    assert "Virus_Scan.publication.json_finalization.compact_record" in imports
    assert "Virus_Scan.runtime.api" not in imports
    assert "Virus_Scan.runtime.api" in _imports_for(ROOT / "publication" / "json_finalization" / "streaming.py")
    assert "Virus_Scan.runtime.api" in _imports_for(ROOT / "publication" / "json_finalization" / "success_context.py")


def test_stage1442_final_json_decomposition_modules_are_bounded() -> None:
    package = ROOT / "publication" / "json_finalization"
    modules = sorted(path for path in package.glob("*.py") if path.name != "__init__.py")

    assert modules
    assert all(_line_count(path) <= 300 for path in modules)


def test_stage1442_final_json_publication_boundary_does_not_import_model_compute_owners() -> None:
    package = ROOT / "publication" / "json_finalization"
    forbidden_prefixes = (
        "Virus_Scan.models.markov",
        "Virus_Scan.models.temporal",
        "Virus_Scan.models.profiles",
        "Virus_Scan.models.clustering",
        "Virus_Scan.models.graph",
        "Virus_Scan.detection.scoring",
        "Virus_Scan.scanners",
    )

    for path in package.glob("*.py"):
        imports = _imports_for(path)
        assert not any(
            module == prefix or module.startswith(prefix + ".")
            for module in imports
            for prefix in forbidden_prefixes
        ), path


def test_stage1442_final_json_keeps_existing_public_and_tested_internal_boundaries() -> None:
    assert callable(json_writer.finalize_scan_results)
    assert callable(json_writer.write_partial_scan_results)
    assert callable(json_writer.compact_result_record)
    assert callable(json_writer.normalize_compact_result_record)
    assert callable(json_writer.build_compact_error_record)
    assert callable(json_writer.compact_success_context)
