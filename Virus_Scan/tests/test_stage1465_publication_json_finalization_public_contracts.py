from __future__ import annotations

import ast
from pathlib import Path

PUBLICATION_ROOT = Path(__file__).resolve().parents[1] / "publication"
FINALIZATION_ROOT = PUBLICATION_ROOT / "json_finalization"


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def test_stage1465_publication_finalization_modules_do_not_import_private_helpers() -> None:
    offenders = []
    for root in (PUBLICATION_ROOT, FINALIZATION_ROOT):
        for path in root.glob("*.py"):
            tree = _tree(path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom):
                    continue
                if not (node.module or "").startswith("Virus_Scan.publication.json_finalization"):
                    continue
                for alias in node.names:
                    if alias.name.startswith("_") and not alias.name.startswith("__"):
                        offenders.append((path.relative_to(PUBLICATION_ROOT).as_posix(), node.lineno, alias.name))
    assert offenders == []


def test_stage1465_publication_json_writer_uses_public_finalization_contracts() -> None:
    writer = PUBLICATION_ROOT / "json_writer.py"
    tree = _tree(writer)
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("Virus_Scan.publication.json_finalization"):
            imported.extend(alias.name for alias in node.names)
    assert "build_compact_error_record" in imported
    assert "compact_success_context" in imported
    assert "existing_scheduler_final_json_fields" in imported
    assert "normalize_compact_result_record" in imported
    assert all(not name.startswith("_") for name in imported)
