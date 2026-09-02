from __future__ import annotations

import ast
import re
from pathlib import Path


FORBIDDEN_RUNTIME_TERMS = re.compile(
    r"\b(fallback|legacy|adapter|shim|bridge|alias|monkey|patch|override|deprecated|migration|lazy import|import inside function|globals\(\)|setattr\(|__dict__|sys\.modules|runtime injection)\b",
    re.IGNORECASE,
)


def test_stage326_runtime_static_ownership_terms_are_absent() -> None:
    root = Path(__file__).resolve().parents[1] / "runtime"
    hits: list[str] = []
    for path in sorted(root.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            if FORBIDDEN_RUNTIME_TERMS.search(line):
                hits.append(f"{path.relative_to(root.parent)}:{lineno}:{line.strip()}")
    assert hits == []


def test_stage326_runtime_files_have_no_nested_imports() -> None:
    root = Path(__file__).resolve().parents[1] / "runtime"
    nested: list[str] = []
    for path in sorted(root.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if child is node:
                        continue
                    if isinstance(child, (ast.Import, ast.ImportFrom)):
                        nested.append(f"{path.relative_to(root.parent)}:{child.lineno}:{node.name}")
    assert nested == []
