from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners.archives.path_safety import safe_archive_child_path


def _import_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_archive_member_path_safety_is_scanner_owned(tmp_path: Path) -> None:
    assert safe_archive_child_path(tmp_path, "safe/member.txt") == (tmp_path / "safe/member.txt").resolve()
    assert safe_archive_child_path(tmp_path, "../escape.txt") is None
    assert safe_archive_child_path(tmp_path, "/absolute/escape.txt") is None


def test_zip_and_tar_scanners_do_not_import_core_path_utils() -> None:
    for rel in ("zip_scanner.py", "tar_scanner.py"):
        modules = _import_modules(Path("Virus_Scan/scanners/archives") / rel)
        assert "Virus_Scan.core.path_utils" not in modules
        assert "Virus_Scan.scanners.archives.path_safety" in modules
