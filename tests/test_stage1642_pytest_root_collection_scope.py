from __future__ import annotations

from configparser import ConfigParser
from pathlib import Path


def test_stage1642_pytest_root_collection_is_limited_to_canonical_test_trees() -> None:
    parser = ConfigParser()
    parser.read("pytest.ini")
    raw = parser.get("pytest", "testpaths")
    configured = tuple(line.strip() for line in raw.splitlines() if line.strip())

    assert configured == ("tests", "Virus_Scan/tests")


def test_stage1642_all_repository_test_files_are_inside_canonical_test_trees() -> None:
    canonical_roots = (Path("tests"), Path("Virus_Scan/tests"))
    offenders = []
    for path in Path(".").rglob("test_*.py"):
        if any(part == "__pycache__" for part in path.parts):
            continue
        relative = path.relative_to(Path("."))
        if not any(relative.is_relative_to(root) for root in canonical_roots):
            offenders.append(str(relative))

    assert offenders == []
