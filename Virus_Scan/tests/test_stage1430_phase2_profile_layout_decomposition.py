from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.models.profiles import api as profile_api
from Virus_Scan.models.profiles import corruption, schema


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
        elif isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
    return names


def test_stage1430_profile_monolith_removed_and_package_has_real_owners() -> None:
    assert not Path("Virus_Scan/models/profiles.py").exists()
    for relative in (
        "Virus_Scan/models/profiles/api.py",
        "Virus_Scan/models/profiles/schema.py",
        "Virus_Scan/models/profiles/corruption.py",
        "Virus_Scan/models/profiles/baseline.py",
        "Virus_Scan/models/profiles/snapshots.py",
        "Virus_Scan/models/profiles/__init__.py",
    ):
        assert Path(relative).is_file(), relative


def test_stage1430_profile_schema_and_corruption_are_not_api_reexports_only() -> None:
    schema_source = read_python_file(Path("Virus_Scan/models/profiles/schema.py"))
    corruption_source = read_python_file(Path("Virus_Scan/models/profiles/corruption.py"))

    assert "class EngineProfileSchemaSnapshot" in schema_source
    assert "def validate_engine_profile_schema" in schema_source
    assert "class ProfileCorruptionEvidence" in corruption_source
    assert "def profile_corruption_evidence" in corruption_source
    assert "from Virus_Scan.models.profiles.api" not in schema_source
    assert "from Virus_Scan.models.profiles.api" not in corruption_source


def test_stage1430_profile_api_consumes_schema_and_corruption_owners() -> None:
    imports = _imports(Path("Virus_Scan/models/profiles/api.py"))

    assert "Virus_Scan.models.profiles.schema" in imports
    assert "Virus_Scan.models.profiles.corruption" in imports
    assert profile_api.validate_engine_profile_schema is schema.validate_engine_profile_schema
    evidence = corruption.profile_corruption_evidence(
        "profile.json",
        "renpy",
        "invalid profile schema_version",
        profile={"schema_version": float("nan")},
    )
    payload = evidence.to_json()
    assert payload["profile_schema_error"] is True
    assert payload["actual_schema_version"]["reason"] == "non_finite_profile_corruption_value"
    assert payload["profile_corruption_event_key"]
