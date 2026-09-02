from __future__ import annotations

import ast
from pathlib import Path

import Virus_Scan.models.profiles.api as profile_api


def test_stage1458_profile_api_does_not_publish_private_facade_attributes() -> None:
    leaked = sorted(
        name
        for name in dir(profile_api)
        if name.startswith("_") and not (name.startswith("__") and name.endswith("__"))
    )
    assert leaked == []


def test_stage1458_profile_api_does_not_keep_private_import_aliases_or_private_defs() -> None:
    repo = Path(__file__).resolve().parents[1]
    path = repo / "models" / "profiles" / "api.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    offenders: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                local_name = alias.asname or alias.name
                if local_name.startswith("_"):
                    offenders.append(f"import:{node.lineno}:{local_name}")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name.startswith("_"):
                offenders.append(f"def:{node.lineno}:{node.name}")
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.startswith("_") and target.id != "__all__":
                    offenders.append(f"assign:{node.lineno}:{target.id}")
    assert offenders == []
