from __future__ import annotations

import ast
from pathlib import Path

import Virus_Scan.models.profiles.api as profile_api
from Virus_Scan.models.profiles.context import (
    contextual_profile_bucket_key,
    profile_context_container_root,
)


def test_stage1457_profile_context_uses_public_owner_names() -> None:
    assert profile_context_container_root("stage1457_synthetic_node.exe") is None
    key, context = contextual_profile_bucket_key("stage1457_synthetic_node.exe")
    assert key == context.learning_baseline_key or key == context.baseline_key


def test_stage1457_profile_api_does_not_expose_private_context_helpers() -> None:
    assert not hasattr(profile_api, "_profile_context_container_root")
    assert not hasattr(profile_api, "_contextual_profile_bucket_key")


def test_stage1457_profile_context_callers_do_not_import_private_context_helpers() -> None:
    repo = Path(__file__).resolve().parents[1]
    offenders: list[str] = []
    for relative in (
        "models/profiles/api.py",
        "models/profiles/baseline.py",
        "models/profiles/learning_gate.py",
    ):
        path = repo / relative
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "Virus_Scan.models.profiles.context":
                for alias in node.names:
                    if alias.name in {"_profile_context_container_root", "_contextual_profile_bucket_key"}:
                        offenders.append(f"{relative}:{node.lineno}:{alias.name}")
    assert offenders == []
