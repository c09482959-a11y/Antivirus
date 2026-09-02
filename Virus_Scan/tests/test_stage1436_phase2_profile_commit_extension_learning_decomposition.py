from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.models.profiles import api as profile_api
from Virus_Scan.models.profiles import commit, extension_learning, learning_gate, promotion


def _function_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}


def _source(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_stage1436_profile_commit_and_mutation_have_explicit_owner_modules() -> None:
    assert profile_api.commit_promoted_learning is commit.commit_promoted_learning
    assert profile_api.update_profile_from_scan_result is commit.update_profile_from_scan_result
    assert profile_api.record_learning_rejection is learning_gate.record_learning_rejection
    assert extension_learning.apply_extension_learning_decision is not None
    assert promotion.prepare_benign_observation is not None
    for removed in (
        "stage_benign_observation", "prepare_benign_observation", "update_extension_baseline",
        "update_behavior_bucket_learning", "update_filetype",
    ):
        assert removed not in profile_api.__all__
        assert not hasattr(profile_api, removed)

    api_functions = _function_names(Path("Virus_Scan/models/profiles/api.py"))
    assert "commit_promoted_learning" not in api_functions
    assert "stage_benign_observation" not in api_functions
    assert "prepare_benign_observation" not in api_functions
    assert "record_learning_rejection" not in api_functions
    assert "update_extension_baseline" not in api_functions
    assert "update_behavior_bucket_learning" not in api_functions


def test_stage1436_new_profile_owner_modules_do_not_import_profile_api() -> None:
    for path in (
        "Virus_Scan/models/profiles/commit.py",
        "Virus_Scan/models/profiles/extension_learning.py",
        "Virus_Scan/models/profiles/learning_gate.py",
        "Virus_Scan/models/profiles/promotion.py",
    ):
        tree = ast.parse(_source(path), filename=path)
        imports = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        direct_imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        assert "Virus_Scan.models.profiles.api" not in imports
        assert "Virus_Scan.models.profiles.api" not in direct_imports


def test_stage1436_profile_facade_and_owner_files_are_bounded() -> None:
    limits = {
        "Virus_Scan/models/profiles/api.py": 250,
        "Virus_Scan/models/profiles/baseline.py": 250,
        "Virus_Scan/models/profiles/commit.py": 160,
        "Virus_Scan/models/profiles/extension_learning.py": 220,
        "Virus_Scan/models/profiles/learning_gate.py": 200,
        "Virus_Scan/models/profiles/promotion.py": 200,
    }
    for path, limit in limits.items():
        assert len(Path(path).read_text(encoding="utf-8").splitlines()) <= limit


def test_stage1436_profile_owner_modules_have_no_function_local_imports() -> None:
    for path in (
        "Virus_Scan/models/profiles/commit.py",
        "Virus_Scan/models/profiles/extension_learning.py",
        "Virus_Scan/models/profiles/learning_gate.py",
        "Virus_Scan/models/profiles/promotion.py",
    ):
        tree = ast.parse(Path(path).read_text(encoding="utf-8"), filename=path)
        for function in (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)):
            assert not any(isinstance(child, (ast.Import, ast.ImportFrom)) for child in ast.walk(function))
