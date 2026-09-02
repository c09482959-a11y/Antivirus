from __future__ import annotations

import ast
import inspect
from pathlib import Path

import Virus_Scan.models.api as model_api
from Virus_Scan.models import replay
from Virus_Scan.models.replay import api as replay_api
from Virus_Scan.models.api import replay_learning
from Virus_Scan.publication.api import pipeline_finalization


def _imports_for(path: str) -> set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
    return imports


def test_publication_finalization_uses_public_model_replay_learning_contract():
    imports = _imports_for("Virus_Scan/publication/api/pipeline_finalization.py")

    assert "Virus_Scan.models.replay" not in imports
    assert "Virus_Scan.models.api.replay_learning" in imports
    assert pipeline_finalization.model_replay_learning_contract is replay_learning


def test_model_api_namespace_exports_replay_learning_contract_name():
    assert "replay_learning" in model_api.__all__


def test_model_replay_learning_contract_preserves_canonical_owner():
    assert replay_learning.replay_model_api is replay_api
