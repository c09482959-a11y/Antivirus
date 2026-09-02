"""Stage 1440 Phase 2 regression tests for replay package decomposition."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.models.api import replay_learning
from Virus_Scan.models.replay import api as replay_api
from Virus_Scan.models.api.bootstrap_registration import MODEL_BOOTSTRAP_MODULE_NAMES

REPLAY_PACKAGE = Path("Virus_Scan/models/replay")


def _imports_for(path: Path) -> set[str]:
    paths = sorted(path.glob("*.py")) if path.is_dir() else [path]
    imports: set[str] = set()
    for source_path in paths:
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)
            elif isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
    return imports


def test_stage1440_replay_is_package_not_monolith() -> None:
    assert not Path("Virus_Scan/models/replay.py").exists()
    for name in ("__init__.py", "api.py", "detachment.py", "payload.py", "learning.py"):
        assert (REPLAY_PACKAGE / name).exists()
    assert not (REPLAY_PACKAGE / "runtime_observation.py").exists()
    assert all(
        len(path.read_text(encoding="utf-8").splitlines()) < 260
        for path in REPLAY_PACKAGE.glob("*.py")
    )


def test_stage1440_public_replay_learning_enters_replay_api() -> None:
    assert replay_learning.replay_model_api is replay_api
    assert "Virus_Scan.models.replay.api" in MODEL_BOOTSTRAP_MODULE_NAMES


def test_stage1440_replay_package_uses_only_decision_bound_public_model_mutation() -> None:
    imports = _imports_for(REPLAY_PACKAGE)
    for module in (
        "Virus_Scan.models.markov",
        "Virus_Scan.models.temporal",
        "Virus_Scan.models.graph",
        "Virus_Scan.models.clustering",
        "Virus_Scan.models.profiles",
        "Virus_Scan.models.api.temporal_contracts",
        "Virus_Scan.models.api.graph_contracts",
        "Virus_Scan.models.api.clustering_contracts",
    ):
        assert module not in imports
    assert "Virus_Scan.models.api.profile_learning_contracts" in imports
    assert "Virus_Scan.models.api.markov_contracts" not in imports


def test_stage1440_publication_still_uses_replay_learning_contract() -> None:
    imports = _imports_for(Path("Virus_Scan/publication/api/pipeline_finalization.py"))
    assert "Virus_Scan.models.replay" not in imports
    assert "Virus_Scan.models.replay.api" not in imports
    assert "Virus_Scan.models.api.replay_learning" in imports
