"""Stage 1429 temporal canonical ownership and bounded-module regressions."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.models import temporal
from Virus_Scan.models.api import temporal_contracts
from Virus_Scan.models.api.bootstrap_registration import MODEL_BOOTSTRAP_MODULE_NAMES
from Virus_Scan.models.temporal import api as temporal_api

TEMPORAL_PACKAGE = Path("Virus_Scan/models/temporal")


def _imports_for(path: Path) -> set[str]:
    imports: set[str] = set()
    paths = sorted(path.glob("*.py")) if path.is_dir() else [path]
    for source_path in paths:
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)
            elif isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
    return imports


def test_stage1429_temporal_is_canonical_v5_package_not_monolith_or_legacy_decay_owner() -> None:
    assert not Path("Virus_Scan/models/temporal.py").exists()
    required = (
        "api.py", "overlay.py", "anomaly.py", "accumulator.py",
        "event_materialization.py", "dwell_baseline.py", "policy.py",
        "learning.py", "state_projection.py", "evidence.py",
        "validation.py", "validation_support.py",
    )
    assert all((TEMPORAL_PACKAGE / name).exists() for name in required)
    assert not (TEMPORAL_PACKAGE / "decay.py").exists()
    assert not Path("Virus_Scan/runtime/temporal_state_migration.py").exists()
    assert all(
        len(path.read_text(encoding="utf-8").splitlines()) < 300
        for path in TEMPORAL_PACKAGE.glob("*.py")
    )


def test_stage1429_temporal_public_contracts_enter_api_module() -> None:
    assert temporal.compute_temporal_validation is temporal_api.compute_temporal_validation
    assert temporal.transition_probability_overlay is temporal_api.transition_probability_overlay
    assert temporal_contracts.owner_transition_probability_overlay is temporal_api.transition_probability_overlay
    assert "Virus_Scan.models.temporal.api" in MODEL_BOOTSTRAP_MODULE_NAMES


def test_stage1429_temporal_delegates_markov_to_public_contract() -> None:
    imports = _imports_for(TEMPORAL_PACKAGE)
    assert "Virus_Scan.models.markov" not in imports
    assert "Virus_Scan.models.markov.api" not in imports
    assert "Virus_Scan.models.api.markov_contracts" in imports


def test_stage1429_temporal_owner_boundaries_are_split_by_behavior() -> None:
    overlay_source = (TEMPORAL_PACKAGE / "overlay.py").read_text(encoding="utf-8")
    anomaly_source = (TEMPORAL_PACKAGE / "anomaly.py").read_text(encoding="utf-8")
    learning_source = (TEMPORAL_PACKAGE / "learning.py").read_text(encoding="utf-8")
    state_source = (TEMPORAL_PACKAGE / "state_projection.py").read_text(encoding="utf-8")

    assert "commit_temporal_learning_request" not in overlay_source
    assert "mark_runtime_models_dirty" not in overlay_source
    assert "markov_stage_probability" in overlay_source
    assert "tag_pair_anomaly" in anomaly_source
    assert "commit_temporal_learning_request" in learning_source
    assert "commit_temporal_runtime_learning" in state_source
    assert "record_temporal_observation" not in overlay_source + learning_source + state_source
