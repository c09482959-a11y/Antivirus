from __future__ import annotations

import ast
import inspect
from pathlib import Path

import Virus_Scan.models.api as model_api
from Virus_Scan.models import temporal
from Virus_Scan.models.temporal import validation as temporal_validation
from Virus_Scan.models.temporal import state_projection as temporal_state_projection
from Virus_Scan.models.api import temporal_contracts
from Virus_Scan.detection.correlation.multi_signal import model_projections
from Virus_Scan.detection.scoring.adaptive import feature_bundle


def _imports_for(path: str) -> set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
    return imports


def test_detection_temporal_projection_uses_public_temporal_contract() -> None:
    imports = _imports_for("Virus_Scan/detection/correlation/multi_signal/model_projections.py")

    assert "Virus_Scan.models.temporal" not in imports
    assert "Virus_Scan.models.api.temporal_contracts" in imports
    assert model_projections.compute_temporal_validation is temporal_contracts.compute_temporal_validation


def test_adaptive_feature_bundle_uses_public_temporal_contract() -> None:
    imports = _imports_for("Virus_Scan/detection/scoring/adaptive/feature_bundle.py")

    assert "Virus_Scan.models.temporal" not in imports
    assert "Virus_Scan.models.api.temporal_contracts" in imports
    assert feature_bundle.snapshot_temporal is temporal_contracts.snapshot_temporal


def test_model_temporal_public_contract_preserves_canonical_owner() -> None:
    assert "temporal_contracts" in model_api.__all__
    assert temporal_contracts.owner_compute_temporal_validation is temporal.compute_temporal_validation
    assert temporal_contracts.owner_snapshot_temporal is temporal.snapshot_temporal
    assert inspect.getmodule(temporal_contracts.owner_compute_temporal_validation) is temporal_validation
    assert inspect.getmodule(temporal_contracts.owner_snapshot_temporal) is temporal_state_projection


def test_temporal_public_contract_returns_explicit_evidence() -> None:
    validation = temporal_contracts.compute_temporal_validation("node", tags=("network",))
    snapshot = temporal_contracts.snapshot_temporal("node")

    assert isinstance(validation, dict)
    assert isinstance(snapshot, dict)
    assert validation.get("evidence_type") in {None, "temporal_validation"}
    assert snapshot.get("evidence_type") in {None, "temporal_snapshot"}
