"""Phase 2 regression tests for detection bootstrap dependency boundaries."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.detection.api.bootstrap_registration import DETECTION_BOOTSTRAP_MODULE_NAMES


def _import_modules(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
        elif isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
    return tuple(modules)


def test_orchestration_bootstrap_uses_public_detection_bootstrap_contract_only():
    path = Path("Virus_Scan/orchestration/bootstrap_initialization.py")
    detection_imports = tuple(
        module for module in _import_modules(path) if module.startswith("Virus_Scan.detection")
    )
    assert detection_imports == (
        "Virus_Scan.detection.api",
    )


def test_detection_bootstrap_contract_publishes_immutable_module_names():
    assert isinstance(DETECTION_BOOTSTRAP_MODULE_NAMES, tuple)
    assert DETECTION_BOOTSTRAP_MODULE_NAMES == tuple(sorted(DETECTION_BOOTSTRAP_MODULE_NAMES))
    assert "Virus_Scan.detection.scoring.adaptive.model_score" in DETECTION_BOOTSTRAP_MODULE_NAMES
    assert "Virus_Scan.detection.scoring.yara.context_evidence" in DETECTION_BOOTSTRAP_MODULE_NAMES
    assert "Virus_Scan.detection.scoring.yara.evidence_calibration" not in DETECTION_BOOTSTRAP_MODULE_NAMES
