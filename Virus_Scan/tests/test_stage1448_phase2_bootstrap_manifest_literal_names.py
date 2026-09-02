"""Stage 1448 Phase 2 bootstrap manifest ownership regressions."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.detection.api.bootstrap_registration import DETECTION_BOOTSTRAP_MODULE_NAMES
from Virus_Scan.models.api.bootstrap_registration import MODEL_BOOTSTRAP_MODULE_NAMES


def _imported_modules(path: str) -> tuple[str, ...]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
    return tuple(modules)


def test_stage1448_model_bootstrap_manifest_does_not_import_model_implementations() -> None:
    imports = _imported_modules("Virus_Scan/models/api/bootstrap_registration.py")
    assert imports == ("__future__",)
    assert "Virus_Scan.models.markov.api" in MODEL_BOOTSTRAP_MODULE_NAMES
    assert "Virus_Scan.models.temporal.api" in MODEL_BOOTSTRAP_MODULE_NAMES
    assert MODEL_BOOTSTRAP_MODULE_NAMES == tuple(sorted(MODEL_BOOTSTRAP_MODULE_NAMES))


def test_stage1448_detection_bootstrap_manifest_does_not_import_detection_implementations() -> None:
    imports = _imported_modules("Virus_Scan/detection/api/bootstrap_registration.py")
    assert imports == ("__future__",)
    assert "Virus_Scan.detection.scoring.adaptive.model_score" in DETECTION_BOOTSTRAP_MODULE_NAMES
    assert "Virus_Scan.detection.scoring.yara.context_evidence" in DETECTION_BOOTSTRAP_MODULE_NAMES
    assert DETECTION_BOOTSTRAP_MODULE_NAMES == tuple(sorted(DETECTION_BOOTSTRAP_MODULE_NAMES))
