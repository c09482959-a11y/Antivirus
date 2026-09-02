
"""Stage 994 Phase 1 guard for detection-owned adaptive numeric scoring."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.detection.scoring.weighting.numeric import adaptive_weight_float


def test_adaptive_weight_float_preserves_scanner_pipeline_coercion_semantics() -> None:
    assert adaptive_weight_float("3.5") == 3.5
    assert adaptive_weight_float(None, 2.25) == 2.25
    assert adaptive_weight_float(float("nan"), 7.0) == 7.0


def test_detection_model_score_no_longer_imports_scanner_pipeline_contracts() -> None:
    source = read_python_file(Path("Virus_Scan/detection/scoring/adaptive/confidence.py")) + "\n" + read_python_file(Path("Virus_Scan/detection/scoring/adaptive/model_caps.py"))
    tree = ast.parse(source)
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert "Virus_Scan.scanners.api.pipeline_contracts" not in imported_modules
    assert "Virus_Scan.detection.scoring.weighting.numeric" in imported_modules


def test_stage1601_adaptive_weight_float_rejects_hostile_numeric_without_float_hook() -> None:
    class HostileNumber:
        touched = 0

        def __float__(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("caller-owned __float__ invoked")

        def __repr__(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("caller-owned __repr__ invoked")

    value = HostileNumber()

    assert adaptive_weight_float(value, 2.5) == 2.5
    assert HostileNumber.touched == 0


def test_stage2023_adaptive_weight_float_source_removed_fallback_route() -> None:
    source = read_python_file(Path("Virus_Scan/detection/scoring/weighting/numeric.py"))

    assert "fallback, _ = no_hook_finite_float(" not in source
    assert "return fallback" not in source
