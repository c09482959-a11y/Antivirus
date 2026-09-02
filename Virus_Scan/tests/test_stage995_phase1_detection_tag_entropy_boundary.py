
"""Stage 995 Phase 1 guard for detection-owned tag entropy scoring."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
import math
from pathlib import Path

from Virus_Scan.detection.scoring.weighting.tag_entropy import tag_entropy


def test_detection_tag_entropy_preserves_scanner_contract_semantics() -> None:
    assert tag_entropy([]) == 0.0
    assert tag_entropy(None) == 0.0
    observed = tag_entropy(["a", "b", "a"])
    expected = -((2 / 3) * math.log2((2 / 3) + 1e-09) + (1 / 3) * math.log2((1 / 3) + 1e-09))
    assert observed == expected


def test_detection_model_score_no_longer_imports_scanner_entropy_contracts() -> None:
    source = read_python_file(Path("Virus_Scan/detection/scoring/adaptive/evidence_projection.py"))
    tree = ast.parse(source)
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert "Virus_Scan.scanners.api.entropy_contracts" not in imported_modules
    assert "Virus_Scan.detection.scoring.weighting.tag_entropy" in imported_modules
