from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.detection.scoring.calibration import analytical_bundle
from Virus_Scan.runtime import analytical_calibration
from Virus_Scan.contracts import analytical_evidence
from Virus_Scan.utils import probability


def test_stage1168_runtime_analytical_calibration_uses_public_probability_contract():
    source = read_python_file(Path("Virus_Scan/runtime/analytical_calibration.py"))

    assert "def _sigmoid01" not in source
    assert "import math" not in source
    contract_source = read_python_file(Path("Virus_Scan/contracts/analytical_evidence.py"))
    assert "centered_sigmoid_probability" in contract_source
    assert "analytical_format_oddity_snapshot as format_oddity_snapshot" in source

    oddity = analytical_calibration.format_oddity_snapshot(path="sample.exe", entropy=9.0, tags=[])
    zscore = abs((oddity["entropy"] - oddity["mean"]) / oddity["std"])
    expected = round(probability.centered_sigmoid_probability(zscore, midpoint=2.0, scale=0.8, min_scale=0.05), 4)
    assert oddity["confidence"] == expected
    assert 0.0 <= oddity["confidence"] <= 1.0


def test_stage1168_detection_analytical_bundle_uses_public_probability_contract():
    source = read_python_file(Path("Virus_Scan/detection/scoring/calibration/analytical_bundle.py"))

    assert "def _sigmoid01" not in source
    assert "import math" not in source
    contract_source = read_python_file(Path("Virus_Scan/contracts/analytical_evidence.py"))
    assert "centered_sigmoid_probability" in contract_source
    assert "analytical_format_oddity_snapshot as format_oddity_snapshot" in source

    oddity = analytical_bundle.format_oddity_snapshot(path="sample.exe", entropy=9.0, tags=[])
    zscore = abs((oddity["entropy"] - oddity["mean"]) / oddity["std"])
    expected = round(probability.centered_sigmoid_probability(zscore, midpoint=2.0, scale=0.8, min_scale=0.05), 4)
    assert oddity["confidence"] == expected
    assert 0.0 <= oddity["confidence"] <= 1.0
