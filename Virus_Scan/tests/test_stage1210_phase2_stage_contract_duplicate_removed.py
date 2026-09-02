from pathlib import Path

from Virus_Scan.utils.entropy import entropy_from_counts, shannon_entropy_bytes
from Virus_Scan.utils.stages import (
    effective_stage_for_path,
    normalize_profile_extension,
    normalize_stage,
    resolve_content_evidence_stage,
)


def test_detection_stage_contract_duplicate_removed():
    assert not Path("Virus_Scan/detection/contracts/stages.py").exists()


def test_detection_callers_use_canonical_stage_contract():
    offenders = []
    for path in Path("Virus_Scan/detection").rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        if "Virus_Scan.detection.contracts.stages" in source:
            offenders.append(str(path))
    assert offenders == []


def test_canonical_stage_contract_preserves_detection_stage_behavior():
    assert normalize_stage(".rpy") == "runtime"
    assert normalize_stage(".png") == "image"
    assert normalize_stage(".assets") == "asset"
    assert normalize_profile_extension("Game.RPY") == ".rpy"
    assert effective_stage_for_path(["router_stage_image"], "script.py") == "image"
    assert resolve_content_evidence_stage("asset", ["encoded_powershell"]) == "runtime"


def test_detection_entropy_contract_duplicate_removed():
    assert not Path("Virus_Scan/detection/contracts/entropy.py").exists()


def test_detection_callers_use_canonical_entropy_contract():
    offenders = []
    for path in Path("Virus_Scan/detection").rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        if "Virus_Scan.detection.contracts.entropy" in source:
            offenders.append(str(path))
    assert offenders == []


def test_canonical_entropy_contract_preserves_detection_entropy_behavior():
    assert shannon_entropy_bytes(b"") == 0.0
    assert shannon_entropy_bytes(None) == 0.0
    assert round(shannon_entropy_bytes(b"\x00\x01"), 6) == 1.0
    assert round(entropy_from_counts([1, 1], 2), 6) == 1.0
    assert entropy_from_counts([1, 1], 0) == 0.0
