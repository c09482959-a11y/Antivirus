from pathlib import Path

from Virus_Scan.scanners.pickle.fragment_tags import pickle_fragment_tags
from Virus_Scan.scanners.text import library_baseline_has_hard_proof, validate_high_risk_tag


def test_scanner_modules_do_not_import_detection_private_profiles():
    scanner_root = Path("Virus_Scan/scanners")
    offenders = [
        path.as_posix()
        for path in sorted(scanner_root.rglob("*.py"))
        if "Virus_Scan.detection.profiles" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_text_profile_policy_contract_preserves_hard_proof_behavior():
    assert library_baseline_has_hard_proof(tags=["powershell_exec"], strings_blob="",) is True
    assert validate_high_risk_tag(
        "renpy_pickle_exec",
        strings_blob="pickle GLOBAL REDUCE os.system subprocess powershell exec(",
        path="game/script.rpy",
    ) is True


def test_pickle_fragment_family_tags_flow_through_contextual_scanner_only():
    tags = pickle_fragment_tags(
        {"text": "regsvr32.exe scrobj.dll"},
        path="game/script.rpy",
    )

    assert "regsvr32_exec" in tags
    assert tags.count("regsvr32_exec") <= 2
