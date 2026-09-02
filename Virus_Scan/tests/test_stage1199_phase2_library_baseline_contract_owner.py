from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.contracts.library_baseline import (
    library_baseline_hard_proof_status,
    library_baseline_has_hard_proof,
)



def test_library_baseline_hard_proof_contract_preserves_tag_and_text_behavior() -> None:
    assert library_baseline_has_hard_proof(tags=["known_bad_hash"], strings_blob="") is True
    assert library_baseline_has_hard_proof(tags=[], strings_blob="plain benign text") is False
    status, has_proof = library_baseline_hard_proof_status(tags=[], strings_blob="powershell -enc payload")
    assert status == "text_hard_proof"
    assert has_proof is True


def test_profile_model_consumes_neutral_library_baseline_contract_not_core_or_scanner_owner() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/baseline.py"))
    assert "from Virus_Scan.contracts.library_baseline import library_baseline_has_hard_proof" in source
    assert "Virus_Scan.core.library_baseline" not in source
    assert "Virus_Scan.scanners" not in source


def test_core_library_baseline_duplicate_owner_removed() -> None:
    assert not Path("Virus_Scan/core/library_baseline.py").exists()
    source = read_python_file(Path("Virus_Scan/core/paths.py"))
    assert "from Virus_Scan.contracts.library_baseline import library_baseline_has_hard_proof" in source
    assert "Virus_Scan.core.library_baseline" not in source
