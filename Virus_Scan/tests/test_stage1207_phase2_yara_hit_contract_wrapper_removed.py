from Virus_Scan.tests.support.static_inventory import import_modules, python_files_under, read_python_file

from pathlib import Path



def test_detection_yara_hit_wrapper_removed_and_callers_use_neutral_contract():
    assert not Path("Virus_Scan/detection/contracts/yara_hits.py").exists()
    detection_sources = python_files_under("Virus_Scan/detection")
    assert detection_sources
    for path in detection_sources:
        imports = import_modules(path)
        assert "Virus_Scan.detection.contracts.yara_hits" not in imports, path
    neutral_callers = [
        path for path in detection_sources
        if "Virus_Scan.contracts.yara_hits" in import_modules(path)
    ]
    assert neutral_callers


def test_neutral_yara_hit_contract_is_single_rule_identity_owner():
    source = read_python_file(Path("Virus_Scan/contracts/yara_hits.py"))
    assert "def normalize_yara_hits" in source
    assert "def normalize_yara_rule_name" in source
    assert "YARA_CALIBRATION_VERSION" in source
