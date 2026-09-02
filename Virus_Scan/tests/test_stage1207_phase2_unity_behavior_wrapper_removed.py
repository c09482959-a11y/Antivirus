from Virus_Scan.tests.support.static_inventory import import_modules, read_python_file, virus_scan_python_files

from pathlib import Path



def test_detection_unity_behavior_wrapper_removed_after_neutral_contract_adoption():
    assert not Path("Virus_Scan/detection/contracts/unity_behavior.py").exists()
    for path in virus_scan_python_files():
        assert "Virus_Scan.detection.contracts.unity_behavior" not in import_modules(path), path


def test_neutral_unity_behavior_contract_remains_canonical_owner():
    source = read_python_file(Path("Virus_Scan/contracts/unity_behavior.py"))
    assert "def detect_unity_runtime_behavior" in source
    assert "UNITY_LIFECYCLE_HOOKS" in source
    assert "UNITY_RUNTIME_CHECKS" in source
