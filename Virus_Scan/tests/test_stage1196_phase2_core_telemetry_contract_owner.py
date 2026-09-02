from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.contracts.telemetry import log_error as contract_log_error
from Virus_Scan.contracts import library_baseline
from Virus_Scan.core import cache, paths
from Virus_Scan.core import jsonio


CORE_MODEL_CONSUMED_FILES = (
    Path("Virus_Scan/core/paths.py"),
    Path("Virus_Scan/core/cache.py"),
    Path("Virus_Scan/core/jsonio.py"),
)


def test_model_consumed_core_modules_use_neutral_telemetry_contract() -> None:
    violations = []
    for path in CORE_MODEL_CONSUMED_FILES:
        source = path.read_text(encoding="utf-8")
        if "from Virus_Scan.runtime.scan_dependencies import log_error" in source:
            violations.append(str(path))
    assert violations == []


def test_core_and_library_baseline_telemetry_exports_resolve_to_contract_owner() -> None:
    assert paths.log_error is contract_log_error
    assert library_baseline.log_error is contract_log_error
    assert cache.log_error is contract_log_error
    assert jsonio.log_error is contract_log_error


def test_jsonio_has_no_superseded_yara_cache_provider_dependency() -> None:
    source = read_python_file(Path("Virus_Scan/core/jsonio.py"))
    assert "from Virus_Scan.contracts.telemetry import log_error" in source
    assert "call_yara_cache_provider" not in source
    assert "_write_yara_manifest" not in source
