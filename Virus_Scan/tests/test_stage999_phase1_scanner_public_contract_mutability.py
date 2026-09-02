from types import ModuleType

from Virus_Scan.scanners.api import public_contracts
from Virus_Scan.orchestration import bootstrap_initialization as initialization


def test_stage999_scanner_public_contract_exports_no_module_objects():
    exported_names = tuple(public_contracts.__all__)

    assert "SCANNER_BOOTSTRAP_MODULE_NAMES" in exported_names
    assert "SCANNER_BOOTSTRAP_MODULES" not in exported_names

    for name in exported_names:
        value = getattr(public_contracts, name)
        assert not isinstance(value, ModuleType), name


def test_stage999_bootstrap_manifest_uses_immutable_scanner_module_names():
    scanner_names = public_contracts.SCANNER_BOOTSTRAP_MODULE_NAMES

    assert isinstance(scanner_names, tuple)
    assert scanner_names == tuple(sorted(scanner_names))
    assert len(scanner_names) == len(set(scanner_names))
    assert all(isinstance(module_name, str) for module_name in scanner_names)
    assert all(module_name.startswith("Virus_Scan.scanners.") for module_name in scanner_names)
    runtime_scanner_modules = tuple(
        module_name
        for module_name in initialization._BOOTSTRAP_REGISTRATION_MODULE_NAMES
        if module_name.startswith("Virus_Scan.scanners.")
    )

    assert runtime_scanner_modules == ("Virus_Scan.scanners.api.public_contracts",)
    for module_name in scanner_names:
        assert module_name in initialization._BOOTSTRAP_REQUIRED_MODULE_NAMES
