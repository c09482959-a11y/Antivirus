from types import ModuleType

from Virus_Scan.orchestration import bootstrap_initialization as initialization


def test_stage1000_runtime_bootstrap_manifest_is_name_only_and_immutable():
    assert not hasattr(initialization, "_BOOTSTRAP_REGISTRATION_MODULES")

    names = initialization._BOOTSTRAP_REGISTRATION_MODULE_NAMES
    assert isinstance(names, tuple)
    assert names == tuple(sorted(names))
    assert len(names) == len(set(names))
    assert all(isinstance(name, str) for name in names)
    assert all(not isinstance(name, ModuleType) for name in names)
    assert "Virus_Scan.scanners.api.public_contracts" in names


def test_stage1000_runtime_bootstrap_required_names_cover_public_scanner_contracts():
    required = initialization._BOOTSTRAP_REQUIRED_MODULE_NAMES
    assert isinstance(required, tuple)
    assert required == tuple(sorted(required))
    assert "Virus_Scan.scanners.api.public_contracts" in required
    assert all(isinstance(name, str) for name in required)

    scanner_impl_names = tuple(
        name for name in initialization._BOOTSTRAP_REGISTRATION_MODULE_NAMES
        if name.startswith("Virus_Scan.scanners.")
    )
    assert scanner_impl_names == ("Virus_Scan.scanners.api.public_contracts",)
