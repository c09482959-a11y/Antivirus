from types import ModuleType

from Virus_Scan import runtime_main


def test_runtime_main_static_import_manifest_exposes_names_not_module_objects():
    assert not hasattr(runtime_main, "_STATIC_RUNTIME_IMPORT_OWNERS")
    owner_names = runtime_main._STATIC_RUNTIME_IMPORT_OWNER_NAMES
    assert isinstance(owner_names, tuple)
    assert owner_names == tuple(sorted(owner_names))
    assert owner_names
    assert all(isinstance(name, str) for name in owner_names)
    assert all(not isinstance(name, ModuleType) for name in owner_names)


def test_runtime_main_static_import_manifest_preserves_packager_visibility_names():
    owner_names = runtime_main._STATIC_RUNTIME_IMPORT_OWNER_NAMES
    assert "Virus_Scan.orchestration" in owner_names
    assert "Virus_Scan.orchestration.bootstrap_initialization" in owner_names
    assert "Virus_Scan.orchestration.lifecycle" in owner_names
    assert "Virus_Scan.scanners.api.public_contracts" in owner_names
    assert "Virus_Scan.scheduler.api.runner" in owner_names


def test_runtime_main_static_import_manifest_does_not_make_entrypoint_own_domains():
    source = runtime_main.__loader__.get_source(runtime_main.__name__)
    forbidden_direct_imports = (
        "from Virus_Scan.detection",
        "import Virus_Scan.detection",
        "from Virus_Scan.scanners",
        "import Virus_Scan.scanners",
        "from Virus_Scan.scheduler",
        "import Virus_Scan.scheduler",
        "from Virus_Scan.reporting",
        "import Virus_Scan.reporting",
        "from Virus_Scan.models",
        "import Virus_Scan.models",
        "from Virus_Scan.yara",
        "import Virus_Scan.yara",
    )
    assert source is not None
    for marker in forbidden_direct_imports:
        assert marker not in source
