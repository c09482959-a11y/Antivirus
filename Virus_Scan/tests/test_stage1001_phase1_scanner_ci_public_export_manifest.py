from types import ModuleType

from Virus_Scan.scanners.ci import public_export_smoke


def test_scanner_public_export_smoke_does_not_publish_module_object_manifest():
    assert not hasattr(public_export_smoke, "SCANNER_PUBLIC_MODULES")
    module_names = public_export_smoke._SCANNER_PUBLIC_MODULE_NAMES
    assert isinstance(module_names, tuple)
    assert module_names == tuple(sorted(module_names))
    assert module_names
    assert all(isinstance(name, str) for name in module_names)
    assert all(not isinstance(name, ModuleType) for name in module_names)


def test_scanner_public_export_discovery_resolves_static_names_without_manifest_state():
    exports = public_export_smoke.discover_scanner_public_exports()
    module_names = public_export_smoke._SCANNER_PUBLIC_MODULE_NAMES
    assert exports
    assert all(export.module in module_names for export in exports)
    assert any(export.name == "scan_archive_file" for export in exports)
