from Virus_Scan.scanners.ci.production_import_audit import audit_production_scanner_imports


def test_production_callers_use_scanner_public_api_contracts():
    result = audit_production_scanner_imports(".")
    assert result.scanned_files > 0
    assert result.findings == ()
    assert result.ok is True
