from Virus_Scan.contracts.yara_hits import YaraScanResult
from Virus_Scan.yara.match import yara_scan, yara_scan_with_optional_zip


def test_yara_scan_without_compiled_rules_fails_closed(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"clean-looking bytes")

    result = yara_scan(str(sample), compiled_rules=None)

    assert type(result) is YaraScanResult
    assert result.status == "unavailable"
    assert result.unavailable_reason == "yara_compiled_rules_unavailable"
    assert result.hits == ()


def test_yara_optional_zip_without_compiled_rules_fails_closed(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"clean-looking bytes")

    result = yara_scan_with_optional_zip(str(sample), compiled_rules=None)

    assert type(result) is YaraScanResult
    assert result.status == "unavailable"
    assert result.unavailable_reason == "yara_compiled_rules_unavailable"
    assert result.hits == ()
