from pathlib import Path

from Virus_Scan.detection.enrichment.strings.raw_stage_strings import scan_strings as detection_scan_strings
from Virus_Scan.runtime.scan_dependencies import register_scan_strings_provider
from Virus_Scan.runtime.scan_dependencies import scan_strings as runtime_scan_strings
from Virus_Scan.scanners.api.public_contracts import scan_strings_provider


def test_detection_tags_scan_strings_accepts_scanner_contract_kwargs(tmp_path):

    p = tmp_path / "Clock03.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\n")
    result = detection_scan_strings("https://example.invalid/test", path=p, finalize=False)
    assert isinstance(result, list)


def test_runtime_scan_dependency_provider_accepts_scanner_contract_kwargs(tmp_path):

    old_result = runtime_scan_strings("noop", path=tmp_path / "before.txt", finalize=False)
    assert old_result == set() or isinstance(old_result, (set, list, tuple))
    register_scan_strings_provider(scan_strings_provider)
    result = runtime_scan_strings("powershell -enc AAAA", path=tmp_path / "sample.txt", finalize=False)
    assert isinstance(result, list)
