import Virus_Scan.scanners.binary as binary

from pathlib import Path

from Virus_Scan.scanners.entropy import detect_packer_entropy_anomaly
from Virus_Scan.scanners.binary_pe import _dotnet_pe_result


def test_entropy_empty_input_returns_json_visible_failure_evidence(tmp_path):
    sample = tmp_path / "empty.bin"
    sample.write_bytes(b"")

    result = detect_packer_entropy_anomaly(str(sample))

    tags = set(result.get("tags") or [])
    assert result["score"] == 0.0
    assert "entropy_scan_empty_input" in tags
    assert "scanner_failure" in tags
    assert "scanner_degraded" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert "scanner_failure_evidence:entropy:entropy_empty_input" in tags
    assert "entropy_final_json_must_record" in tags
    assert result.get("scanner_failure_evidence")
    integrity = result.get("scan_integrity") or {}
    assert integrity.get("final_json_must_record") is True
    assert integrity.get("scanner_failure_evidence")


def test_entropy_read_failure_returns_json_visible_failure_evidence(tmp_path):
    missing = tmp_path / "missing.bin"

    result = detect_packer_entropy_anomaly(str(missing))

    tags = set(result.get("tags") or [])
    assert result["score"] == 0.0
    assert "entropy_scan_error" in tags
    assert "scanner_failure" in tags
    assert "scanner_degraded" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert "scanner_failure_evidence:entropy:entropy_read_or_analysis" in tags
    assert "entropy_final_json_must_record" in tags
    assert result.get("scanner_failure_evidence")
    integrity = result.get("scan_integrity") or {}
    assert integrity.get("final_json_must_record") is True
    assert integrity.get("scanner_failure_evidence")


def test_dotnet_pe_malformed_header_uses_immutable_binary_evidence():
    result = _dotnet_pe_result(b"MZ\x00", input_path="truncated.exe")

    assert result.ok is False
    assert result.detected is False
    tags = set(result.failure_tags)
    assert "binary_parse_failed" in tags
    assert "scanner_failure" in tags
    assert "scanner_degraded" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert result.failure_evidence
    metadata = result.to_metadata()
    assert metadata["scan_integrity"]["final_json_must_record"] is True
    assert metadata["scanner_failure_evidence"]


def test_binary_scanner_has_no_function_attribute_error_side_channel():

    for name, value in vars(binary).items():
        if callable(value):
            assert not hasattr(value, "last_error_tags"), name
            assert not hasattr(value, "last_error"), name
