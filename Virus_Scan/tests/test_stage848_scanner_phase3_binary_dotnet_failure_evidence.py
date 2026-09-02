import dataclasses

import pytest

from Virus_Scan.scanners import binary
from Virus_Scan.scanners import binary_pe
from Virus_Scan.scanners.contracts.binary_result import BinaryAnalysisResult


def test_dotnet_pe_truncated_header_returns_immutable_malformed_result():
    result = binary_pe._dotnet_pe_result(b"MZ")

    assert isinstance(result, BinaryAnalysisResult)
    assert dataclasses.is_dataclass(result)
    assert result.ok is False
    assert result.detected is False
    assert result.failure_evidence
    assert result.failure_evidence[0]["scanner_name"] == "binary"
    assert result.failure_evidence[0]["scanner_stage"] == "dotnet_pe_header"
    assert result.failure_evidence[0]["state"] == "malformed"
    assert result.failure_evidence[0]["final_json_must_record"] is True
    assert "binary_parse_failed" in result.failure_tags
    assert "scanner_failure_evidence_recorded" in result.failure_tags


def test_is_dotnet_pe_preserves_bool_api_without_hidden_exception():
    assert binary.is_dotnet_pe(b"MZ") is False
    assert binary.is_dotnet_pe(b"not a pe") is False


def test_extract_dotnet_metadata_publishes_malformed_binary_evidence(tmp_path):
    malformed_pe = tmp_path / "truncated.exe"
    malformed_pe.write_bytes(b"MZ")

    metadata = binary.extract_dotnet_metadata(str(malformed_pe))

    assert metadata["is_dotnet"] is False
    assert metadata["error"] is True
    assert metadata["scanner_degraded"] is True
    assert metadata["scanner_failure_evidence"]
    evidence = metadata["scanner_failure_evidence"][0]
    assert evidence["scanner_name"] == "binary"
    assert evidence["scanner_stage"] == "dotnet_pe_header"
    assert evidence["error_category"] == "malformed_binary_input"
    assert metadata["scan_integrity"]["final_json_must_record"] is True


def test_dotnet_pe_result_is_frozen():
    result = binary_pe._dotnet_pe_result(b"MZ")

    with pytest.raises(dataclasses.FrozenInstanceError):
        result.ok = True
