"""Stage 904 Phase 10 entropy runtime dependency ownership tests."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners import entropy


def test_entropy_module_uses_scanner_owned_binary_io_not_runtime_scan_dependencies():
    path = Path("Virus_Scan/scanners/entropy.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    forbidden = "Virus_Scan.runtime.scan_dependencies"
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.module != forbidden
        elif isinstance(node, ast.Import):
            assert all(alias.name != forbidden for alias in node.names)


def test_entropy_missing_file_failure_publishes_binary_json_evidence(tmp_path):
    result = entropy.detect_packer_entropy_anomaly(str(tmp_path / "missing.bin"))
    assert result["score"] == 0.0
    assert "entropy_scan_error" in result["tags"]
    assert "entropy_final_json_must_record" in result["tags"]
    assert "scanner_failure_evidence_recorded" in result["tags"]
    assert "scanner_failure_evidence:entropy:entropy_read_or_analysis" in result["tags"]
    assert result["scan_integrity"]["final_json_must_record"] is True
    assert result["scanner_failure_evidence"][0]["scanner_name"] == "entropy"


def test_entropy_empty_file_failure_publishes_binary_json_evidence(tmp_path):
    sample = tmp_path / "empty.bin"
    sample.write_bytes(b"")
    result = entropy.detect_packer_entropy_anomaly(str(sample))
    assert "entropy_scan_empty_input" in result["tags"]
    assert "entropy_final_json_must_record" in result["tags"]
    assert "scanner_failure_evidence:entropy:entropy_empty_input" in result["tags"]
