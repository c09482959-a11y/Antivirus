"""Stage 905 Phase 10 binary behavior decomposition tests."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners.binary_behavior_detectors import detect_ransomware_file_rename_heuristic
from Virus_Scan.scanners.binary_behavior_filetype_model import (
    FiletypeBucketModelRequest,
    filetype_bucket_model_signal,
)


def _function_lengths(path: str) -> dict[str, int]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    return {
        node.name: getattr(node, "end_lineno", node.lineno) - node.lineno + 1
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    }


def test_binary_phase10_decomposed_functions_stay_under_preferred_gate():
    for path in (
        "Virus_Scan/scanners/binary_behavior_detectors.py",
        "Virus_Scan/scanners/binary_behavior_filetype_model.py",
    ):
        too_large = {name: length for name, length in _function_lengths(path).items() if length > 40}
        assert too_large == {}


def test_ransomware_detector_preserves_write_crypto_rename_behavior():
    result = detect_ransomware_file_rename_heuristic(
        "FindFirstFile WriteFile MoveFile CryptEncrypt recover files bitcoin",
        tags={"file_collection"},
    )
    assert result["score"] > 0.7
    assert {"file_traversal", "rapid_file_write", "file_rename_delete", "crypto_file_operation", "ransom_note_indicator"}.issubset(set(result["tags"]))
    assert "crypto plus file write behavior" in result["hits"]


def test_filetype_model_signal_preserves_nonexec_violation_evidence(tmp_path):
    sample = tmp_path / "asset.png"
    sample.write_bytes(b"not-relevant")
    result = filetype_bucket_model_signal(FiletypeBucketModelRequest("media", str(sample), ["process_exec", "network_download"], strings_blob="CreateProcess http://x"))
    assert "context" in result
    assert "records" in result
    assert isinstance(result["filetype_anomaly"], float)
