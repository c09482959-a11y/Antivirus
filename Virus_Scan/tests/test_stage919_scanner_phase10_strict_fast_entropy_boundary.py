"""Stage 919 Phase 10 strict-fast entropy boundary evidence tests."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.scanners import binary_strict_fast


def test_strict_fast_entropy_helper_failure_records_binary_evidence(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("plain ascii text that is otherwise boring\n", encoding="utf-8")

    def boom(_data: bytes) -> float:
        raise ValueError("entropy helper failed")

    ok, metadata = binary_strict_fast._strict_fast_file_is_boring_text(sample, entropy_calculator=boom)

    assert ok is False
    assert metadata["binary_strict_fast_failure"] == "entropy"
    assert metadata["binary_strict_fast_exception_type"] == "ValueError"
    assert metadata["scanner_failure"] is True
    assert metadata["scanner_degraded"] is True
    assert metadata["scan_incomplete"] is True
    assert metadata["scanner_failure_evidence_recorded"] is True
    assert metadata["binary_final_json_must_record"] is True


def test_strict_fast_entropy_success_path_preserved(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("plain ascii text that is otherwise boring\n", encoding="utf-8")

    ok, metadata = binary_strict_fast._strict_fast_file_is_boring_text(sample)

    assert ok is True
    assert metadata["entropy"] < 5.2
    assert "binary_strict_fast_failure" not in metadata
