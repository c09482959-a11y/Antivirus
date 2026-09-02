from __future__ import annotations

from pathlib import Path

from Virus_Scan.scanners.archives.rpa import scan_rpa_file


def test_missing_rpa_container_publishes_archive_rpa_failure_evidence(tmp_path: Path) -> None:
    missing = tmp_path / "missing.rpa"

    tags, suspicious = scan_rpa_file(str(missing))

    assert suspicious is True
    assert "rpa_scan_error" in tags
    assert "rpa_failure_evidence_recorded" in tags
    assert "archive_rpa_failure_evidence_recorded" in tags
    assert "archive_rpa_failure:rpa_scan_error" in tags
    assert "archive_rpa_failure_path" in tags
    assert "archive_final_json_must_record" in tags
    assert "scanner_failure_evidence:archive:rpa_scan" in tags
    assert "scan_incomplete" in tags


def test_corrupt_rpa_pickle_failure_retains_archive_rpa_publication(tmp_path: Path) -> None:
    sample = tmp_path / "corrupt.rpa"
    sample.write_bytes(b"RPA-3.0\x00\x00\x80pickle\x00broken")

    tags, suspicious = scan_rpa_file(str(sample))

    assert suspicious is True
    assert "rpa_failure_evidence_recorded" in tags
    assert "archive_rpa_failure_evidence_recorded" in tags
    assert "archive_final_json_must_record" in tags
    assert any(tag.startswith("scanner_failure_evidence:") for tag in tags)
