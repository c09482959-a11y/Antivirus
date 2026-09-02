from pathlib import Path

from Virus_Scan.scanners import archives
from Virus_Scan.scanners.ci.archive_boundary_audit import run_archive_boundary_audit


def _low(tags):
    return {str(tag).lower() for tag in tags or []}


def _assert_rpa_publication(tags, finding_tag):
    low = _low(tags)
    assert finding_tag in low
    assert "archive_rpa_finding_evidence_recorded" in low
    assert f"archive_rpa_finding:{finding_tag}" in low
    assert "archive_rpa_finding_path" in low
    assert "archive_final_json_must_record" in low


def test_raw_rpa_execution_finding_requires_archive_json_publication(tmp_path: Path):
    sample = tmp_path / "raw_exec.rpa"
    sample.write_bytes(b"RPA-3.0 synthetic\nrenpy python exec(\"calc\") subprocess.Popen")

    tags, suspicious = archives.scan_rpa_file(str(sample))
    low = _low(tags)

    assert suspicious
    assert "rpa_archive" in low
    assert "rpa_custom_container" in low
    assert "bytecode_exec" in low
    assert "process_exec" in low
    _assert_rpa_publication(tags, "rpa_raw_execution_finding")


def test_raw_rpa_network_finding_requires_archive_json_publication(tmp_path: Path):
    sample = tmp_path / "raw_network.rpa"
    sample.write_bytes(b"RPA-3.0 synthetic renpy socket connect http://example.invalid")

    tags, suspicious = archives.scan_rpa_file(str(sample))
    low = _low(tags)

    assert suspicious
    assert "rpa_archive" in low
    assert "network_activity" in low
    assert "reverse_shell" in low
    _assert_rpa_publication(tags, "rpa_raw_network_finding")


def test_raw_rpa_string_scanner_finding_requires_archive_json_publication(tmp_path: Path):
    sample = tmp_path / "raw_encoded.rpa"
    sample.write_bytes(b"RPA-3.0 synthetic renpy powershell -enc AAAA http://example.invalid/payload")

    tags, suspicious = archives.scan_rpa_file(str(sample))
    low = _low(tags)

    assert suspicious
    assert "rpa_archive" in low
    assert "archive_rpa_finding_evidence_recorded" in low
    assert "archive_final_json_must_record" in low


def test_phase9_archive_boundary_audit_clean_after_raw_rpa_publication_hooks():
    result = run_archive_boundary_audit(Path("."))
    assert result.ok, result.to_record()
    assert result.files_scanned >= 13
