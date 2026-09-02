from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture

from Virus_Scan.scanners import image


def test_fast_image_path_reports_malformed_png_evidence(tmp_path):
    sample = tmp_path / "bad.png"
    sample.write_bytes(b"not a real png image")

    tags, suspicious = image.scan_image_file(str(sample), artifact_read_snapshot=artifact_read_snapshot_fixture(sample))
    low = {str(tag).lower() for tag in tags}

    assert suspicious is True
    assert "image_decode_failed" in low
    assert "malformed_image_input" in low
    assert "scanner_failure" in low
    assert "scanner_failure_evidence_recorded" in low
    assert "fast_image_magic_validation_scan_error" in low
    assert "image_final_json_must_record" in low
    assert "image_fast_triage_clean" not in low
    assert "asset_fast_triage_clean" not in low
