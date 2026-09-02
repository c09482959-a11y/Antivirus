from pathlib import Path
import zipfile

from Virus_Scan.scanners import archives
from Virus_Scan.scanners.archives.evidence import append_archive_quota_evidence
from Virus_Scan.scanners.archives.malformed import append_archive_failure_evidence
from Virus_Scan.scanners.ci.archive_boundary_audit import run_archive_boundary_audit
from Virus_Scan.runtime.resource_quotas import ResourceQuotaExceeded


def _lower(tags):
    return {str(tag).lower() for tag in (tags or [])}


def test_custom_rpa_bad_header_emits_member_parse_final_json_evidence(tmp_path: Path):
    sample = tmp_path / "broken_index.rpa"
    sample.write_bytes(b"RPA-3.0 not_hex 00000000\nrenpy pickle python exec(")
    tags, suspicious = archives.scan_rpa_file(str(sample))
    low = _lower(tags)
    assert suspicious
    assert "rpa_archive" in low
    assert "rpa_member_parse_failure" in low
    assert "rpa_member_decode_failure" in low
    assert "rpa_failure_evidence_recorded" in low
    assert "scanner_failure_evidence_recorded" in low
    assert "scanner_failure_evidence:archive_rpa:rpa_member_parse" in low
    assert "archive_final_json_must_record" in low


def test_archive_quota_evidence_is_marked_for_final_json_projection():
    tags = []
    tag = append_archive_quota_evidence(tags, ResourceQuotaExceeded("archive_member_limit"), member_name="payload.bin")
    low = _lower(tags)
    assert tag == "archive_member_limit"
    assert "archive_member_quota_exceeded" in low
    assert "scanner_failure_evidence_recorded" in low
    assert "scanner_failure_evidence:archive:archive_quota" in low
    assert "archive_final_json_must_record" in low


def test_archive_malformed_evidence_is_marked_for_final_json_projection(tmp_path: Path):
    sample = tmp_path / "bad.zip"
    exc = zipfile.BadZipFile("bad central directory")
    tags = append_archive_failure_evidence(["archive"], "scan_archive_file", exc, str(sample), "archive_scan_error")
    low = _lower(tags)
    assert "archive_scan_error" in low
    assert "failure_domain_extraction" in low
    assert "scanner_failure_evidence_recorded" in low
    assert "scanner_failure_evidence:archive:archive_scan_error" in low
    assert "archive_final_json_must_record" in low


def test_phase9_archive_boundary_audit_requires_rpa_member_behavior_module():
    result = run_archive_boundary_audit(Path("."))
    assert result.ok, result.to_record()
    assert result.files_scanned >= 13
