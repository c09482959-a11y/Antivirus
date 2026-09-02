from pathlib import Path
import zipfile

from Virus_Scan.scanners import archives
from Virus_Scan.scanners.ci.archive_boundary_audit import run_archive_boundary_audit


def _low(tags):
    return {str(tag).lower() for tag in tags or []}


def _assert_quota_publication(tags, reason_tag):
    low = _low(tags)
    assert reason_tag in low
    assert "archive_member_quota_exceeded" in low
    assert "scanner_failure" in low
    assert "scanner_degraded" in low
    assert "scan_incomplete" in low
    assert "scanner_failure_evidence_recorded" in low
    assert "scanner_failure_evidence:archive:archive_quota" in low
    assert "archive_final_json_must_record" in low


def test_nested_archive_depth_limit_requires_archive_json_evidence(tmp_path: Path):
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.txt", "benign text")
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(inner, "inner.zip")

    tags, suspicious = archives.scan_archive_file(str(outer), max_depth=0)
    low = _low(tags)

    assert suspicious
    assert "zip_archive" in low
    assert "archive_inner:archive_depth_limit" in low
    _assert_quota_publication(tags, "archive_depth_limit")


def test_zip_member_count_limit_requires_archive_json_evidence(tmp_path: Path):
    sample = tmp_path / "many_members.zip"
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("one.txt", "one")
        archive.writestr("two.txt", "two")

    tags, suspicious = archives.scan_archive_file(str(sample), max_members=1)
    low = _low(tags)

    assert suspicious
    assert "zip_archive" in low
    _assert_quota_publication(tags, "archive_member_limit")


def test_rpa_zip_nested_archive_depth_limit_preserves_archive_json_evidence(tmp_path: Path):
    leaf = tmp_path / "leaf.zip"
    with zipfile.ZipFile(leaf, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.txt", "benign text")
    middle = tmp_path / "middle.zip"
    with zipfile.ZipFile(middle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(leaf, "leaf.zip")
    sample = tmp_path / "nested_depth.rpa"
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(middle, "middle.zip")

    tags, suspicious = archives.scan_rpa_file(str(sample))
    low = _low(tags)

    assert suspicious
    assert "rpa_archive" in low
    assert "rpa_zip_container" in low
    assert "archive_depth_limit" in low
    _assert_quota_publication(tags, "archive_depth_limit")


def test_phase9_archive_boundary_audit_clean_after_quota_publication():
    result = run_archive_boundary_audit(Path("."))
    assert result.ok, result.to_record()
    assert result.files_scanned >= 13
