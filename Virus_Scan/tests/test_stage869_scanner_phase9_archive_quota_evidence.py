from pathlib import Path
import zipfile

from Virus_Scan.scanners import archives
from Virus_Scan.scanners.ci.archive_boundary_audit import run_archive_boundary_audit


def test_zip_large_member_quota_emits_archive_evidence(tmp_path: Path):
    sample = tmp_path / "oversized.zip"
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.bin", b"A" * 128)
    tags, suspicious = archives.scan_archive_file(str(sample), max_member_size=8)
    assert suspicious
    assert "zip_archive" in tags
    assert "archive_large_member_skipped" in tags
    assert "archive_member_quota_exceeded" in tags
    assert "failure_domain_extraction" in tags


def test_nested_zip_member_size_limit_is_preserved(tmp_path: Path):
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.bin", b"B" * 2048)
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(inner, "inner.zip")
    tags, suspicious = archives.scan_archive_file(str(outer), max_member_size=512, max_depth=2)
    assert suspicious
    assert "archive_large_member_skipped" in tags
    assert any(str(tag).startswith("archive_inner:archive_large_member_skipped") for tag in tags)


def test_phase9_archive_boundary_audit_includes_evidence_module():
    result = run_archive_boundary_audit(Path("."))
    assert result.ok, result.to_record()
    assert result.files_scanned >= 11

import tarfile


def test_tar_member_scanner_detects_embedded_binary_payload(tmp_path: Path):
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"MZ" + (b"\x00" * 64))
    sample = tmp_path / "payload.tar"
    with tarfile.open(sample, "w") as archive:
        archive.add(payload, arcname="payload.bin")
    tags, suspicious = archives.scan_archive_file(str(sample), max_member_size=1024)
    assert suspicious
    assert "tar_archive" in tags
    assert "embedded_pe_payload" in tags
    assert any(str(tag).startswith("archive_inner:embedded_pe_payload") for tag in tags)


def test_tar_large_member_quota_emits_archive_evidence(tmp_path: Path):
    payload = tmp_path / "large.bin"
    payload.write_bytes(b"C" * 2048)
    sample = tmp_path / "large.tar"
    with tarfile.open(sample, "w") as archive:
        archive.add(payload, arcname="large.bin")
    tags, suspicious = archives.scan_archive_file(str(sample), max_member_size=512)
    assert suspicious
    assert "tar_archive" in tags
    assert "archive_large_member_skipped" in tags
    assert "archive_member_quota_exceeded" in tags


def test_rpa_zip_corrupt_member_emits_archive_member_failure_evidence(tmp_path: Path):
    sample = tmp_path / "corrupt_member.rpa"
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.txt", b"hello world")
    with zipfile.ZipFile(sample) as archive:
        info = archive.getinfo("payload.txt")
        data_offset = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
    raw = bytearray(sample.read_bytes())
    raw[data_offset] ^= 0xFF
    sample.write_bytes(raw)
    tags, suspicious = archives.scan_rpa_file(str(sample))
    assert suspicious
    assert "rpa_archive" in tags
    assert "rpa_zip_container" in tags
    assert "archive_member_scan_error" in tags
    assert "failure_domain_extraction" in tags


def test_rpa_zip_large_member_uses_rpa_archive_policy_evidence(tmp_path: Path):
    sample = tmp_path / "large_member.rpa"
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.bin", b"D" * (9 * 1024 * 1024))
    tags, suspicious = archives.scan_rpa_file(str(sample))
    assert suspicious
    assert "rpa_zip_container" in tags
    assert "archive_large_member_skipped" in tags
    assert "archive_member_quota_exceeded" in tags
