from pathlib import Path
import struct
import zipfile

from Virus_Scan.scanners import archives
from Virus_Scan.scanners.ci.archive_boundary_audit import run_archive_boundary_audit


def test_phase9_archive_boundary_audit_is_clean():
    result = run_archive_boundary_audit(Path('.'))
    assert result.ok, result.to_record()
    assert result.files_scanned >= 9


def test_nested_archive_respects_outer_depth_boundary(tmp_path):
    inner = tmp_path / 'inner.zip'
    with zipfile.ZipFile(inner, 'w') as archive:
        archive.writestr('payload.txt', 'benign text')
    outer = tmp_path / 'outer.zip'
    with zipfile.ZipFile(outer, 'w') as archive:
        archive.write(inner, 'inner.zip')
    tags, suspicious = archives.scan_archive_file(str(outer), max_depth=0)
    assert suspicious
    assert 'zip_archive' in tags
    assert 'archive_depth_limit' in tags
    assert any(str(tag).startswith('archive_inner:archive_depth_limit') for tag in tags)


def test_bad_zip_central_directory_emits_archive_failure_evidence(tmp_path):
    bad = tmp_path / 'bad.zip'
    bad.write_bytes(struct.pack('<4s4H2LH', b'PK\x05\x06', 0, 0, 1, 1, 46, 999, 0))
    tags, suspicious = archives.scan_archive_file(str(bad))
    assert suspicious
    assert 'zip_archive' in tags or 'archive_scan_error' in tags
    assert 'archive_scan_error' in tags
    assert any('failure' in str(tag).lower() or 'error' in str(tag).lower() for tag in tags)


def test_unsupported_archive_extension_is_malformed_evidence(tmp_path):
    sample = tmp_path / 'asset.7z'
    sample.write_bytes(b'not a real seven zip container')
    tags, suspicious = archives.scan_archive_file(str(sample))
    assert suspicious
    assert 'unknown_archive' in tags
    assert 'malformed_container' in tags
    assert 'malformed_7z_container' in tags


def test_archive_member_boundary_detects_payload_magic(tmp_path):
    sample = tmp_path / 'payload.bin'
    sample.write_bytes(b'prefix' + (b'\x00' * 64) + b'MZ')
    tags, suspicious = archives.scan_extracted_archive_member(str(sample))
    assert suspicious
    assert 'archive_member' in tags
    assert 'appended_pe_payload' in tags
