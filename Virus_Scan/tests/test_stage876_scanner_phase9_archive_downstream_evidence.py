from pathlib import Path
import zipfile

from Virus_Scan.scanners import archives
from Virus_Scan.scanners.ci.archive_boundary_audit import run_archive_boundary_audit


def _low(tags):
    return {str(tag).lower() for tag in tags or []}


def _assert_archive_failure_publication(tags):
    low = _low(tags)
    assert "scanner_failure" in low
    assert "scanner_degraded" in low
    assert "scan_incomplete" in low
    assert "scanner_failure_evidence_recorded" in low
    assert "archive_final_json_must_record" in low


def test_unsupported_rar_container_requires_downstream_archive_json_evidence(tmp_path: Path):
    sample = tmp_path / "fake.rar"
    sample.write_bytes(b"not a rar container")
    tags, suspicious = archives.scan_archive_file(str(sample))
    low = _low(tags)
    assert suspicious
    assert "unknown_archive" in low
    assert "malformed_container" in low
    assert "malformed_rar_container" in low
    assert "archive_container_failure_evidence_recorded" in low
    assert "scanner_failure_evidence:archive:archive_unsupported_container" in low
    _assert_archive_failure_publication(tags)


def test_zip_unsafe_member_path_requires_archive_json_evidence(tmp_path: Path):
    sample = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../escape.txt", b"payload")
    tags, suspicious = archives.scan_archive_file(str(sample))
    low = _low(tags)
    assert suspicious
    assert "zip_archive" in low
    assert "archive_blocked_unsafe_path" in low
    assert "archive_member_failure_evidence_recorded" in low
    assert "scanner_failure_evidence:archive:archive_blocked_unsafe_path" in low
    _assert_archive_failure_publication(tags)


def test_zip_malformed_binary_member_requires_archive_json_evidence(tmp_path: Path):
    sample = tmp_path / "malformed_binary.zip"
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.exe", b"MZ")
    tags, suspicious = archives.scan_archive_file(str(sample))
    low = _low(tags)
    assert suspicious
    assert "zip_archive" in low
    assert "archive_member_malformed_binary" in low
    assert "malformed_binary_archive_member" in low
    assert "archive_inner:archive_member_malformed_binary" in low
    assert "scanner_failure_evidence:archive:archive_member_malformed_binary" in low
    _assert_archive_failure_publication(tags)


def test_rpa_zip_malformed_binary_member_propagates_archive_json_evidence(tmp_path: Path):
    sample = tmp_path / "malformed_binary.rpa"
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.dll", b"MZ")
    tags, suspicious = archives.scan_rpa_file(str(sample))
    low = _low(tags)
    assert suspicious
    assert "rpa_archive" in low
    assert "rpa_zip_container" in low
    assert "archive_member_malformed_binary" in low
    assert "scanner_failure_evidence:archive:archive_member_malformed_binary" in low
    assert "archive_final_json_must_record" in low
    assert "archive_inner:archive_member_malformed_binary" in low


def test_phase9_archive_boundary_audit_still_clean_after_downstream_evidence_hooks():
    result = run_archive_boundary_audit(Path("."))
    assert result.ok, result.to_record()
    assert result.files_scanned >= 13


def test_custom_rpa_corpus_preserves_failure_evidence_and_final_json_markers(tmp_path: Path):
    corpus = []
    bad_header = tmp_path / "bad_header.rpa"
    bad_header.write_bytes(b"RPA-3.0 not_hex 00000000\nrenpy pickle python exec(")
    corpus.append((bad_header, "scanner_failure_evidence:archive_rpa:rpa_member_parse"))

    zip_malformed = tmp_path / "malformed_payload.rpa"
    with zipfile.ZipFile(zip_malformed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.exe", b"MZ")
    corpus.append((zip_malformed, "scanner_failure_evidence:archive:archive_member_malformed_binary"))

    zip_unsafe = tmp_path / "unsafe_member.rpa"
    with zipfile.ZipFile(zip_unsafe, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../escape.rpy", b"eval('x')")
    corpus.append((zip_unsafe, "scanner_failure_evidence:archive:archive_blocked_unsafe_path"))

    for sample, required_tag in corpus:
        tags, suspicious = archives.scan_rpa_file(str(sample))
        low = _low(tags)
        assert suspicious, sample.name
        assert "rpa_archive" in low
        assert required_tag in low
        assert "archive_final_json_must_record" in low
        assert "scanner_failure_evidence_recorded" in low
