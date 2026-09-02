from pathlib import Path
import zipfile

from Virus_Scan.scanners import archives
from Virus_Scan.scanners.ci.archive_boundary_audit import run_archive_boundary_audit


def _low(tags):
    return {str(tag).lower() for tag in tags or []}


def _assert_archive_publication(tags, finding_tag):
    low = _low(tags)
    assert finding_tag in low
    assert "archive_member_finding_evidence_recorded" in low
    assert f"archive_member_finding:{finding_tag}" in low
    assert "archive_member_finding_member" in low
    assert "archive_final_json_must_record" in low


def test_zip_embedded_pe_member_finding_requires_archive_json_publication(tmp_path: Path):
    sample = tmp_path / "pe_member.zip"
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("game/plugin.dll", b"MZ" + (b"A" * 96))

    tags, suspicious = archives.scan_archive_file(str(sample))
    low = _low(tags)

    assert suspicious
    assert "zip_archive" in low
    assert "embedded_pe_payload" in low
    assert "archive_member_magic_pe" in low
    _assert_archive_publication(tags, "archive_member_magic_pe_finding")


def test_zip_embedded_dotnet_member_finding_requires_archive_json_publication(tmp_path: Path):
    sample = tmp_path / "dotnet_member.zip"
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("Managed/Assembly-CSharp.dll", b"BSJB #~ Assembly-CSharp" + (b"A" * 96))

    tags, suspicious = archives.scan_archive_file(str(sample))
    low = _low(tags)

    assert suspicious
    assert "archive_member_dotnet_metadata" in low
    assert "embedded_dotnet_payload" in low
    _assert_archive_publication(tags, "archive_member_dotnet_payload_finding")


def test_zip_renpy_member_pickle_failure_requires_archive_json_publication(tmp_path: Path):
    sample = tmp_path / "renpy_member.zip"
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("game/archive.rpa", b"RPA-3.0 not-a-valid-pickle-but-renpy-member")

    tags, suspicious = archives.scan_archive_file(str(sample))
    low = _low(tags)

    assert suspicious
    assert "embedded_renpy_payload" in low
    assert "archive_member_renpy_payload_finding" in low
    assert "archive_member_pickle_payload" in low
    assert "scanner_failure_evidence:pickle:pickle_payload_opcode_decode" in low
    assert "archive_member_pickle_payload_failure" in low
    assert "archive_member_payload_failure_evidence_recorded" in low
    assert "archive_member_payload_failure:archive_member_pickle_payload_failure" in low
    assert "archive_final_json_must_record" in low


def test_phase9_archive_boundary_audit_still_clean_after_member_publication_hooks():
    result = run_archive_boundary_audit(Path("."))
    assert result.ok, result.to_record()
    assert result.files_scanned >= 13
