from __future__ import annotations

import base64
import io
import pickle
import tarfile
import zipfile
from pathlib import Path

from Virus_Scan.scanners import archives
from Virus_Scan.scanners.archives.scanner import scan_archive_file
from Virus_Scan.scanners.ci.archive_boundary_audit import run_archive_boundary_audit


def _low(tags: list[str]) -> set[str]:
    return {str(tag).lower() for tag in tags or []}


def _assert_archive_publication(tags: list[str]) -> None:
    low = _low(tags)
    assert "archive_final_json_must_record" in low


def _write_zip(path: Path, members: dict[str, bytes | str]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in members.items():
            data = payload.encode("utf-8") if isinstance(payload, str) else payload
            archive.writestr(name, data)


def _write_tar_with_symlink(path: Path) -> None:
    with tarfile.open(path, "w") as archive:
        info = tarfile.TarInfo("link_out")
        info.type = tarfile.SYMTYPE
        info.linkname = "../outside"
        archive.addfile(info)


def test_archive_phase9_stress_matrix_publication_for_corrupt_unsupported_depth_and_member_failures(tmp_path: Path) -> None:
    corrupt_zip = tmp_path / "corrupt.zip"
    corrupt_zip.write_bytes(b"PK\x03\x04truncated")
    tags, suspicious = scan_archive_file(str(corrupt_zip))
    low = _low(tags)
    assert suspicious is True
    assert "malformed_zip_container" in low or "archive_scan_error" in low or "archive_unsupported_container" in low
    assert any(tag.startswith("scanner_failure_evidence:archive:") for tag in low)
    _assert_archive_publication(tags)

    unsupported = tmp_path / "unsupported.7z"
    unsupported.write_bytes(b"not a supported 7z fixture")
    tags, suspicious = scan_archive_file(str(unsupported))
    low = _low(tags)
    assert suspicious is True
    assert "archive_unsupported_container" in low
    assert "archive_container_failure_evidence_recorded" in low
    _assert_archive_publication(tags)

    inner = tmp_path / "inner.zip"
    _write_zip(inner, {"payload.txt": "plain"})
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.write(inner, "inner.zip")
    tags, suspicious = scan_archive_file(str(outer), max_depth=0)
    low = _low(tags)
    assert suspicious is True
    assert "archive_depth_limit" in low
    assert "scanner_failure_evidence:archive:archive_quota" in low
    _assert_archive_publication(tags)

    tiny_pe = tmp_path / "tiny_pe.zip"
    _write_zip(tiny_pe, {"tiny.exe": b"MZ"})
    tags, suspicious = scan_archive_file(str(tiny_pe))
    low = _low(tags)
    assert suspicious is True
    assert "malformed_binary_archive_member" in low
    assert "archive_member_malformed_binary" in low
    assert "archive_member_failure_evidence_recorded" in low
    _assert_archive_publication(tags)

    tar_with_symlink = tmp_path / "unsupported_member.tar"
    _write_tar_with_symlink(tar_with_symlink)
    tags, suspicious = scan_archive_file(str(tar_with_symlink))
    low = _low(tags)
    assert suspicious is True
    assert "archive_unsupported_member_type" in low
    assert "archive_member_failure_evidence_recorded" in low
    _assert_archive_publication(tags)


def test_archive_phase9_stress_matrix_publication_for_payload_pickle_and_rpa_findings(tmp_path: Path) -> None:
    pickle_zip = tmp_path / "pickle_payload.zip"
    _write_zip(pickle_zip, {"bad.pkl": pickle.dumps(eval)})
    tags, suspicious = scan_archive_file(str(pickle_zip))
    low = _low(tags)
    assert suspicious is True
    assert "archive_member_pickle_payload_finding" in low
    assert "archive_member_finding_evidence_recorded" in low
    _assert_archive_publication(tags)

    encoded_payload = base64.b64encode(b"subprocess.Popen(['calc']) exec('x')").decode("ascii")
    payload_zip = tmp_path / "payload_chain.zip"
    _write_zip(payload_zip, {"payload.txt": encoded_payload})
    tags, suspicious = scan_archive_file(str(payload_zip))
    low = _low(tags)
    assert suspicious is True
    assert "archive_member_decoded_payload_finding" in low
    assert "archive_member_finding_evidence_recorded" in low
    _assert_archive_publication(tags)

    raw_rpa = tmp_path / "raw_exec_network.rpa"
    raw_rpa.write_bytes(b"RPA-3.0 renpy python pickle exec('x') socket connect http://example.invalid")
    tags, suspicious = archives.scan_rpa_file(str(raw_rpa))
    low = _low(tags)
    assert suspicious is True
    assert "archive_rpa_finding_evidence_recorded" in low
    assert "archive_rpa_finding:rpa_raw_execution_finding" in low
    assert "archive_rpa_finding:rpa_raw_network_finding" in low
    _assert_archive_publication(tags)

    rpa_zip = tmp_path / "embedded_binary.rpa"
    _write_zip(rpa_zip, {"tiny.dll": b"MZ"})
    tags, suspicious = archives.scan_rpa_file(str(rpa_zip))
    low = _low(tags)
    assert suspicious is True
    assert "rpa_zip_container" in low
    assert "malformed_binary_archive_member" in low
    assert "archive_member_failure_evidence_recorded" in low
    _assert_archive_publication(tags)


def test_archive_phase9_boundary_audit_remains_clean_after_stress_matrix_coverage() -> None:
    result = run_archive_boundary_audit(Path("."))
    assert result.ok, result.to_record()
