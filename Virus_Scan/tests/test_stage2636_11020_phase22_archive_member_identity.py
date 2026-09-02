from __future__ import annotations

from io import BytesIO
from pathlib import Path
import stat
import tarfile
import warnings
import zipfile

from Virus_Scan.scanners.archives.scanner import scan_archive_file


def _write_tar_member(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    archive.addfile(info, BytesIO(payload))


def test_phase22_duplicate_zip_member_path_fails_closed_before_second_scan(tmp_path: Path) -> None:
    archive_path = tmp_path / "duplicate.zip"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("same.txt", "benign text")
            archive.writestr("same.txt", "powershell -enc ZQB2AGkAbAA=")

    tags, suspicious = scan_archive_file(str(archive_path))

    assert suspicious is True
    assert "archive_duplicate_member_path" in tags
    assert "archive_member_failure_evidence_recorded" in tags
    assert "archive_final_json_must_record" in tags
    assert "powershell_encoded" not in tags


def test_phase22_duplicate_tar_member_path_fails_closed_before_second_scan(tmp_path: Path) -> None:
    archive_path = tmp_path / "duplicate.tar"
    with tarfile.open(archive_path, "w") as archive:
        _write_tar_member(archive, "same.txt", b"benign text")
        _write_tar_member(archive, "same.txt", b"powershell -enc ZQB2AGkAbAA=")

    tags, suspicious = scan_archive_file(str(archive_path))

    assert suspicious is True
    assert "archive_duplicate_member_path" in tags
    assert "archive_member_failure_evidence_recorded" in tags
    assert "archive_final_json_must_record" in tags
    assert "powershell_encoded" not in tags


def test_phase22_zip_symlink_is_rejected_before_materialization(tmp_path: Path) -> None:
    archive_path = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(info, "../../outside")

    tags, suspicious = scan_archive_file(str(archive_path))

    assert suspicious is True
    assert "archive_unsupported_member_type" in tags
    assert "archive_member_failure_evidence_recorded" in tags
    assert "archive_final_json_must_record" in tags
    assert "archive_member" not in tags


def test_phase22_zip_special_file_is_rejected_before_materialization(tmp_path: Path) -> None:
    archive_path = tmp_path / "fifo.zip"
    info = zipfile.ZipInfo("pipe")
    info.create_system = 3
    info.external_attr = (stat.S_IFIFO | 0o600) << 16
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(info, b"")

    tags, suspicious = scan_archive_file(str(archive_path))

    assert suspicious is True
    assert "archive_unsupported_member_type" in tags
    assert "archive_member_failure_evidence_recorded" in tags
    assert "archive_final_json_must_record" in tags
    assert "archive_member" not in tags
