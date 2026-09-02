from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

from Virus_Scan.scanners.archives.scanner import scan_archive_file


def _make_zip_ecosystem_limit(path: Path, members: int = 120) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for index in range(members):
            archive.writestr(f"member_{index}.ext{index}", b"")


def _make_tar_ecosystem_limit(path: Path, members: int = 120) -> None:
    with tarfile.open(path, "w") as archive:
        for index in range(members):
            info = tarfile.TarInfo(f"member_{index}.ext{index}")
            info.size = 0
            archive.addfile(info, io.BytesIO(b""))


def _assert_ecosystem_publication(tags: list[str]) -> None:
    assert "archive_ecosystem_score_limit" in tags
    assert "archive_ecosystem_boundary_evidence_recorded" in tags
    assert "archive_ecosystem_boundary:archive_ecosystem_score_limit" in tags
    assert "archive_ecosystem_boundary_path" in tags
    assert "archive_ecosystem_boundary_score" in tags
    assert "archive_ecosystem_member_scan_limited" in tags
    assert "scanner_degraded" in tags
    assert "scan_incomplete" in tags
    assert "archive_final_json_must_record" in tags


def test_zip_ecosystem_score_limit_publishes_archive_json_evidence(tmp_path: Path) -> None:
    archive = tmp_path / "ecosystem.zip"
    _make_zip_ecosystem_limit(archive)

    tags, suspicious = scan_archive_file(str(archive), max_members=250)

    assert suspicious is True
    _assert_ecosystem_publication(tags)


def test_tar_ecosystem_score_limit_publishes_archive_json_evidence(tmp_path: Path) -> None:
    archive = tmp_path / "ecosystem.tar"
    _make_tar_ecosystem_limit(archive)

    tags, suspicious = scan_archive_file(str(archive), max_members=250)

    assert suspicious is True
    _assert_ecosystem_publication(tags)
