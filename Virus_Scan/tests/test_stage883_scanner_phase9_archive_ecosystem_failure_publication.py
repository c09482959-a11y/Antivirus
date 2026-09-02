from __future__ import annotations

from pathlib import Path
from zipfile import ZipInfo

from Virus_Scan.scanners.archives.tar_scanner import _bounded_tar_members
from Virus_Scan.scanners.archives.zip_scanner import _bounded_zip_infos


class _BadInt:
    def __int__(self) -> int:
        raise ValueError("synthetic archive ecosystem score conversion failure")


class _ZipArchiveWithBadSize:
    def infolist(self) -> list[ZipInfo]:
        info = ZipInfo("payload.txt")
        info.compress_size = _BadInt()
        info.file_size = 1
        return [info]


class _TarMemberWithBadSize:
    name = "payload.txt"
    size = _BadInt()


class _TarArchiveWithBadSize:
    def getmembers(self) -> list[_TarMemberWithBadSize]:
        return [_TarMemberWithBadSize()]


def _assert_ecosystem_failure_publication(tags: list[str]) -> None:
    lowered = {str(tag).lower() for tag in tags or []}
    assert "archive_ecosystem_score_failure" in lowered
    assert "archive_ecosystem_failure_evidence_recorded" in lowered
    assert "archive_ecosystem_failure:archive_ecosystem_score_failure" in lowered
    assert "archive_ecosystem_failure_path" in lowered
    assert "scanner_degraded" in lowered
    assert "scan_incomplete" in lowered
    assert "archive_final_json_must_record" in lowered


def test_zip_ecosystem_scoring_failure_publishes_archive_json_evidence(tmp_path: Path) -> None:
    archive_path = tmp_path / "bad_ecosystem.zip"
    archive_path.write_bytes(b"placeholder")
    tags = ["archive_scan", "zip_archive"]

    infos, original_count, suspicious = _bounded_zip_infos(
        str(archive_path),
        _ZipArchiveWithBadSize(),
        archive_depth=0,
        max_members=8,
        tags=tags,
        suspicious=False,
    )

    assert original_count == 1
    assert len(infos) == 1
    assert suspicious is True
    _assert_ecosystem_failure_publication(tags)


def test_tar_ecosystem_scoring_failure_publishes_archive_json_evidence(tmp_path: Path) -> None:
    archive_path = tmp_path / "bad_ecosystem.tar"
    archive_path.write_bytes(b"placeholder")
    tags = ["archive_scan", "tar_archive"]

    members, original_count, suspicious = _bounded_tar_members(
        str(archive_path),
        _TarArchiveWithBadSize(),
        archive_depth=0,
        max_members=8,
        tags=tags,
        suspicious=False,
    )

    assert original_count == 1
    assert len(members) == 1
    assert suspicious is True
    _assert_ecosystem_failure_publication(tags)
