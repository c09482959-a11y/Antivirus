"""Phase 22 shared archive context and cumulative nested quota gates."""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import zipfile

from Virus_Scan.scanners import archives


@contextmanager
def _archive_limits(**values: str):
    names = {
        "UMIGE_ARCHIVE_MAX_DEPTH": "3",
        "UMIGE_ARCHIVE_MAX_MEMBERS": "20",
        "UMIGE_ARCHIVE_MAX_MEMBER_SIZE": "4096",
        "UMIGE_ARCHIVE_MAX_TOTAL_BYTES": "4096",
        "UMIGE_ARCHIVE_MAX_TOTAL_FILES": "20",
        "UMIGE_ARCHIVE_MAX_RATIO": "120",
    }
    names.update(values)
    previous = {name: os.environ.get(name) for name in names}
    os.environ.update(names)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _nested_zip(tmp_path: Path, *, payload_size: int = 3000) -> Path:
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.bin", b"A" * payload_size)
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.write(inner, "inner.zip")
    return outer


def test_phase22_nested_archives_share_total_byte_budget(tmp_path: Path) -> None:
    outer = _nested_zip(tmp_path)
    with _archive_limits():
        tags, suspicious = archives.scan_archive_file(
            str(outer), max_depth=3, max_members=20, max_member_size=4096,
        )
    assert suspicious is True
    assert "archive_total_byte_limit" in tags
    assert "archive_member_quota_exceeded" in tags
    assert any(tag.startswith("archive_inner:archive_total_byte_limit") for tag in tags)


def test_phase22_nested_archives_share_total_file_budget(tmp_path: Path) -> None:
    outer = _nested_zip(tmp_path, payload_size=512)
    with _archive_limits(
        UMIGE_ARCHIVE_MAX_TOTAL_BYTES="8192",
        UMIGE_ARCHIVE_MAX_TOTAL_FILES="1",
    ):
        tags, suspicious = archives.scan_archive_file(
            str(outer), max_depth=3, max_members=20, max_member_size=4096,
        )
    assert suspicious is True
    assert "archive_total_file_limit" in tags
    assert "archive_member_quota_exceeded" in tags
    assert any(tag.startswith("archive_inner:archive_total_file_limit") for tag in tags)


def test_phase22_sibling_members_share_one_root_member_budget(tmp_path: Path) -> None:
    sample = tmp_path / "siblings.zip"
    with zipfile.ZipFile(sample, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("one.txt", "one")
        archive.writestr("two.txt", "two")
    with _archive_limits(UMIGE_ARCHIVE_MAX_MEMBERS="1"):
        tags, suspicious = archives.scan_archive_file(
            str(sample), max_depth=3, max_members=20, max_member_size=4096,
        )
    assert suspicious is True
    assert "archive_member_limit" in tags
    assert "archive_member_quota_exceeded" in tags
