from __future__ import annotations

import tarfile
import zipfile

import pytest

from Virus_Scan.runtime.config import ArchiveScanLimits
from Virus_Scan.runtime.resource_quotas import (
    ExtractionQuotaTracker,
    ResourceQuotaExceeded,
    extract_zip_member_with_quota,
    quota_tag,
    safe_zip_target,
)


class HostileArchiveMember:
    touched = 0

    @property
    def filename(self):  # pragma: no cover - regression asserts no access
        type(self).touched += 1
        raise RuntimeError("do not read filename")

    @property
    def file_size(self):  # pragma: no cover - regression asserts no access
        type(self).touched += 1
        raise RuntimeError("do not read file_size")

    @property
    def compress_size(self):  # pragma: no cover - regression asserts no access
        type(self).touched += 1
        raise RuntimeError("do not read compress_size")

    @property
    def name(self):  # pragma: no cover - regression asserts no access
        type(self).touched += 1
        raise RuntimeError("do not read name")

    @property
    def size(self):  # pragma: no cover - regression asserts no access
        type(self).touched += 1
        raise RuntimeError("do not read size")

    def is_dir(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise RuntimeError("do not call is_dir")

    def __str__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileZipInfo(zipfile.ZipInfo):
    touched = 0

    @property
    def filename(self):  # pragma: no cover - regression asserts no access
        type(self).touched += 1
        raise RuntimeError("do not read subclass filename")

    def is_dir(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise RuntimeError("do not call subclass is_dir")

    def __str__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise RuntimeError("do not stringify subclass")


class HostilePathText:
    touched = 0

    def __str__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise RuntimeError("do not stringify member name")

    def __fspath__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise RuntimeError("do not fspath member name")


class HostileQuotaError(ResourceQuotaExceeded):
    touched = 0

    @property
    def args(self):  # pragma: no cover - regression asserts no access
        type(self).touched += 1
        raise RuntimeError("do not read args")

    def __str__(self):  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise RuntimeError("do not stringify exception")


def _tracker() -> ExtractionQuotaTracker:
    return ExtractionQuotaTracker(
        ArchiveScanLimits(
            max_depth=2,
            max_members=10,
            max_member_size=1024,
            max_total_extracted_bytes=4096,
            max_total_extracted_files=10,
            max_decompression_ratio=120.0,
        )
    )


def test_stage1754_resource_quota_rejects_unknown_archive_member_without_hooks(tmp_path) -> None:
    HostileArchiveMember.touched = 0
    member = HostileArchiveMember()
    tracker = _tracker()

    for call in (
        tracker.reserve_member,
        tracker.record_zip_member,
        tracker.reserve_tar_member,
        tracker.record_tar_member,
    ):
        with pytest.raises(ResourceQuotaExceeded, match="archive_member_unsupported"):
            call(member)

    class DummyZip:
        def open(self, *_args, **_kwargs):  # pragma: no cover - must not be reached
            raise AssertionError("zip open should not run for unsupported member")

    with pytest.raises(ResourceQuotaExceeded, match="archive_member_unsupported"):
        extract_zip_member_with_quota(DummyZip(), member, tmp_path, tracker=_tracker())

    assert HostileArchiveMember.touched == 0


def test_stage1754_resource_quota_rejects_zipinfo_subclass_without_hooks() -> None:
    HostileZipInfo.touched = 0
    member = object.__new__(HostileZipInfo)

    with pytest.raises(ResourceQuotaExceeded, match="archive_member_unsupported"):
        _tracker().reserve_member(member)

    assert HostileZipInfo.touched == 0


def test_stage1754_resource_quota_rejects_unsafe_zip_target_text_without_hooks(tmp_path) -> None:
    HostilePathText.touched = 0

    with pytest.raises(ValueError, match="archive_member_name_unsupported"):
        safe_zip_target(tmp_path, HostilePathText())

    assert HostilePathText.touched == 0


def test_stage1754_resource_quota_tag_does_not_probe_hostile_exception_hooks() -> None:
    HostileQuotaError.touched = 0

    assert quota_tag(HostileQuotaError("archive_depth_limit")) == "archive_resource_quota_exceeded"
    assert HostileQuotaError.touched == 0


def test_stage1754_exact_stdlib_zip_and_tar_members_still_work(tmp_path) -> None:
    tracker = _tracker()
    zip_path = tmp_path / "sample.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("nested/archive.rpa", b"abc")
    with zipfile.ZipFile(zip_path, "r") as archive:
        member = archive.infolist()[0]
        assert type(member) is zipfile.ZipInfo
        assert tracker.reserve_member(member) == 3
        extracted = extract_zip_member_with_quota(archive, member, tmp_path / "out", tracker=_tracker())
        assert extracted is not None
        assert extracted.endswith("nested/archive.rpa")

    tar_member = tarfile.TarInfo("nested/archive.zip")
    tar_member.size = 12
    assert _tracker().reserve_tar_member(tar_member) == 12
