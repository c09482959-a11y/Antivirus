"""Immutable archive-member identity, container classification, and bounded views."""

from __future__ import annotations

from dataclasses import dataclass
from os import fstat
from pathlib import Path
from stat import S_ISREG
import tarfile
from typing import BinaryIO, Literal
import zipfile

from Virus_Scan.runtime.api import path_contains_filesystem_alias

ArchiveContainerKind = Literal["zip", "tar", "unknown"]

_CONTAINER_KINDS = frozenset({"zip", "tar", "unknown"})


@dataclass(frozen=True, slots=True)
class ArchiveMemberView:
    """One race-checked read/classification result for an extracted member."""

    path: str
    size: int
    container_kind: ArchiveContainerKind
    prefix: bytes
    suffix: bytes
    raw: bytes
    text: str
    truncated: bool

    def __post_init__(self) -> None:
        if type(self) is not ArchiveMemberView:
            raise TypeError("archive_member_view_owner_invalid")
        if type(self.path) is not str or not str.strip(self.path):
            raise ValueError("archive_member_view_path_invalid")
        if type(self.size) is not int or type(self.size) is bool or self.size < 0:
            raise ValueError("archive_member_view_size_invalid")
        if type(self.container_kind) is not str or self.container_kind not in _CONTAINER_KINDS:
            raise ValueError("archive_member_view_container_kind_invalid")
        if any(type(value) is not bytes for value in (self.prefix, self.suffix, self.raw)):
            raise TypeError("archive_member_view_bytes_invalid")
        if type(self.text) is not str:
            raise TypeError("archive_member_view_text_invalid")
        if type(self.truncated) is not bool:
            raise TypeError("archive_member_view_truncated_invalid")
        if self.container_kind != "unknown" and any((self.prefix, self.suffix, self.raw, self.text, self.truncated)):
            raise ValueError("archive_member_view_container_content_invalid")
        if self.container_kind == "unknown" and self.text != self.raw.decode("utf-8", errors="ignore"):
            raise ValueError("archive_member_view_text_mismatch")


def inspect_archive_member(
    path: str,
    *,
    probe_bytes: int,
    text_max_size: int,
) -> ArchiveMemberView:
    """Classify and, for a non-container, read all compatible bounded views once."""
    path_text = _exact_path(path)
    probe_limit = _positive_limit(probe_bytes, "archive_member_probe_limit_invalid")
    text_limit = _positive_limit(text_max_size, "archive_member_text_limit_invalid")
    file_path = Path(path_text)
    before = _regular_identity(file_path)
    with file_path.open("rb") as handle:
        opened = _open_identity(handle)
        _require_same_identity(before, opened, "archive_member_changed_before_read")
        container_kind = _container_kind_from_handle(handle)
        if container_kind != "unknown":
            after = _regular_identity(file_path)
            _require_same_identity(opened, after, "archive_member_changed_during_read")
            return ArchiveMemberView(
                path=path_text,
                size=opened[2],
                container_kind=container_kind,
                prefix=b"",
                suffix=b"",
                raw=b"",
                text="",
                truncated=False,
            )
        prefix, suffix, raw = _read_compatible_views(
            handle,
            size=opened[2],
            probe_limit=probe_limit,
            text_limit=text_limit,
        )
        after = _regular_identity(file_path)
        _require_same_identity(opened, after, "archive_member_changed_during_read")
    return ArchiveMemberView(
        path=path_text,
        size=opened[2],
        container_kind="unknown",
        prefix=prefix,
        suffix=suffix,
        raw=raw,
        text=raw.decode("utf-8", errors="ignore"),
        truncated=opened[2] > text_limit,
    )


def detect_archive_container_kind(path: str) -> ArchiveContainerKind:
    """Return one exact root-container classification from one race-checked open."""
    path_text = _exact_path(path)
    file_path = Path(path_text)
    before = _regular_identity(file_path)
    with file_path.open("rb") as handle:
        opened = _open_identity(handle)
        _require_same_identity(before, opened, "archive_container_changed_before_read")
        kind = _container_kind_from_handle(handle)
        after = _regular_identity(file_path)
        _require_same_identity(opened, after, "archive_container_changed_during_read")
    return kind


def _container_kind_from_handle(handle: BinaryIO) -> ArchiveContainerKind:
    handle.seek(0)
    if zipfile.is_zipfile(handle):
        return "zip"
    handle.seek(0)
    try:
        archive = tarfile.open(fileobj=handle, mode="r:*")
    except tarfile.TarError:
        handle.seek(0)
        return "unknown"
    else:
        archive.close()
        handle.seek(0)
        return "tar"


def _read_compatible_views(
    handle: BinaryIO,
    *,
    size: int,
    probe_limit: int,
    text_limit: int,
) -> tuple[bytes, bytes, bytes]:
    handle.seek(0)
    sample = handle.read(max(probe_limit, text_limit))
    raw = sample[:text_limit]
    prefix = sample[:probe_limit]
    if size <= len(sample):
        suffix = sample[max(0, size - probe_limit):size]
    else:
        handle.seek(max(0, size - probe_limit))
        suffix = handle.read(probe_limit)
    return prefix, suffix, raw


def _exact_path(path: object) -> str:
    if type(path) is not str:
        raise TypeError("archive_member_view_path_invalid")
    text = str.__str__(path)
    if not str.strip(text):
        raise ValueError("archive_member_view_path_invalid")
    return text


def _positive_limit(value: object, reason: str) -> int:
    if type(value) is not int or type(value) is bool or value <= 0:
        raise ValueError(reason)
    return value


def _regular_identity(path: Path) -> tuple[int, int, int, int]:
    info = path.lstat()
    if path_contains_filesystem_alias(path) or not S_ISREG(info.st_mode):
        raise ValueError("archive_member_not_regular_file")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _open_identity(handle: BinaryIO) -> tuple[int, int, int, int]:
    info = fstat(handle.fileno())
    if not S_ISREG(info.st_mode):
        raise ValueError("archive_member_not_regular_file")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _require_same_identity(
    expected: tuple[int, int, int, int],
    observed: tuple[int, int, int, int],
    reason: str,
) -> None:
    if expected != observed:
        raise OSError(reason)


__all__ = (
    "ArchiveContainerKind",
    "ArchiveMemberView",
    "detect_archive_container_kind",
    "inspect_archive_member",
)
