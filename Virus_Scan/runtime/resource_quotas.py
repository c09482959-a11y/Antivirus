"""Hard extraction/resource quota helpers.

All archive-like expansion paths should use this module before writing extracted
members.  It enforces zip-slip protection, member count, byte budgets, file-count
budgets, and decompression-ratio limits in one place.
"""
from __future__ import annotations

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from dataclasses import dataclass, field
from pathlib import Path, PosixPath, PurePosixPath, PureWindowsPath, WindowsPath
import os
import shutil
import tarfile
import zipfile
from typing import NoReturn

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_owner_field,
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
)
from Virus_Scan.runtime.config import ArchiveScanLimits
from Virus_Scan.runtime.resource_economics import ExtractionEconomics


class ResourceQuotaExceeded(RuntimeError):
    """Raised when an extraction/resource hard quota is exceeded."""


_STDLIB_PATH_TYPES = (Path, PosixPath, WindowsPath, PurePosixPath, PureWindowsPath)
_ARCHIVE_SUFFIXES = (".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".rpa")
_BLOCKED_UNSAFE_ZIP_MEMBER_NAME = "blocked unsafe zip member: archive_member_name_unsupported"


def _raise_blocked_unsafe_zip_member_name() -> NoReturn:
    raise ValueError(_BLOCKED_UNSAFE_ZIP_MEMBER_NAME)


def _quota_nonnegative_int(value: object, reason: str) -> int:
    parsed, unavailable = no_hook_exact_nonnegative_int(
        value,
        reason=reason,
        non_finite_reason=reason,
        allow_exact_text=False,
    )
    if unavailable:
        raise ResourceQuotaExceeded(reason)
    return parsed


def _quota_positive_float(value: object, reason: str) -> float:
    parsed, unavailable = no_hook_finite_float(
        value,
        minimum=0.0,
        reason=reason,
        non_finite_reason=reason,
        allow_exact_text=False,
    )
    if unavailable or parsed <= 0.0:
        raise ResourceQuotaExceeded(reason)
    return parsed


def _quota_member_text(value: object) -> str | None:
    if type(value) is str:
        return str.__str__(value)
    if type(value) is bytes:
        return value.decode("utf-8", errors="replace")
    if type(value) is bytearray:
        return bytes(value).decode("utf-8", errors="replace")
    if type(value) is Path:
        return Path.as_posix(value)
    if type(value) is PosixPath:
        return PosixPath.as_posix(value)
    if type(value) is WindowsPath:
        return WindowsPath.as_posix(value)
    if type(value) is PurePosixPath:
        return PurePosixPath.as_posix(value)
    if type(value) is PureWindowsPath:
        return PureWindowsPath.as_posix(value)
    return None


def _quota_text(value: object, standard_text: str) -> str:
    if type(value) is str:
        return str.__str__(value)
    return standard_text


def _quota_reason(value: object, suffix: str) -> str:
    return _quota_text(value, "quota") + "_" + str.__str__(suffix)


def _quota_env_reason(name: object) -> str:
    if type(name) is str:
        return str.__str__(name).lower() + "_unsupported"
    return "runtime_budget_env_unsupported"


def _quota_base_exception_text(exc: BaseException) -> str:
    return BaseException.__str__(exc)


def _quota_exception_reason(exc: BaseException | str, *, standard_reason: str = "archive_resource_quota_exceeded") -> str:
    if type(exc) is str:
        text = str.__str__(exc)
    elif type(exc) is ResourceQuotaExceeded:
        text = _quota_base_exception_text(exc)
    elif type(exc) is RuntimeError:
        text = _quota_base_exception_text(exc)
    elif type(exc) is ValueError:
        text = _quota_base_exception_text(exc)
    elif type(exc) is OSError:
        text = _quota_base_exception_text(exc)
    else:
        text = standard_reason
    return text if text.startswith("archive_") else standard_reason


def _zip_member_fields(member: object) -> tuple[str, int, int]:
    if type(member) is not zipfile.ZipInfo:
        raise ResourceQuotaExceeded("archive_member_unsupported")
    filename = _quota_member_text(member.filename)
    if filename is None:
        raise ResourceQuotaExceeded("archive_member_name_unsupported")
    file_size = _quota_nonnegative_int(member.file_size, "archive_member_size_unsupported")
    compressed_size = _quota_nonnegative_int(member.compress_size, "archive_compressed_size_unsupported")
    return (filename, file_size, max(1, compressed_size))


def _tar_member_fields(member: object) -> tuple[str, int]:
    if type(member) is not tarfile.TarInfo:
        raise ResourceQuotaExceeded("archive_member_unsupported")
    name = _quota_member_text(member.name)
    if name is None:
        raise ResourceQuotaExceeded("archive_member_name_unsupported")
    size = _quota_nonnegative_int(member.size, "archive_member_size_unsupported")
    return (name, size)


def _zip_member_is_dir(member: object) -> bool:
    if type(member) is not zipfile.ZipInfo:
        raise ResourceQuotaExceeded("archive_member_unsupported")
    filename = _quota_member_text(member.filename)
    if filename is None:
        raise ResourceQuotaExceeded("archive_member_name_unsupported")
    return filename.endswith("/")


@dataclass
class ExtractionQuotaTracker:
    limits: ArchiveScanLimits
    depth: int = 0
    members_seen: int = 0
    files_extracted: int = 0
    bytes_extracted: int = 0
    economics: ExtractionEconomics = field(default_factory=ExtractionEconomics)

    def __post_init__(self) -> None:
        if type(self) is not ExtractionQuotaTracker:
            raise ResourceQuotaExceeded("archive_quota_tracker_owner_unsupported")
        if type(self.limits) is not ArchiveScanLimits:
            raise ResourceQuotaExceeded("archive_limits_unsupported")
        limits = ArchiveScanLimits(
            max_depth=_quota_nonnegative_int(self.limits.max_depth, "archive_max_depth_unsupported"),
            max_members=_quota_nonnegative_int(self.limits.max_members, "archive_max_members_unsupported"),
            max_member_size=_quota_nonnegative_int(self.limits.max_member_size, "archive_max_member_size_unsupported"),
            max_total_extracted_bytes=_quota_nonnegative_int(
                self.limits.max_total_extracted_bytes,
                "archive_max_total_bytes_unsupported",
            ),
            max_total_extracted_files=_quota_nonnegative_int(
                self.limits.max_total_extracted_files,
                "archive_max_total_files_unsupported",
            ),
            max_decompression_ratio=_quota_positive_float(
                self.limits.max_decompression_ratio,
                "archive_max_ratio_unsupported",
            ),
        )
        if type(self.economics) is not ExtractionEconomics:
            raise ResourceQuotaExceeded("archive_economics_unsupported")
        self.limits = limits
        self.depth = _quota_nonnegative_int(self.depth, "archive_depth_unsupported")
        self.members_seen = _quota_nonnegative_int(self.members_seen, "archive_members_seen_unsupported")
        self.files_extracted = _quota_nonnegative_int(self.files_extracted, "archive_files_extracted_unsupported")
        self.bytes_extracted = _quota_nonnegative_int(self.bytes_extracted, "archive_bytes_extracted_unsupported")

    @classmethod
    def from_env(cls, *, depth: int = 0) -> "ExtractionQuotaTracker":
        return cls(ArchiveScanLimits.from_env(), depth=depth)

    def check_depth(self) -> None:
        if self.depth > self.limits.max_depth:
            raise ResourceQuotaExceeded("archive_depth_limit")


    def check_member_count(self, count: int) -> None:
        member_count = _quota_nonnegative_int(count, "archive_member_count_unsupported")
        if member_count > self.limits.max_members:
            raise ResourceQuotaExceeded("archive_member_limit")

    def allow_zip_member(self, member: object) -> int:
        return self.reserve_member(member)

    def record_zip_member(self, member: object) -> None:
        # Older scanner code called allow_zip_member() before extraction and
        # record_zip_member() after extraction. reserve_member() already checked
        # budgets, so this method only commits exact stdlib ZipInfo bytes.
        _filename, file_size, _compressed_size = _zip_member_fields(member)
        self.commit_file(file_size)

    def reserve_member(self, member: object) -> int:
        self.check_depth()
        name, file_size, compressed_size = _zip_member_fields(member)
        prospective_members = self.members_seen + 1
        if prospective_members > self.limits.max_members:
            raise ResourceQuotaExceeded("archive_member_limit")
        if file_size > self.limits.max_member_size:
            raise ResourceQuotaExceeded("archive_large_member_skipped")
        if (file_size / compressed_size) > self.limits.max_decompression_ratio:
            raise ResourceQuotaExceeded("archive_decompression_ratio_limit")
        if self.files_extracted + 1 > self.limits.max_total_extracted_files:
            raise ResourceQuotaExceeded("archive_total_file_limit")
        if self.bytes_extracted + file_size > self.limits.max_total_extracted_bytes:
            raise ResourceQuotaExceeded("archive_total_byte_limit")
        try:
            self.economics.observe_member(
                compressed_size=compressed_size,
                extracted_size=file_size,
                is_archive=name.lower().endswith(_ARCHIVE_SUFFIXES),
            )
        except ResourceQuotaExceeded:
            raise
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            raise ResourceQuotaExceeded(_quota_exception_reason(exc)) from exc
        self.members_seen = prospective_members
        return file_size


    def reserve_tar_member(self, member: object) -> int:
        self.check_depth()
        name, file_size = _tar_member_fields(member)
        prospective_members = self.members_seen + 1
        if prospective_members > self.limits.max_members:
            raise ResourceQuotaExceeded("archive_member_limit")
        if file_size > self.limits.max_member_size:
            raise ResourceQuotaExceeded("archive_large_member_skipped")
        if self.files_extracted + 1 > self.limits.max_total_extracted_files:
            raise ResourceQuotaExceeded("archive_total_file_limit")
        if self.bytes_extracted + file_size > self.limits.max_total_extracted_bytes:
            raise ResourceQuotaExceeded("archive_total_byte_limit")
        try:
            self.economics.observe_member(
                compressed_size=max(1, file_size),
                extracted_size=file_size,
                is_archive=name.lower().endswith(_ARCHIVE_SUFFIXES),
            )
        except ResourceQuotaExceeded:
            raise
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            raise ResourceQuotaExceeded(_quota_exception_reason(exc)) from exc
        self.members_seen = prospective_members
        return file_size

    def allow_tar_member(self, member: object) -> int:
        return self.reserve_tar_member(member)

    def record_tar_member(self, member: object) -> None:
        _name, file_size = _tar_member_fields(member)
        self.commit_file(file_size)

    def commit_file(self, byte_count: int) -> None:
        count = _quota_nonnegative_int(byte_count, "archive_commit_byte_count_unsupported")
        prospective_files = self.files_extracted + 1
        prospective_bytes = self.bytes_extracted + count
        if prospective_files > self.limits.max_total_extracted_files:
            raise ResourceQuotaExceeded("archive_total_file_limit")
        if prospective_bytes > self.limits.max_total_extracted_bytes:
            raise ResourceQuotaExceeded("archive_total_byte_limit")
        self.files_extracted = prospective_files
        self.bytes_extracted = prospective_bytes


def safe_zip_target(tmp_dir: str | os.PathLike[str], member_name: str) -> str:
    name = _quota_member_text(member_name)
    if name is None:
        _raise_blocked_unsafe_zip_member_name()
    root_text = _quota_member_text(tmp_dir)
    if root_text is None:
        exception_message = "blocked unsafe zip root: archive_root_unsupported"
        raise ValueError(exception_message)
    if os.path.isabs(name) or ".." in Path(name).parts:
        exception_message = "blocked unsafe zip member"
        raise ValueError(exception_message)
    root = str(Path(root_text).resolve())
    target = str(Path(root, name).resolve())
    if not target.startswith(root + os.sep):
        exception_message = "blocked zip-slip path"
        raise ValueError(exception_message)
    return target.replace("\\", "/")


def extract_zip_member_with_quota(z: object, member: object, tmp_dir: str | os.PathLike[str], tracker: ExtractionQuotaTracker | None = None) -> str | None:
    member_name, _file_size, _compressed_size = _zip_member_fields(member)
    root_text = _quota_member_text(tmp_dir)
    if root_text is None:
        exception_message = "blocked unsafe zip root: archive_root_unsupported"
        raise ValueError(exception_message)
    member_is_dir = _zip_member_is_dir(member)
    if member_is_dir:
        target = safe_zip_target(root_text, member_name)
        Path(target).mkdir(parents=True, exist_ok=True)
        return None
    size = None
    if tracker is not None:
        size = tracker.reserve_member(member)
    target = safe_zip_target(root_text, member_name)
    Path(target).parent.mkdir(parents=True, exist_ok=True)
    with z.open(member, "r") as src, Path(target).open("wb") as dst:
        if tracker is None:
            shutil.copyfileobj(src, dst)
        else:
            remaining = size if size is not None else 0
            while True:
                chunk_size = min(1024 * 1024, max(1, remaining)) if remaining else 1024 * 1024
                data = src.read(chunk_size)
                if not data:
                    break
                dst.write(data)
                remaining -= len(data)
                if remaining < 0:
                    raise ResourceQuotaExceeded("archive_member_size_mismatch")
            tracker.commit_file(size or Path(target).stat().st_size)
    return target



@dataclass
class RuntimeBudget:
    """Deterministic per-parent ceilings used outside archive extraction."""
    max_descendants: int = 5000
    max_string_bytes: int = 64 * 1024 * 1024
    max_entropy_windows: int = 250000
    max_replay_lineage: int = 2000
    descendants: int = 0
    string_bytes: int = 0
    entropy_windows: int = 0
    replay_lineage: int = 0

    def __post_init__(self) -> None:
        if type(self) is not RuntimeBudget:
            raise ResourceQuotaExceeded("runtime_budget_owner_unsupported")
        for field_name in (
            "max_descendants",
            "max_string_bytes",
            "max_entropy_windows",
            "max_replay_lineage",
            "descendants",
            "string_bytes",
            "entropy_windows",
            "replay_lineage",
        ):
            object.__setattr__(
                self,
                field_name,
                _quota_nonnegative_int(
                    no_hook_exact_owner_field(self, RuntimeBudget, field_name),
                    _quota_reason(field_name, "unsupported"),
                ),
            )

    @classmethod
    def from_env(cls) -> "RuntimeBudget":
        def iv(name: str, default: int) -> int:
            raw = os.environ.get(name)
            if raw is None:
                return default
            unsupported_reason = _quota_env_reason(name)
            parsed, reason = no_hook_exact_nonnegative_int(
                raw,
                default=default,
                reason=unsupported_reason,
                non_finite_reason=unsupported_reason,
                allow_exact_text=True,
            )
            if reason:
                raise ResourceQuotaExceeded(reason)
            return parsed
        return cls(
            max_descendants=iv("UMIGE_MAX_DESCENDANTS", 5000),
            max_string_bytes=iv("UMIGE_MAX_STRING_BYTES", 64 * 1024 * 1024),
            max_entropy_windows=iv("UMIGE_MAX_ENTROPY_WINDOWS", 250000),
            max_replay_lineage=iv("UMIGE_MAX_REPLAY_LINEAGE", 2000),
        )

    def reserve_descendant(self, count: int = 1) -> None:
        increment = _quota_nonnegative_int(count, "runtime_descendant_count_unsupported")
        prospective = self.descendants + increment
        if prospective > self.max_descendants:
            raise ResourceQuotaExceeded("runtime_descendant_limit")
        self.descendants = prospective

    def reserve_string_bytes(self, count: int) -> None:
        increment = _quota_nonnegative_int(count, "runtime_string_byte_count_unsupported")
        prospective = self.string_bytes + increment
        if prospective > self.max_string_bytes:
            raise ResourceQuotaExceeded("runtime_string_byte_limit")
        self.string_bytes = prospective

    def reserve_entropy_windows(self, count: int) -> None:
        increment = _quota_nonnegative_int(count, "runtime_entropy_window_count_unsupported")
        prospective = self.entropy_windows + increment
        if prospective > self.max_entropy_windows:
            raise ResourceQuotaExceeded("runtime_entropy_window_limit")
        self.entropy_windows = prospective

    def reserve_replay_lineage(self, count: int = 1) -> None:
        increment = _quota_nonnegative_int(count, "runtime_replay_lineage_count_unsupported")
        prospective = self.replay_lineage + increment
        if prospective > self.max_replay_lineage:
            raise ResourceQuotaExceeded("runtime_replay_lineage_limit")
        self.replay_lineage = prospective


def runtime_budget_from_env() -> RuntimeBudget:
    return RuntimeBudget.from_env()

__all__ = (
    "ExtractionQuotaTracker",
    "ResourceQuotaExceeded",
    "RuntimeBudget",
    "extract_zip_member_with_quota",
    "quota_tag",
    "runtime_budget_from_env",
    "safe_zip_target",
)


def quota_tag(exc: Exception | str) -> str:
    return _quota_exception_reason(exc)
