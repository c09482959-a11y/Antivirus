"""Bounded ZIP validation and deterministic rule-member evidence."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path, PosixPath, PurePosixPath, WindowsPath
import stat
import zipfile

from Virus_Scan.runtime.api import path_contains_filesystem_alias
from Virus_Scan.yara.config import YaraConfig
from Virus_Scan.yara.contracts import YaraArchiveMember

_PATH_TYPES = (Path, PosixPath, WindowsPath)
_RULE_SUFFIXES = (".yar", ".yara")
_ALLOWED_METADATA_SUFFIXES = (".md", ".txt", ".json", ".yaml", ".yml", ".license")
_ALLOWED_METADATA_NAMES = ("license", "notice", "readme")
_ALLOWED_COMPRESSION_METHODS = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)


def _safe_member_name(name: object) -> str:
    if type(name) is not str:
        raise TypeError("yara_archive_member_name_invalid")
    text = str.__str__(name)
    if text == "" or len(text) > 4096 or "\\" in text or "\x00" in text or text.startswith("/"):
        raise ValueError("yara_archive_member_path_invalid")
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in ("", ".", "..") or ":" in part for part in path.parts):
        raise ValueError("yara_archive_member_path_invalid")
    return path.as_posix()


def _validated_member_kind(info: zipfile.ZipInfo, name: str) -> str:
    if type(info) is not zipfile.ZipInfo:
        raise TypeError("yara_archive_member_owner_invalid")
    is_dir = info.is_dir()
    if info.compress_type not in _ALLOWED_COMPRESSION_METHODS:
        raise ValueError("yara_archive_compression_method_rejected")
    if info.create_system == 3:
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(unix_mode)
        if is_dir:
            if file_type not in (0, stat.S_IFDIR):
                raise ValueError("yara_archive_special_member_rejected")
        elif file_type not in (0, stat.S_IFREG):
            raise ValueError("yara_archive_special_member_rejected")
    if is_dir and (info.file_size != 0 or info.compress_size != 0):
        raise ValueError("yara_archive_directory_shape_invalid")
    return _member_kind(name, is_dir)


def _member_kind(name: str, is_dir: bool) -> str:
    if is_dir:
        return "directory"
    lower = name.lower()
    if lower.endswith(_RULE_SUFFIXES):
        return "rule"
    leaf = PurePosixPath(lower).name
    if leaf in _ALLOWED_METADATA_NAMES or lower.endswith(_ALLOWED_METADATA_SUFFIXES):
        return "metadata"
    raise ValueError("yara_archive_member_extension_rejected")


def validate_rule_archive(path: Path, config: YaraConfig) -> tuple[YaraArchiveMember, ...]:
    if type(path) not in _PATH_TYPES or type(config) is not YaraConfig:
        raise TypeError("yara_archive_validation_owner_invalid")
    if path_contains_filesystem_alias(path) or not path.is_file():
        raise ValueError("yara_archive_file_invalid")
    mode = path.stat().st_mode
    if not stat.S_ISREG(mode) or path.stat().st_size < 22 or path.stat().st_size > config.maximum_archive_bytes:
        raise ValueError("yara_archive_file_invalid")
    members: list[YaraArchiveMember] = []
    seen: set[str] = set()
    total_uncompressed = 0
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            if not infos or len(infos) > config.maximum_members:
                raise ValueError("yara_archive_member_count_invalid")
            for info in infos:
                name = _safe_member_name(info.filename)
                folded = name.casefold()
                if folded in seen:
                    raise ValueError("yara_archive_duplicate_member")
                seen.add(folded)
                kind = _validated_member_kind(info, name)
                if info.flag_bits & 0x1:
                    raise ValueError("yara_archive_encrypted_member")
                if info.file_size < 0 or info.compress_size < 0 or info.file_size > config.maximum_member_bytes:
                    raise ValueError("yara_archive_member_size_invalid")
                total_uncompressed += info.file_size
                if total_uncompressed > config.maximum_total_uncompressed_bytes:
                    raise ValueError("yara_archive_total_size_invalid")
                ratio = float(info.file_size) / float(max(1, info.compress_size))
                if ratio > config.maximum_compression_ratio:
                    raise ValueError("yara_archive_compression_ratio_invalid")
                if kind != "rule":
                    continue
                digest = sha256()
                consumed = 0
                with archive.open(info, "r") as source:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if chunk == b"":
                            break
                        consumed += len(chunk)
                        if consumed > info.file_size or consumed > config.maximum_member_bytes:
                            raise ValueError("yara_archive_member_size_invalid")
                        digest.update(chunk)
                if consumed != info.file_size:
                    raise ValueError("yara_archive_member_size_mismatch")
                members.append(YaraArchiveMember(name, digest.hexdigest(), info.compress_size, info.file_size))
            bad_member = archive.testzip()
            if bad_member is not None:
                raise ValueError("yara_archive_crc_invalid")
    except zipfile.BadZipFile as exc:
        raise ValueError("yara_archive_zip_invalid") from exc
    if not members:
        raise ValueError("yara_archive_rules_missing")
    ordered = tuple(sorted(members, key=lambda item: item.name))
    if len({item.name.casefold() for item in ordered}) != len(ordered):
        raise ValueError("yara_archive_duplicate_member")
    return ordered


__all__ = ("validate_rule_archive",)
