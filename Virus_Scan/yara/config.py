"""Immutable YARA configuration and deterministic generated controls."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path, PosixPath, WindowsPath
import stat
import tomllib

from Virus_Scan.runtime.api import (
    path_contains_filesystem_alias,
    stat_result_is_filesystem_alias,
)
from Virus_Scan.yara.validation import (
    RELEASE_API_URL, bounded_float, bounded_int, exact_bool, release_api_url, sha256_text,
)
from Virus_Scan.yara.versioning import YARA_CONFIG_VERSION

_PATH_TYPES = (Path, PosixPath, WindowsPath)
_MAX_CONFIG_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_MEMBERS = 50_000
MAX_TOTAL_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200.0


@dataclass(frozen=True, slots=True)
class YaraConfig:
    enabled: bool = True
    full_enabled: bool = True
    light_enabled: bool = True
    allow_full_download: bool = False
    allow_light_download: bool = True
    force_refresh: bool = False
    release_api_url: str = RELEASE_API_URL
    partial_compile_threshold: float = 0.95
    maximum_archive_bytes: int = MAX_ARCHIVE_BYTES
    maximum_manifest_bytes: int = MAX_MANIFEST_BYTES
    maximum_members: int = MAX_MEMBERS
    maximum_total_uncompressed_bytes: int = MAX_TOTAL_UNCOMPRESSED_BYTES
    maximum_member_bytes: int = MAX_MEMBER_BYTES
    maximum_compression_ratio: float = MAX_COMPRESSION_RATIO
    full_expected_sha256: str = ""
    light_expected_sha256: str = ""
    custom_rule_expected_sha256: str = ""

    def __post_init__(self) -> None:
        if type(self) is not YaraConfig:
            raise TypeError("yara_config_owner_invalid")
        for field in ("enabled", "full_enabled", "light_enabled", "allow_full_download", "allow_light_download", "force_refresh"):
            object.__setattr__(self, field, exact_bool(object.__getattribute__(self, field), "yara_config_" + field + "_invalid"))
        object.__setattr__(self, "release_api_url", release_api_url(self.release_api_url))
        object.__setattr__(self, "partial_compile_threshold", bounded_float(self.partial_compile_threshold, "yara_partial_threshold_invalid", minimum=0.5))
        limits = (
            ("maximum_archive_bytes", 1024, MAX_ARCHIVE_BYTES),
            ("maximum_manifest_bytes", 64, MAX_MANIFEST_BYTES),
            ("maximum_members", 1, MAX_MEMBERS),
            ("maximum_total_uncompressed_bytes", 1024, MAX_TOTAL_UNCOMPRESSED_BYTES),
            ("maximum_member_bytes", 1, MAX_MEMBER_BYTES),
        )
        for field, minimum, maximum in limits:
            value = bounded_int(object.__getattribute__(self, field), "yara_config_" + field + "_invalid", minimum=minimum, maximum=maximum)
            object.__setattr__(self, field, value)
        if self.maximum_member_bytes > self.maximum_total_uncompressed_bytes:
            raise ValueError("yara_config_member_limit_inconsistent")
        ratio = self.maximum_compression_ratio
        if type(ratio) not in (int, float) or type(ratio) is bool or not 1.0 <= float(ratio) <= MAX_COMPRESSION_RATIO:
            raise ValueError("yara_config_compression_ratio_invalid")
        object.__setattr__(self, "maximum_compression_ratio", float(ratio))
        for field, reason in (
            ("full_expected_sha256", "yara_full_expected_sha256_invalid"),
            ("light_expected_sha256", "yara_light_expected_sha256_invalid"),
            ("custom_rule_expected_sha256", "yara_custom_rule_expected_sha256_invalid"),
        ):
            raw_digest = object.__getattribute__(self, field)
            if type(raw_digest) is not str:
                raise TypeError(reason)
            digest = str.__str__(raw_digest)
            if digest != "":
                digest = sha256_text(digest, reason)
            object.__setattr__(self, field, digest)


def config_toml(config: YaraConfig | None = None) -> str:
    owner = YaraConfig() if config is None else config
    if type(owner) is not YaraConfig:
        raise TypeError("yara_config_toml_owner_invalid")
    return (
        'config_version = "' + YARA_CONFIG_VERSION + '"\n'
        "enabled = " + str(owner.enabled).lower() + "\n"
        "full_enabled = " + str(owner.full_enabled).lower() + "\n"
        "light_enabled = " + str(owner.light_enabled).lower() + "\n"
        "allow_full_download = " + str(owner.allow_full_download).lower() + "\n"
        "allow_light_download = " + str(owner.allow_light_download).lower() + "\n"
        "force_refresh = " + str(owner.force_refresh).lower() + "\n"
        'release_api_url = "' + owner.release_api_url + '"\n'
        "partial_compile_threshold = " + repr(owner.partial_compile_threshold) + "\n"
        "maximum_archive_bytes = " + str(owner.maximum_archive_bytes) + "\n"
        "maximum_manifest_bytes = " + str(owner.maximum_manifest_bytes) + "\n"
        "maximum_members = " + str(owner.maximum_members) + "\n"
        "maximum_total_uncompressed_bytes = " + str(owner.maximum_total_uncompressed_bytes) + "\n"
        "maximum_member_bytes = " + str(owner.maximum_member_bytes) + "\n"
        "maximum_compression_ratio = " + repr(owner.maximum_compression_ratio) + "\n"
        'full_expected_sha256 = "' + owner.full_expected_sha256 + '"\n'
        'light_expected_sha256 = "' + owner.light_expected_sha256 + '"\n'
        'custom_rule_expected_sha256 = "' + owner.custom_rule_expected_sha256 + '"\n'
    )


def config_schema_json() -> str:
    properties = {
        "allow_full_download": {"type": "boolean"}, "allow_light_download": {"type": "boolean"},
        "config_version": {"const": YARA_CONFIG_VERSION},
        "custom_rule_expected_sha256": {"pattern": "^(?:[0-9a-f]{64})?$", "type": "string"},
        "full_expected_sha256": {"pattern": "^(?:[0-9a-f]{64})?$", "type": "string"},
        "light_expected_sha256": {"pattern": "^(?:[0-9a-f]{64})?$", "type": "string"},
        "enabled": {"type": "boolean"}, "force_refresh": {"type": "boolean"},
        "full_enabled": {"type": "boolean"}, "light_enabled": {"type": "boolean"},
        "maximum_archive_bytes": {"maximum": MAX_ARCHIVE_BYTES, "minimum": 1024, "type": "integer"},
        "maximum_compression_ratio": {"maximum": MAX_COMPRESSION_RATIO, "minimum": 1.0, "type": "number"},
        "maximum_manifest_bytes": {"maximum": MAX_MANIFEST_BYTES, "minimum": 64, "type": "integer"},
        "maximum_member_bytes": {"maximum": MAX_MEMBER_BYTES, "minimum": 1, "type": "integer"},
        "maximum_members": {"maximum": MAX_MEMBERS, "minimum": 1, "type": "integer"},
        "maximum_total_uncompressed_bytes": {"maximum": MAX_TOTAL_UNCOMPRESSED_BYTES, "minimum": 1024, "type": "integer"},
        "partial_compile_threshold": {"maximum": 1.0, "minimum": 0.5, "type": "number"},
        "release_api_url": {"const": RELEASE_API_URL},
    }
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema", "additionalProperties": False,
        "properties": properties, "required": sorted(properties), "title": "UMIGE YARA configuration", "type": "object",
    }
    return json.dumps(schema, sort_keys=True, indent=2) + "\n"


def config_readme() -> str:
    return (
        "UMIGE YARA configuration\n\n"
        "Normal startup uses canonical typed YARA defaults and does not read Yara/yara_config.toml.\n"
        "Yara/yara_config.toml is the editable input and is loaded only when --yara-config explicitly selects that canonical root file.\n"
        "Full YARA automatic download remains disabled by default; YARA-light automatic download remains enabled.\n"
        "Official archives require the exact release-wide YARA Forge SHA-256 manifest and local SHA-256 verification.\n"
        "ETag and Last-Modified are freshness metadata only. Existing user configuration edits are never overwritten.\n"
    )


def _read_config_text(path: Path) -> str:
    try:
        initial = path.lstat()
    except OSError as exc:
        raise ValueError("yara_config_file_invalid") from exc
    if (
        path_contains_filesystem_alias(path)
        or stat_result_is_filesystem_alias(initial)
        or not stat.S_ISREG(initial.st_mode)
        or initial.st_size > _MAX_CONFIG_BYTES
    ):
        raise ValueError("yara_config_file_invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("yara_config_file_invalid") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino)
        ):
            raise ValueError("yara_config_file_invalid")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(_MAX_CONFIG_BYTES + 1)
        if len(data) > _MAX_CONFIG_BYTES:
            raise ValueError("yara_config_file_invalid")
    finally:
        os.close(descriptor)
    try:
        final = path.lstat()
    except OSError as exc:
        raise ValueError("yara_config_file_invalid") from exc
    if (
        path_contains_filesystem_alias(path)
        or stat_result_is_filesystem_alias(final)
        or not stat.S_ISREG(final.st_mode)
        or (final.st_dev, final.st_ino) != (initial.st_dev, initial.st_ino)
    ):
        raise ValueError("yara_config_file_invalid")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("yara_config_file_invalid") from exc


def load_config(path: Path) -> YaraConfig:
    if type(path) not in _PATH_TYPES:
        raise ValueError("yara_config_file_invalid")
    raw = tomllib.loads(_read_config_text(path))
    expected = set(YaraConfig.__dataclass_fields__) | {"config_version"}
    if type(raw) is not dict or set(raw) != expected or dict.get(raw, "config_version") != YARA_CONFIG_VERSION:
        raise ValueError("yara_config_fields_rejected")
    values = {name: dict.get(raw, name) for name in YaraConfig.__dataclass_fields__}
    return YaraConfig(**values)


__all__ = ("YaraConfig", "config_readme", "config_schema_json", "config_toml", "load_config")
