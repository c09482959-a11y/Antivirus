"""Release-wide manifest parsing and SHA-256 evidence for official YARA archives."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PosixPath, WindowsPath
import re

from Virus_Scan.runtime.api import path_contains_filesystem_alias
from Virus_Scan.yara.validation import archive_asset_name, bounded_int, sha256_text
from Virus_Scan.yara.versioning import YARA_MANIFEST_GRAMMAR_VERSION

_PATH_TYPES = (Path, PosixPath, WindowsPath)
_MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  (yara-forge-rules-(?:core|extended|full)\.zip)$")
_REQUIRED_ARCHIVES = (
    "yara-forge-rules-core.zip",
    "yara-forge-rules-extended.zip",
    "yara-forge-rules-full.zip",
)


@dataclass(frozen=True, slots=True)
class YaraManifestEntry:
    filename: str
    sha256: str

    def __post_init__(self) -> None:
        if type(self) is not YaraManifestEntry:
            raise TypeError("yara_manifest_entry_owner_invalid")
        object.__setattr__(self, "filename", archive_asset_name(self.filename, "yara_manifest_filename_invalid"))
        object.__setattr__(self, "sha256", sha256_text(self.sha256))


@dataclass(frozen=True, slots=True)
class YaraReleaseManifest:
    entries: tuple[YaraManifestEntry, ...]
    manifest_sha256: str
    grammar_version: str = YARA_MANIFEST_GRAMMAR_VERSION

    def __post_init__(self) -> None:
        if type(self) is not YaraReleaseManifest or type(self.entries) is not tuple:
            raise TypeError("yara_release_manifest_owner_invalid")
        if any(type(item) is not YaraManifestEntry for item in self.entries):
            raise TypeError("yara_release_manifest_entries_invalid")
        names = tuple(item.filename for item in self.entries)
        if names != _REQUIRED_ARCHIVES:
            raise ValueError("yara_release_manifest_archive_set_invalid")
        object.__setattr__(self, "manifest_sha256", sha256_text(self.manifest_sha256))
        if type(self.grammar_version) is not str or self.grammar_version != YARA_MANIFEST_GRAMMAR_VERSION:
            raise ValueError("yara_release_manifest_version_invalid")

    def expected_digest(self, target_name: str) -> str:
        target = archive_asset_name(target_name)
        matches = tuple(item.sha256 for item in self.entries if item.filename == target)
        if len(matches) != 1:
            raise ValueError("yara_release_manifest_target_missing")
        return matches[0]


def bytes_sha256(data: bytes) -> str:
    if type(data) is not bytes:
        raise TypeError("yara_digest_bytes_required")
    return sha256(data).hexdigest()


def file_sha256(path: Path, *, maximum_bytes: int) -> str:
    if (
        type(path) not in _PATH_TYPES
        or path_contains_filesystem_alias(path)
        or not path.is_file()
    ):
        raise ValueError("yara_digest_file_invalid")
    maximum = bounded_int(maximum_bytes, "yara_digest_limit_invalid", minimum=1, maximum=1 << 40)
    if path.stat().st_size > maximum:
        raise ValueError("yara_digest_file_oversized")
    digest = sha256()
    with path.open("rb") as stream:
        total = 0
        while True:
            chunk = stream.read(1024 * 1024)
            if chunk == b"":
                break
            total += len(chunk)
            if total > maximum:
                raise ValueError("yara_digest_file_oversized")
            digest.update(chunk)
    return digest.hexdigest()


def parse_release_manifest(data: bytes, *, maximum_bytes: int) -> YaraReleaseManifest:
    if type(data) is not bytes:
        raise TypeError("yara_release_manifest_bytes_required")
    maximum = bounded_int(maximum_bytes, "yara_release_manifest_limit_invalid", minimum=256, maximum=16 * 1024 * 1024)
    if not data or len(data) > maximum or b"\x00" in data or b"\r" in data:
        raise ValueError("yara_release_manifest_artifact_invalid")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("yara_release_manifest_encoding_invalid") from exc
    if not text.endswith("\n") or text.endswith("\n\n"):
        raise ValueError("yara_release_manifest_termination_invalid")
    lines = tuple(text[:-1].split("\n"))
    if len(lines) != len(_REQUIRED_ARCHIVES) or any(line == "" for line in lines):
        raise ValueError("yara_release_manifest_line_count_invalid")
    entries: list[YaraManifestEntry] = []
    for line in lines:
        match = _MANIFEST_LINE.fullmatch(line)
        if match is None:
            raise ValueError("yara_release_manifest_line_invalid")
        entries.append(YaraManifestEntry(match.group(2), match.group(1)))
    ordered = tuple(sorted(entries, key=lambda item: item.filename))
    if len({item.filename for item in ordered}) != len(ordered):
        raise ValueError("yara_release_manifest_duplicate_filename")
    return YaraReleaseManifest(ordered, bytes_sha256(data))


__all__ = (
    "YaraManifestEntry", "YaraReleaseManifest", "bytes_sha256", "file_sha256",
    "parse_release_manifest",
)
