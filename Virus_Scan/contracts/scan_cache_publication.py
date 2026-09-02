"""Typed parent-side identity for final semantic scan-cache publication."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from Virus_Scan.contracts.artifact_read_snapshot import ARTIFACT_READ_SNAPSHOT_SCHEMA_VERSION
from Virus_Scan.utils.pathing import normalize_scan_path

SCAN_CACHE_PUBLICATION_IDENTITY_VERSION = "scan_cache_publication_identity_v1"


def _digest(value: object, reason: str) -> str:
    if type(value) is not str:
        raise TypeError(reason)
    text = str.__str__(value).lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(reason)
    return text


def _nonnegative_int(value: object, reason: str) -> int:
    if type(value) is not int or type(value) is bool or value < 0:
        raise ValueError(reason)
    return value


@dataclass(frozen=True, slots=True)
class ScanCachePublicationIdentity:
    """Exact immutable content identity required by the parent cache writer."""

    canonical_path: str
    content_sha256: str
    content_size: int
    stat_mtime_ns: int
    file_name: str
    schema_version: str = SCAN_CACHE_PUBLICATION_IDENTITY_VERSION

    def __post_init__(self) -> None:
        if type(self.canonical_path) is not str or not self.canonical_path:
            raise TypeError("scan_cache_publication_path_invalid")
        canonical_path = str.__str__(self.canonical_path)
        content_sha256 = _digest(
            self.content_sha256,
            "scan_cache_publication_content_sha256_invalid",
        )
        content_size = _nonnegative_int(
            self.content_size,
            "scan_cache_publication_content_size_invalid",
        )
        stat_mtime_ns = _nonnegative_int(
            self.stat_mtime_ns,
            "scan_cache_publication_mtime_invalid",
        )
        if type(self.file_name) is not str or not self.file_name:
            raise TypeError("scan_cache_publication_file_name_invalid")
        file_name = str.__str__(self.file_name)
        if file_name != Path(canonical_path).name:
            raise ValueError("scan_cache_publication_file_name_mismatch")
        if self.schema_version != SCAN_CACHE_PUBLICATION_IDENTITY_VERSION:
            raise ValueError("scan_cache_publication_schema_invalid")
        object.__setattr__(self, "canonical_path", canonical_path)
        object.__setattr__(self, "content_sha256", content_sha256)
        object.__setattr__(self, "content_size", content_size)
        object.__setattr__(self, "stat_mtime_ns", stat_mtime_ns)
        object.__setattr__(self, "file_name", file_name)


def scan_cache_publication_identity_from_result(
    result: object,
) -> ScanCachePublicationIdentity | None:
    """Resolve one complete artifact identity from a worker result or cache hit."""
    if type(result) is not dict:
        return None
    artifact_read = dict.get(result, "artifact_read")
    if type(artifact_read) is not dict:
        return None
    expected_keys = {
        "read_ledger",
        "canonical_path",
        "content_sha256",
        "device",
        "extension",
        "inode",
        "mtime_ns",
        "prefix_length",
        "prefix_sha256",
        "prefix_truncated",
        "schema_version",
        "size",
        "state",
        "tail_length",
        "unavailable_reason",
    }
    if set(artifact_read) != expected_keys:
        raise ValueError("scan_cache_publication_artifact_record_keys_invalid")
    if dict.get(artifact_read, "schema_version") != ARTIFACT_READ_SNAPSHOT_SCHEMA_VERSION:
        raise ValueError("scan_cache_publication_artifact_schema_invalid")
    if dict.get(artifact_read, "state") != "complete":
        return None
    size = _nonnegative_int(
        dict.get(artifact_read, "size"),
        "scan_cache_publication_artifact_size_invalid",
    )
    read_ledger = dict.get(artifact_read, "read_ledger")
    if type(read_ledger) is not dict or set(read_ledger) != {
        "physical_open_count", "retained_prefix_bytes", "retained_tail_bytes",
        "schema_version", "stream_bytes_read", "total_physical_bytes_read",
        "verification_bytes_read",
    }:
        raise ValueError("scan_cache_publication_artifact_read_ledger_invalid")
    stream_bytes_read = _nonnegative_int(
        dict.get(read_ledger, "stream_bytes_read"),
        "scan_cache_publication_artifact_stream_bytes_invalid",
    )
    physical_open_count = _nonnegative_int(
        dict.get(read_ledger, "physical_open_count"),
        "scan_cache_publication_artifact_open_count_invalid",
    )
    if stream_bytes_read != size or physical_open_count != 1:
        raise ValueError("scan_cache_publication_artifact_read_incomplete")
    canonical_path = dict.get(artifact_read, "canonical_path")
    if type(canonical_path) is not str or not canonical_path:
        raise TypeError("scan_cache_publication_artifact_path_invalid")
    path_text = str.__str__(canonical_path)
    result_path = dict.get(result, "path", dict.get(result, "file"))
    if type(result_path) is str and result_path:
        normalized_result_path = normalize_scan_path(result_path, require_exists=False)
        if normalized_result_path != path_text:
            raise ValueError("scan_cache_publication_result_path_mismatch")
    return ScanCachePublicationIdentity(
        canonical_path=path_text,
        content_sha256=dict.get(artifact_read, "content_sha256"),
        content_size=size,
        stat_mtime_ns=dict.get(artifact_read, "mtime_ns"),
        file_name=Path(path_text).name,
    )


__all__ = (
    "SCAN_CACHE_PUBLICATION_IDENTITY_VERSION",
    "ScanCachePublicationIdentity",
    "scan_cache_publication_identity_from_result",
)
