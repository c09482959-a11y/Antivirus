"""Immutable bounded artifact bytes, stat identity, and full content digest."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import stat
from pathlib import Path

from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.utils.pathing import normalize_scan_path
from Virus_Scan.contracts.path_identity import get_scan_extension

ARTIFACT_READ_SNAPSHOT_SCHEMA_VERSION = "artifact_read_snapshot_v3"
ARTIFACT_READ_LEDGER_SCHEMA_VERSION = "artifact_read_ledger_v1"
ARTIFACT_READ_PREFIX_LIMIT = 10 * 1024 * 1024
ARTIFACT_FAST_FINGERPRINT_SAMPLE = 64 * 1024
_ARTIFACT_READ_CHUNK_SIZE = 1024 * 1024
_ARTIFACT_READ_STATES = frozenset({"complete", "unavailable", "mutated"})


def _hex_digest(value: object, *, blank: bool = False) -> str:
    if type(value) is not str:
        raise TypeError("artifact_read_digest_invalid")
    text = str.__str__(value).lower()
    if blank and text == "":
        return ""
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise ValueError("artifact_read_digest_invalid")
    return text


def _exact_nonnegative_int(value: object, reason: str) -> int:
    if type(value) is not int or type(value) is bool or value < 0:
        raise ValueError(reason)
    return value


@dataclass(frozen=True, slots=True)
class ArtifactReadLedger:
    """Immutable physical-read accounting for one artifact snapshot build."""

    physical_open_count: int
    stream_bytes_read: int
    verification_bytes_read: int
    total_physical_bytes_read: int
    retained_prefix_bytes: int
    retained_tail_bytes: int
    schema_version: str = ARTIFACT_READ_LEDGER_SCHEMA_VERSION

    def __post_init__(self) -> None:
        open_count = _exact_nonnegative_int(self.physical_open_count, "artifact_read_open_count_invalid")
        if open_count > 1:
            raise ValueError("artifact_read_open_count_invalid")
        stream = _exact_nonnegative_int(self.stream_bytes_read, "artifact_read_stream_bytes_invalid")
        verification = _exact_nonnegative_int(self.verification_bytes_read, "artifact_read_verification_bytes_invalid")
        total = _exact_nonnegative_int(self.total_physical_bytes_read, "artifact_read_total_bytes_invalid")
        prefix = _exact_nonnegative_int(self.retained_prefix_bytes, "artifact_read_retained_prefix_invalid")
        tail = _exact_nonnegative_int(self.retained_tail_bytes, "artifact_read_retained_tail_invalid")
        if total != stream + verification:
            raise ValueError("artifact_read_total_bytes_mismatch")
        if prefix > ARTIFACT_READ_PREFIX_LIMIT or tail > ARTIFACT_FAST_FINGERPRINT_SAMPLE:
            raise ValueError("artifact_read_retained_bytes_invalid")
        if self.schema_version != ARTIFACT_READ_LEDGER_SCHEMA_VERSION:
            raise ValueError("artifact_read_ledger_schema_invalid")
        object.__setattr__(self, "physical_open_count", open_count)
        object.__setattr__(self, "stream_bytes_read", stream)
        object.__setattr__(self, "verification_bytes_read", verification)
        object.__setattr__(self, "total_physical_bytes_read", total)
        object.__setattr__(self, "retained_prefix_bytes", prefix)
        object.__setattr__(self, "retained_tail_bytes", tail)

    def to_record(self) -> dict[str, object]:
        return {
            "physical_open_count": self.physical_open_count,
            "retained_prefix_bytes": self.retained_prefix_bytes,
            "retained_tail_bytes": self.retained_tail_bytes,
            "schema_version": self.schema_version,
            "stream_bytes_read": self.stream_bytes_read,
            "total_physical_bytes_read": self.total_physical_bytes_read,
            "verification_bytes_read": self.verification_bytes_read,
        }


def _empty_read_ledger(*, physical_open_count: int = 0, stream_bytes_read: int = 0, verification_bytes_read: int = 0, retained_prefix_bytes: int = 0, retained_tail_bytes: int = 0) -> ArtifactReadLedger:
    return ArtifactReadLedger(
        physical_open_count=physical_open_count,
        stream_bytes_read=stream_bytes_read,
        verification_bytes_read=verification_bytes_read,
        total_physical_bytes_read=stream_bytes_read + verification_bytes_read,
        retained_prefix_bytes=retained_prefix_bytes,
        retained_tail_bytes=retained_tail_bytes,
    )


@dataclass(frozen=True, slots=True)
class ArtifactReadSnapshot:
    """One immutable scan-time view of a physical artifact."""

    canonical_path: str
    size: int
    mtime_ns: int
    inode: int
    device: int
    extension: str
    prefix_bytes: bytes
    tail_bytes: bytes
    content_sha256: str
    read_ledger: ArtifactReadLedger
    state: str
    unavailable_reason: str = ""
    schema_version: str = ARTIFACT_READ_SNAPSHOT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self.canonical_path) is not str:
            raise TypeError("artifact_read_path_invalid")
        path = str.__str__(self.canonical_path)
        state = self.state if type(self.state) is str else ""
        if state not in _ARTIFACT_READ_STATES:
            raise ValueError("artifact_read_state_invalid")
        size = _exact_nonnegative_int(self.size, "artifact_read_size_invalid")
        mtime_ns = _exact_nonnegative_int(self.mtime_ns, "artifact_read_mtime_invalid")
        inode = _exact_nonnegative_int(self.inode, "artifact_read_inode_invalid")
        device = _exact_nonnegative_int(self.device, "artifact_read_device_invalid")
        if type(self.read_ledger) is not ArtifactReadLedger:
            raise TypeError("artifact_read_ledger_invalid")
        read_ledger = self.read_ledger
        if type(self.extension) is not str:
            raise TypeError("artifact_read_extension_invalid")
        extension = str.__str__(self.extension).lower()
        if type(self.prefix_bytes) is not bytes:
            raise TypeError("artifact_read_prefix_invalid")
        if type(self.tail_bytes) is not bytes:
            raise TypeError("artifact_read_tail_invalid")
        prefix = self.prefix_bytes
        tail = self.tail_bytes
        if len(prefix) > ARTIFACT_READ_PREFIX_LIMIT:
            raise ValueError("artifact_read_prefix_too_large")
        if len(tail) > ARTIFACT_FAST_FINGERPRINT_SAMPLE:
            raise ValueError("artifact_read_tail_too_large")
        reason = self.unavailable_reason if type(self.unavailable_reason) is str else ""
        schema = self.schema_version if type(self.schema_version) is str else ""
        if schema != ARTIFACT_READ_SNAPSHOT_SCHEMA_VERSION:
            raise ValueError("artifact_read_schema_invalid")
        digest = _hex_digest(self.content_sha256, blank=state != "complete")
        if state == "complete":
            expected_tail = 0 if size <= ARTIFACT_FAST_FINGERPRINT_SAMPLE else min(size, ARTIFACT_FAST_FINGERPRINT_SAMPLE)
            if (
                not path or read_ledger.physical_open_count != 1
                or read_ledger.stream_bytes_read != size
                or len(prefix) != min(size, ARTIFACT_READ_PREFIX_LIMIT)
                or len(tail) != expected_tail
                or read_ledger.retained_prefix_bytes != len(prefix)
                or read_ledger.retained_tail_bytes != len(tail)
            ):
                raise ValueError("artifact_read_complete_contract_invalid")
            if reason:
                raise ValueError("artifact_read_complete_reason_present")
        else:
            if digest or prefix or tail:
                raise ValueError("artifact_read_unavailable_bytes_present")
            if not reason:
                raise ValueError("artifact_read_unavailable_reason_missing")
        for name, value in (
            ("canonical_path", path), ("size", size), ("mtime_ns", mtime_ns),
            ("inode", inode), ("device", device), ("extension", extension),
            ("prefix_bytes", prefix), ("tail_bytes", tail), ("content_sha256", digest),
            ("read_ledger", read_ledger), ("state", state),
            ("unavailable_reason", reason), ("schema_version", schema),
        ):
            object.__setattr__(self, name, value)

    @property
    def complete(self) -> bool:
        return self.state == "complete"

    @property
    def prefix_truncated(self) -> bool:
        return self.complete and self.size > len(self.prefix_bytes)

    def read_prefix(self, limit: int) -> bytes:
        if type(limit) is not int or type(limit) is bool or limit < 0:
            raise ValueError("artifact_read_limit_invalid")
        if not self.complete:
            return b""
        return self.prefix_bytes[:limit]

    def fast_fingerprint(self) -> tuple[str, dict[str, object]]:
        if not self.complete:
            return "", {}
        head = self.prefix_bytes[:ARTIFACT_FAST_FINGERPRINT_SAMPLE]
        digest = hashlib.sha256()
        digest.update(int.__str__(self.size).encode("ascii"))
        digest.update(b"|")
        digest.update(int.__str__(self.mtime_ns).encode("ascii"))
        digest.update(b"|")
        digest.update(head)
        digest.update(b"|")
        digest.update(self.tail_bytes)
        return digest.hexdigest(), {
            "extension": self.extension,
            "mtime_ns": self.mtime_ns,
            "size": self.size,
        }

    def to_record(self) -> dict[str, object]:
        prefix_digest = hashlib.sha256(self.prefix_bytes).hexdigest() if self.complete else ""
        return {
            "read_ledger": self.read_ledger.to_record(),
            "canonical_path": self.canonical_path,
            "content_sha256": self.content_sha256,
            "device": self.device,
            "extension": self.extension,
            "inode": self.inode,
            "mtime_ns": self.mtime_ns,
            "prefix_length": len(self.prefix_bytes),
            "prefix_sha256": prefix_digest,
            "prefix_truncated": self.prefix_truncated,
            "schema_version": self.schema_version,
            "size": self.size,
            "state": self.state,
            "tail_length": len(self.tail_bytes),
            "unavailable_reason": self.unavailable_reason,
        }



def read_artifact_prefix(path: object, limit: int) -> bytes:
    """Read at most ``limit`` bytes through the canonical physical-read owner.

    This is reserved for pre-session/standalone identity probes that cannot yet
    consume a full :class:`ArtifactReadSnapshot`.  Active scan stages must reuse
    the snapshot instead of calling this helper again.
    """
    if type(limit) is not int or type(limit) is bool or limit < 0 or limit > ARTIFACT_READ_PREFIX_LIMIT:
        raise ValueError("artifact_prefix_read_limit_invalid")
    resolved = normalize_scan_path(path, require_exists=True)
    source = Path(resolved)
    before = source.stat()
    if not stat.S_ISREG(before.st_mode):
        raise OSError("artifact_not_regular_file")
    with source.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        data = handle.read(limit)
        opened_after = os.fstat(handle.fileno())
    after = source.stat()
    if len({_stat_identity(item) for item in (before, opened, opened_after, after)}) != 1:
        raise OSError("artifact_changed_during_prefix_read")
    return data


def _stat_identity(stat_result: os.stat_result) -> tuple[int, int, int, int, int]:
    """Return the complete metadata identity used to detect an in-place write.

    ``mtime`` alone is not sufficient on every supported filesystem.  Some
    filesystems coalesce rapid timestamp updates, so a writer can change bytes
    during a bounded read while the before/after ``mtime`` values still compare
    equal.  ``ctime`` is an additional metadata signal on POSIX and remains a
    harmless stable field on platforms where it represents creation time.
    Content-window verification below remains the cross-platform byte-level
    authority.
    """
    ctime_ns = getattr(stat_result, "st_ctime_ns", int(stat_result.st_ctime * 1_000_000_000))
    return (
        int(stat_result.st_dev),
        int(stat_result.st_ino),
        int(stat_result.st_size),
        int(stat_result.st_mtime_ns),
        int(ctime_ns),
    )


def _read_verification_window(handle: object, offset: int, length: int) -> bytes:
    """Read one exact bounded window from the already-open canonical handle."""
    if type(offset) is not int or offset < 0:
        raise ValueError("artifact_read_verification_offset_invalid")
    if type(length) is not int or length < 0:
        raise ValueError("artifact_read_verification_length_invalid")
    if length == 0:
        return b""
    seek = getattr(handle, "seek")
    read = getattr(handle, "read")
    seek(offset)
    remaining = length
    chunks: list[bytes] = []
    while remaining:
        chunk = read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _same_process_writable_alias_open(
    stat_result: os.stat_result,
    *,
    current_fd: int,
) -> bool:
    """Return whether this process already owns another writable file handle.

    Linux exposes exact descriptor flags through ``/proc/self/fdinfo``.  This
    check closes a race that metadata sampling cannot: a writer may already
    have the same inode open and be blocked in its own flush for the complete
    duration of a hot-cache read.  Accepting that path as stable would allow it
    to change immediately after the final stat check.

    The check is an additional fail-closed signal inside the one canonical
    artifact-read owner.  Platforms without ``/proc`` continue to use the
    metadata and byte-window validation below; they do not gain a second read
    implementation or fallback owner.
    """
    proc_fd_root = Path("/proc/self/fd")
    proc_fdinfo_root = Path("/proc/self/fdinfo")
    if not proc_fd_root.is_dir() or not proc_fdinfo_root.is_dir():
        return False
    target_identity = (int(stat_result.st_dev), int(stat_result.st_ino))
    try:
        descriptor_names = tuple(proc_fd_root.iterdir())
    except OSError:
        return False
    for descriptor_path in descriptor_names:
        try:
            descriptor = int(descriptor_path.name)
        except ValueError:
            continue
        if descriptor == current_fd:
            continue
        try:
            descriptor_stat = os.stat(descriptor_path)
        except OSError:
            continue
        if (int(descriptor_stat.st_dev), int(descriptor_stat.st_ino)) != target_identity:
            continue
        try:
            fdinfo = (proc_fdinfo_root / descriptor_path.name).read_text(
                encoding="ascii",
                errors="strict",
            )
        except (OSError, UnicodeError):
            continue
        flags_line = next(
            (line for line in fdinfo.splitlines() if line.startswith("flags:")),
            "",
        )
        if not flags_line:
            continue
        try:
            flags = int(flags_line.split(":", 1)[1].strip(), 8)
        except ValueError:
            continue
        if flags & os.O_ACCMODE != os.O_RDONLY:
            return True
    return False


def build_artifact_read_snapshot(path: object) -> ArtifactReadSnapshot:
    """Read one artifact once, retaining the canonical bounded scanner view and full SHA-256."""
    resolved = ""
    physical_open_count = 0
    stream_bytes_read = 0
    verification_bytes_read = 0
    retained_prefix_bytes = 0
    retained_tail_bytes = 0
    try:
        resolved = normalize_scan_path(path, require_exists=True)
        source = Path(resolved)
        before = source.stat()
        if not stat.S_ISREG(before.st_mode):
            return _unavailable_snapshot(resolved, "artifact_not_regular_file")
        digest = hashlib.sha256()
        prefix = bytearray()
        tail = b""
        total = 0
        with source.open("rb") as handle:
            physical_open_count = 1
            opened_before = os.fstat(handle.fileno())
            if _same_process_writable_alias_open(opened_before, current_fd=handle.fileno()):
                return _unavailable_snapshot(
                    resolved,
                    "artifact_changed_during_read",
                    state="mutated",
                    read_ledger=_empty_read_ledger(physical_open_count=physical_open_count),
                )
            while True:
                chunk = handle.read(_ARTIFACT_READ_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
                total += len(chunk)
                stream_bytes_read += len(chunk)
                remaining = ARTIFACT_READ_PREFIX_LIMIT - len(prefix)
                if remaining > 0:
                    prefix.extend(chunk[:remaining])
                if total > ARTIFACT_FAST_FINGERPRINT_SAMPLE:
                    tail = (
                        chunk[-ARTIFACT_FAST_FINGERPRINT_SAMPLE:]
                        if len(chunk) >= ARTIFACT_FAST_FINGERPRINT_SAMPLE
                        else (tail + chunk)[-ARTIFACT_FAST_FINGERPRINT_SAMPLE:]
                    )
            opened_after_stream = os.fstat(handle.fileno())
            expected_head = bytes(prefix[: min(total, ARTIFACT_FAST_FINGERPRINT_SAMPLE)])
            first_verified_head = _read_verification_window(handle, 0, len(expected_head))
            verification_bytes_read += len(first_verified_head)
            expected_tail = tail if total > ARTIFACT_FAST_FINGERPRINT_SAMPLE else b""
            first_verified_tail = _read_verification_window(
                handle,
                max(0, total - len(expected_tail)),
                len(expected_tail),
            )
            verification_bytes_read += len(first_verified_tail)
            opened_after_verification = os.fstat(handle.fileno())
        after = source.stat()
        identities = {
            _stat_identity(item)
            for item in (
                before,
                opened_before,
                opened_after_stream,
                opened_after_verification,
                after,
            )
        }
        content_windows_stable = (
            first_verified_head == expected_head
            and first_verified_tail == expected_tail
        )
        retained_prefix_bytes = len(prefix)
        retained_tail_bytes = len(tail if int(before.st_size) > ARTIFACT_FAST_FINGERPRINT_SAMPLE else b"")
        if len(identities) != 1 or total != int(before.st_size) or not content_windows_stable:
            return _unavailable_snapshot(
                resolved,
                "artifact_changed_during_read",
                state="mutated",
                read_ledger=_empty_read_ledger(
                    physical_open_count=physical_open_count,
                    stream_bytes_read=stream_bytes_read,
                    verification_bytes_read=verification_bytes_read,
                    retained_prefix_bytes=retained_prefix_bytes,
                    retained_tail_bytes=retained_tail_bytes,
                ),
            )
        return ArtifactReadSnapshot(
            canonical_path=resolved,
            size=int(before.st_size),
            mtime_ns=int(before.st_mtime_ns),
            inode=int(before.st_ino),
            device=int(before.st_dev),
            extension=get_scan_extension(resolved),
            prefix_bytes=bytes(prefix),
            tail_bytes=tail if int(before.st_size) > ARTIFACT_FAST_FINGERPRINT_SAMPLE else b"",
            content_sha256=digest.hexdigest(),
            read_ledger=_empty_read_ledger(
                physical_open_count=physical_open_count,
                stream_bytes_read=stream_bytes_read,
                verification_bytes_read=verification_bytes_read,
                retained_prefix_bytes=retained_prefix_bytes,
                retained_tail_bytes=retained_tail_bytes,
            ),
            state="complete",
        )
    except IO_CONFIGURATION_ERRORS as exc:
        return _unavailable_snapshot(
            resolved,
            type(exc).__name__ or "artifact_read_unavailable",
            read_ledger=_empty_read_ledger(
                physical_open_count=physical_open_count,
                stream_bytes_read=stream_bytes_read,
                verification_bytes_read=verification_bytes_read,
                retained_prefix_bytes=retained_prefix_bytes,
                retained_tail_bytes=retained_tail_bytes,
            ),
        )


def _unavailable_snapshot(path: str, reason: str, *, state: str = "unavailable", read_ledger: ArtifactReadLedger | None = None) -> ArtifactReadSnapshot:
    return ArtifactReadSnapshot(
        canonical_path=path,
        size=0,
        mtime_ns=0,
        inode=0,
        device=0,
        extension=get_scan_extension(path),
        prefix_bytes=b"",
        tail_bytes=b"",
        content_sha256="",
        read_ledger=read_ledger if read_ledger is not None else _empty_read_ledger(),
        state=state,
        unavailable_reason=reason,
    )


def require_artifact_read_snapshot(snapshot: object, path: object | None = None) -> ArtifactReadSnapshot:
    if type(snapshot) is not ArtifactReadSnapshot:
        raise TypeError("artifact_read_snapshot_required")
    if path is not None and snapshot.canonical_path:
        resolved = normalize_scan_path(path, require_exists=False)
        if resolved != snapshot.canonical_path:
            raise ValueError("artifact_read_snapshot_path_mismatch")
    return snapshot


def attach_artifact_read_record(record: object, snapshot: object) -> object:
    owned = require_artifact_read_snapshot(snapshot)
    if type(record) is dict:
        record["artifact_read"] = owned.to_record()
        if owned.complete:
            record["source_sha256"] = owned.content_sha256
    return record


__all__ = (
    "ARTIFACT_FAST_FINGERPRINT_SAMPLE",
    "ARTIFACT_READ_PREFIX_LIMIT",
    "ARTIFACT_READ_LEDGER_SCHEMA_VERSION",
    "ARTIFACT_READ_SNAPSHOT_SCHEMA_VERSION",
    "ArtifactReadLedger",
    "ArtifactReadSnapshot",
    "attach_artifact_read_record",
    "build_artifact_read_snapshot",
    "read_artifact_prefix",
    "require_artifact_read_snapshot",
)
