"""Strict pre-recovery validation for SQLite write-ahead logs."""
from __future__ import annotations

from pathlib import Path
import os

_WAL_HEADER_BYTES = 32
_WAL_FRAME_HEADER_BYTES = 24
_WAL_VERSION = 3_007_000
_WAL_MAGIC_LITTLE_CHECKSUM = 0x377F0682
_WAL_MAGIC_BIG_CHECKSUM = 0x377F0683
_DATABASE_HEADER_BYTES = 100
_DATABASE_MAGIC = b"SQLite format 3\x00"
_UINT32_MASK = 0xFFFFFFFF


class SQLiteWALIntegrityError(RuntimeError):
    """Raised when a hot WAL cannot be proven structurally intact."""


def _page_size(value: int) -> int:
    page_size = 65_536 if value == 1 else value
    if page_size < 512 or page_size > 65_536 or page_size & (page_size - 1):
        raise SQLiteWALIntegrityError("sqlite_wal_page_size_invalid")
    return page_size


def _checksum(
    data: bytes, *, byteorder: str, seed: tuple[int, int] = (0, 0),
) -> tuple[int, int]:
    if len(data) % 8:
        raise SQLiteWALIntegrityError("sqlite_wal_checksum_input_invalid")
    first, second = seed
    for offset in range(0, len(data), 8):
        word_one = int.from_bytes(data[offset:offset + 4], byteorder)
        word_two = int.from_bytes(data[offset + 4:offset + 8], byteorder)
        first = (first + word_one + second) & _UINT32_MASK
        second = (second + word_two + first) & _UINT32_MASK
    return first, second


def _database_page_size(database_path: Path) -> int:
    try:
        with database_path.open("rb") as handle:
            header = handle.read(_DATABASE_HEADER_BYTES)
    except OSError as exc:
        raise SQLiteWALIntegrityError("sqlite_database_header_unreadable") from exc
    if len(header) < _DATABASE_HEADER_BYTES or header[:16] != _DATABASE_MAGIC:
        raise SQLiteWALIntegrityError("sqlite_database_header_invalid")
    return _page_size(int.from_bytes(header[16:18], "big"))


def validate_wal_before_recovery(database_path: Path) -> None:
    """Reject a malformed/torn WAL before SQLite can ignore it and expose stale state.

    SQLite may safely ignore an invalid trailing WAL and open the older main database.
    That default is unacceptable for authoritative state because it can hide loss of a
    previously committed transaction. This validator requires a complete header and
    complete checksum-valid frames whenever a non-empty WAL is present.
    """
    wal_path = Path(str(database_path) + "-wal")
    try:
        wal_stat = wal_path.stat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SQLiteWALIntegrityError("sqlite_wal_stat_failed") from exc
    if wal_stat.st_size == 0:
        return
    if not database_path.is_file():
        raise SQLiteWALIntegrityError("sqlite_wal_without_database")
    database_page_size = _database_page_size(database_path)

    try:
        with wal_path.open("rb") as handle:
            opened_stat = os.fstat(handle.fileno())
            if opened_stat.st_size != wal_stat.st_size:
                raise SQLiteWALIntegrityError("sqlite_wal_changed_before_validation")
            if opened_stat.st_size < _WAL_HEADER_BYTES:
                raise SQLiteWALIntegrityError("sqlite_wal_header_truncated")
            header = handle.read(_WAL_HEADER_BYTES)
            if len(header) != _WAL_HEADER_BYTES:
                raise SQLiteWALIntegrityError("sqlite_wal_header_truncated")
            magic = int.from_bytes(header[0:4], "big")
            if magic == _WAL_MAGIC_LITTLE_CHECKSUM:
                checksum_order = "little"
            elif magic == _WAL_MAGIC_BIG_CHECKSUM:
                checksum_order = "big"
            else:
                raise SQLiteWALIntegrityError("sqlite_wal_magic_invalid")
            if int.from_bytes(header[4:8], "big") != _WAL_VERSION:
                raise SQLiteWALIntegrityError("sqlite_wal_version_invalid")
            wal_page_size = _page_size(int.from_bytes(header[8:12], "big"))
            if wal_page_size != database_page_size:
                raise SQLiteWALIntegrityError("sqlite_wal_database_page_size_mismatch")
            checksum_state = _checksum(header[:24], byteorder=checksum_order)
            stored_header_checksum = (
                int.from_bytes(header[24:28], "big"),
                int.from_bytes(header[28:32], "big"),
            )
            if checksum_state != stored_header_checksum:
                raise SQLiteWALIntegrityError("sqlite_wal_header_checksum_invalid")

            frame_size = _WAL_FRAME_HEADER_BYTES + wal_page_size
            payload_size = opened_stat.st_size - _WAL_HEADER_BYTES
            if payload_size % frame_size:
                raise SQLiteWALIntegrityError("sqlite_wal_frame_truncated")
            frame_count = payload_size // frame_size
            header_salts = header[16:24]
            for _frame_index in range(frame_count):
                frame_header = handle.read(_WAL_FRAME_HEADER_BYTES)
                page = handle.read(wal_page_size)
                if len(frame_header) != _WAL_FRAME_HEADER_BYTES or len(page) != wal_page_size:
                    raise SQLiteWALIntegrityError("sqlite_wal_frame_truncated")
                if int.from_bytes(frame_header[:4], "big") == 0:
                    raise SQLiteWALIntegrityError("sqlite_wal_frame_page_invalid")
                if frame_header[8:16] != header_salts:
                    raise SQLiteWALIntegrityError("sqlite_wal_frame_salt_mismatch")
                checksum_state = _checksum(
                    frame_header[:8] + page,
                    byteorder=checksum_order,
                    seed=checksum_state,
                )
                stored_frame_checksum = (
                    int.from_bytes(frame_header[16:20], "big"),
                    int.from_bytes(frame_header[20:24], "big"),
                )
                if checksum_state != stored_frame_checksum:
                    raise SQLiteWALIntegrityError("sqlite_wal_frame_checksum_invalid")
            if handle.read(1):
                raise SQLiteWALIntegrityError("sqlite_wal_trailing_bytes")
            final_stat = os.fstat(handle.fileno())
            if (
                final_stat.st_size != opened_stat.st_size
                or final_stat.st_mtime_ns != opened_stat.st_mtime_ns
            ):
                raise SQLiteWALIntegrityError("sqlite_wal_changed_during_validation")
    except SQLiteWALIntegrityError:
        raise
    except OSError as exc:
        raise SQLiteWALIntegrityError("sqlite_wal_read_failed") from exc


__all__ = ("SQLiteWALIntegrityError", "validate_wal_before_recovery")
