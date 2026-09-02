"""Canonical Linux and Windows filesystem durability bindings."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path, PosixPath, WindowsPath
import stat
import sys

from Virus_Scan.runtime.filesystem_alias_integrity import (
    path_contains_filesystem_alias,
    stat_result_is_filesystem_alias,
    windows_file_attributes_indicate_alias,
)

if sys.platform == "win32":
    from ctypes import wintypes
    import msvcrt
else:
    wintypes = None
    msvcrt = None

_PATH_TYPES = (Path, PosixPath, WindowsPath)
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_GENERIC_WRITE = 0x40000000
_OPEN_EXISTING = 3
_SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004
_MOVEFILE_REPLACE_EXISTING = 0x00000001
_MOVEFILE_WRITE_THROUGH = 0x00000008
_AT_FDCWD = -100
_RENAME_NOREPLACE = 1


class FilesystemDurabilityError(RuntimeError):
    """A durable filesystem transition cannot satisfy its exact contract."""


def _exact_path(value: object) -> Path:
    if type(value) not in _PATH_TYPES:
        raise TypeError("filesystem_durability_path_invalid")
    return value if value.is_absolute() else value.absolute()


def _require_kind(path: Path, *, directory: bool, reason: str) -> os.stat_result:
    try:
        if path_contains_filesystem_alias(path):
            raise FilesystemDurabilityError(reason)
        state = path.lstat()
    except OSError as exc:
        raise FilesystemDurabilityError(reason) from exc
    expected = stat.S_ISDIR(state.st_mode) if directory else stat.S_ISREG(state.st_mode)
    if stat_result_is_filesystem_alias(state) or not expected:
        raise FilesystemDurabilityError(reason)
    return state


def _require_supported_platform() -> None:
    if sys.platform not in {"linux", "win32"}:
        raise FilesystemDurabilityError("filesystem_durability_platform_unsupported")


def _windows_path_text(path: Path) -> str:
    text = str(path)
    if text.startswith("\\\\?\\"):
        return text
    if text.startswith("\\\\"):
        return "\\\\?\\UNC\\" + text[2:]
    return "\\\\?\\" + text


def _windows_flush_handle(handle: object, *, directory: bool) -> None:
    if wintypes is None:
        raise FilesystemDurabilityError("filesystem_durability_windows_backend_unavailable")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    class FileInformation(ctypes.Structure):
        _fields_ = (
            ("file_attributes", wintypes.DWORD),
            ("creation_time", wintypes.FILETIME),
            ("last_access_time", wintypes.FILETIME),
            ("last_write_time", wintypes.FILETIME),
            ("volume_serial_number", wintypes.DWORD),
            ("file_size_high", wintypes.DWORD),
            ("file_size_low", wintypes.DWORD),
            ("number_of_links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        )

    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = (wintypes.HANDLE, ctypes.POINTER(FileInformation))
    get_information.restype = wintypes.BOOL
    flush_buffers = kernel32.FlushFileBuffers
    flush_buffers.argtypes = (wintypes.HANDLE,)
    flush_buffers.restype = wintypes.BOOL
    information = FileInformation()
    if not get_information(handle, ctypes.byref(information)):
        raise ctypes.WinError(ctypes.get_last_error())
    attributes = int(information.file_attributes)
    actual_directory = bool(attributes & _FILE_ATTRIBUTE_DIRECTORY)
    if actual_directory is not directory or windows_file_attributes_indicate_alias(attributes):
        raise FilesystemDurabilityError("filesystem_durability_target_invalid")
    if not flush_buffers(handle):
        raise ctypes.WinError(ctypes.get_last_error())


def _windows_flush(path: Path, *, directory: bool) -> None:
    if wintypes is None:
        raise FilesystemDurabilityError("filesystem_durability_windows_backend_unavailable")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    flags = _FILE_FLAG_OPEN_REPARSE_POINT
    flags |= _FILE_FLAG_BACKUP_SEMANTICS if directory else _FILE_ATTRIBUTE_NORMAL
    handle = create_file(
        _windows_path_text(path),
        _GENERIC_WRITE,
        _SHARE_ALL,
        None,
        _OPEN_EXISTING,
        flags,
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    failure: BaseException | None = None
    try:
        _windows_flush_handle(handle, directory=directory)
    except (OSError, FilesystemDurabilityError) as exc:
        failure = exc
    close_error = 0
    if not close_handle(handle):
        close_error = ctypes.get_last_error()
    if failure is not None:
        raise failure.with_traceback(failure.__traceback__)
    if close_error:
        raise ctypes.WinError(close_error)


def flush_open_writable_file(descriptor: object) -> None:
    """Flush one caller-owned open regular-file descriptor without closing it."""
    _require_supported_platform()
    if type(descriptor) is not int or descriptor < 0:
        raise TypeError("filesystem_durability_descriptor_invalid")
    try:
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise FilesystemDurabilityError("filesystem_durability_descriptor_invalid") from exc
    if not stat.S_ISREG(opened.st_mode):
        raise FilesystemDurabilityError("filesystem_durability_descriptor_file_invalid")
    if sys.platform == "win32":
        if msvcrt is None:
            raise FilesystemDurabilityError("filesystem_durability_windows_backend_unavailable")
        _windows_flush_handle(msvcrt.get_osfhandle(descriptor), directory=False)
    else:
        os.fsync(descriptor)


def _posix_flush(path: Path, *, directory: bool) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        expected = stat.S_ISDIR(opened.st_mode) if directory else stat.S_ISREG(opened.st_mode)
        if not expected:
            raise FilesystemDurabilityError("filesystem_durability_target_invalid")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def flush_existing_regular_file(path: object) -> None:
    """Flush one already-closed, non-aliased regular file to stable storage."""
    _require_supported_platform()
    target = _exact_path(path)
    _require_kind(target, directory=False, reason="filesystem_durability_file_invalid")
    if sys.platform == "win32":
        _windows_flush(target, directory=False)
    else:
        _posix_flush(target, directory=False)


def flush_directory(path: object) -> None:
    """Flush one real directory through the supported platform binding."""
    _require_supported_platform()
    target = _exact_path(path)
    _require_kind(target, directory=True, reason="filesystem_durability_directory_invalid")
    if sys.platform == "win32":
        _windows_flush(target, directory=True)
    else:
        _posix_flush(target, directory=True)


def _require_same_volume(source: Path, destination_parent: Path) -> None:
    source_state = source.stat()
    parent_state = destination_parent.stat()
    if source_state.st_dev != parent_state.st_dev:
        raise FilesystemDurabilityError("filesystem_durability_cross_volume_rejected")


def _windows_move(source: Path, destination: Path, *, replace_existing: bool) -> None:
    if wintypes is None:
        raise FilesystemDurabilityError("filesystem_durability_windows_backend_unavailable")
    move_file = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
    move_file.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
    move_file.restype = wintypes.BOOL
    flags = _MOVEFILE_WRITE_THROUGH
    if replace_existing:
        flags |= _MOVEFILE_REPLACE_EXISTING
    if not move_file(
        _windows_path_text(source),
        _windows_path_text(destination),
        flags,
    ):
        raise ctypes.WinError(ctypes.get_last_error())


def _linux_activate_directory(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    rename_at_2 = getattr(libc, "renameat2", None)
    if rename_at_2 is None:
        raise FilesystemDurabilityError("filesystem_directory_activation_backend_unavailable")
    rename_at_2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    rename_at_2.restype = ctypes.c_int
    if rename_at_2(
        _AT_FDCWD,
        os.fsencode(source),
        _AT_FDCWD,
        os.fsencode(destination),
        _RENAME_NOREPLACE,
    ) != 0:
        raise OSError(ctypes.get_errno(), "filesystem_directory_activation_failed")


def _flush_transition_parents(source_parent: Path, destination_parent: Path) -> None:
    flush_directory(destination_parent)
    if source_parent != destination_parent:
        flush_directory(source_parent)


def durable_replace_regular_file(source: object, destination: object) -> None:
    """Flush and atomically replace one same-volume regular-file destination."""
    _require_supported_platform()
    source_path = _exact_path(source)
    destination_path = _exact_path(destination)
    _require_kind(source_path, directory=False, reason="filesystem_durability_source_file_invalid")
    _require_kind(destination_path.parent, directory=True, reason="filesystem_durability_destination_parent_invalid")
    try:
        destination_state = destination_path.lstat()
    except FileNotFoundError:
        destination_state = None
    if destination_state is not None and (
        stat_result_is_filesystem_alias(destination_state)
        or path_contains_filesystem_alias(destination_path)
        or not stat.S_ISREG(destination_state.st_mode)
    ):
        raise FilesystemDurabilityError("filesystem_durability_destination_file_invalid")
    _require_same_volume(source_path, destination_path.parent)
    flush_existing_regular_file(source_path)
    source_parent = source_path.parent
    if sys.platform == "win32":
        _windows_move(source_path, destination_path, replace_existing=True)
    else:
        os.replace(source_path, destination_path)
    _flush_transition_parents(source_parent, destination_path.parent)


def durable_activate_directory(source: object, destination: object) -> None:
    """Durably activate one new same-volume directory without replacement."""
    _require_supported_platform()
    source_path = _exact_path(source)
    destination_path = _exact_path(destination)
    _require_kind(source_path, directory=True, reason="filesystem_durability_source_directory_invalid")
    _require_kind(destination_path.parent, directory=True, reason="filesystem_durability_destination_parent_invalid")
    try:
        destination_path.lstat()
    except FileNotFoundError:
        destination_exists = False
    else:
        destination_exists = True
    if destination_exists:
        raise FilesystemDurabilityError("filesystem_durability_destination_preexisting")
    _require_same_volume(source_path, destination_path.parent)
    flush_directory(source_path)
    source_parent = source_path.parent
    if sys.platform == "win32":
        _windows_move(source_path, destination_path, replace_existing=False)
    else:
        _linux_activate_directory(source_path, destination_path)
    _flush_transition_parents(source_parent, destination_path.parent)


__all__ = (
    "FilesystemDurabilityError",
    "durable_activate_directory",
    "durable_replace_regular_file",
    "flush_directory",
    "flush_existing_regular_file",
    "flush_open_writable_file",
)
