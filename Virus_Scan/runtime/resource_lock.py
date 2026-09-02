"""Canonical exclusive resource-file locking for persistent runtime caches."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PosixPath, WindowsPath
import stat
import sys

from Virus_Scan.runtime.filesystem_alias_integrity import (
    stat_result_is_filesystem_alias,
    windows_file_attributes_indicate_alias,
)

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes
    fcntl = None
else:
    import fcntl
    ctypes = None
    wintypes = None

_PATH_TYPES = (Path, PosixPath, WindowsPath)


def _absolute_path(path: Path) -> Path:
    return path if path.is_absolute() else path.absolute()


def _require_real_windows_parent(path: Path) -> None:
    parent = _absolute_path(path).parent
    current = Path(parent.anchor)
    for component in parent.parts[1:]:
        current /= component
        try:
            current.mkdir()
        except FileExistsError:
            parent_state = current.lstat()
        else:
            parent_state = current.lstat()
        if (
            stat_result_is_filesystem_alias(parent_state)
            or not stat.S_ISDIR(parent_state.st_mode)
        ):
            raise ValueError("resource_lock_parent_invalid")


def _open_real_posix_parent(path: Path) -> int:
    absolute_parent = _absolute_path(path).parent
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(absolute_parent.anchor, flags)
    completed = False
    try:
        for component in absolute_parent.parts[1:]:
            try:
                directory_state = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    directory_state = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
                else:
                    directory_state = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if stat_result_is_filesystem_alias(directory_state) or not stat.S_ISDIR(directory_state.st_mode):
                raise ValueError("resource_lock_parent_invalid")
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            opened_state = os.fstat(next_descriptor)
            if (
                not stat.S_ISDIR(opened_state.st_mode)
                or opened_state.st_dev != directory_state.st_dev
                or opened_state.st_ino != directory_state.st_ino
            ):
                os.close(next_descriptor)
                raise ValueError("resource_lock_parent_invalid")
            os.close(descriptor)
            descriptor = next_descriptor
        completed = True
        return descriptor
    finally:
        if not completed:
            os.close(descriptor)


@dataclass(slots=True)
class ResourceFileLock:
    path: Path
    writable: bool
    _handle: object = None

    def acquire(self) -> None:
        if type(self) is not ResourceFileLock:
            raise TypeError("resource_lock_owner_invalid")
        if type(self.path) not in _PATH_TYPES or type(self.writable) is not bool:
            raise TypeError("resource_lock_contract_invalid")
        if self._handle is not None:
            raise RuntimeError("resource_lock_already_acquired")
        if sys.platform == "win32":
            _require_real_windows_parent(self.path)
            self._acquire_windows()
        else:
            self._acquire_posix()

    def _acquire_posix(self) -> None:
        if fcntl is None:
            raise OSError("resource_lock_posix_backend_unavailable")
        parent_descriptor = _open_real_posix_parent(self.path)
        descriptor = -1
        try:
            flags = (os.O_RDWR | os.O_CREAT) if self.writable else os.O_RDONLY
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path.name, flags, 0o600, dir_fd=parent_descriptor)
        finally:
            os.close(parent_descriptor)
        file_state = os.fstat(descriptor)
        if not stat.S_ISREG(file_state.st_mode):
            os.close(descriptor)
            raise ValueError("resource_lock_target_invalid")
        mode = "r+b" if self.writable else "rb"
        handle = os.fdopen(descriptor, mode)
        operation = fcntl.LOCK_EX if self.writable else fcntl.LOCK_SH
        try:
            fcntl.flock(handle.fileno(), operation | fcntl.LOCK_NB)
        except (OSError, BlockingIOError):
            handle.close()
            raise
        self._handle = handle

    def _acquire_windows(self) -> None:
        if ctypes is None or wintypes is None:
            raise OSError("resource_lock_windows_backend_unavailable")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = (
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        )
        create_file.restype = wintypes.HANDLE
        desired = 0x80000000 | (0x40000000 if self.writable else 0)
        share_mode = 0 if self.writable else 0x00000001
        creation = 4 if self.writable else 3
        handle = create_file(
            str(self.path), desired, share_mode, None, creation,
            0x80 | 0x00200000, None,
        )
        if handle == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        class FileBasicInfo(ctypes.Structure):
            _fields_ = (
                ("creation_time", ctypes.c_longlong),
                ("last_access_time", ctypes.c_longlong),
                ("last_write_time", ctypes.c_longlong),
                ("change_time", ctypes.c_longlong),
                ("file_attributes", wintypes.DWORD),
            )
        get_information = kernel32.GetFileInformationByHandleEx
        get_information.argtypes = (
            wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
        )
        get_information.restype = wintypes.BOOL
        information = FileBasicInfo()
        if not get_information(handle, 0, ctypes.byref(information), ctypes.sizeof(information)):
            error = ctypes.get_last_error()
            kernel32.CloseHandle(handle)
            raise ctypes.WinError(error)
        if (
            information.file_attributes & 0x00000010
            or windows_file_attributes_indicate_alias(int(information.file_attributes))
        ):
            kernel32.CloseHandle(handle)
            raise ValueError("resource_lock_target_invalid")
        self._handle = handle

    def release(self) -> None:
        if type(self) is not ResourceFileLock:
            raise TypeError("resource_lock_owner_invalid")
        handle = self._handle
        self._handle = None
        if handle is None:
            return
        if sys.platform == "win32":
            if ctypes is None or wintypes is None:
                raise OSError("resource_lock_windows_backend_unavailable")
            close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
            close_handle.argtypes = (wintypes.HANDLE,)
            close_handle.restype = wintypes.BOOL
            if not close_handle(handle):
                raise ctypes.WinError(ctypes.get_last_error())
            return
        if fcntl is None:
            raise OSError("resource_lock_posix_backend_unavailable")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()

    @property
    def acquired(self) -> bool:
        return self._handle is not None


class ResourceLockSet:
    def __init__(self) -> None:
        if type(self) is not ResourceLockSet:
            raise TypeError("resource_lock_set_owner_invalid")
        self._locks: list[ResourceFileLock] = []

    def acquire(self, path: Path, *, writable: bool) -> ResourceFileLock:
        if type(self) is not ResourceLockSet:
            raise TypeError("resource_lock_set_owner_invalid")
        lock = ResourceFileLock(path=path, writable=writable)
        lock.acquire()
        self._locks.append(lock)
        return lock

    def release_all(self) -> None:
        if type(self) is not ResourceLockSet:
            raise TypeError("resource_lock_set_owner_invalid")
        failure: OSError | None = None
        while self._locks:
            try:
                self._locks.pop().release()
            except OSError as exc:
                if failure is None:
                    failure = exc
        if failure is not None:
            raise failure

    @property
    def paths(self) -> tuple[Path, ...]:
        return tuple(lock.path for lock in self._locks if lock.acquired)


__all__ = ("ResourceFileLock", "ResourceLockSet")
