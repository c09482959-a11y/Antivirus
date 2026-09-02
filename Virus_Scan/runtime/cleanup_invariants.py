"""Deterministic runtime cleanup invariant checks.

These checks are explicit validation boundaries for tests and scheduler/CLI smoke
runs.  They do not create cleanup side effects and never downgrade failures to a
clean result; callers receive a hard invariant exception with the surviving
runtime ownership details.
"""
from __future__ import annotations

from dataclasses import dataclass
from multiprocessing import active_children
from pathlib import Path, PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
from threading import Thread, Timer, enumerate as enumerate_threads
from typing import Iterable

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_owner_field, no_hook_type_name

_STDLIB_PATH_TYPES = (Path, PosixPath, WindowsPath, PurePosixPath, PureWindowsPath)
_STDLIB_THREAD_TYPES = (Thread, Timer)


def _cleanup_exact_text(value: object) -> str | None:
    if type(value) is str:
        text: str | None = str.__str__(value)
    elif type(value) is bytes:
        text = value.decode("utf-8", errors="replace")
    elif type(value) is bytearray:
        text = bytes(value).decode("utf-8", errors="replace")
    elif type(value) is Path:
        text = Path.as_posix(value)
    elif type(value) is PosixPath:
        text = PosixPath.as_posix(value)
    elif type(value) is WindowsPath:
        text = WindowsPath.as_posix(value)
    elif type(value) is PurePosixPath:
        text = PurePosixPath.as_posix(value)
    elif type(value) is PureWindowsPath:
        text = PureWindowsPath.as_posix(value)
    else:
        text = None
    return text


def _cleanup_root_path(value: object) -> Path | None:
    text = _cleanup_exact_text(value)
    if text is None or text == "":
        return None
    return Path(text)


def _cleanup_ignored_names(values: Iterable[object]) -> frozenset[str]:
    if type(values) not in (tuple, list, set, frozenset):
        return frozenset()
    names: list[str] = []
    for item in values:
        text = _cleanup_exact_text(item)
        if text:
            names.append(text)
    return frozenset(names)


def _cleanup_root_objects(values: Iterable[object]) -> tuple[object, ...]:
    if type(values) not in (tuple, list, set, frozenset):
        return (values,)
    return tuple(values)


def _cleanup_context_text(value: object) -> str:
    text = _cleanup_exact_text(value)
    if text:
        return text
    return "unsupported_cleanup_context:" + no_hook_type_name(value)


def _cleanup_path_text(path: Path) -> str:
    return PurePath.as_posix(path)


def _unsupported_cleanup_root(value: object) -> str:
    return "<unsupported_cleanup_root:" + no_hook_type_name(value) + ">"


def _cleanup_thread_name(thread: object) -> str | None:
    if not isinstance(thread, Thread):
        return "<unsupported_thread:" + no_hook_type_name(thread) + ">"
    name_value = thread.name
    name = str.__str__(name_value) if type(name_value) is str else ""
    if name == "MainThread" or not thread.is_alive():
        return None
    suffix = " [daemon]" if thread.daemon is True else ""
    return (name or "<unnamed_thread>") + suffix


def _cleanup_field_rejected(field_name: str) -> str:
    return "runtime cleanup " + field_name + " rejected"


@dataclass(frozen=True, slots=True)
class RuntimeCleanupSnapshot:
    active_thread_names: tuple[str, ...]
    active_process_ids: tuple[int, ...]
    queue_artifacts: tuple[str, ...]
    tmp_artifacts: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self) is not RuntimeCleanupSnapshot:
            exception_message = "runtime cleanup snapshot owner rejected"
            raise TypeError(exception_message)
        for field_name in (
            "active_thread_names",
            "queue_artifacts",
            "tmp_artifacts",
        ):
            values = no_hook_exact_owner_field(self, RuntimeCleanupSnapshot, field_name)
            if type(values) is not tuple or any(
                type(value) is not str for value in values
            ):
                raise TypeError(_cleanup_field_rejected(field_name))
        if type(self.active_process_ids) is not tuple or any(
            type(pid) is not int or pid < 0 for pid in self.active_process_ids
        ):
            exception_message = "runtime cleanup process ids rejected"
            raise ValueError(exception_message)

    @classmethod
    def capture(
        cls,
        *,
        roots: Iterable[object] = (),
        ignored_thread_names: Iterable[str] = (),
    ) -> "RuntimeCleanupSnapshot":
        ignored = _cleanup_ignored_names(ignored_thread_names)
        thread_names = []
        for thread in enumerate_threads():
            name = _cleanup_thread_name(thread)
            if name is None or name in ignored:
                continue
            thread_names.append(name)
        process_ids = tuple(
            sorted(
                child.pid
                for child in active_children()
                if type(child.pid) is int and child.pid >= 0
            )
        )
        queue_artifacts: list[str] = []
        tmp_artifacts: list[str] = []
        for root_obj in _cleanup_root_objects(roots):
            root = _cleanup_root_path(root_obj)
            if root is None:
                tmp_artifacts.append(_unsupported_cleanup_root(root_obj))
                continue
            if not root.exists():
                continue
            for candidate in root.rglob("*"):
                name = candidate.name
                suffix = candidate.suffix.lower()
                if name in {"pending", "active", "done", "failed", "file_results", "work_queue"}:
                    queue_artifacts.append(_cleanup_path_text(candidate))
                if suffix in {".tmp", ".partial", ".lock", ".lck", ".pid"} or name.endswith(".tmp"):
                    tmp_artifacts.append(_cleanup_path_text(candidate))
        return cls(tuple(sorted(thread_names)), process_ids, tuple(sorted(queue_artifacts)), tuple(sorted(tmp_artifacts)))

    def validate_clean(self, *, context: str = "runtime_cleanup") -> bool:
        context_text = _cleanup_context_text(context)
        errors: list[str] = []
        if self.active_thread_names:
            errors.append("active threads=" + ",".join(self.active_thread_names))
        if self.active_process_ids:
            errors.append(
                "active child processes="
                + ",".join(int.__str__(pid) for pid in self.active_process_ids)
            )
        if self.queue_artifacts:
            errors.append("queue artifacts=" + ",".join(self.queue_artifacts[:16]))
        if self.tmp_artifacts:
            errors.append("runtime tmp artifacts=" + ",".join(self.tmp_artifacts[:16]))
        if errors:
            raise RuntimeError(context_text + ": dirty runtime cleanup state: " + "; ".join(errors))
        return True


def validate_runtime_cleanup(*, roots: Iterable[object] = (), ignored_thread_names: Iterable[str] = (), context: str = "runtime_cleanup") -> bool:
    return RuntimeCleanupSnapshot.capture(roots=roots, ignored_thread_names=ignored_thread_names).validate_clean(context=context)
