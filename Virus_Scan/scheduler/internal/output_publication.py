"""Scheduler-wide aggregate output publication owner."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile

from Virus_Scan.contracts.worker_record import make_json_safe
from Virus_Scan.runtime.api import (
    FilesystemDurabilityError,
    durable_replace_regular_file,
    flush_open_writable_file,
    path_contains_filesystem_alias,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text


WORKER_OUTPUT_PUBLICATION_FAILED = False
_WORKER_OUTPUT_PUBLICATION_SUCCEEDED = True
_WORKER_OUTPUT_PUBLICATION_EXCEPTIONS = (
    OSError,
    FilesystemDurabilityError,
    TypeError,
    ValueError,
    json.JSONDecodeError,
)


def _worker_output_path_text(path: object) -> tuple[str, str]:
    path_text, reason = scheduler_path_text(path)
    if reason:
        return "", reason
    if not path_text:
        return "", "scheduler_worker_output_path_blank"
    return path_text, ""


def _close_owned_worker_output_fd(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        return


def _remove_owned_worker_output_file(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink()
    except (FileNotFoundError, OSError):
        return


def _worker_output_target(path_text: str) -> Path:
    target = Path(path_text).absolute()
    if path_contains_filesystem_alias(target):
        raise FilesystemDurabilityError("scheduler_worker_output_alias_rejected")
    target.parent.mkdir(parents=True, exist_ok=True)
    if path_contains_filesystem_alias(target):
        raise FilesystemDurabilityError("scheduler_worker_output_alias_rejected")
    parent_state = target.parent.lstat()
    if not stat.S_ISDIR(parent_state.st_mode):
        raise FilesystemDurabilityError("scheduler_worker_output_parent_invalid")
    try:
        target_state = target.lstat()
    except FileNotFoundError:
        return target
    if not stat.S_ISREG(target_state.st_mode):
        raise FilesystemDurabilityError("scheduler_worker_output_target_invalid")
    return target


def write_worker_output_payload(path: object, payload: object) -> bool:
    """Durably publish one aggregate worker-output payload and verify readback."""
    safe_path, path_reason = _worker_output_path_text(path)
    if path_reason:
        return WORKER_OUTPUT_PUBLICATION_FAILED
    temporary_path: Path | None = None
    published_path: Path | None = None
    open_fd: int | None = None
    try:
        target = _worker_output_target(safe_path)
        expected = make_json_safe(payload)
        open_fd, temporary_text = tempfile.mkstemp(
            prefix=target.name + ".",
            suffix=".tmp",
            dir=target.parent,
            text=True,
        )
        temporary_path = Path(temporary_text)
        file_object = os.fdopen(open_fd, "w", encoding="utf-8")
        open_fd = None
        with file_object as handle:
            json.dump(
                expected,
                handle,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            )
            handle.flush()
            flush_open_writable_file(handle.fileno())
        durable_replace_regular_file(temporary_path, target)
        temporary_path = None
        published_path = target
        with target.open("r", encoding="utf-8") as verify_handle:
            loaded = json.load(verify_handle)
        if loaded != expected:
            _remove_owned_worker_output_file(published_path)
            return WORKER_OUTPUT_PUBLICATION_FAILED
    except _WORKER_OUTPUT_PUBLICATION_EXCEPTIONS:
        _close_owned_worker_output_fd(open_fd)
        _remove_owned_worker_output_file(temporary_path)
        _remove_owned_worker_output_file(published_path)
        return WORKER_OUTPUT_PUBLICATION_FAILED
    return _WORKER_OUTPUT_PUBLICATION_SUCCEEDED


__all__ = ("write_worker_output_payload",)
