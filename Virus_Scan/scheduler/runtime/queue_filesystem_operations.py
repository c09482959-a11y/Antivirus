"""Retrying queue filesystem operations for scheduler runtime ownership."""
from __future__ import annotations

from pathlib import Path
import os
from Virus_Scan.contracts.env_config import float_env, int_env
import time

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.runtime.api import durable_replace_regular_file, log_error
from Virus_Scan.scheduler.internal.exception_projection import scheduler_error_detail
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_float,
    scheduler_int,
    scheduler_text,
)
from Virus_Scan.scheduler.runtime.queue_filesystem_common import QUEUE_FILESYSTEM_EXCEPTIONS, queue_filesystem_path_text
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import QueueListdirFailure, queue_listdir_failure

QUEUE_FS_OPERATION_FAILED = False
QUEUE_FS_OPERATION_COMPLETE = True
QUEUE_FS_RETRY_NOT_ALLOWED = False


def safe_queue_listdir(path: object) -> list[str] | QueueListdirFailure:
    d_path, path_reason = queue_filesystem_path_text(path)
    if path_reason:
        return queue_listdir_failure(path, reason=path_reason)
    if type(d_path) is str and d_path == "":
        return queue_listdir_failure(path, reason="queue_listdir_path_missing")
    try:
        if not Path(d_path).is_dir():
            try:
                Path(d_path).mkdir(parents=True, exist_ok=True)
            except QUEUE_FILESYSTEM_EXCEPTIONS as exc:
                return queue_listdir_failure(path, reason="queue_listdir_directory_create_failed", error=exc)
        return os.listdir(d_path)
    except (FileNotFoundError, NotADirectoryError, PermissionError, OSError) as exc:
        return queue_listdir_failure(path, reason="queue_listdir_failed", error=exc)
    except QUEUE_FILESYSTEM_EXCEPTIONS as exc:
        return queue_listdir_failure(path, reason="queue_listdir_failed", error=exc)


def queue_fs_backoff(index: int, delay: object=None) -> float:
    raw_base = delay if delay is not None else float_env("UMIGE_QUEUE_FS_RETRY_DELAY", 0.025, 0.0, None)
    base, base_reason = scheduler_float(
        raw_base,
        default=0.025,
        minimum=0.0,
        maximum=0.5,
        reason="queue_fs_retry_delay_rejected",
    )
    clean_index, index_reason = scheduler_int(
        index,
        default=0,
        minimum=0,
        reason="queue_fs_retry_index_rejected",
    )
    if base_reason or index_reason:
        _queue_fs_log_failure(
            "queue fs backoff policy rejected "
            + "delay_reason=" + (base_reason or "none") + " index_reason=" + (index_reason or "none")
        )
    return min(0.5, base * (1.0 + clean_index))


def _queue_fs_retry_count(retries: object) -> int:
    raw_retries = int_env("UMIGE_QUEUE_FS_RETRIES", 12, 1, None) if retries is None else retries
    parsed, reason = scheduler_int(
        raw_retries,
        default=12,
        minimum=1,
        reason="queue_fs_retry_count_rejected",
    )
    if reason:
        _queue_fs_log_failure("queue fs retry count rejected reason=" + reason)
    return parsed


def _queue_fs_log_failure(message: str) -> None:
    try:
        log_error(message)
    except QUEUE_FILESYSTEM_EXCEPTIONS as exc:
        _ = exc


def _queue_fs_fail(message: str) -> bool:
    _queue_fs_log_failure(message)
    return QUEUE_FS_OPERATION_FAILED



def _queue_fs_retryable_os_error(exc: OSError) -> bool:
    if type(exc) is not OSError:
        return QUEUE_FS_RETRY_NOT_ALLOWED
    winerr = OSError.__getattribute__(exc, "winerror") if hasattr(exc, "winerror") else None
    errno = OSError.__getattribute__(exc, "errno")
    return winerr in (5, 32, 33) or errno in (13, 16, 26)


def queue_atomic_replace(src: object, dst: object, *, retries: object=None, delay: object=None, log_context: object=None) -> bool:
    retries = _queue_fs_retry_count(retries)
    src_s, src_reason = queue_filesystem_path_text(src)
    dst_s, dst_reason = queue_filesystem_path_text(dst)
    if log_context is None:
        context_text, context_reason = "queue_atomic_replace", ""
    else:
        context_text, context_reason = scheduler_text(
            log_context,
            replacement_text="queue_atomic_replace",
            unsupported_reason="queue_atomic_replace_context_rejected",
        )
    if src_reason or dst_reason or context_reason:
        return _queue_fs_fail(
            "queue fs replace boundary rejected "
            + "context=" + context_text + " src_type=" + no_hook_type_name(src)
            + " dst_type=" + no_hook_type_name(dst)
            + " reason=" + (src_reason or dst_reason or context_reason)
        )
    try:
        parent = str(Path(dst_s).parent)
        if parent:
            Path(parent).mkdir(parents=True, exist_ok=True)
    except QUEUE_FILESYSTEM_EXCEPTIONS as exc:
        return _queue_fs_fail("queue fs parent create failed context=" + context_text + " dst=" + dst_s + " error=" + scheduler_error_detail(exc, max_length=500))
    last_exc: BaseException | None = None
    for i in range(retries):
        try:
            durable_replace_regular_file(Path(src_s), Path(dst_s))
            return QUEUE_FS_OPERATION_COMPLETE
        except FileNotFoundError as exc:
            return _queue_fs_fail("queue fs replace source missing context=" + context_text + " src=" + src_s + " dst=" + dst_s + " error=" + scheduler_error_detail(exc, max_length=500))
        except PermissionError as exc:
            last_exc = exc
            time.sleep(queue_fs_backoff(i, delay))
        except OSError as exc:
            last_exc = exc
            if _queue_fs_retryable_os_error(exc):
                time.sleep(queue_fs_backoff(i, delay))
                continue
            return _queue_fs_fail("queue fs replace failed context=" + context_text + " src=" + src_s + " dst=" + dst_s + " error=" + scheduler_error_detail(exc, max_length=500))
        except QUEUE_FILESYSTEM_EXCEPTIONS as exc:
            last_exc = exc
            return _queue_fs_fail("queue fs replace failed context=" + context_text + " src=" + src_s + " dst=" + dst_s + " error=" + scheduler_error_detail(exc, max_length=500))
    return _queue_fs_fail("queue fs replace busy after retries context=" + context_text + " src=" + src_s + " dst=" + dst_s + " error=" + (scheduler_error_detail(last_exc, max_length=500) if isinstance(last_exc, BaseException) else "none"))


def queue_safe_unlink(path: object, *, retries: object=None, delay: object=None, log_context: object=None) -> bool:
    retries = _queue_fs_retry_count(retries)
    p_s, path_reason = queue_filesystem_path_text(path)
    if log_context is None:
        context_text, context_reason = "queue_safe_unlink", ""
    else:
        context_text, context_reason = scheduler_text(
            log_context,
            replacement_text="queue_safe_unlink",
            unsupported_reason="queue_safe_unlink_context_rejected",
        )
    if path_reason or context_reason:
        return _queue_fs_fail(
            "queue fs unlink boundary rejected "
            + "context=" + context_text + " path_type=" + no_hook_type_name(path)
            + " reason=" + (path_reason or context_reason)
        )
    last_exc: BaseException | None = None
    for i in range(retries):
        try:
            os.unlink(p_s)
            return QUEUE_FS_OPERATION_COMPLETE
        except FileNotFoundError:
            return QUEUE_FS_OPERATION_COMPLETE
        except PermissionError as exc:
            last_exc = exc
            time.sleep(queue_fs_backoff(i, delay))
        except OSError as exc:
            last_exc = exc
            if _queue_fs_retryable_os_error(exc):
                time.sleep(queue_fs_backoff(i, delay))
                continue
            return _queue_fs_fail("queue fs unlink failed context=" + context_text + " path=" + p_s + " error=" + scheduler_error_detail(exc, max_length=500))
        except QUEUE_FILESYSTEM_EXCEPTIONS as exc:
            last_exc = exc
            return _queue_fs_fail("queue fs unlink failed context=" + context_text + " path=" + p_s + " error=" + scheduler_error_detail(exc, max_length=500))
    return _queue_fs_fail("queue fs unlink busy after retries context=" + context_text + " path=" + p_s + " error=" + (scheduler_error_detail(last_exc, max_length=500) if isinstance(last_exc, BaseException) else "none"))


_queue_fs_backoff = queue_fs_backoff
