"""Bounded queue JSON replacement publication steps."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from Virus_Scan.scheduler.runtime.queue_json_common import QUEUE_JSON_EXCEPTIONS
from Virus_Scan.scheduler.runtime.queue_json_replace_locked import queue_json_replace_locked


def queue_json_log_replace_failure(
    *,
    safe_context: str,
    filesystem_path: object,
    exc: BaseException,
    log_func: Callable[[str], object],
    path_name_func: Callable[[object], str],
    exception_text_func: Callable[[BaseException], str],
    record_degraded: Callable[..., object],
) -> None:
    """Log a replacement failure and record telemetry logger failure explicitly."""
    try:
        if safe_context:
            log_func(
                "queue json replace failed context="
                + safe_context
                + " path="
                + path_name_func(filesystem_path)
                + ": "
                + exception_text_func(exc)
            )
    except QUEUE_JSON_EXCEPTIONS as logging_exc:
        record_degraded("queue_json_logging_failed", logging_exc, domain="telemetry")


def queue_json_cleanup_failed_tmp(
    tmp: Path | None,
    *,
    safe_unlink: object,
    record_degraded: Callable[..., object],
) -> None:
    """Clean a failed replacement temp path when it still exists."""
    try:
        if tmp is not None and Path(tmp).exists():
            bool(safe_unlink(tmp, log_context="queue_json_failed_tmp_cleanup"))
    except QUEUE_JSON_EXCEPTIONS as cleanup_exc:
        record_degraded("queue_json_cleanup_failed", cleanup_exc, domain="persistence")


def queue_json_publish_locked_replacement(
    *,
    context: object,
    payload: object,
    safe_unlink: object,
    lock_owner: object,
    path_name_func: Callable[[object], str],
    exception_text_func: Callable[[BaseException], str],
    make_safe_func: Callable[[object], object],
    normalize_func: Callable[[object], object],
    validate_func: Callable[..., object],
    verify_file_func: Callable[..., object],
    parent_small_func: Callable[..., bool],
    cleanup_due_func: Callable[..., bool],
    cleanup_temps_func: Callable[..., object],
    log_func: Callable[[str], object],
    record_degraded: Callable[..., object],
) -> bool:
    """Publish one queue JSON payload while holding the queue path lock."""
    tmp = None
    token = None
    try:
        context.target.parent.mkdir(parents=True, exist_ok=True)
        token = lock_owner.acquire_for(context.target)
        ok, tmp = queue_json_replace_locked(
            target=context.target,
            safe_suffix=context.safe_suffix,
            safe_context=context.safe_context,
            verify_required=context.verify_required,
            payload=payload,
            safe_unlink=safe_unlink,
            parent_small_func=parent_small_func,
            cleanup_due_func=cleanup_due_func,
            cleanup_temps_func=cleanup_temps_func,
            make_safe_func=make_safe_func,
            normalize_func=normalize_func,
            validate_func=validate_func,
            verify_file_func=verify_file_func,
            log_func=log_func,
            exception_text_func=exception_text_func,
            record_degraded=record_degraded,
        )
        return ok
    except QUEUE_JSON_EXCEPTIONS as exc:
        queue_json_log_replace_failure(
            safe_context=context.safe_context,
            filesystem_path=context.target,
            exc=exc,
            log_func=log_func,
            path_name_func=path_name_func,
            exception_text_func=exception_text_func,
            record_degraded=record_degraded,
        )
        queue_json_cleanup_failed_tmp(
            tmp,
            safe_unlink=safe_unlink,
            record_degraded=record_degraded,
        )
        return False
    finally:
        if token is not None:
            lock_owner.release_for(token)


__all__ = (
    "queue_json_cleanup_failed_tmp",
    "queue_json_log_replace_failure",
    "queue_json_publish_locked_replacement",
)
