"""Bounded queue JSON replacement orchestration."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.scheduler.runtime.queue_json_replace_context import queue_json_replace_context
from Virus_Scan.scheduler.runtime.queue_json_replace_publication_steps import (
    queue_json_cleanup_failed_tmp,
    queue_json_log_replace_failure,
    queue_json_publish_locked_replacement,
)


def queue_write_json_replace_with_dependencies(
    path: object,
    payload: object,
    *,
    tmp_suffix: object,
    verify: object,
    log_context: object,
    safe_unlink: object,
    lock_owner: object,
    context_func: Callable[..., str],
    tmp_suffix_func: Callable[[object], str],
    verify_flag_func: Callable[[object], bool],
    filesystem_path_func: Callable[[object], tuple[object, str | None]],
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
    """Publish queue JSON through explicit dependency-injected owners."""
    context = queue_json_replace_context(
        path,
        tmp_suffix=tmp_suffix,
        verify=verify,
        log_context=log_context,
        context_func=context_func,
        tmp_suffix_func=tmp_suffix_func,
        verify_flag_func=verify_flag_func,
        filesystem_path_func=filesystem_path_func,
        record_degraded=record_degraded,
    )
    if context is None:
        return False
    return queue_json_publish_locked_replacement(
        context=context,
        payload=payload,
        safe_unlink=safe_unlink,
        lock_owner=lock_owner,
        path_name_func=path_name_func,
        exception_text_func=exception_text_func,
        make_safe_func=make_safe_func,
        normalize_func=normalize_func,
        validate_func=validate_func,
        verify_file_func=verify_file_func,
        parent_small_func=parent_small_func,
        cleanup_due_func=cleanup_due_func,
        cleanup_temps_func=cleanup_temps_func,
        log_func=log_func,
        record_degraded=record_degraded,
    )


__all__ = (
    "queue_json_cleanup_failed_tmp",
    "queue_json_log_replace_failure",
    "queue_write_json_replace_with_dependencies",
)
