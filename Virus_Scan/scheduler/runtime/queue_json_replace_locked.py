"""Locked write path for scheduler queue JSON replacement."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from Virus_Scan.scheduler.runtime.queue_json_common import QUEUE_JSON_EXCEPTIONS
from Virus_Scan.scheduler.runtime.queue_json_replace_commit import (
    queue_json_commit_tmp,
    queue_json_verify_target,
)
from Virus_Scan.scheduler.runtime.queue_json_replace_tmp import (
    queue_json_cleanup_orphan_temps_if_due,
    queue_json_expected_payload,
    queue_json_tmp_path,
    queue_json_write_tmp_payload,
)


def queue_json_replace_locked(
    *,
    target: Path,
    safe_suffix: str,
    safe_context: str,
    verify_required: bool,
    payload: object,
    safe_unlink: object,
    parent_small_func: Callable[..., bool],
    cleanup_due_func: Callable[..., bool],
    cleanup_temps_func: Callable[..., object],
    make_safe_func: Callable[[object], object],
    normalize_func: Callable[[object], object],
    validate_func: Callable[..., object],
    verify_file_func: Callable[..., object],
    log_func: Callable[[str], object],
    exception_text_func: Callable[[BaseException], str],
    record_degraded: Callable[..., object],
) -> tuple[bool, Path | None]:
    """Write, commit, and verify a queue JSON replacement under an acquired lock."""

    queue_json_cleanup_orphan_temps_if_due(
        target,
        parent_small_func=parent_small_func,
        cleanup_due_func=cleanup_due_func,
        cleanup_temps_func=cleanup_temps_func,
        record_degraded=record_degraded,
    )
    tmp = queue_json_tmp_path(target, safe_suffix)
    try:
        expected = queue_json_expected_payload(
            payload,
            safe_context=safe_context,
            make_safe_func=make_safe_func,
            normalize_func=normalize_func,
            validate_func=validate_func,
        )
        queue_json_write_tmp_payload(
            tmp,
            expected,
            exception_text_func=exception_text_func,
        )
        verify_file_func(
            tmp,
            expected=expected,
            context=safe_context or "queue_json_replace_tmp",
            require_match=True,
        )
        if not queue_json_commit_tmp(tmp, target, safe_unlink=safe_unlink):
            return False, tmp
        verified = queue_json_verify_target(
            target,
            expected,
            safe_context=safe_context,
            verify_required=verify_required,
            safe_unlink=safe_unlink,
            verify_file_func=verify_file_func,
            log_func=log_func,
            exception_text_func=exception_text_func,
            record_degraded=record_degraded,
        )
        return verified, tmp
    except QUEUE_JSON_EXCEPTIONS:
        if tmp.exists():
            bool(safe_unlink(tmp, log_context="queue_json_failed_tmp_cleanup"))
        raise
