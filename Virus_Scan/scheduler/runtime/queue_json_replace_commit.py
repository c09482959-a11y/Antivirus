"""Commit and verification helpers for scheduler queue JSON replacement."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from Virus_Scan.scheduler.runtime.queue_filesystem import queue_atomic_replace
from Virus_Scan.scheduler.runtime.queue_json_common import QUEUE_JSON_EXCEPTIONS


def queue_json_commit_tmp(
    tmp: Path,
    target: Path,
    *,
    safe_unlink: object,
) -> bool:
    """Atomically publish a temp file or clean it if replacement fails."""

    if queue_atomic_replace(tmp, target, log_context="json_replace"):
        return True
    bool(safe_unlink(tmp, log_context="json_replace_tmp_cleanup"))
    return False


def queue_json_log_verify_failure(
    *,
    safe_context: str,
    target: Path,
    verify_exc: BaseException | None,
    log_func: Callable[[str], object],
    exception_text_func: Callable[[BaseException], str],
    record_degraded: Callable[..., object],
) -> None:
    """Publish queue JSON verification failure telemetry without hiding logger failure."""

    try:
        if verify_exc is None:
            log_func("queue json verify mismatch context=" + safe_context + " path=" + str(target))
        else:
            log_func(
                "queue json verify failed context="
                + safe_context
                + " path="
                + str(target)
                + ": "
                + exception_text_func(verify_exc)
            )
    except QUEUE_JSON_EXCEPTIONS as logging_exc:
        record_degraded("queue_json_verify_logging_failed", logging_exc, domain="telemetry")


def queue_json_verify_target(
    target: Path,
    expected: object,
    *,
    safe_context: str,
    verify_required: bool,
    safe_unlink: object,
    verify_file_func: Callable[..., object],
    log_func: Callable[[str], object],
    exception_text_func: Callable[[BaseException], str],
    record_degraded: Callable[..., object],
) -> bool:
    """Verify the published target and delete invalid output on failure."""

    try:
        loaded = verify_file_func(
            target,
            expected=expected,
            context=safe_context or "queue_json_replace",
            require_match=verify_required,
        )
    except QUEUE_JSON_EXCEPTIONS as verify_exc:
        queue_json_log_verify_failure(
            safe_context=safe_context,
            target=target,
            verify_exc=verify_exc,
            log_func=log_func,
            exception_text_func=exception_text_func,
            record_degraded=record_degraded,
        )
        bool(safe_unlink(target, log_context="queue_json_verify_failed"))
        return False
    if verify_required and loaded != expected:
        queue_json_log_verify_failure(
            safe_context=safe_context,
            target=target,
            verify_exc=None,
            log_func=log_func,
            exception_text_func=exception_text_func,
            record_degraded=record_degraded,
        )
        bool(safe_unlink(target, log_context="queue_json_verify_mismatch"))
        return False
    return True
