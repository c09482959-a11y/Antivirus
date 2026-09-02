"""Temporary file preparation for scheduler queue JSON replacement."""
from __future__ import annotations

import json
import os
from pathlib import Path
import threading
import time
from typing import Callable

from Virus_Scan.contracts.env_config import float_env, int_env
from Virus_Scan.runtime.api import flush_open_writable_file
from Virus_Scan.scheduler.runtime.queue_json_common import QUEUE_JSON_EXCEPTIONS


def queue_json_cleanup_orphan_temps_if_due(
    target: Path,
    *,
    parent_small_func: Callable[..., bool],
    cleanup_due_func: Callable[..., bool],
    cleanup_temps_func: Callable[..., object],
    record_degraded: Callable[..., object],
) -> None:
    """Clean stale queue JSON temps when the bounded cleanup policy says to."""

    try:
        cleanup_stride = int_env("UMIGE_QUEUE_JSON_TMP_CLEAN_STRIDE", 64, 1, None)
        small_limit = int_env("UMIGE_QUEUE_JSON_TMP_SMALL_DIR_LIMIT", 128, 1, None)
        small_parent = parent_small_func(target.parent, limit=small_limit)
        cleanup_due = cleanup_due_func(target, stride=cleanup_stride)
        if small_parent or cleanup_due:
            cleanup_temps_func(
                target,
                max_remove=int_env("UMIGE_QUEUE_JSON_TMP_CLEAN_MAX", 64, 1, None),
                min_age_sec=float_env("UMIGE_QUEUE_JSON_TMP_MIN_AGE", 30.0, 0.0, None),
            )
    except QUEUE_JSON_EXCEPTIONS as cleanup_exc:
        record_degraded("queue_json_orphan_cleanup_failed", cleanup_exc, domain="scheduler")


def queue_json_tmp_path(target: Path, safe_suffix: str) -> Path:
    """Build a unique temporary path without caller-owned hooks."""

    try:
        tid = threading.get_ident()
    except QUEUE_JSON_EXCEPTIONS:
        tid = 0
    try:
        nonce = int.__str__(time.time_ns()) + "_" + int.__str__(os.getpid())
    except QUEUE_JSON_EXCEPTIONS:
        nonce = int.__str__(os.getpid())
    return target.with_name(
        target.name
        + safe_suffix
        + "."
        + int.__str__(os.getpid())
        + "."
        + int.__str__(tid)
        + "."
        + nonce
    )


def queue_json_expected_payload(
    payload: object,
    *,
    safe_context: str,
    make_safe_func: Callable[[object], object],
    normalize_func: Callable[[object], object],
    validate_func: Callable[..., object],
) -> object:
    """Normalize, materialize, and validate the replacement payload."""

    expected = make_safe_func(normalize_func(payload))
    validate_func(expected, context=safe_context or "queue_json_replace_expected")
    return expected


def queue_json_write_tmp_payload(
    tmp: Path,
    expected: object,
    *,
    exception_text_func: Callable[[BaseException], str],
) -> None:
    """Write and fsync one JSON replacement temp file."""

    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(expected, handle, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        try:
            handle.flush()
            flush_open_writable_file(handle.fileno())
        except (OSError, ValueError) as exc:
            message = "queue json sync failed for " + str(tmp) + ": " + exception_text_func(exc)
            raise OSError(message) from exc
