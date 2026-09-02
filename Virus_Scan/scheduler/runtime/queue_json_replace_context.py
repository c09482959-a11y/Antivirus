"""No-hook context materialization for scheduler queue JSON replacement."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from Virus_Scan.scheduler.runtime.queue_json_common import QUEUE_JSON_EXCEPTIONS


@dataclass(frozen=True)
class QueueJsonReplaceContext:
    """Materialized queue JSON replacement boundary values."""

    target: Path
    safe_context: str
    safe_suffix: str
    verify_required: bool


def queue_json_replace_context(
    path: object,
    *,
    tmp_suffix: object,
    verify: object,
    log_context: object,
    context_func: Callable[..., str],
    tmp_suffix_func: Callable[[object], str],
    verify_flag_func: Callable[[object], bool],
    filesystem_path_func: Callable[[object], tuple[object, str | None]],
    record_degraded: Callable[..., object],
) -> QueueJsonReplaceContext | None:
    """Return replacement context or record an explicit path-rejection defect."""

    safe_context = context_func(log_context, default_text="queue_json_replace")
    safe_suffix = tmp_suffix_func(tmp_suffix)
    verify_required = verify_flag_func(verify)
    filesystem_path, path_reason = filesystem_path_func(path)
    if path_reason:
        record_degraded(
            "queue_json_replace_path_rejected",
            ValueError(path_reason),
            domain="persistence",
        )
        return None
    return QueueJsonReplaceContext(
        target=Path(filesystem_path),
        safe_context=safe_context,
        safe_suffix=safe_suffix,
        verify_required=verify_required,
    )


def queue_json_release_lock(lock_owner: object, token: object | None) -> None:
    """Release a queue JSON replacement lock when a token exists."""

    if token is not None:
        try:
            lock_owner.release_for(token)
        except QUEUE_JSON_EXCEPTIONS:
            raise
