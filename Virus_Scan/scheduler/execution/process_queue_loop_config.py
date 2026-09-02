"""Typed scalar parsing for queue-child loop environment config."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_text


def _queue_child_env_value(environ_get: Callable[[str, str], str], name: str, default: str) -> str:
    try:
        value = environ_get(name, default)
    except (TypeError, ValueError, OSError, RuntimeError):
        return default
    text, reason = no_hook_text(
        value,
        missing_reason="queue_child_env_text_missing",
        unsupported_reason="queue_child_env_text_rejected",
    )
    if reason or text == "":
        return default
    return text


__all__ = ("_queue_child_env_value",)
