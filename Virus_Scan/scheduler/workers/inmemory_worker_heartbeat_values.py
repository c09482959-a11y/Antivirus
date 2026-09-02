"""Validated scalar parsing for parent-side heartbeat messages."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_float,
    scheduler_int,
    scheduler_text,
)

_INMEMORY_HEARTBEAT_WALL_TIME_UNAVAILABLE = "inmemory heartbeat wall time unavailable"


def heartbeat_int(value: object, *, field_name: str) -> int | None:
    parsed, reason = scheduler_int(
        value,
        minimum=0,
        reason="inmemory_heartbeat_" + str.__str__(field_name) + "_rejected" if type(field_name) is str and field_name else "inmemory_heartbeat_field_rejected",
    )
    return None if reason else parsed


def heartbeat_float(value: object, *, field_name: str) -> float | None:
    parsed, reason = scheduler_float(
        value,
        minimum=0.0,
        reason="inmemory_heartbeat_" + str.__str__(field_name) + "_rejected" if type(field_name) is str and field_name else "inmemory_heartbeat_field_rejected",
    )
    return None if reason else parsed


def heartbeat_text(value: object, *, field_name: str, missing_text: str = "") -> str | None:
    safe_missing = str.__str__(missing_text) if type(missing_text) is str else ""
    text, reason = scheduler_text(
        value,
        replacement_text=safe_missing,
        unsupported_reason="inmemory_heartbeat_" + str.__str__(field_name) + "_rejected" if type(field_name) is str and field_name else "inmemory_heartbeat_field_rejected",
    )
    return None if reason or text == "" else text


def wall_time_value(wall_time: Callable[[], float]) -> float | None:
    try:
        raw = wall_time()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError(_INMEMORY_HEARTBEAT_WALL_TIME_UNAVAILABLE) from exc
    return heartbeat_float(raw, field_name="wall_time")


__all__ = ("heartbeat_float", "heartbeat_int", "heartbeat_text", "wall_time_value")
