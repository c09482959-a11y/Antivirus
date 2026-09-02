"""Deterministic queue-child monitor-loop policies for raw queue orchestration."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from Virus_Scan.contracts.env_config import str_env
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool
from Virus_Scan.scheduler.execution.process_queue_loop_config import _queue_child_env_value

_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


@dataclass(frozen=True)
class QueueChildIdleDecisionDependencies:
    """Explicit dependencies for idle queue-child loop decisions."""

    consume_retire: Callable[[str], bool]
    raw_has_live_work: Callable[[str], bool]
    feed_is_complete: Callable[[str], bool]
    raw_queue_enabled: Callable[[], bool]
    environ_get: Callable[[str, str], str] = str_env


def queue_child_idle_decision(work_queue_dir: Optional[str], deps: QueueChildIdleDecisionDependencies) -> str:
    """Return deterministic child idle action: ``retire``, ``wait_raw``, ``wait_feed``, or ``exit``.

    This is intentionally side-effect limited to the injected retire-token consumer.
    Sleeping remains owned by the caller so tests and replay do not depend on wall-clock delay.
    """
    if not work_queue_dir:
        return "exit"

    elastic_enabled = _queue_child_env_enabled(
        deps.environ_get,
        "UMIGE_ELASTIC_QUEUE_SCHEDULER",
        default=True,
    )
    if elastic_enabled and deps.consume_retire(work_queue_dir):
        return "retire"

    if deps.raw_queue_enabled() and deps.raw_has_live_work(work_queue_dir):
        return "wait_raw"

    dynamic_feed_enabled = _queue_child_env_enabled(
        deps.environ_get,
        "UMIGE_DYNAMIC_QUEUE_FEED",
        default=True,
    )
    if dynamic_feed_enabled and not deps.feed_is_complete(work_queue_dir):
        return "wait_feed"

    return "exit"


def _queue_child_env_enabled(environ_get: Callable[[str, str], str], name: str, *, default: bool) -> bool:
    value = _queue_child_env_value(environ_get, name, "1" if default else "0")
    parsed, reason = scheduler_bool(
        value,
        default=default,
        reason="queue_child_env_bool_rejected",
    )
    if reason:
        return default
    return parsed


__all__ = (
    "QueueChildIdleDecisionDependencies",
    "queue_child_idle_decision",
)
