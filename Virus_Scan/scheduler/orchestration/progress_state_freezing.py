"""Canonical no-hook progress-state freezing for scheduler orchestration."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_value


def freeze_scheduler_progress_state(value: object) -> object:
    return immutable_value(value)


__all__ = ("freeze_scheduler_progress_state",)
