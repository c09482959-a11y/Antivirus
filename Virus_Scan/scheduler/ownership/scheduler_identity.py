"""Canonical scheduler process identity ownership.

Owns immutable process-spawn identity needed by scheduler workers. Queue job
identity, duplicate admission guards, and identity-lock filesystem transitions are
owned by queue authority/queue identity ownership, not this module.
"""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.core.paths import get_current_script_path_for_spawn, get_python_executable_for_spawn
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class SchedulerProcessIdentity:
    script_path: Path
    python_executable: str


def build_scheduler_process_identity() -> SchedulerProcessIdentity:
    """Return the immutable spawn identity for scheduler-owned workers."""
    return SchedulerProcessIdentity(
        script_path=get_current_script_path_for_spawn(),
        python_executable=get_python_executable_for_spawn(),
    )


__all__ = ("SchedulerProcessIdentity", "build_scheduler_process_identity")
