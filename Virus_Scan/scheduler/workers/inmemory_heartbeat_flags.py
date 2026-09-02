"""Worker-owned immutable heartbeat flag snapshot for in-memory workers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class InMemoryHeartbeatFlags:
    running: int
    cancel_request: int
    poisoned: int
    stalled: int
    force_retire: int

    @property
    def cancel_stall_poison_mask(self) -> int:
        return int(self.cancel_request | self.stalled | self.poisoned)

    @property
    def poisoned_or_retire_mask(self) -> int:
        return int(self.poisoned | self.force_retire)


def build_inmemory_heartbeat_flags(get_init_value: Callable[[str], object]) -> InMemoryHeartbeatFlags:
    """Build the immutable heartbeat flag snapshot from runtime initialization values."""
    return InMemoryHeartbeatFlags(
        running=int(get_init_value("HB_RUNNING") or 1),
        cancel_request=int(get_init_value("HB_CANCEL_REQUEST") or 2),
        poisoned=int(get_init_value("HB_POISONED") or 4),
        stalled=int(get_init_value("HB_STALLED") or 8),
        force_retire=int(get_init_value("HB_FORCE_RETIRE") or 16),
    )
