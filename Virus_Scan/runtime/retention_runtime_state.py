"""Lifecycle-owned retention/pruning runtime state."""
from __future__ import annotations

from threading import RLock
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.runtime.governance_inputs import runtime_bool, runtime_int


class RetentionRuntimeState:
    def __init__(self) -> None:
        self._lock = RLock()
        self._prune_update_count = 0

    def should_prune(self, threshold: int, *, force: bool = False) -> bool:
        limit, limit_issues = runtime_int(
            threshold, field_name="retention_prune_threshold", default=1
        )
        forced, force_issues = runtime_bool(
            force, field_name="retention_prune_force", default=False
        )
        if limit_issues or force_issues or limit < 1:
            raise ValueError("retention_prune_input_rejected")
        with self._lock:
            self._prune_update_count += 1
            if forced or self._prune_update_count >= limit:
                self._prune_update_count = 0
                return True
            return False

    def snapshot(self) -> Mapping[str, int]:
        """Return an immutable, detached retention counter snapshot.

        Runtime owns the mutable pruning counter; model/retention callers may
        observe it but must not receive caller-mutable runtime state.
        """
        with self._lock:
            return MappingProxyType({"prune_update_count": self._prune_update_count})


_RETENTION_RUNTIME_STATE = RetentionRuntimeState()


def retention_runtime_state() -> RetentionRuntimeState:
    return _RETENTION_RUNTIME_STATE


__all__ = ("RetentionRuntimeState", "retention_runtime_state")
