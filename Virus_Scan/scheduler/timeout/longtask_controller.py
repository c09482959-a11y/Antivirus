"""Canonical scheduler timeout long-task guard ownership.

This module owns hard wall-clock per-file timeout enforcement. Heartbeat and
progress remain the primary stalled-worker signals; this context manager is only
the deterministic hard limit used by serial/single-worker execution paths.
"""

from __future__ import annotations

import signal
from typing import Callable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int


class FileScanTimeoutError(TimeoutError):
    """Raised when a file exceeds the configured hard scan budget."""


_SIGNAL_ALARM: object = getattr(signal, "SIGALRM", None)
_SIGNAL_ALARM_CALL: Callable[[int], int] | None = getattr(signal, "alarm", None)


class per_file_timeout:
    """Signal-based per-file timeout guard for deterministic single-worker scans."""
    def __init__(self, seconds: object=0) -> None:
        parsed_seconds, _reason = scheduler_int(value=seconds, default=0, minimum=0, reason="per_file_timeout_seconds_rejected")
        self.seconds = parsed_seconds
        self.old_handler: object = None

    def __enter__(self) -> object:
        alarm_call = _SIGNAL_ALARM_CALL
        if self.seconds <= 0 or _SIGNAL_ALARM is None or not callable(alarm_call):
            return self
        self.old_handler = signal.getsignal(_SIGNAL_ALARM)

        def _raise_timeout(signum: object, frame: object) -> object:
            del frame, signum  # Explicitly unused contract parameters.
            raise FileScanTimeoutError("per-file timeout exceeded: " + int.__str__(self.seconds) + "s")

        signal.signal(_SIGNAL_ALARM, _raise_timeout)
        alarm_call(self.seconds)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> object:
        alarm_call = _SIGNAL_ALARM_CALL
        if self.seconds > 0 and _SIGNAL_ALARM is not None and callable(alarm_call):
            alarm_call(0)
            if self.old_handler is not None:
                signal.signal(_SIGNAL_ALARM, self.old_handler)
        return False
