"""Scheduler-owned deep-scan policy queries."""
from __future__ import annotations

from Virus_Scan.runtime.api import get_deep_scan_mode


def scheduler_deep_scan_mode() -> str:
    """Return the normalized deep-scan mode visible to scheduler runtime code."""
    return str(get_deep_scan_mode("auto") or "auto").lower()


def scheduler_deep_scan_thorough() -> bool:
    """Return whether scheduler-owned execution should use thorough/deep behavior."""
    return scheduler_deep_scan_mode() in {"thorough", "deep", "exhaustive"}


def scheduler_deep_scan_auto() -> bool:
    """Return whether scheduler-owned execution should use auto/adaptive behavior."""
    return scheduler_deep_scan_mode() in {"auto", "adaptive", "escalate"}


__all__ = ("scheduler_deep_scan_auto", "scheduler_deep_scan_mode", "scheduler_deep_scan_thorough")
