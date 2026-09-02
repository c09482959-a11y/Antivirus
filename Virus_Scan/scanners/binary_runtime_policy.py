"""Scanner-owned binary runtime policy snapshot helpers."""
from __future__ import annotations

from Virus_Scan.scanners.config import load_binary_policy_snapshot

_BINARY_POLICY = load_binary_policy_snapshot()


def binarydeep_scan_thorough_enabled() -> bool:
    """Return scanner-owned deep-mode policy.

    Binary Phase 10 must not consult runtime mode state directly. Current scanner
    binary policy does not enable unconditional thorough escalation by default,
    so raw escalation remains driven by explicit suspicious evidence.
    """
    return False


__all__ = ("binarydeep_scan_thorough_enabled",)
