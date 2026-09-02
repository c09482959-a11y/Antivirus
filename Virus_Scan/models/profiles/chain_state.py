"""Canonical versioned profile chain-frequency state."""

from __future__ import annotations

from typing import Final

PROFILE_CHAIN_STATE_SCHEMA_VERSION: Final[int] = 2


def default_profile_chain_state() -> dict[str, object]:
    """Return a fresh canonical suspicious-chain audit state."""
    return {
        "schema_version": PROFILE_CHAIN_STATE_SCHEMA_VERSION,
        "registry_version": "",
        "registry_digest": "",
        "suspicious_audit": {},
    }


__all__ = (
    "PROFILE_CHAIN_STATE_SCHEMA_VERSION",
    "default_profile_chain_state",
)
