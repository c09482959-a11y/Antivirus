"""Immutable runtime constants with static ownership.

This module replaces the old generated standard-import aggregate as the
canonical owner for small process-stable defaults.  It intentionally does not
import broad stdlib surfaces or own mutable runtime state.
"""
from __future__ import annotations

from Virus_Scan.contracts.env_config import int_env

GLOBAL_HALF_LIFE = 1800
FAST_FINGERPRINT_SAMPLE = 64 * 1024
DECODE_LAYER_MAX_DEPTH = 5

STAGE_PARALLEL_DEFAULT_WORKERS = int_env("UMIGE_STAGE_PARALLEL_WORKERS", 6, 1, None)

__all__ = (
    "DECODE_LAYER_MAX_DEPTH",
    "FAST_FINGERPRINT_SAMPLE",
    "GLOBAL_HALF_LIFE",
    "STAGE_PARALLEL_DEFAULT_WORKERS",
)
