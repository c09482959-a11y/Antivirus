"""Canonical YARA initialization snapshot.

The YARA package owns its default rule/cache configuration directly.  The init
path returns an immutable snapshot and does not publish runtime globals.
"""
from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.contracts.env_config import str_env
from Virus_Scan.yara.no_hook import yara_message, yara_positive_int, yara_text

from Virus_Scan.yara.constants import (
    YARALIGHT_CACHE_DIRNAME,
    YARALIGHT_CACHE_MANIFEST,
    YARALIGHT_COMPILED_CACHE,
    YARA_CACHE_DIRNAME,
    YARA_CACHE_MANIFEST,
    YARA_COMPILED_CACHE,
    YARA_GROUP_CACHE_DIRNAME,
)


def _positive_int_from_env(name: str, default: int) -> int:
    raw = str_env(name, "")
    raw_text = yara_text(raw).strip()
    if raw_text == "":
        return yara_positive_int(default, default=1)
    value, reason = no_hook_exact_nonnegative_int(raw_text, default=0, reason="invalid_yara_default_integer")
    if reason or value < 1:
        raise ValueError(yara_message(name, " must be >= 1"))
    return value


def yara_default_snapshot() -> MappingProxyType:
    """Return immutable YARA startup defaults owned by the YARA package."""
    default_groups = _positive_int_from_env("UMIGE_YARA_PARALLEL_GROUPS", 8)
    max_groups = _positive_int_from_env("UMIGE_YARA_PARALLEL_GROUPS_MAX", 16)
    if max_groups < default_groups:
        raise ValueError("UMIGE_YARA_PARALLEL_GROUPS_MAX must be >= UMIGE_YARA_PARALLEL_GROUPS")
    return MappingProxyType({
        "YARA_CACHE_DIRNAME": YARA_CACHE_DIRNAME,
        "YARA_CACHE_MANIFEST": YARA_CACHE_MANIFEST,
        "YARA_COMPILED_CACHE": YARA_COMPILED_CACHE,
        "YARALIGHT_CACHE_DIRNAME": YARALIGHT_CACHE_DIRNAME,
        "YARALIGHT_CACHE_MANIFEST": YARALIGHT_CACHE_MANIFEST,
        "YARALIGHT_COMPILED_CACHE": YARALIGHT_COMPILED_CACHE,
        "YARA_RULES_SOURCE_PATH": None,
        "YARA_PARALLEL_GROUPS_DEFAULT": default_groups,
        "YARA_PARALLEL_GROUPS_MAX": max_groups,
        "YARA_GROUP_CACHE_DIRNAME": YARA_GROUP_CACHE_DIRNAME,
        "YARALIGHT_AUTO_DOWNLOAD": True,
        "YARALIGHT_ENABLED": True,
        "FAST_FINGERPRINT_SAMPLE": 64 * 1024,
    })


def init_yara_defaults() -> MappingProxyType:
    """Return immutable YARA defaults without wrapper state."""
    return yara_default_snapshot()


__all__ = ("init_yara_defaults", "yara_default_snapshot")
