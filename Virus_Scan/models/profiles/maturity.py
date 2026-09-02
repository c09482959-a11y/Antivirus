"""Canonical profile maturity and learned-suppression authority owner."""
from __future__ import annotations

from types import MappingProxyType
from typing import Final

from Virus_Scan.models.profiles.common import profile_int, profile_mapping_get
from Virus_Scan.models.profiles.feature_registry import (
    PROFILE_RAW_FEATURE_NAMES,
    PROFILE_RAW_FEATURE_SCHEMA_VERSION,
)
from Virus_Scan.runtime.init_state import get_init_value

PROFILE_MATURITY_VERSION: Final[str] = "profile_maturity_v2_trusted_diversity"
PROFILE_WARMING_MIN_TRUSTED_SUPPORT: Final[int] = int(
    get_init_value("BASELINE_MATURITY_COLD_FILES") or 3
)
PROFILE_MATURE_MIN_TRUSTED_SUPPORT: Final[int] = int(
    get_init_value("BASELINE_MATURITY_WARM_FILES") or 12
)
PROFILE_WARMING_MIN_CLEAN_DIVERSITY: Final[int] = 2
PROFILE_MATURE_MIN_CLEAN_DIVERSITY: Final[int] = int(
    get_init_value("PROFILE_MIN_CLEAN_DIVERSITY") or 3
)


def unavailable_profile_maturity(reason: str) -> object:
    return MappingProxyType({
        "version": PROFILE_MATURITY_VERSION,
        "ready": False,
        "reason": reason,
        "maturity": "unknown",
        "count": 0,
        "trusted_count": 0,
        "clean_diversity_count": 0,
        "minimum_support": MappingProxyType({
            "warming": PROFILE_WARMING_MIN_TRUSTED_SUPPORT,
            "mature": PROFILE_MATURE_MIN_TRUSTED_SUPPORT,
        }),
        "minimum_clean_diversity": MappingProxyType({
            "warming": PROFILE_WARMING_MIN_CLEAN_DIVERSITY,
            "mature": PROFILE_MATURE_MIN_CLEAN_DIVERSITY,
        }),
        "suppression_strength": "none",
        "suppression_authority": 0.0,
    })


def profile_maturity_evidence(vector_baseline: object) -> object:
    """Derive maturity from validated trusted support and clean diversity."""
    if type(vector_baseline) is not dict:
        return unavailable_profile_maturity("profile_vector_statistics_unavailable")
    if vector_baseline.get("feature_schema_version") != PROFILE_RAW_FEATURE_SCHEMA_VERSION:
        return unavailable_profile_maturity("profile_feature_schema_unavailable")
    if tuple(vector_baseline.get("feature_names", ())) != PROFILE_RAW_FEATURE_NAMES:
        return unavailable_profile_maturity("profile_feature_registry_unavailable")
    count = profile_int(profile_mapping_get(vector_baseline, "count", -1), -1)
    trusted = profile_int(profile_mapping_get(vector_baseline, "trusted_count", -1), -1)
    diversity = profile_int(
        profile_mapping_get(vector_baseline, "clean_diversity_count", -1), -1,
    )
    diversity_keys = profile_mapping_get(vector_baseline, "clean_diversity_keys", ())
    if count < 0 or trusted < 0 or trusted > count:
        return unavailable_profile_maturity("profile_trusted_support_invalid")
    if (
        diversity < 0
        or type(diversity_keys) is not list
        or len(diversity_keys) != diversity
        or any(type(key) is not str or key == "" for key in diversity_keys)
        or diversity_keys != sorted(set(diversity_keys))
        or diversity > trusted
    ):
        return unavailable_profile_maturity("profile_clean_diversity_invalid")
    if (
        trusted >= PROFILE_MATURE_MIN_TRUSTED_SUPPORT
        and diversity >= PROFILE_MATURE_MIN_CLEAN_DIVERSITY
    ):
        maturity, strength, authority, reason = "mature", "full", 1.0, None
    elif (
        trusted >= PROFILE_WARMING_MIN_TRUSTED_SUPPORT
        and diversity >= PROFILE_WARMING_MIN_CLEAN_DIVERSITY
    ):
        maturity, strength, authority, reason = "warming", "limited", 0.35, None
    else:
        maturity, strength, authority = "cold", "none", 0.0
        reason = (
            "insufficient_clean_profile_diversity"
            if trusted >= PROFILE_WARMING_MIN_TRUSTED_SUPPORT
            else "insufficient_trusted_profile_support"
        )
    return MappingProxyType({
        "version": PROFILE_MATURITY_VERSION,
        "ready": maturity != "cold",
        "reason": reason,
        "maturity": maturity,
        "count": count,
        "trusted_count": trusted,
        "clean_diversity_count": diversity,
        "minimum_support": MappingProxyType({
            "warming": PROFILE_WARMING_MIN_TRUSTED_SUPPORT,
            "mature": PROFILE_MATURE_MIN_TRUSTED_SUPPORT,
        }),
        "minimum_clean_diversity": MappingProxyType({
            "warming": PROFILE_WARMING_MIN_CLEAN_DIVERSITY,
            "mature": PROFILE_MATURE_MIN_CLEAN_DIVERSITY,
        }),
        "suppression_strength": strength,
        "suppression_authority": authority,
    })


__all__ = (
    "PROFILE_MATURE_MIN_CLEAN_DIVERSITY",
    "PROFILE_MATURE_MIN_TRUSTED_SUPPORT",
    "PROFILE_MATURITY_VERSION",
    "PROFILE_WARMING_MIN_CLEAN_DIVERSITY",
    "PROFILE_WARMING_MIN_TRUSTED_SUPPORT",
    "profile_maturity_evidence",
    "unavailable_profile_maturity",
)
