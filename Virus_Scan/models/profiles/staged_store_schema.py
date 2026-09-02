"""Strict current schema for staged benign candidates."""
from __future__ import annotations

import math

from Virus_Scan.models.profiles.promotion_observations import (
    new_observation_ledger,
    validate_observation_ledger,
)
from Virus_Scan.models.profiles.schema_versions import (
    PROFILE_STAGED_STORE_SCHEMA_VERSION,
)

_STAGED_STORE_REQUIRED_KEYS = frozenset((
    "schema_version", "candidates", "promotions", "rejections",
    "observation_ledger",
))
_STAGED_STORE_ALLOWED_KEYS = _STAGED_STORE_REQUIRED_KEYS | {"retention"}


def default_staged_benign_store() -> dict[str, object]:
    return {
        "schema_version": PROFILE_STAGED_STORE_SCHEMA_VERSION,
        "candidates": {},
        "promotions": 0,
        "rejections": {},
        "observation_ledger": new_observation_ledger(),
    }


def _finite_nonnegative(value: object) -> bool:
    return (
        type(value) in (int, float) and type(value) is not bool
        and math.isfinite(float(value)) and float(value) >= 0.0
    )


def _sorted_text_list(value: object) -> bool:
    return (
        type(value) is list
        and all(type(item) is str and item != "" for item in value)
        and value == sorted(set(value))
    )


def _validate_candidate(key: object, candidate: object) -> None:
    if type(key) is not str or key == "" or type(candidate) is not dict:
        raise ValueError("staged benign candidate invalid")
    for field in ("sha256", "engine", "extension", "path_example"):
        if type(candidate.get(field)) is not str:
            raise ValueError("staged benign candidate identity invalid")
    sha = candidate["sha256"]
    if len(sha) != 64 or any(char not in "0123456789abcdef" for char in sha):
        raise ValueError("staged benign candidate digest invalid")
    if not candidate["engine"] or key != ":".join((candidate["engine"], candidate["extension"], sha)):
        raise ValueError("staged benign candidate identity invalid")
    first_seen = candidate.get("first_seen")
    last_seen = candidate.get("last_seen")
    if not _finite_nonnegative(first_seen) or not _finite_nonnegative(last_seen):
        raise ValueError("staged benign candidate ordinal invalid")
    if float(last_seen) < float(first_seen):
        raise ValueError("staged benign candidate ordinal invalid")
    observations = candidate.get("clean_observations")
    if type(observations) is not int or type(observations) is bool or observations < 0:
        raise ValueError("staged benign candidate count invalid")
    if not _finite_nonnegative(candidate.get("max_score_seen")):
        raise ValueError("staged benign candidate risk invalid")
    if not _sorted_text_list(candidate.get("tags_seen")) or not _sorted_text_list(candidate.get("real_ordered_events_seen")):
        raise ValueError("staged benign candidate evidence invalid")
    promoted = candidate.get("promoted")
    if type(promoted) is not bool:
        raise ValueError("staged benign candidate promotion invalid")
    promoted_at = candidate.get("promoted_at")
    if promoted:
        if not _finite_nonnegative(promoted_at) or float(promoted_at) < float(first_seen):
            raise ValueError("staged benign candidate promotion invalid")
    elif promoted_at is not None:
        raise ValueError("staged benign candidate promotion invalid")


def validate_staged_benign_store(value: object) -> bool:
    if type(value) is not dict:
        raise ValueError("staged benign store must be an object")
    keys = frozenset(value)
    if not _STAGED_STORE_REQUIRED_KEYS.issubset(keys) or not keys.issubset(_STAGED_STORE_ALLOWED_KEYS):
        raise ValueError("staged benign store fields invalid")
    if value.get("schema_version") != PROFILE_STAGED_STORE_SCHEMA_VERSION:
        raise ValueError("staged benign store schema invalid")
    candidates = value.get("candidates")
    rejections = value.get("rejections")
    if type(candidates) is not dict or type(rejections) is not dict:
        raise ValueError("staged benign store mappings invalid")
    for key, candidate in candidates.items():
        _validate_candidate(key, candidate)
    for reason, count in rejections.items():
        if type(reason) is not str or reason == "" or type(count) is not int or type(count) is bool or count < 0:
            raise ValueError("staged benign rejection record invalid")
    promotions = value.get("promotions")
    if type(promotions) is not int or type(promotions) is bool or promotions < 0:
        raise ValueError("staged benign promotions invalid")
    validate_observation_ledger(value.get("observation_ledger"))
    entries = value["observation_ledger"]["entries"]
    for entry in entries.values():
        status = entry["status"]
        candidate_key = entry["candidate_key"]
        if status in {"staged", "promoted"}:
            candidate = candidates.get(candidate_key)
            if type(candidate) is not dict:
                raise ValueError("staged benign ledger candidate mismatch")
            if status == "promoted" and candidate["promoted"] is not True:
                raise ValueError("staged benign ledger candidate mismatch")
        elif candidate_key != "":
            raise ValueError("staged benign ledger candidate mismatch")
    retention = value.get("retention")
    if retention is not None and type(retention) is not dict:
        raise ValueError("staged benign retention invalid")
    return True



__all__ = (
    "default_staged_benign_store",
    "validate_staged_benign_store",
)
