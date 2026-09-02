"""Deterministic staged-benign candidate state transitions."""
from __future__ import annotations

from Virus_Scan.models.profiles.common import profile_finite_float, profile_int
from Virus_Scan.models.profiles.learning import real_ordered_event_names


def candidate_observation_time(
    candidate: object, *, minimum_spread_days: float, promote_after: int,
) -> float:
    """Derive observation time from deterministic candidate state."""
    if not isinstance(candidate, dict):
        return 0.0
    first_seen = profile_finite_float(candidate.get("first_seen"), 0.0)
    last_seen = profile_finite_float(candidate.get("last_seen"), first_seen)
    next_observation = profile_int(candidate.get("clean_observations"), 0) + 1
    spread_seconds = max(0.0, minimum_spread_days) * 86400.0
    denominator = max(1, promote_after - 1)
    step_seconds = spread_seconds / denominator if spread_seconds else 1.0
    ordinal_seen = first_seen + max(0, next_observation - 1) * step_seconds
    return max(first_seen, last_seen, ordinal_seen)


def stage_candidate_record(
    store: dict[str, object],
    key: str,
    sha: str,
    engine: str,
    path: str,
    extension: str,
    risk: float,
    tags: set[str],
    ordered_events: object,
    *,
    minimum_spread_days: float,
    promote_after: int,
) -> tuple[dict[str, object], float]:
    """Update one candidate record using deterministic observation state."""
    candidates = store.setdefault("candidates", {})
    if not isinstance(candidates, dict):
        candidates = {}
        store["candidates"] = candidates
    candidate = candidates.get(key) or {
        "sha256": sha, "engine": engine, "extension": extension,
        "path_example": path, "first_seen": 0.0, "last_seen": 0.0,
        "clean_observations": 0, "max_score_seen": 0.0,
        "tags_seen": [], "real_ordered_events_seen": [], "promoted": False,
    }
    now = candidate_observation_time(
        candidate,
        minimum_spread_days=minimum_spread_days,
        promote_after=promote_after,
    )
    candidate.setdefault("first_seen", now)
    candidate["clean_observations"] = profile_int(
        candidate.get("clean_observations", 0), 0,
    ) + 1
    candidate["last_seen"] = now
    candidate["max_score_seen"] = max(
        profile_finite_float(candidate.get("max_score_seen", 0.0), 0.0), risk,
    )
    candidate["tags_seen"] = sorted(set(candidate.get("tags_seen", [])) | tags)
    candidate["real_ordered_events_seen"] = sorted(
        set(candidate.get("real_ordered_events_seen", []))
        | set(real_ordered_event_names(ordered_events))
    )
    candidates[key] = candidate
    return candidate, now


def candidate_should_promote(
    candidate: dict[str, object],
    now: float,
    *,
    promote_after: int,
    maximum_risk: float,
    minimum_spread_days: float,
) -> bool:
    """Return whether the deterministic promotion gates are all satisfied."""
    age_days = (
        profile_finite_float(candidate.get("last_seen"), now)
        - profile_finite_float(candidate.get("first_seen"), now)
    ) / 86400.0
    return (
        not bool(candidate.get("promoted", False))
        and profile_int(candidate.get("clean_observations", 0), 0) >= promote_after
        and profile_finite_float(candidate.get("max_score_seen", 0.0), 0.0)
        <= maximum_risk
        and age_days >= minimum_spread_days
    )


__all__ = (
    "candidate_observation_time",
    "candidate_should_promote",
    "stage_candidate_record",
)
