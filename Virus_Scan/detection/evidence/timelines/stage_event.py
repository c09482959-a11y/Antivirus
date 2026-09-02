"""Canonical immutable detection stage event emission ownership.

This module creates immutable stage-event snapshots.  It does not mutate runtime
state; callers can record the returned publication request in the runtime/JSON
owner that already owns persistence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from Virus_Scan.contracts.stage_event_time import deterministic_stage_event_time
from Virus_Scan.detection.scoring.weighting.policy_constants import VALID_STAGES
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags


@dataclass(frozen=True)
class StageEventSnapshot:
    """Immutable emitted detection stage event."""

    time: float
    stage: str
    tags: Tuple[str, ...]

    def as_mapping(self) -> dict:
        """Return the scanner-facing mapping shape without sharing state."""
        return {"time": self.time, "stage": self.stage, "tags": list(self.tags)}


def emit_stage_event(file: object, stage: object, tags: object) -> object:
    """Return one bounded temporal/stage event for timeline scoring/publication."""
    canonical_stage = stage if stage in VALID_STAGES else "unknown"
    normalized_tags = tuple(normalize_tags(tags or []))
    deterministic_time = deterministic_stage_event_time(file, canonical_stage, normalized_tags)
    snapshot = StageEventSnapshot(time=deterministic_time, stage=canonical_stage, tags=normalized_tags)
    record = snapshot.as_mapping()
    record["event_time_available"] = False
    record["event_time_source"] = "deterministic_content_digest"
    record["stage_event_publication_request"] = {
        "kind": "stage_event",
        "file": str(file),
        "event": snapshot.as_mapping(),
        "event_time_available": False,
        "event_time_source": "deterministic_content_digest",
    }
    return record
