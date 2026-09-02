"""Raw-stage eligibility replayable decision records."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RawStageEligibilityDecision:
    """Typed replayable raw-stage admission decision."""

    eligible: bool
    reason: str
    stage: str
    extension: str
    size: int
    minimum_size: int

    @classmethod
    def accepted(
        cls,
        *,
        stage: str,
        extension: str,
        size: int,
        minimum_size: int,
    ) -> "RawStageEligibilityDecision":
        return cls(True, "raw_queue_eligible", stage, extension, size, minimum_size)

    @classmethod
    def rejected(
        cls,
        reason: str,
        *,
        stage: str = "",
        extension: str = "",
        size: int = 0,
        minimum_size: int = 0,
    ) -> "RawStageEligibilityDecision":
        return cls(False, reason, stage, extension, size, minimum_size)
