"""Immutable final detection output contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.detection.models.stage_value_utils import freeze_mapping_or_empty, thaw_detection_value


@dataclass(frozen=True)
class DetectionResult:
    """Final immutable detection output snapshot."""

    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        """Deep-freeze direct constructor payloads before publication handoff."""
        object.__setattr__(self, "payload", freeze_mapping_or_empty(self.payload))

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> "DetectionResult":
        return cls(payload=payload)

    def as_result_record(self) -> dict[str, object]:
        """Return a mutable scheduler/reporting-owned handoff copy."""
        return thaw_detection_value(self.payload)


__all__ = ("DetectionResult",)
