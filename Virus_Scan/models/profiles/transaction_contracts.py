"""Immutable profiles-owned input contract for one learning transaction."""
from __future__ import annotations

from dataclasses import dataclass
import math

from Virus_Scan.models.contracts.learning_authority import LearningDecision
from Virus_Scan.models.profiles.learning_decision import (
    canonical_context_identity,
    content_sha256_for_path,
    observation_digest,
)


@dataclass(frozen=True, slots=True)
class LearningCommitRequest:
    """Detached normalized facts consumed by the single transaction owner."""

    decision: LearningDecision
    engine: str
    file_path: str
    content_sha256: str
    tag_evidence: object
    yara_hits: tuple[object, ...]
    risk: float
    strings_blob: str
    verdict: str
    api_calls: tuple[object, ...]
    ordered_events: tuple[object, ...]
    behavior_flow: tuple[str, ...]
    previous_stage: str
    current_stage: str
    validation: dict[str, object]
    scan_integrity: dict[str, object]

    def validate(self) -> bool:
        if type(self.decision) is not LearningDecision:
            raise ValueError("learning decision required")
        self.decision.validate()
        if type(self.engine) is not str or self.engine != self.decision.engine:
            raise ValueError("learning transaction engine mismatch")
        if type(self.file_path) is not str or self.file_path == "":
            raise ValueError("learning transaction file path required")
        if type(self.content_sha256) is not str:
            raise ValueError("learning transaction content identity invalid")
        actual_content = content_sha256_for_path(self.file_path)
        if self.content_sha256 != actual_content:
            raise ValueError("learning transaction content identity mismatch")
        if type(self.verdict) is not str or self.verdict != self.decision.verdict:
            raise ValueError("learning transaction verdict mismatch")
        if type(self.risk) not in (int, float) or isinstance(self.risk, bool):
            raise ValueError("learning transaction risk invalid")
        if not math.isfinite(float(self.risk)) or float(self.risk) != float(self.decision.risk):
            raise ValueError("learning transaction risk mismatch")
        if type(self.validation) is not dict or type(self.scan_integrity) is not dict:
            raise ValueError("learning transaction evidence must be detached")
        context = canonical_context_identity(self.validation)
        if context != self.decision.context_identity:
            raise ValueError("learning transaction context mismatch")
        digest = observation_digest(
            engine=self.engine,
            file_path=self.file_path,
            content_sha256=self.content_sha256,
            verdict=self.verdict,
            risk=self.risk,
            tags=self.tag_evidence,
            yara_hits=self.yara_hits,
            behavior_flow=self.behavior_flow,
            ordered_events=self.ordered_events,
            previous_stage=self.previous_stage,
            current_stage=self.current_stage,
            scan_integrity=self.scan_integrity,
            context_identity=context,
        )
        if digest != self.decision.observation_digest:
            raise ValueError("learning transaction observation mismatch")
        return True


__all__ = ("LearningCommitRequest",)
