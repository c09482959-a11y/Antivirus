"""Immutable deterministic scheduler replay record projection."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.replay.replay_projection import (
    canonical_replay_label,
    canonical_replay_sequence,
    queue_replay_result_file_identity,
    queue_replay_result_job_identity,
    replay_result_evidence,
)
from Virus_Scan.scheduler.replay.replay_result_fields import (
    first_replay_text,
    replay_count_value,
    replay_mapping_value,
)


@dataclass(frozen=True, slots=True)
class QueueReplayComparisonRecord:
    """Immutable deterministic scheduler replay result projection."""

    job_id: str
    file_identity: str
    verdict: str
    tags: tuple[str, ...]
    chains: tuple[str, ...]
    engine_routing: str
    duplicate_count: int
    recovery_count: int
    failed_count: int
    scheduler_evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "tags", canonical_replay_sequence(self.tags))
        object.__setattr__(self, "chains", canonical_replay_sequence(self.chains))
        object.__setattr__(
            self,
            "scheduler_evidence",
            canonical_replay_sequence(self.scheduler_evidence),
        )

    @classmethod
    def from_result(
        cls,
        result: Mapping[str, object],
    ) -> "QueueReplayComparisonRecord":
        job_id = queue_replay_result_job_identity(result)
        file_identity = queue_replay_result_file_identity(result)
        verdict = canonical_replay_label(
            first_replay_text(
                result,
                "verdict",
                "status",
                "classification",
                default="",
            ),
            field_name="verdict for " + job_id,
        )
        tags = canonical_replay_sequence(
            replay_mapping_value(
                result,
                "tags",
                default=replay_mapping_value(
                    result,
                    "tag_evidence",
                    default=(),
                ),
            )
        )
        chains = canonical_replay_sequence(
            replay_mapping_value(
                result,
                "chains",
                default=replay_mapping_value(
                    result,
                    "chain_evidence",
                    default=(),
                ),
            )
        )
        engine_routing = canonical_replay_label(
            first_replay_text(
                result,
                "engine",
                "detected_engine",
                "engine_routing",
                "profile",
                default="unknown",
            ),
            field_name="engine routing for " + job_id,
        )
        return cls(
            job_id=job_id,
            file_identity=file_identity,
            verdict=verdict,
            tags=tags,
            chains=chains,
            engine_routing=engine_routing,
            duplicate_count=replay_count_value(
                result,
                "duplicate_count",
                "duplicates",
            ),
            recovery_count=replay_count_value(
                result,
                "recovery_count",
                "recoveries",
            ),
            failed_count=replay_count_value(
                result,
                "failed_count",
                "failures",
            ),
            scheduler_evidence=replay_result_evidence(result),
        )

    def sort_key(self) -> tuple[str, str]:
        return (self.job_id.casefold(), self.file_identity.casefold())

    def as_dict(self) -> dict[str, object]:
        return {
            "job_id": self.job_id,
            "file_identity": self.file_identity,
            "verdict": self.verdict,
            "tags": list(self.tags),
            "chains": list(self.chains),
            "engine_routing": self.engine_routing,
            "duplicate_count": self.duplicate_count,
            "recovery_count": self.recovery_count,
            "failed_count": self.failed_count,
            "scheduler_evidence": list(self.scheduler_evidence),
        }


__all__ = ("QueueReplayComparisonRecord",)
