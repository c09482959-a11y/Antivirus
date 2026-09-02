"""Independent metrics for context-only ATT&CK candidate retrieval."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.detection.attack.candidate_retrieval import AttackCandidateRetrievalResult
from Virus_Scan.detection.attack.validation import official_attack_id
from Virus_Scan.utils.probability import safe_clamp


@dataclass(frozen=True, slots=True)
class AttackCandidateEvaluationSample:
    sample_id: str
    expected_technique_ids: tuple[str, ...]
    result: AttackCandidateRetrievalResult
    drifted: bool = False

    def __post_init__(self) -> None:
        if type(self.sample_id) is not str or not self.sample_id or len(self.sample_id) > 256:
            raise ValueError("attack_candidate_evaluation_sample_id_invalid")
        if type(self.expected_technique_ids) is not tuple:
            raise TypeError("attack_candidate_evaluation_expected_invalid")
        expected = tuple(sorted(
            official_attack_id(
                value, "attack_candidate_evaluation_expected_invalid",
            )
            for value in self.expected_technique_ids
        ))
        if (
            not expected
            or any(not value.startswith("T") or value.startswith("TA") for value in expected)
            or len(expected) != len(set(expected))
        ):
            raise ValueError("attack_candidate_evaluation_expected_invalid")
        if type(self.result) is not AttackCandidateRetrievalResult:
            raise TypeError("attack_candidate_evaluation_result_required")
        object.__setattr__(self, "expected_technique_ids", expected)
        object.__setattr__(self, "drifted", self.drifted is True)


@dataclass(frozen=True, slots=True)
class AttackCandidateEvaluationMetrics:
    sample_count: int
    k: int
    recall_at_k: float
    precision_at_k: float
    mean_reciprocal_rank: float
    abstention_rate: float
    stable_recall_at_k: float
    drifted_recall_at_k: float
    drift_recall_delta: float

    def to_record(self) -> dict[str, object]:
        return {
            "sample_count": self.sample_count,
            "k": self.k,
            "recall_at_k": self.recall_at_k,
            "precision_at_k": self.precision_at_k,
            "mean_reciprocal_rank": self.mean_reciprocal_rank,
            "abstention_rate": self.abstention_rate,
            "stable_recall_at_k": self.stable_recall_at_k,
            "drifted_recall_at_k": self.drifted_recall_at_k,
            "drift_recall_delta": self.drift_recall_delta,
            "evaluation_scope": "candidate_retrieval_only",
            "eligible_for_probability": False,
        }


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def evaluate_attack_candidate_retrieval(
    samples: tuple[AttackCandidateEvaluationSample, ...],
    *,
    k: int = 5,
) -> AttackCandidateEvaluationMetrics:
    if type(samples) is not tuple or any(type(item) is not AttackCandidateEvaluationSample for item in samples):
        raise TypeError("attack_candidate_evaluation_samples_invalid")
    if type(k) is not int or type(k) is bool or k < 1 or k > 16:
        raise ValueError("attack_candidate_evaluation_k_invalid")
    recalls: list[float] = []
    precisions: list[float] = []
    reciprocal_ranks: list[float] = []
    stable_recalls: list[float] = []
    drifted_recalls: list[float] = []
    abstained = 0
    for sample in samples:
        expected = set(sample.expected_technique_ids)
        ranked = tuple(item.technique_id for item in sample.result.candidates[:k])
        if sample.result.abstained:
            abstained += 1
        hits = expected & set(ranked)
        recall = len(hits) / len(expected) if expected else 1.0
        precision = len(hits) / k
        reciprocal = 0.0
        for index, technique_id in enumerate(ranked, 1):
            if technique_id in expected:
                reciprocal = 1.0 / index
                break
        recalls.append(recall)
        precisions.append(precision)
        reciprocal_ranks.append(reciprocal)
        (drifted_recalls if sample.drifted else stable_recalls).append(recall)
    stable = _mean(stable_recalls)
    drifted = _mean(drifted_recalls)
    return AttackCandidateEvaluationMetrics(
        sample_count=len(samples), k=k,
        recall_at_k=safe_clamp(_mean(recalls)),
        precision_at_k=safe_clamp(_mean(precisions)),
        mean_reciprocal_rank=safe_clamp(_mean(reciprocal_ranks)),
        abstention_rate=safe_clamp(abstained / len(samples) if samples else 0.0),
        stable_recall_at_k=safe_clamp(stable),
        drifted_recall_at_k=safe_clamp(drifted),
        drift_recall_delta=max(-1.0, min(1.0, stable - drifted)),
    )


__all__ = (
    "AttackCandidateEvaluationMetrics",
    "AttackCandidateEvaluationSample",
    "evaluate_attack_candidate_retrieval",
)
