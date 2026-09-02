"""Immutable aggregate metrics for ATT&CK production-path evaluation."""
from __future__ import annotations

from Virus_Scan.contracts.numeric_boundaries import (
    exact_bounded_nonnegative_int,
    exact_optional_rate,
)

from dataclasses import dataclass

from Virus_Scan.detection.attack.evaluation_results import (
    AttackProductionEvaluationRow,
)
from Virus_Scan.detection.attack.validation import exact_bool

_MAX_ROWS = 100_000
_MAX_OUTCOMES = 409_600_000


@dataclass(frozen=True, slots=True)
class AttackProductionEvaluationMetrics:
    """Bounded engineering metrics derived only from reconciled runtime rows."""

    row_count: int
    completed_count: int
    degraded_count: int
    scan_failure_count: int
    technique_outcome_count: int
    exact_state_match_count: int
    confirmed_expected_count: int
    confirmed_observed_count: int
    confirmed_true_positive_count: int
    candidate_expected_count: int
    candidate_state_match_count: int
    rejected_expected_count: int
    rejected_state_match_count: int
    unavailable_expected_count: int
    unavailable_state_match_count: int
    control_confirmed_count: int
    nonconfirming_zero_probability: bool
    synthetic_development: bool
    production_authority: bool

    def __post_init__(self) -> None:
        if type(self) is not AttackProductionEvaluationMetrics:
            raise TypeError("attack_evaluation_metrics_owner_invalid")
        row_fields = ("row_count", "completed_count", "degraded_count", "scan_failure_count")
        outcome_fields = (
            "technique_outcome_count", "exact_state_match_count",
            "confirmed_expected_count", "confirmed_observed_count",
            "confirmed_true_positive_count", "candidate_expected_count",
            "candidate_state_match_count", "rejected_expected_count",
            "rejected_state_match_count", "unavailable_expected_count",
            "unavailable_state_match_count", "control_confirmed_count",
        )
        for name in row_fields:
            object.__setattr__(self, name, exact_bounded_nonnegative_int(
                getattr(self, name),
                "attack_evaluation_metrics_" + name + "_invalid",
                maximum=_MAX_ROWS,
            ))
        for name in outcome_fields:
            object.__setattr__(self, name, exact_bounded_nonnegative_int(
                getattr(self, name),
                "attack_evaluation_metrics_" + name + "_invalid",
                maximum=_MAX_OUTCOMES,
            ))
        for name in (
            "nonconfirming_zero_probability", "synthetic_development",
            "production_authority",
        ):
            object.__setattr__(self, name, exact_bool(
                getattr(self, name),
                "attack_evaluation_metrics_" + name + "_invalid",
            ))
        if self.completed_count + self.scan_failure_count != self.row_count:
            raise ValueError("attack_evaluation_metrics_completion_invalid")
        if self.exact_state_match_count > self.technique_outcome_count:
            raise ValueError("attack_evaluation_metrics_state_match_invalid")
        if self.production_authority and self.synthetic_development:
            raise ValueError("attack_evaluation_synthetic_authority_invalid")

    @classmethod
    def from_rows(
        cls,
        rows: tuple[AttackProductionEvaluationRow, ...],
        *,
        synthetic_development: bool,
        production_authority: bool,
    ) -> "AttackProductionEvaluationMetrics":
        if (
            type(rows) is not tuple
            or len(rows) > _MAX_ROWS
            or any(type(row) is not AttackProductionEvaluationRow for row in rows)
            or type(synthetic_development) is not bool
            or type(production_authority) is not bool
        ):
            raise TypeError("attack_evaluation_metrics_rows_invalid")
        outcomes = tuple(outcome for row in rows for outcome in row.outcomes)
        confirmed_expected = sum(item.expected_state == "confirmed" for item in outcomes)
        confirmed_observed = sum(item.observed_state == "confirmed" for item in outcomes)
        return cls(
            row_count=len(rows),
            completed_count=sum(row.completed for row in rows),
            degraded_count=sum(bool(row.degraded_reasons) for row in rows),
            scan_failure_count=sum(not row.completed for row in rows),
            technique_outcome_count=len(outcomes),
            exact_state_match_count=sum(item.state_matches for item in outcomes),
            confirmed_expected_count=confirmed_expected,
            confirmed_observed_count=confirmed_observed,
            confirmed_true_positive_count=sum(
                item.expected_state == item.observed_state == "confirmed"
                for item in outcomes
            ),
            candidate_expected_count=sum(item.expected_state == "candidate" for item in outcomes),
            candidate_state_match_count=sum(
                item.expected_state == item.observed_state == "candidate"
                for item in outcomes
            ),
            rejected_expected_count=sum(item.expected_state == "rejected" for item in outcomes),
            rejected_state_match_count=sum(
                item.expected_state == item.observed_state == "rejected"
                for item in outcomes
            ),
            unavailable_expected_count=sum(item.expected_state == "unavailable" for item in outcomes),
            unavailable_state_match_count=sum(
                item.expected_state == item.observed_state == "unavailable"
                for item in outcomes
            ),
            control_confirmed_count=sum(
                item.observed_state == "confirmed"
                for row in rows if row.malware_class == "control"
                for item in row.outcomes
            ),
            nonconfirming_zero_probability=all(
                item.observed_state == "confirmed" or item.probability == 0.0
                for item in outcomes
            ),
            synthetic_development=synthetic_development,
            production_authority=production_authority,
        )

    def to_record(self) -> dict[str, object]:
        return {
            "row_count": self.row_count,
            "completed_count": self.completed_count,
            "degraded_count": self.degraded_count,
            "scan_failure_count": self.scan_failure_count,
            "technique_outcome_count": self.technique_outcome_count,
            "exact_state_match_count": self.exact_state_match_count,
            "state_exact_accuracy": exact_optional_rate(
                self.exact_state_match_count, self.technique_outcome_count,
            ),
            "confirmed_precision": exact_optional_rate(
                self.confirmed_true_positive_count, self.confirmed_observed_count,
            ),
            "confirmed_recall": exact_optional_rate(
                self.confirmed_true_positive_count, self.confirmed_expected_count,
            ),
            "candidate_state_accuracy": exact_optional_rate(
                self.candidate_state_match_count, self.candidate_expected_count,
            ),
            "rejected_state_accuracy": exact_optional_rate(
                self.rejected_state_match_count, self.rejected_expected_count,
            ),
            "unavailable_state_accuracy": exact_optional_rate(
                self.unavailable_state_match_count, self.unavailable_expected_count,
            ),
            "confirmed_expected_count": self.confirmed_expected_count,
            "confirmed_observed_count": self.confirmed_observed_count,
            "confirmed_true_positive_count": self.confirmed_true_positive_count,
            "candidate_expected_count": self.candidate_expected_count,
            "candidate_state_match_count": self.candidate_state_match_count,
            "rejected_expected_count": self.rejected_expected_count,
            "rejected_state_match_count": self.rejected_state_match_count,
            "unavailable_expected_count": self.unavailable_expected_count,
            "unavailable_state_match_count": self.unavailable_state_match_count,
            "control_confirmed_count": self.control_confirmed_count,
            "nonconfirming_zero_probability": self.nonconfirming_zero_probability,
            "synthetic_development": self.synthetic_development,
            "production_authority": self.production_authority,
        }


__all__ = ("AttackProductionEvaluationMetrics",)
