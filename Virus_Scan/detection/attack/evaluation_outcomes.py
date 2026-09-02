"""Immutable per-technique outcomes for ATT&CK production evaluation."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.detection.attack.evaluation_contracts import (
    ATTACK_EVALUATION_EXPECTED_STATES,
)
from Virus_Scan.detection.attack.validation import (
    bounded_float,
    official_attack_id,
    ordered_text_tuple,
)

ATTACK_PRODUCTION_OBSERVED_STATES = frozenset({
    "confirmed", "candidate", "rejected", "unavailable",
})


@dataclass(frozen=True, slots=True, order=True)
class AttackTechniqueEvaluationOutcome:
    """Expected and observed state for one technique on one raw artifact."""

    technique_id: str
    expected_state: str
    observed_state: str
    probability: float
    evidence_completeness: float
    claim_scopes: tuple[str, ...]
    implementation_ids: tuple[str, ...]
    rejection_reason: str
    unavailable_reason: str
    missing_requirements: tuple[str, ...]
    unavailable_fields: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self) is not AttackTechniqueEvaluationOutcome:
            raise TypeError("attack_evaluation_outcome_owner_invalid")
        technique_id = official_attack_id(
            self.technique_id, "attack_evaluation_outcome_technique_invalid",
        )
        if not technique_id.startswith("T") or technique_id.startswith("TA"):
            raise ValueError("attack_evaluation_outcome_technique_invalid")
        expected_state = exact_bounded_text(
            self.expected_state,
            "attack_evaluation_outcome_expected_state_invalid",
            maximum=16,
        )
        observed_state = exact_bounded_text(
            self.observed_state,
            "attack_evaluation_outcome_observed_state_invalid",
            maximum=16,
        )
        if expected_state not in ATTACK_EVALUATION_EXPECTED_STATES:
            raise ValueError("attack_evaluation_outcome_expected_state_invalid")
        if observed_state not in ATTACK_PRODUCTION_OBSERVED_STATES:
            raise ValueError("attack_evaluation_outcome_observed_state_invalid")
        probability = bounded_float(
            self.probability, "attack_evaluation_outcome_probability_invalid",
        )
        completeness = bounded_float(
            self.evidence_completeness,
            "attack_evaluation_outcome_completeness_invalid",
        )
        claim_scopes = ordered_text_tuple(
            self.claim_scopes,
            "attack_evaluation_outcome_claim_scopes_invalid",
            maximum_items=32,
        )
        implementation_ids = ordered_text_tuple(
            self.implementation_ids,
            "attack_evaluation_outcome_implementation_ids_invalid",
            maximum_items=128,
        )
        rejection_reason = exact_bounded_text(
            self.rejection_reason,
            "attack_evaluation_outcome_rejection_reason_invalid",
            maximum=256,
            allow_blank=True,
        )
        unavailable_reason = exact_bounded_text(
            self.unavailable_reason,
            "attack_evaluation_outcome_unavailable_reason_invalid",
            maximum=256,
            allow_blank=True,
        )
        missing_requirements = ordered_text_tuple(
            self.missing_requirements,
            "attack_evaluation_outcome_missing_requirements_invalid",
            maximum_items=256,
        )
        unavailable_fields = ordered_text_tuple(
            self.unavailable_fields,
            "attack_evaluation_outcome_unavailable_fields_invalid",
            maximum_items=256,
        )
        if observed_state != "confirmed" and probability != 0.0:
            raise ValueError("attack_evaluation_nonconfirmed_probability_invalid")
        if observed_state != "rejected" and rejection_reason:
            raise ValueError("attack_evaluation_rejection_reason_state_invalid")
        if observed_state == "rejected" and not rejection_reason:
            raise ValueError("attack_evaluation_rejection_reason_required")
        if observed_state != "unavailable" and unavailable_reason:
            raise ValueError("attack_evaluation_unavailable_reason_state_invalid")
        if observed_state == "unavailable" and not unavailable_reason:
            raise ValueError("attack_evaluation_unavailable_reason_required")
        for name, value in (
            ("technique_id", technique_id),
            ("expected_state", expected_state),
            ("observed_state", observed_state),
            ("probability", probability),
            ("evidence_completeness", completeness),
            ("claim_scopes", claim_scopes),
            ("implementation_ids", implementation_ids),
            ("rejection_reason", rejection_reason),
            ("unavailable_reason", unavailable_reason),
            ("missing_requirements", missing_requirements),
            ("unavailable_fields", unavailable_fields),
        ):
            object.__setattr__(self, name, value)

    @property
    def state_matches(self) -> bool:
        return self.expected_state == self.observed_state

    def to_record(self) -> dict[str, object]:
        return {
            "technique_id": self.technique_id,
            "expected_state": self.expected_state,
            "observed_state": self.observed_state,
            "state_matches": self.state_matches,
            "probability": self.probability,
            "evidence_completeness": self.evidence_completeness,
            "claim_scopes": self.claim_scopes,
            "implementation_ids": self.implementation_ids,
            "rejection_reason": self.rejection_reason,
            "unavailable_reason": self.unavailable_reason,
            "missing_requirements": self.missing_requirements,
            "unavailable_fields": self.unavailable_fields,
        }


__all__ = (
    "ATTACK_PRODUCTION_OBSERVED_STATES",
    "AttackTechniqueEvaluationOutcome",
)
