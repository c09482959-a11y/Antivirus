"""ATT&CK mapping completeness helpers; probabilities require calibration."""
from __future__ import annotations


def attack_evidence_completeness(
    *, matched_requirements: int, total_requirements: int,
) -> float:
    if (
        type(matched_requirements) is not int
        or type(matched_requirements) is bool
        or matched_requirements < 0
    ):
        raise TypeError("attack_mapping_matched_requirements_invalid")
    if (
        type(total_requirements) is not int
        or type(total_requirements) is bool
        or total_requirements < 1
    ):
        raise TypeError("attack_mapping_total_requirements_invalid")
    if matched_requirements > total_requirements:
        raise ValueError("attack_mapping_requirement_count_invalid")
    return round(min(0.999999, matched_requirements / total_requirements), 6)


__all__ = ("attack_evidence_completeness",)
