"""Immutable reconciled rows for ATT&CK production-path evaluation."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.numeric_boundaries import exact_bounded_nonnegative_int
from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.cli.exit_codes import completed_scan_final_status
from Virus_Scan.detection.attack.evaluation_contracts import (
    ATTACK_EVALUATION_MALWARE_CLASSES,
    ATTACK_EVALUATION_PARTITIONS,
)
from Virus_Scan.detection.attack.evaluation_outcomes import (
    AttackTechniqueEvaluationOutcome,
)
from Virus_Scan.detection.attack.validation import (
    exact_hex,
    ordered_text_tuple,
)

_MAX_OUTCOMES = 4_096


@dataclass(frozen=True, slots=True)
class AttackProductionEvaluationRow:
    """One reconciled raw-file runtime result and its multi-label outcomes."""

    sample_id: str
    partition: str
    malware_class: str
    artifact_path: str
    artifact_sha256: str
    runtime_sample_id: str
    runtime_exit_code: int
    final_status: str
    classification: str
    degraded_reasons: tuple[str, ...]
    repository_digest: str
    dataset_version: str
    policy_version: str
    outcomes: tuple[AttackTechniqueEvaluationOutcome, ...]

    def __post_init__(self) -> None:
        if type(self) is not AttackProductionEvaluationRow:
            raise TypeError("attack_evaluation_row_owner_invalid")
        text_values = {
            "sample_id": exact_bounded_text(
                self.sample_id,
                "attack_evaluation_row_sample_id_invalid",
                maximum=128,
            ),
            "partition": exact_bounded_text(
                self.partition,
                "attack_evaluation_row_partition_invalid",
                maximum=32,
            ),
            "malware_class": exact_bounded_text(
                self.malware_class,
                "attack_evaluation_row_malware_class_invalid",
                maximum=16,
            ),
            "artifact_path": exact_bounded_text(
                self.artifact_path,
                "attack_evaluation_row_artifact_path_invalid",
                maximum=4096,
            ),
            "runtime_sample_id": exact_bounded_text(
                self.runtime_sample_id,
                "attack_evaluation_row_runtime_sample_id_invalid",
                maximum=128,
            ),
            "final_status": exact_bounded_text(
                self.final_status,
                "attack_evaluation_row_final_status_invalid",
                maximum=64,
            ),
            "classification": exact_bounded_text(
                self.classification,
                "attack_evaluation_row_classification_invalid",
                maximum=128,
            ),
            "policy_version": exact_bounded_text(
                self.policy_version,
                "attack_evaluation_row_policy_version_invalid",
                maximum=128,
            ),
        }
        if text_values["partition"] not in ATTACK_EVALUATION_PARTITIONS:
            raise ValueError("attack_evaluation_row_partition_invalid")
        if text_values["malware_class"] not in ATTACK_EVALUATION_MALWARE_CLASSES:
            raise ValueError("attack_evaluation_row_malware_class_invalid")
        artifact_sha256 = exact_hex(
            self.artifact_sha256,
            "attack_evaluation_row_artifact_sha256_invalid",
            length=64,
        )
        runtime_exit_code = exact_bounded_nonnegative_int(
            self.runtime_exit_code,
            "attack_evaluation_row_exit_code_invalid",
            maximum=255,
        )
        if completed_scan_final_status(runtime_exit_code) != text_values["final_status"]:
            raise ValueError("attack_evaluation_row_completion_invalid")
        degraded_reasons = ordered_text_tuple(
            self.degraded_reasons,
            "attack_evaluation_row_degraded_reasons_invalid",
            maximum_items=128,
        )
        repository_digest = exact_hex(
            self.repository_digest,
            "attack_evaluation_row_repository_digest_invalid",
            length=64,
        )
        dataset_version = exact_hex(
            self.dataset_version,
            "attack_evaluation_row_dataset_version_invalid",
            length=40,
        )
        if (
            type(self.outcomes) is not tuple
            or not self.outcomes
            or len(self.outcomes) > _MAX_OUTCOMES
            or any(
                type(item) is not AttackTechniqueEvaluationOutcome
                for item in self.outcomes
            )
        ):
            raise TypeError("attack_evaluation_row_outcomes_invalid")
        outcomes = tuple(sorted(self.outcomes))
        if len({item.technique_id for item in outcomes}) != len(outcomes):
            raise ValueError("attack_evaluation_row_duplicate_outcome")
        for name, value in text_values.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "artifact_sha256", artifact_sha256)
        object.__setattr__(self, "runtime_exit_code", runtime_exit_code)
        object.__setattr__(self, "degraded_reasons", degraded_reasons)
        object.__setattr__(self, "repository_digest", repository_digest)
        object.__setattr__(self, "dataset_version", dataset_version)
        object.__setattr__(self, "outcomes", outcomes)

    @property
    def completed(self) -> bool:
        return completed_scan_final_status(self.runtime_exit_code) == self.final_status

    def to_record(self) -> dict[str, object]:
        return {
            "sample_id": self.sample_id,
            "partition": self.partition,
            "malware_class": self.malware_class,
            "artifact_path": self.artifact_path,
            "artifact_sha256": self.artifact_sha256,
            "runtime_sample_id": self.runtime_sample_id,
            "runtime_exit_code": self.runtime_exit_code,
            "final_status": self.final_status,
            "classification": self.classification,
            "degraded_reasons": self.degraded_reasons,
            "repository_digest": self.repository_digest,
            "dataset_version": self.dataset_version,
            "policy_version": self.policy_version,
            "completed": self.completed,
            "outcomes": tuple(item.to_record() for item in self.outcomes),
        }


__all__ = ("AttackProductionEvaluationRow",)
