"""Immutable schedule/version contract for the 10,000-sample static ATT&CK matrix."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.stress.static_semantic_schema import (
    STATIC_SEMANTIC_PARTITION_BY_ID,
    CorpusFixtureDefinition,
)

SYNTHETIC_ENGINEERING_DOMAIN = "synthetic_engineering"
SYNTHETIC_CORPUS_SCHEMA_VERSION = "stage2636_11020_static_attack_matrix_schema_v7"
SYNTHETIC_ORACLE_VERSION = "stage2636_11020_static_attack_oracle_v4"
SYNTHETIC_SAFETY_VERSION = "stage2636_11020_static_attack_safety_v3"
SYNTHETIC_METADATA_VERSION = "stage2636_11020_static_attack_metadata_v3"
SYNTHETIC_CHALLENGE_PAIR_VERSION = "stage2636_11020_static_attack_challenge_pairs_v1"
SYNTHETIC_MASTER_SEED = "stage2636.11020:2026-08-17:static-attack-matrix-v6"
SYNTHETIC_REQUIRED_CHALLENGE_KINDS = (
    "behavior_detectable_without_yara",
    "dead_code",
    "disconnected_flow",
    "documentation_only",
    "incomplete_operation_sequence",
    "strings_only_false_positive",
    "supported_static_behavior",
    "unreachable_behavior",
    "unresolved_dynamic_behavior",
    "unsupported_physically_present_behavior",
    "wrong_target_resource",
    "yara_corroborated_behavior",
)
_ALLOWED_CHALLENGE_KINDS = frozenset((*SYNTHETIC_REQUIRED_CHALLENGE_KINDS, "yara_only_control"))
_PARTITION_RANGES = (
    ("development", 0, 1_000),
    ("validation", 1_000, 2_000),
    ("locked_holdout", 2_000, 4_000),
    ("future_time_holdout", 4_000, 5_000),
)
SYNTHETIC_PARTITION_SCHEDULE = tuple(
    (partition, start, stop, *STATIC_SEMANTIC_PARTITION_BY_ID[partition])
    for partition, start, stop in _PARTITION_RANGES
)


@dataclass(frozen=True, slots=True)
class SyntheticAttackChallengePairDefinition:
    """Evaluation-only positive/control pairing; never a production evidence source."""

    challenge_id: str
    challenge_kinds: tuple[str, ...]
    positive_fixture: CorpusFixtureDefinition
    control_fixture: CorpusFixtureDefinition
    reviewed_yara_rule_name: str = ""

    def __post_init__(self) -> None:
        if type(self) is not SyntheticAttackChallengePairDefinition:
            raise TypeError("synthetic_challenge_pair_owner_invalid")
        challenge_id = exact_bounded_text(
            self.challenge_id, "synthetic_challenge_pair_id_invalid", maximum=128,
        )
        if (
            type(self.challenge_kinds) is not tuple
            or not self.challenge_kinds
            or any(type(item) is not str for item in self.challenge_kinds)
        ):
            raise TypeError("synthetic_challenge_pair_kinds_invalid")
        kinds = tuple(
            exact_bounded_text(item, "synthetic_challenge_pair_kind_invalid", maximum=64)
            for item in self.challenge_kinds
        )
        if kinds != tuple(sorted(set(kinds))) or any(item not in _ALLOWED_CHALLENGE_KINDS for item in kinds):
            raise ValueError("synthetic_challenge_pair_kinds_invalid")
        if (
            type(self.positive_fixture) is not CorpusFixtureDefinition
            or type(self.control_fixture) is not CorpusFixtureDefinition
        ):
            raise TypeError("synthetic_challenge_pair_fixture_invalid")
        if self.positive_fixture.generation_intent.malware_class != "malware":
            raise ValueError("synthetic_challenge_pair_positive_class_invalid")
        if self.control_fixture.generation_intent.malware_class != "control":
            raise ValueError("synthetic_challenge_pair_control_class_invalid")
        yara_rule = exact_bounded_text(
            self.reviewed_yara_rule_name,
            "synthetic_challenge_pair_yara_rule_invalid",
            maximum=192,
            allow_blank=True,
        )
        if "yara_corroborated_behavior" in kinds and not yara_rule:
            raise ValueError("synthetic_challenge_pair_yara_rule_required")
        if "yara_corroborated_behavior" not in kinds and yara_rule:
            raise ValueError("synthetic_challenge_pair_yara_rule_unexpected")
        object.__setattr__(self, "challenge_id", challenge_id)
        object.__setattr__(self, "challenge_kinds", kinds)
        object.__setattr__(self, "reviewed_yara_rule_name", yara_rule)

    def to_hidden_record(self) -> dict[str, object]:
        return {
            "challenge_id": self.challenge_id,
            "challenge_kinds": self.challenge_kinds,
            "control_generation_id": self.control_fixture.generation_intent.generation_id,
            "positive_generation_id": self.positive_fixture.generation_intent.generation_id,
            "reviewed_yara_rule_name": self.reviewed_yara_rule_name,
            "version": SYNTHETIC_CHALLENGE_PAIR_VERSION,
        }


def partition_for_index(index: int) -> tuple[str, str, str]:
    if type(index) is not int or type(index) is bool or index < 0:
        raise TypeError("synthetic_partition_index_invalid")
    for partition, start, stop, collected_at, seed in SYNTHETIC_PARTITION_SCHEDULE:
        if start <= index < stop:
            return partition, collected_at, seed
    raise ValueError("synthetic_partition_index_invalid")


__all__ = (
    "SYNTHETIC_CHALLENGE_PAIR_VERSION",
    "SYNTHETIC_CORPUS_SCHEMA_VERSION",
    "SYNTHETIC_ENGINEERING_DOMAIN",
    "SYNTHETIC_MASTER_SEED",
    "SYNTHETIC_METADATA_VERSION",
    "SYNTHETIC_ORACLE_VERSION",
    "SYNTHETIC_PARTITION_SCHEDULE",
    "SYNTHETIC_REQUIRED_CHALLENGE_KINDS",
    "SYNTHETIC_SAFETY_VERSION",
    "SyntheticAttackChallengePairDefinition",
    "partition_for_index",
)
