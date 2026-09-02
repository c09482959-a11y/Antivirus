"""Canonical provenance and reviewed YARA projection for attack intelligence."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.tag_evidence import active_tag_evidence_records
from Virus_Scan.contracts.tag_taxonomy import TAG_CLASS_ATOMIC_OBSERVATION
from Virus_Scan.detection.registries.tag_taxonomy_registry import tag_class_for
from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.contracts.yara_hits import (
    YaraHit, YaraScanResult, canonical_yara_scan_result,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence

_DIRECT_KINDS = frozenset({"observed", "normalized"})
_INFERRED_KINDS = frozenset({"derived", "composite"})
_MAX_FAMILY_ALIGNMENTS = 512


@dataclass(frozen=True, slots=True)
class AttackIntelligenceYaraFamilyAlignment:
    """Reviewed exact-rule interpretation owned outside the physical hit."""

    family: str
    package_kind: str
    rule_source_digest: str
    rule_catalog_digest: str
    source_member: str
    compiler_namespace: str
    rule_name: str
    metadata_id: str
    logic_hash: str
    interpretation_provenance: str

    def __post_init__(self) -> None:
        if type(self) is not AttackIntelligenceYaraFamilyAlignment:
            raise TypeError("attack_yara_alignment_owner_invalid")
        for name, maximum, blank in (
            ("family", 128, False),
            ("package_kind", 32, False),
            ("rule_source_digest", 64, False),
            ("rule_catalog_digest", 64, False),
            ("source_member", 4096, False),
            ("compiler_namespace", 160, False),
            ("rule_name", 160, False),
            ("metadata_id", 160, True),
            ("logic_hash", 64, False),
            ("interpretation_provenance", 1024, False),
        ):
            value = exact_bounded_text(
                object.__getattribute__(self, name),
                "attack_yara_alignment_" + name + "_invalid",
                maximum=maximum,
                allow_blank=blank,
            )
            object.__setattr__(self, name, value)
        for name in ("rule_source_digest", "rule_catalog_digest", "logic_hash"):
            value = object.__getattribute__(self, name)
            if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError("attack_yara_alignment_digest_invalid")

    @property
    def rule_key(self) -> tuple[str, ...]:
        return (
            self.package_kind,
            self.rule_source_digest,
            self.rule_catalog_digest,
            self.source_member,
            self.compiler_namespace,
            self.rule_name,
            self.metadata_id,
            self.logic_hash,
        )


ATTACK_INTELLIGENCE_YARA_ALIGNMENTS: tuple[AttackIntelligenceYaraFamilyAlignment, ...] = ()


def classifier_root_profile(
    tag_evidence: TagEvidence,
    root_ids: tuple[str, ...],
    allowed_evidence_kinds: frozenset[str],
) -> dict[str, object]:
    wanted = frozenset(root_ids)
    records = tuple(
        record for record in active_tag_evidence_records(tag_evidence.records)
        if record.root_observation_id in wanted
        and record.polarity == "positive"
        and record.evidence_kind in allowed_evidence_kinds
        and tag_class_for(record.canonical_tag_id) == TAG_CLASS_ATOMIC_OBSERVATION
    )
    direct_roots = frozenset(
        record.root_observation_id for record in records if record.evidence_kind in _DIRECT_KINDS
    )
    inferred_roots = frozenset(
        record.root_observation_id for record in records
        if record.evidence_kind in _INFERRED_KINDS and record.root_observation_id not in direct_roots
    )
    return {
        "root_ids": tuple(sorted({record.root_observation_id for record in records if record.root_observation_id}))[:64],
        "canonical_tags": tuple(sorted({record.canonical_tag_id for record in records if record.canonical_tag_id}))[:64],
        "correlation_groups": tuple(sorted({record.correlation_group for record in records if record.correlation_group}))[:64],
        "direct_root_count": len(direct_roots),
        "inferred_root_count": len(inferred_roots),
    }


def attack_yara_evidence(value: object) -> tuple[tuple[YaraHit, ...], str]:
    if value is None or (type(value) is tuple and not value):
        return (), "unavailable"
    if type(value) not in (YaraScanResult, dict):
        return (), "yara_input_rejected"
    result = canonical_yara_scan_result(value)
    if result.status in ("complete", "complete_no_match"):
        if result.hits and result.verified:
            return result.hits, "verified"
        if result.hits:
            return result.hits, "present_unverified"
        return (), "complete_no_match"
    if result.status in ("partial", "truncated"):
        return result.hits, result.status
    return (), result.status


def yara_for_family(
    records: tuple[YaraHit, ...],
    family: str,
    *,
    alignments: tuple[AttackIntelligenceYaraFamilyAlignment, ...] = ATTACK_INTELLIGENCE_YARA_ALIGNMENTS,
) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    if type(alignments) is not tuple or len(alignments) > _MAX_FAMILY_ALIGNMENTS or any(
        type(item) is not AttackIntelligenceYaraFamilyAlignment for item in alignments
    ):
        raise TypeError("attack_yara_alignment_registry_invalid")
    by_key = {item.rule_key: item for item in alignments if item.family == family}
    matched = tuple(
        record for record in records
        if record.verified
        and record.rule_identity.mapping_eligible
        and (
            record.rule_identity.package_kind,
            record.rule_identity.rule_source_digest,
            record.rule_identity.rule_catalog_digest,
            record.rule_identity.source_member,
            record.rule_identity.compiler_namespace,
            record.rule_identity.rule_name,
            record.rule_identity.metadata_id,
            record.rule_identity.logic_hash,
        ) in by_key
    )
    if matched:
        return (
            tuple(sorted({record.rule_identity.rule_name for record in matched})),
            tuple(sorted({record.root_observation_id for record in matched})),
            "verified_corroborating",
        )
    if any(record.verified for record in records):
        return (), (), "verified_conflicting_or_rejected"
    if records:
        return (), (), "present_unverified"
    return (), (), "unavailable"


__all__ = (
    "ATTACK_INTELLIGENCE_YARA_ALIGNMENTS",
    "AttackIntelligenceYaraFamilyAlignment",
    "attack_yara_evidence",
    "classifier_root_profile",
    "yara_for_family",
)
