"""Public immutable Enterprise ATT&CK repository snapshot contract."""
from __future__ import annotations

from Virus_Scan.contracts.numeric_boundaries import exact_bounded_nonnegative_int
from Virus_Scan.contracts.text_boundaries import exact_bounded_text

from dataclasses import dataclass
from hashlib import sha256
import json
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.detection.attack.contracts import AttackDatasetVersion
from Virus_Scan.detection.attack.domain_contracts import (
    ATTACK_DOMAIN_OBJECT_TYPES, ATTACK_TECHNIQUE_TYPES, AttackRelationship,
    AttackSubTechnique, AttackTactic,
)
from Virus_Scan.detection.attack.requirements import build_attack_requirement_indexes
from Virus_Scan.detection.attack.versioning import ATTACK_DOMAIN_SCHEMA_VERSION


def _attack_id(item: object) -> str:
    return object.__getattribute__(item, "attack_id")


def _active(item: object) -> bool:
    return (
        object.__getattribute__(item, "revoked") is False
        and object.__getattribute__(item, "deprecated") is False
    )


def _digest(objects: tuple[object, ...], relationships: tuple[AttackRelationship, ...]) -> str:
    records = [item.to_record() for item in objects]
    records.extend(item.to_record() for item in relationships)
    payload = json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return sha256(payload).hexdigest()


def _freeze_exact_index(value: object, expected: dict[str, object], reason: str) -> Mapping[str, object]:
    if type(value) is not dict or len(value) != len(expected):
        raise TypeError(reason)
    out: dict[str, object] = {}
    for key, expected_value in dict.items(expected):
        key_text = exact_bounded_text(key, reason, maximum=128)
        if key_text not in value or dict.get(value, key_text) != expected_value:
            raise ValueError(reason)
        out[key_text] = expected_value
    return MappingProxyType(out)


@dataclass(frozen=True, slots=True)
class AttackRepositorySnapshot:
    version: AttackDatasetVersion
    digest: str
    tactics: tuple[AttackTactic, ...]
    techniques: tuple[object, ...]
    objects: tuple[object, ...]
    relationships: tuple[AttackRelationship, ...]
    by_attack_id: Mapping[str, object]
    by_stix_id: Mapping[str, object]
    by_tactic_id: Mapping[str, tuple[object, ...]]
    by_parent_technique_id: Mapping[str, tuple[AttackSubTechnique, ...]]
    source_relationships: Mapping[str, tuple[AttackRelationship, ...]]
    target_relationships: Mapping[str, tuple[AttackRelationship, ...]]
    data_component_by_attack_id: Mapping[str, object]
    data_component_by_stix_id: Mapping[str, object]
    analytic_by_attack_id: Mapping[str, object]
    analytic_by_stix_id: Mapping[str, object]
    strategy_by_attack_id: Mapping[str, object]
    strategy_by_stix_id: Mapping[str, object]
    analytics_by_strategy_id: Mapping[str, tuple[object, ...]]
    data_components_by_analytic_id: Mapping[str, tuple[object, ...]]
    strategies_by_technique_id: Mapping[str, tuple[object, ...]]
    techniques_by_strategy_id: Mapping[str, tuple[object, ...]]
    analytic_requirement_digest_by_id: Mapping[str, str]
    object_counts: Mapping[str, int]

    def __post_init__(self) -> None:
        if type(self) is not AttackRepositorySnapshot:
            raise TypeError("attack_repository_snapshot_owner_invalid")
        if type(self.version) is not AttackDatasetVersion:
            raise TypeError("attack_dataset_version_required")
        if type(self.objects) is not tuple or len(self.objects) > 16384 or any(type(item) not in ATTACK_DOMAIN_OBJECT_TYPES for item in self.objects):
            raise TypeError("attack_repository_objects_invalid")
        if type(self.relationships) is not tuple or len(self.relationships) > 65536 or any(type(item) is not AttackRelationship for item in self.relationships):
            raise TypeError("attack_repository_relationships_invalid")
        ordered_objects = tuple(sorted(self.objects, key=lambda item: (item.object_type, _attack_id(item), item.stix_id)))
        ordered_relationships = tuple(sorted(self.relationships, key=lambda item: item.stix_id))
        if self.objects != ordered_objects or self.relationships != ordered_relationships:
            raise ValueError("attack_repository_order_invalid")
        expected_tactics = tuple(item for item in ordered_objects if type(item) is AttackTactic)
        expected_techniques = tuple(item for item in ordered_objects if type(item) in ATTACK_TECHNIQUE_TYPES)
        if type(self.tactics) is not tuple or self.tactics != expected_tactics:
            raise ValueError("attack_repository_tactics_invalid")
        if type(self.techniques) is not tuple or self.techniques != expected_techniques:
            raise ValueError("attack_repository_techniques_invalid")
        expected_by_stix: dict[str, object] = {}
        expected_by_attack: dict[str, object] = {}
        technique_identities: set[str] = set()
        for item in ordered_objects:
            if item.stix_id in expected_by_stix:
                raise ValueError("attack_repository_duplicate_stix_identity")
            expected_by_stix[item.stix_id] = item
            attack_id = _attack_id(item)
            if type(item) in ATTACK_TECHNIQUE_TYPES:
                if attack_id in technique_identities:
                    raise ValueError("attack_repository_duplicate_attack_identity")
                technique_identities.add(attack_id)
            if attack_id and _active(item):
                if attack_id in expected_by_attack:
                    raise ValueError("attack_repository_duplicate_attack_identity")
                expected_by_attack[attack_id] = item
        expected_source: dict[str, list[AttackRelationship]] = {}
        expected_target: dict[str, list[AttackRelationship]] = {}
        relationship_ids: set[str] = set()
        for relation in ordered_relationships:
            if relation.stix_id in relationship_ids:
                raise ValueError("attack_repository_duplicate_relationship")
            relationship_ids.add(relation.stix_id)
            if relation.source_stix_id not in expected_by_stix or relation.target_stix_id not in expected_by_stix:
                raise ValueError("attack_repository_relationship_endpoint_missing")
            expected_source.setdefault(relation.source_stix_id, []).append(relation)
            expected_target.setdefault(relation.target_stix_id, []).append(relation)
        expected_by_tactic = {
            tactic.attack_id: tuple(
                item for item in expected_techniques
                if _active(item) and tactic.attack_id in item.tactic_ids
            )
            for tactic in expected_tactics if _active(tactic)
        }
        expected_by_parent: dict[str, tuple[AttackSubTechnique, ...]] = {}
        for item in expected_techniques:
            if type(item) is AttackSubTechnique and _active(item):
                parent = expected_by_attack.get(item.parent_attack_id)
                if type(parent) not in ATTACK_TECHNIQUE_TYPES:
                    raise ValueError("attack_repository_parent_technique_missing")
                expected_by_parent[item.parent_attack_id] = (*expected_by_parent.get(item.parent_attack_id, ()), item)
        object.__setattr__(self, "by_attack_id", _freeze_exact_index(self.by_attack_id, expected_by_attack, "attack_repository_attack_index_invalid"))
        object.__setattr__(self, "by_stix_id", _freeze_exact_index(self.by_stix_id, expected_by_stix, "attack_repository_stix_index_invalid"))
        object.__setattr__(self, "by_tactic_id", _freeze_exact_index(self.by_tactic_id, expected_by_tactic, "attack_repository_tactic_index_invalid"))
        object.__setattr__(self, "by_parent_technique_id", _freeze_exact_index(self.by_parent_technique_id, expected_by_parent, "attack_repository_parent_index_invalid"))
        object.__setattr__(self, "source_relationships", _freeze_exact_index(self.source_relationships, {key: tuple(value) for key, value in expected_source.items()}, "attack_repository_source_index_invalid"))
        object.__setattr__(self, "target_relationships", _freeze_exact_index(self.target_relationships, {key: tuple(value) for key, value in expected_target.items()}, "attack_repository_target_index_invalid"))
        requirements = build_attack_requirement_indexes(
            objects=ordered_objects, relationships=ordered_relationships,
        )
        requirement_indexes = (
            ("data_component_by_attack_id", requirements.data_component_by_attack_id, "attack_repository_data_component_attack_index_invalid"),
            ("data_component_by_stix_id", requirements.data_component_by_stix_id, "attack_repository_data_component_stix_index_invalid"),
            ("analytic_by_attack_id", requirements.analytic_by_attack_id, "attack_repository_analytic_attack_index_invalid"),
            ("analytic_by_stix_id", requirements.analytic_by_stix_id, "attack_repository_analytic_stix_index_invalid"),
            ("strategy_by_attack_id", requirements.strategy_by_attack_id, "attack_repository_strategy_attack_index_invalid"),
            ("strategy_by_stix_id", requirements.strategy_by_stix_id, "attack_repository_strategy_stix_index_invalid"),
            ("analytics_by_strategy_id", requirements.analytics_by_strategy_id, "attack_repository_strategy_analytics_index_invalid"),
            ("data_components_by_analytic_id", requirements.data_components_by_analytic_id, "attack_repository_analytic_components_index_invalid"),
            ("strategies_by_technique_id", requirements.strategies_by_technique_id, "attack_repository_technique_strategies_index_invalid"),
            ("techniques_by_strategy_id", requirements.techniques_by_strategy_id, "attack_repository_strategy_techniques_index_invalid"),
            ("analytic_requirement_digest_by_id", requirements.analytic_requirement_digest_by_id, "attack_repository_requirement_digest_index_invalid"),
        )
        for attribute, expected, reason in requirement_indexes:
            object.__setattr__(
                self,
                attribute,
                _freeze_exact_index(object.__getattribute__(self, attribute), expected, reason),
            )
        expected_counts: dict[str, int] = {}
        for item in ordered_objects:
            expected_counts[item.object_type] = expected_counts.get(item.object_type, 0) + 1
        expected_counts["relationship"] = len(ordered_relationships)
        if type(self.object_counts) is not dict or self.object_counts != expected_counts:
            raise ValueError("attack_repository_counts_invalid")
        object.__setattr__(self, "object_counts", MappingProxyType({key: exact_bounded_nonnegative_int(value, "attack_object_count_invalid", maximum=1_000_000) for key, value in expected_counts.items()}))
        digest = exact_bounded_text(self.digest, "attack_repository_digest_invalid", maximum=64)
        if digest != _digest(ordered_objects, ordered_relationships):
            raise ValueError("attack_repository_digest_invalid")
        object.__setattr__(self, "digest", digest)

    def to_record(self) -> dict[str, object]:
        return {
            "schema_version": ATTACK_DOMAIN_SCHEMA_VERSION,
            "dataset_version": self.version.dataset_version,
            "repository_digest": self.digest,
            "object_counts": dict(self.object_counts),
            "active_requirement_counts": {
                "data_components": len(self.data_component_by_attack_id),
                "analytics": len(self.analytic_by_attack_id),
                "detection_strategies": len(self.strategy_by_attack_id),
                "analytic_requirement_digests": len(self.analytic_requirement_digest_by_id),
            },
            "expected_git_blob_sha1": self.version.expected_git_blob_sha1,
            "computed_git_blob_sha1": self.version.computed_git_blob_sha1,
            "local_sha256": self.version.local_sha256,
            "source_ref": self.version.source_ref,
        }


__all__ = ("AttackRepositorySnapshot",)
