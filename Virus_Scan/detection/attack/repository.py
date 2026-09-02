"""Construction and deterministic lookup of immutable ATT&CK repositories."""
from __future__ import annotations

from hashlib import sha256
import json

from Virus_Scan.detection.api.attack_repository_contracts import AttackRepositorySnapshot
from Virus_Scan.detection.attack.contracts import AttackDatasetVersion
from Virus_Scan.detection.attack.domain_contracts import (
    ATTACK_DOMAIN_OBJECT_TYPES, ATTACK_TECHNIQUE_TYPES, AttackRelationship,
    AttackSubTechnique, AttackTactic,
)
from Virus_Scan.detection.attack.requirements import build_attack_requirement_indexes


def _canonical_digest(objects: tuple[object, ...], relationships: tuple[AttackRelationship, ...]) -> str:
    records = [item.to_record() for item in objects]
    records.extend(item.to_record() for item in relationships)
    payload = json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return sha256(payload).hexdigest()


def _attack_id(item: object) -> str:
    value = object.__getattribute__(item, "attack_id")
    return value if type(value) is str else ""


def _active(item: object) -> bool:
    return (
        object.__getattribute__(item, "revoked") is False
        and object.__getattribute__(item, "deprecated") is False
    )


def build_repository_snapshot(
    *,
    version: AttackDatasetVersion,
    objects: tuple[object, ...],
    relationships: tuple[AttackRelationship, ...],
) -> AttackRepositorySnapshot:
    if type(version) is not AttackDatasetVersion:
        raise TypeError("attack_dataset_version_required")
    if type(objects) is not tuple or type(relationships) is not tuple:
        raise TypeError("attack_repository_sequences_required")
    if any(type(item) not in ATTACK_DOMAIN_OBJECT_TYPES for item in objects):
        raise TypeError("attack_repository_object_invalid")
    if any(type(item) is not AttackRelationship for item in relationships):
        raise TypeError("attack_repository_relationship_invalid")
    by_stix: dict[str, object] = {}
    by_attack: dict[str, object] = {}
    technique_identities: set[str] = set()
    for item in sorted(objects, key=lambda record: (record.stix_id, _attack_id(record))):
        if item.stix_id in by_stix:
            raise ValueError("attack_repository_duplicate_stix_identity")
        by_stix[item.stix_id] = item
        attack_id = _attack_id(item)
        if type(item) in ATTACK_TECHNIQUE_TYPES:
            if attack_id in technique_identities:
                raise ValueError("attack_repository_duplicate_attack_identity")
            technique_identities.add(attack_id)
        if attack_id and _active(item):
            if attack_id in by_attack:
                raise ValueError("attack_repository_duplicate_attack_identity")
            by_attack[attack_id] = item
    for item in objects:
        if type(item) is AttackSubTechnique and _active(item) and item.parent_attack_id not in by_attack:
            raise ValueError("attack_repository_parent_technique_missing")
        if type(item) is AttackSubTechnique and _active(item) and type(by_attack[item.parent_attack_id]) not in ATTACK_TECHNIQUE_TYPES:
            raise ValueError("attack_repository_parent_technique_invalid")
    source: dict[str, list[AttackRelationship]] = {}
    target: dict[str, list[AttackRelationship]] = {}
    relation_ids: set[str] = set()
    for relationship in sorted(relationships, key=lambda item: item.stix_id):
        if relationship.stix_id in relation_ids:
            raise ValueError("attack_repository_duplicate_relationship")
        relation_ids.add(relationship.stix_id)
        if relationship.source_stix_id not in by_stix or relationship.target_stix_id not in by_stix:
            raise ValueError("attack_repository_relationship_endpoint_missing")
        source.setdefault(relationship.source_stix_id, []).append(relationship)
        target.setdefault(relationship.target_stix_id, []).append(relationship)
    ordered_objects = tuple(sorted(objects, key=lambda item: (item.object_type, _attack_id(item), item.stix_id)))
    ordered_relationships = tuple(sorted(relationships, key=lambda item: item.stix_id))
    tactics = tuple(item for item in ordered_objects if type(item) is AttackTactic)
    techniques = tuple(item for item in ordered_objects if type(item) in ATTACK_TECHNIQUE_TYPES)
    by_tactic: dict[str, tuple[object, ...]] = {}
    for tactic in tactics:
        if not _active(tactic):
            continue
        by_tactic[tactic.attack_id] = tuple(
            item for item in techniques
            if _active(item) and tactic.attack_id in item.tactic_ids
        )
    by_parent: dict[str, tuple[AttackSubTechnique, ...]] = {}
    for item in techniques:
        if type(item) is AttackSubTechnique and _active(item):
            by_parent.setdefault(item.parent_attack_id, ())
            by_parent[item.parent_attack_id] = (*by_parent[item.parent_attack_id], item)
    counts: dict[str, int] = {}
    for item in ordered_objects:
        counts[item.object_type] = counts.get(item.object_type, 0) + 1
    counts["relationship"] = len(ordered_relationships)
    requirements = build_attack_requirement_indexes(
        objects=ordered_objects, relationships=ordered_relationships,
    )
    return AttackRepositorySnapshot(
        version=version,
        digest=_canonical_digest(ordered_objects, ordered_relationships),
        tactics=tactics,
        techniques=techniques,
        objects=ordered_objects,
        relationships=ordered_relationships,
        by_attack_id=by_attack,
        by_stix_id=by_stix,
        by_tactic_id=by_tactic,
        by_parent_technique_id=by_parent,
        source_relationships={key: tuple(value) for key, value in source.items()},
        target_relationships={key: tuple(value) for key, value in target.items()},
        data_component_by_attack_id=requirements.data_component_by_attack_id,
        data_component_by_stix_id=requirements.data_component_by_stix_id,
        analytic_by_attack_id=requirements.analytic_by_attack_id,
        analytic_by_stix_id=requirements.analytic_by_stix_id,
        strategy_by_attack_id=requirements.strategy_by_attack_id,
        strategy_by_stix_id=requirements.strategy_by_stix_id,
        analytics_by_strategy_id=requirements.analytics_by_strategy_id,
        data_components_by_analytic_id=requirements.data_components_by_analytic_id,
        strategies_by_technique_id=requirements.strategies_by_technique_id,
        techniques_by_strategy_id=requirements.techniques_by_strategy_id,
        analytic_requirement_digest_by_id=requirements.analytic_requirement_digest_by_id,
        object_counts=counts,
    )


def technique_by_id(snapshot: AttackRepositorySnapshot, attack_id: str) -> object | None:
    if type(snapshot) is not AttackRepositorySnapshot or type(attack_id) is not str:
        return None
    matches = tuple(
        item for item in snapshot.techniques
        if object.__getattribute__(item, "attack_id") == attack_id
    )
    return matches[0] if len(matches) == 1 else None


def techniques_by_tactic(snapshot: AttackRepositorySnapshot, tactic_id: str) -> tuple[object, ...]:
    if type(snapshot) is not AttackRepositorySnapshot or type(tactic_id) is not str:
        return ()
    return snapshot.by_tactic_id.get(tactic_id, ())


def subtechniques_by_parent(snapshot: AttackRepositorySnapshot, technique_id: str) -> tuple[AttackSubTechnique, ...]:
    if type(snapshot) is not AttackRepositorySnapshot or type(technique_id) is not str:
        return ()
    return snapshot.by_parent_technique_id.get(technique_id, ())


__all__ = (
    "build_repository_snapshot", "subtechniques_by_parent", "technique_by_id",
    "techniques_by_tactic",
)
