"""Canonical immutable ATT&CK defensive requirement-graph derivation."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

from Virus_Scan.detection.attack.domain_contracts import (
    ATTACK_DOMAIN_OBJECT_TYPES,
    ATTACK_TECHNIQUE_TYPES,
    AttackRelationship,
)
from Virus_Scan.detection.attack.named_contracts import (
    AttackAnalytic,
    AttackDataComponent,
    AttackDetectionStrategy,
)


@dataclass(frozen=True, slots=True)
class AttackRequirementIndexes:
    data_component_by_attack_id: dict[str, AttackDataComponent]
    data_component_by_stix_id: dict[str, AttackDataComponent]
    analytic_by_attack_id: dict[str, AttackAnalytic]
    analytic_by_stix_id: dict[str, AttackAnalytic]
    strategy_by_attack_id: dict[str, AttackDetectionStrategy]
    strategy_by_stix_id: dict[str, AttackDetectionStrategy]
    analytics_by_strategy_id: dict[str, tuple[AttackAnalytic, ...]]
    data_components_by_analytic_id: dict[str, tuple[AttackDataComponent, ...]]
    strategies_by_technique_id: dict[str, tuple[AttackDetectionStrategy, ...]]
    techniques_by_strategy_id: dict[str, tuple[object, ...]]
    analytic_requirement_digest_by_id: dict[str, str]


def _active(value: object) -> bool:
    return (
        object.__getattribute__(value, "revoked") is False
        and object.__getattribute__(value, "deprecated") is False
    )


def _active_enterprise(value: object) -> bool:
    return _active(value) and "enterprise-attack" in object.__getattribute__(value, "domains")


def _index_exact(
    values: tuple[object, ...],
    owner: type,
) -> tuple[dict[str, object], dict[str, object]]:
    by_attack: dict[str, object] = {}
    by_stix: dict[str, object] = {}
    for value in values:
        if type(value) is not owner or not _active_enterprise(value):
            continue
        attack_id = object.__getattribute__(value, "attack_id")
        stix_identity = object.__getattribute__(value, "stix_id")
        if attack_id in by_attack or stix_identity in by_stix:
            raise ValueError("attack_requirement_identity_duplicate")
        by_attack[attack_id] = value
        by_stix[stix_identity] = value
    return by_attack, by_stix


def _requirement_digest(
    analytic: AttackAnalytic,
    components: tuple[AttackDataComponent, ...],
    bindings: tuple[tuple[AttackDetectionStrategy, object], ...],
) -> str:
    record = {
        "analytic_id": analytic.attack_id,
        "analytic_stix_id": analytic.stix_id,
        "platforms": analytic.platforms,
        "domains": analytic.domains,
        "log_source_requirements": tuple(
            reference.to_record() for reference in analytic.log_source_references
        ),
        "mutable_elements": tuple(
            element.to_record() for element in analytic.mutable_elements
        ),
        "analytic_object_version": analytic.object_version,
        "analytic_attack_spec_version": analytic.attack_spec_version,
        "analytic_lifecycle": {
            "revoked": analytic.revoked,
            "deprecated": analytic.deprecated,
        },
        "data_components": tuple({
            "attack_id": component.attack_id,
            "stix_id": component.stix_id,
            "domains": component.domains,
            "log_sources": tuple(source.to_record() for source in component.log_sources),
            "object_version": component.object_version,
            "attack_spec_version": component.attack_spec_version,
            "lifecycle": {
                "revoked": component.revoked,
                "deprecated": component.deprecated,
            },
        } for component in components),
        "bindings": tuple({
            "strategy_id": strategy.attack_id,
            "strategy_stix_id": strategy.stix_id,
            "technique_id": object.__getattribute__(technique, "attack_id"),
            "strategy_domains": strategy.domains,
            "strategy_object_version": strategy.object_version,
            "strategy_attack_spec_version": strategy.attack_spec_version,
            "strategy_lifecycle": {
                "revoked": strategy.revoked,
                "deprecated": strategy.deprecated,
            },
            "technique_lifecycle": {
                "revoked": object.__getattribute__(technique, "revoked"),
                "deprecated": object.__getattribute__(technique, "deprecated"),
            },
        } for strategy, technique in bindings),
    }
    payload = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def build_attack_requirement_indexes(
    *,
    objects: tuple[object, ...],
    relationships: tuple[AttackRelationship, ...],
) -> AttackRequirementIndexes:
    """Derive and validate the active Enterprise Strategy/Analytic graph."""
    if type(objects) is not tuple or type(relationships) is not tuple:
        raise TypeError("attack_requirement_sequences_invalid")
    if any(type(value) not in ATTACK_DOMAIN_OBJECT_TYPES for value in objects):
        raise TypeError("attack_requirement_object_invalid")
    if any(type(value) is not AttackRelationship for value in relationships):
        raise TypeError("attack_requirement_relationship_invalid")
    object_by_stix: dict[str, object] = {}
    for value in objects:
        identity = object.__getattribute__(value, "stix_id")
        if identity in object_by_stix:
            raise ValueError("attack_requirement_stix_identity_duplicate")
        object_by_stix[identity] = value

    component_attack, component_stix = _index_exact(objects, AttackDataComponent)
    analytic_attack, analytic_stix = _index_exact(objects, AttackAnalytic)
    strategy_attack, strategy_stix = _index_exact(objects, AttackDetectionStrategy)

    analytics_by_strategy: dict[str, tuple[AttackAnalytic, ...]] = {}
    strategies_by_analytic: dict[str, list[AttackDetectionStrategy]] = {}
    for strategy_id, strategy in sorted(strategy_attack.items()):
        analytics: list[AttackAnalytic] = []
        for analytic_stix_id in strategy.analytic_stix_ids:
            analytic = analytic_stix.get(analytic_stix_id)
            if type(analytic) is not AttackAnalytic:
                raise ValueError("attack_requirement_strategy_analytic_missing")
            analytics.append(analytic)
            strategies_by_analytic.setdefault(analytic.attack_id, []).append(strategy)
        analytics_by_strategy[strategy_id] = tuple(sorted(
            analytics,
            key=lambda value: (value.attack_id, value.stix_id),
        ))

    components_by_analytic: dict[str, tuple[AttackDataComponent, ...]] = {}
    for analytic_id, analytic in sorted(analytic_attack.items()):
        components: list[AttackDataComponent] = []
        for reference in analytic.log_source_references:
            component = component_stix.get(reference.data_component_stix_id)
            if type(component) is not AttackDataComponent:
                raise ValueError("attack_requirement_analytic_component_missing")
            components.append(component)
        unique_components = {
            component.attack_id: component for component in components
        }
        components_by_analytic[analytic_id] = tuple(
            unique_components[key] for key in sorted(unique_components)
        )

    strategy_targets: dict[str, list[object]] = {
        strategy_id: [] for strategy_id in strategy_attack
    }
    for relationship in relationships:
        if relationship.relationship_type != "detects" or relationship.revoked:
            continue
        source = object_by_stix.get(relationship.source_stix_id)
        target = object_by_stix.get(relationship.target_stix_id)
        if type(source) is not AttackDetectionStrategy or type(target) not in ATTACK_TECHNIQUE_TYPES:
            raise ValueError("attack_requirement_detects_direction_invalid")
        if not _active_enterprise(source) or not _active(target):
            raise ValueError("attack_requirement_detects_endpoint_inactive")
        if source.attack_id not in strategy_targets:
            raise ValueError("attack_requirement_detects_strategy_inactive")
        strategy_targets[source.attack_id].append(target)

    techniques_by_strategy: dict[str, tuple[object, ...]] = {}
    strategies_by_technique_lists: dict[str, list[AttackDetectionStrategy]] = {}
    for strategy_id, targets in sorted(strategy_targets.items()):
        unique_targets = {
            object.__getattribute__(target, "attack_id"): target for target in targets
        }
        if len(unique_targets) != 1:
            raise ValueError("attack_requirement_strategy_detects_cardinality_invalid")
        target_tuple = tuple(unique_targets[key] for key in sorted(unique_targets))
        techniques_by_strategy[strategy_id] = target_tuple
        technique_id = object.__getattribute__(target_tuple[0], "attack_id")
        strategies_by_technique_lists.setdefault(technique_id, []).append(
            strategy_attack[strategy_id]
        )

    strategies_by_technique = {
        technique_id: tuple(sorted(
            strategies,
            key=lambda value: (value.attack_id, value.stix_id),
        ))
        for technique_id, strategies in sorted(strategies_by_technique_lists.items())
    }

    digests: dict[str, str] = {}
    for analytic_id, analytic in sorted(analytic_attack.items()):
        bindings: list[tuple[AttackDetectionStrategy, object]] = []
        for strategy in strategies_by_analytic.get(analytic_id, []):
            for technique in techniques_by_strategy[strategy.attack_id]:
                bindings.append((strategy, technique))
        ordered_bindings = tuple(sorted(
            bindings,
            key=lambda value: (
                value[0].attack_id,
                object.__getattribute__(value[1], "attack_id"),
            ),
        ))
        digests[analytic_id] = _requirement_digest(
            analytic,
            components_by_analytic[analytic_id],
            ordered_bindings,
        )

    return AttackRequirementIndexes(
        data_component_by_attack_id=dict(component_attack),
        data_component_by_stix_id=dict(component_stix),
        analytic_by_attack_id=dict(analytic_attack),
        analytic_by_stix_id=dict(analytic_stix),
        strategy_by_attack_id=dict(strategy_attack),
        strategy_by_stix_id=dict(strategy_stix),
        analytics_by_strategy_id=analytics_by_strategy,
        data_components_by_analytic_id=components_by_analytic,
        strategies_by_technique_id=strategies_by_technique,
        techniques_by_strategy_id=techniques_by_strategy,
        analytic_requirement_digest_by_id=digests,
    )


__all__ = ("AttackRequirementIndexes", "build_attack_requirement_indexes")
