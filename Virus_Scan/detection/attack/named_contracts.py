"""Frozen ATT&CK defensive-object contracts for the current STIX schema."""
from __future__ import annotations

from Virus_Scan.contracts.text_boundaries import exact_bounded_text

from dataclasses import dataclass

from Virus_Scan.detection.attack.validation import (
    exact_bool,
    official_attack_id,
    ordered_text_tuple,
    stix_id,
    stix_timestamp,
    version_text,
)


def _defensive_attack_id(value: object, prefix: str, reason: str) -> str:
    attack_id = official_attack_id(value, reason)
    if not attack_id.startswith(prefix):
        raise ValueError(reason)
    return attack_id


def _validate_named(value: object, owner: type, expected_type: str) -> None:
    if type(value) is not owner:
        raise TypeError("attack_named_object_owner_invalid")
    object.__setattr__(value, "stix_id", stix_id(value.stix_id))
    object_type = exact_bounded_text(value.object_type, "attack_named_object_type_invalid", maximum=64)
    if object_type != expected_type:
        raise ValueError("attack_named_object_type_invalid")
    object.__setattr__(value, "object_type", object_type)
    object.__setattr__(value, "name", exact_bounded_text(value.name, "attack_object_name_invalid", maximum=256))
    object.__setattr__(value, "description", exact_bounded_text(
        value.description,
        "attack_object_description_invalid",
        maximum=16384,
        allow_blank=True,
    ))
    object.__setattr__(value, "revoked", exact_bool(value.revoked, "attack_object_revoked_invalid"))
    object.__setattr__(value, "deprecated", exact_bool(value.deprecated, "attack_object_deprecated_invalid"))


def _validate_versioned(value: object) -> None:
    object.__setattr__(value, "domains", ordered_text_tuple(
        value.domains,
        "attack_object_domains_invalid",
        maximum_items=8,
    ))
    object.__setattr__(value, "object_version", version_text(
        value.object_version,
        "attack_object_version_invalid",
    ))
    object.__setattr__(value, "attack_spec_version", version_text(
        value.attack_spec_version,
        "attack_spec_version_invalid",
    ))
    object.__setattr__(value, "modified", stix_timestamp(value.modified))


def _ordered_owner_tuple(
    value: object,
    owner: type,
    reason: str,
    *,
    maximum_items: int,
    key,
) -> tuple[object, ...]:
    if type(value) is not tuple or len(value) > maximum_items:
        raise TypeError(reason)
    if any(type(item) is not owner for item in value):
        raise TypeError(reason)
    ordered = tuple(sorted(value, key=key))
    if value != ordered or len(value) != len(set(value)):
        raise ValueError(reason)
    return value


@dataclass(frozen=True, slots=True, order=True)
class AttackLogSource:
    name: str
    channel: str

    def __post_init__(self) -> None:
        if type(self) is not AttackLogSource:
            raise TypeError("attack_log_source_owner_invalid")
        object.__setattr__(self, "name", exact_bounded_text(
            self.name,
            "attack_log_source_name_invalid",
            maximum=256,
        ))
        object.__setattr__(self, "channel", exact_bounded_text(
            self.channel,
            "attack_log_source_channel_invalid",
            maximum=2048,
        ))

    def to_record(self) -> dict[str, str]:
        return {"name": self.name, "channel": self.channel}


@dataclass(frozen=True, slots=True, order=True)
class AttackLogSourceReference:
    data_component_stix_id: str
    name: str
    channel: str

    def __post_init__(self) -> None:
        if type(self) is not AttackLogSourceReference:
            raise TypeError("attack_log_source_reference_owner_invalid")
        component = stix_id(
            self.data_component_stix_id,
            "attack_log_source_component_invalid",
        )
        if not component.startswith("x-mitre-data-component--"):
            raise ValueError("attack_log_source_component_invalid")
        object.__setattr__(self, "data_component_stix_id", component)
        object.__setattr__(self, "name", exact_bounded_text(
            self.name,
            "attack_log_source_reference_name_invalid",
            maximum=256,
        ))
        object.__setattr__(self, "channel", exact_bounded_text(
            self.channel,
            "attack_log_source_reference_channel_invalid",
            maximum=2048,
        ))

    def to_record(self) -> dict[str, str]:
        return {
            "data_component_stix_id": self.data_component_stix_id,
            "name": self.name,
            "channel": self.channel,
        }


@dataclass(frozen=True, slots=True, order=True)
class AttackMutableElement:
    field: str
    description: str

    def __post_init__(self) -> None:
        if type(self) is not AttackMutableElement:
            raise TypeError("attack_mutable_element_owner_invalid")
        object.__setattr__(self, "field", exact_bounded_text(
            self.field,
            "attack_mutable_element_field_invalid",
            maximum=256,
        ))
        object.__setattr__(self, "description", exact_bounded_text(
            self.description,
            "attack_mutable_element_description_invalid",
            maximum=4096,
        ))

    def to_record(self) -> dict[str, str]:
        return {"field": self.field, "description": self.description}


def _base_record(value: object) -> dict[str, object]:
    return {
        "attack_id": value.attack_id,
        "stix_id": value.stix_id,
        "object_type": value.object_type,
        "name": value.name,
        "description": value.description,
        "domains": value.domains,
        "object_version": value.object_version,
        "attack_spec_version": value.attack_spec_version,
        "modified": value.modified,
        "revoked": value.revoked,
        "deprecated": value.deprecated,
    }


@dataclass(frozen=True, slots=True)
class AttackDataSource:
    attack_id: str
    stix_id: str
    name: str
    description: str
    domains: tuple[str, ...]
    platforms: tuple[str, ...]
    object_version: str
    attack_spec_version: str
    modified: str
    revoked: bool = False
    deprecated: bool = False
    object_type: str = "x-mitre-data-source"

    def __post_init__(self) -> None:
        _validate_named(self, AttackDataSource, "x-mitre-data-source")
        object.__setattr__(self, "attack_id", _defensive_attack_id(
            self.attack_id,
            "DS",
            "attack_data_source_id_invalid",
        ))
        _validate_versioned(self)
        object.__setattr__(self, "platforms", ordered_text_tuple(
            self.platforms,
            "attack_object_platforms_invalid",
            maximum_items=64,
        ))

    def to_record(self) -> dict[str, object]:
        return {**_base_record(self), "platforms": self.platforms}


@dataclass(frozen=True, slots=True)
class AttackDataComponent:
    attack_id: str
    stix_id: str
    name: str
    description: str
    domains: tuple[str, ...]
    log_sources: tuple[AttackLogSource, ...]
    object_version: str
    attack_spec_version: str
    modified: str
    revoked: bool = False
    deprecated: bool = False
    object_type: str = "x-mitre-data-component"

    def __post_init__(self) -> None:
        _validate_named(self, AttackDataComponent, "x-mitre-data-component")
        object.__setattr__(self, "attack_id", _defensive_attack_id(
            self.attack_id,
            "DC",
            "attack_data_component_id_invalid",
        ))
        _validate_versioned(self)
        object.__setattr__(self, "log_sources", _ordered_owner_tuple(
            self.log_sources,
            AttackLogSource,
            "attack_data_component_log_sources_invalid",
            maximum_items=512,
            key=lambda item: (item.name, item.channel),
        ))

    def to_record(self) -> dict[str, object]:
        return {
            **_base_record(self),
            "log_sources": tuple(item.to_record() for item in self.log_sources),
        }


@dataclass(frozen=True, slots=True)
class AttackAnalytic:
    attack_id: str
    stix_id: str
    name: str
    description: str
    platforms: tuple[str, ...]
    domains: tuple[str, ...]
    log_source_references: tuple[AttackLogSourceReference, ...]
    mutable_elements: tuple[AttackMutableElement, ...]
    object_version: str
    attack_spec_version: str
    modified: str
    revoked: bool = False
    deprecated: bool = False
    object_type: str = "x-mitre-analytic"

    def __post_init__(self) -> None:
        _validate_named(self, AttackAnalytic, "x-mitre-analytic")
        object.__setattr__(self, "attack_id", _defensive_attack_id(
            self.attack_id,
            "AN",
            "attack_analytic_id_invalid",
        ))
        _validate_versioned(self)
        object.__setattr__(self, "platforms", ordered_text_tuple(
            self.platforms,
            "attack_object_platforms_invalid",
            maximum_items=64,
        ))
        object.__setattr__(self, "log_source_references", _ordered_owner_tuple(
            self.log_source_references,
            AttackLogSourceReference,
            "attack_analytic_log_source_references_invalid",
            maximum_items=256,
            key=lambda item: (
                item.data_component_stix_id,
                item.name,
                item.channel,
            ),
        ))
        object.__setattr__(self, "mutable_elements", _ordered_owner_tuple(
            self.mutable_elements,
            AttackMutableElement,
            "attack_analytic_mutable_elements_invalid",
            maximum_items=128,
            key=lambda item: (item.field, item.description),
        ))

    def to_record(self) -> dict[str, object]:
        return {
            **_base_record(self),
            "platforms": self.platforms,
            "log_source_references": tuple(
                item.to_record() for item in self.log_source_references
            ),
            "mutable_elements": tuple(
                item.to_record() for item in self.mutable_elements
            ),
        }


@dataclass(frozen=True, slots=True)
class AttackDetectionStrategy:
    attack_id: str
    stix_id: str
    name: str
    description: str
    domains: tuple[str, ...]
    analytic_stix_ids: tuple[str, ...]
    object_version: str
    attack_spec_version: str
    modified: str
    revoked: bool = False
    deprecated: bool = False
    object_type: str = "x-mitre-detection-strategy"

    def __post_init__(self) -> None:
        _validate_named(self, AttackDetectionStrategy, "x-mitre-detection-strategy")
        object.__setattr__(self, "attack_id", _defensive_attack_id(
            self.attack_id,
            "DET",
            "attack_detection_strategy_id_invalid",
        ))
        _validate_versioned(self)
        analytic_ids = ordered_text_tuple(
            self.analytic_stix_ids,
            "attack_detection_strategy_analytics_invalid",
            maximum_items=128,
        )
        if any(
            not stix_id(
                item,
                "attack_detection_strategy_analytic_invalid",
            ).startswith("x-mitre-analytic--")
            for item in analytic_ids
        ):
            raise ValueError("attack_detection_strategy_analytic_invalid")
        object.__setattr__(self, "analytic_stix_ids", analytic_ids)

    def to_record(self) -> dict[str, object]:
        return {**_base_record(self), "analytic_stix_ids": self.analytic_stix_ids}


ATTACK_STIX_ONLY_OBJECT_TYPES = (
    AttackDataSource,
    AttackDataComponent,
    AttackAnalytic,
    AttackDetectionStrategy,
)

__all__ = (
    "ATTACK_STIX_ONLY_OBJECT_TYPES",
    "AttackAnalytic",
    "AttackDataComponent",
    "AttackDataSource",
    "AttackDetectionStrategy",
    "AttackLogSource",
    "AttackLogSourceReference",
    "AttackMutableElement",
)
