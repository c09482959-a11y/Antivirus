"""Immutable bounded registry snapshot composition for detection."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_module_dict_status,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.detection.registries.immutability import freeze_registry_value
from Virus_Scan.detection.registries import chain_gate_registry_defaults as chain_gate
from Virus_Scan.detection.registries import chain_registry_defaults as chain_defaults
from Virus_Scan.detection.registries import constants_defaults
from Virus_Scan.detection.registries import runtime_profile_registry_defaults as runtime_profile
from Virus_Scan.detection.scoring.registries import scoring_registry_defaults as scoring_defaults
from Virus_Scan.detection.registries import tag_behavior_registry_defaults as tag_behavior
from Virus_Scan.detection.registries.domain_snapshots import (
    ChainRegistrySnapshot,
    DetectionConstantsSnapshot,
    EngineRegistrySnapshot,
    ExplainabilityRegistrySnapshot,
    ProfileRegistrySnapshot,
    ScoringRegistrySnapshot,
    TagRegistrySnapshot,
)


@dataclass(frozen=True)
class DetectionModuleRegistryUnavailable:
    """Typed evidence that a registry module dictionary could not be read."""

    reason: str
    value_type: str

    def as_mapping(self) -> MappingProxyType:
        return freeze_registry_value({
            "detection_registry_unavailable": True,
            "reason": self.reason,
            "value_type": self.value_type,
            "detection_contract": "registry_snapshot",
            "replay_must_record": True,
        })


def _module_registry_unavailable(reason: str, value: object) -> tuple[tuple[object, object], ...]:
    unavailable = DetectionModuleRegistryUnavailable(reason=reason, value_type=no_hook_type_name(value))
    return (("DETECTION_REGISTRY_UNAVAILABLE", unavailable.as_mapping()),)


def _registry_key_text(name: object) -> str:
    text, reason = no_hook_text(
        name,
        missing_reason="missing_detection_registry_name",
        unsupported_reason="unsafe_detection_registry_name_rejected",
    )
    if reason:
        return ""
    return text


def _module_registry_items(module: object) -> tuple[tuple[object, object], ...]:
    module_dict, reason = no_hook_module_dict_status(module)
    if module_dict is None:
        if reason == "module_not_exact_module":
            return ()
        return _module_registry_unavailable(reason, module)
    items = no_hook_mapping_items(module_dict)
    if items is None:
        return _module_registry_unavailable("module_dict_items_unavailable", module)
    return items


def _registry_mapping_items(group: object) -> tuple[tuple[object, object], ...]:
    items = no_hook_mapping_items(group)
    if items is None:
        return ()
    return items


def _public_registry_items(module: object) -> MappingProxyType:
    items: dict[str, object] = {}
    for name, value in _module_registry_items(module):
        if type(name) is not str:
            continue
        registry_name = name.isupper() or (name.startswith("_") and name[1:].isupper())
        if registry_name and not name.endswith("DEFAULTS"):
            items[name] = freeze_registry_value(value)
    return freeze_registry_value(items)


def _merge_registry_values(*groups: Mapping[str, object]) -> MappingProxyType:
    merged: dict[str, object] = {}
    for group in groups:
        for name, value in _registry_mapping_items(group):
            key = _registry_key_text(name)
            if key:
                merged[key] = freeze_registry_value(value)
    tag_zero = merged.get("TAG_RISK_SCORE_ZERO_TAGS", frozenset())
    tag_overrides = merged.get("TAG_RISK_SCORE_OVERRIDES", MappingProxyType({}))
    tag_scores = dict(merged.get("TAG_RISK_SCORES", MappingProxyType({})))
    for tag in tag_zero:
        tag_scores[str(tag)] = 0.0
    tag_scores.update(dict(tag_overrides))
    merged["TAG_RISK_SCORES"] = freeze_registry_value(tag_scores)
    structural_weak = frozenset(merged.get("HIGH_GATE_WEAK_OR_STRUCTURAL_TAGS", frozenset()))
    renpy_failsafe = frozenset(merged.get("RENPY_FAILSAFE_ONLY_TAGS", frozenset()))
    merged["STRUCTURAL_NOISE_TAGS"] = freeze_registry_value(
        structural_weak | renpy_failsafe | {"binary_failover_scan", "scan_failsafe_applied", "unknown_binary_blob"}
    )
    return freeze_registry_value(merged)


@dataclass(frozen=True)
class DetectionRegistrySnapshot:
    chain_registry: ChainRegistrySnapshot
    tag_registry: TagRegistrySnapshot
    scoring_registry: ScoringRegistrySnapshot
    profile_registry: ProfileRegistrySnapshot
    engine_registry: EngineRegistrySnapshot
    explainability_registry: ExplainabilityRegistrySnapshot
    constants_registry: DetectionConstantsSnapshot

    @property
    def domain_snapshots(self) -> tuple[object, ...]:
        return (
            self.chain_registry,
            self.tag_registry,
            self.scoring_registry,
            self.profile_registry,
            self.engine_registry,
            self.explainability_registry,
            self.constants_registry,
        )

    def value(self, name: str, default: object = None) -> object:
        key = str(name)
        for snapshot in self.domain_snapshots:
            if key in snapshot.values:
                return snapshot.values[key]
        return freeze_registry_value(default)

    def publication_items(self) -> tuple[tuple[str, object], ...]:
        merged: dict[str, object] = {}
        for snapshot in self.domain_snapshots:
            for name, value in snapshot.publication_items():
                merged[str(name)] = freeze_registry_value(value)
        return tuple((str(name), merged[name]) for name in sorted(merged))


def _engine_values(scoring_values: Mapping[str, object]) -> MappingProxyType:
    return freeze_registry_value({
        "ENGINE_EXTENSION_BUCKET_POLICIES": scoring_values.get("ENGINE_EXTENSION_BUCKET_POLICIES", MappingProxyType({})),
        "GLOBAL_COMMON_FILETYPE_BUCKETS": scoring_values.get("GLOBAL_COMMON_FILETYPE_BUCKETS", MappingProxyType({})),
        "ENGINE_SPECIFIC_FILETYPE_BUCKETS": scoring_values.get("ENGINE_SPECIFIC_FILETYPE_BUCKETS", MappingProxyType({})),
    })


def _explainability_values(constants_values: Mapping[str, object]) -> MappingProxyType:
    return freeze_registry_value({
        "QUALITY_GATE_VERSION": constants_values.get("QUALITY_GATE_VERSION"),
        "TAG_REPORTING_CANONICAL_NAMES": constants_values.get("TAG_REPORTING_CANONICAL_NAMES", MappingProxyType({})),
        "CONFIRMED_API_HINTS": constants_values.get("CONFIRMED_API_HINTS", frozenset()),
    })


def _constants_values(chain_values: Mapping[str, object], profile_values: Mapping[str, object]) -> MappingProxyType:
    base_constants = _public_registry_items(constants_defaults)
    structural_noise = freeze_registry_value(
        frozenset(chain_values.get("HIGH_GATE_WEAK_OR_STRUCTURAL_TAGS", frozenset()))
        | frozenset(profile_values.get("RENPY_FAILSAFE_ONLY_TAGS", frozenset()))
        | {"binary_failover_scan", "scan_failsafe_applied", "unknown_binary_blob"}
    )
    return _merge_registry_values(base_constants, {"STRUCTURAL_NOISE_TAGS": structural_noise})


def build_detection_registry_snapshot() -> DetectionRegistrySnapshot:
    chain_values = _merge_registry_values(
        _public_registry_items(chain_defaults),
        _public_registry_items(chain_gate),
    )
    scoring_values = _public_registry_items(scoring_defaults)
    tag_values = _public_registry_items(tag_behavior)
    profile_values = _public_registry_items(runtime_profile)
    constants_values = _constants_values(chain_values, profile_values)
    return DetectionRegistrySnapshot(
        chain_registry=ChainRegistrySnapshot(chain_values),
        tag_registry=TagRegistrySnapshot(tag_values),
        scoring_registry=ScoringRegistrySnapshot(scoring_values),
        profile_registry=ProfileRegistrySnapshot(profile_values),
        engine_registry=EngineRegistrySnapshot(_engine_values(scoring_values)),
        explainability_registry=ExplainabilityRegistrySnapshot(_explainability_values(constants_values)),
        constants_registry=DetectionConstantsSnapshot(constants_values),
    )


DEFAULT_DETECTION_REGISTRY_SNAPSHOT = build_detection_registry_snapshot()
DETECTION_CONSTANT_DEFAULTS = _public_registry_items(constants_defaults)


__all__ = (
    "DEFAULT_DETECTION_REGISTRY_SNAPSHOT",
    "DETECTION_CONSTANT_DEFAULTS",
    "DetectionRegistrySnapshot",
    "build_detection_registry_snapshot",
)
