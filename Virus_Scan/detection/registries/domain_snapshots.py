"""Bounded immutable registry snapshot types for detection domains.

Each dataclass owns exactly one registry domain.  The orchestration snapshot may
compose these read-only objects, but individual detection modules should consume
only the domain-specific values they own through ``detection_registry_value`` or
explicit domain snapshots.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.detection.registries.immutability import freeze_registry_value


@dataclass(frozen=True)
class _DomainRegistrySnapshot:
    values: Mapping[str, object]
    domain_name: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", freeze_registry_value(dict(self.values)))

    def value(self, name: str, default: object = None) -> object:
        key = str(name)
        if key in self.values:
            return self.values[key]
        return freeze_registry_value(default)

    def publication_items(self) -> tuple[tuple[str, object], ...]:
        return tuple((str(name), self.values[name]) for name in sorted(self.values))


@dataclass(frozen=True)
class TagRegistrySnapshot(_DomainRegistrySnapshot):
    domain_name: str = "tags"


@dataclass(frozen=True)
class ChainRegistrySnapshot(_DomainRegistrySnapshot):
    domain_name: str = "chains"


@dataclass(frozen=True)
class ScoringRegistrySnapshot(_DomainRegistrySnapshot):
    domain_name: str = "scoring"


@dataclass(frozen=True)
class ProfileRegistrySnapshot(_DomainRegistrySnapshot):
    domain_name: str = "profiles"


@dataclass(frozen=True)
class EngineRegistrySnapshot(_DomainRegistrySnapshot):
    domain_name: str = "engines"


@dataclass(frozen=True)
class ExplainabilityRegistrySnapshot(_DomainRegistrySnapshot):
    domain_name: str = "explainability"


@dataclass(frozen=True)
class DetectionConstantsSnapshot(_DomainRegistrySnapshot):
    domain_name: str = "detection_constants"


__all__ = (
    "ChainRegistrySnapshot",
    "DetectionConstantsSnapshot",
    "EngineRegistrySnapshot",
    "ExplainabilityRegistrySnapshot",
    "ProfileRegistrySnapshot",
    "ScoringRegistrySnapshot",
    "TagRegistrySnapshot",
)
