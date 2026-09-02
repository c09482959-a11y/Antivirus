"""Detection registry context accessors.

Detection-owned modules use this immutable snapshot boundary instead of reading
registry defaults from the global runtime configuration owner.
"""
from __future__ import annotations


from Virus_Scan.detection.registries.snapshot import (
    DEFAULT_DETECTION_REGISTRY_SNAPSHOT,
    DetectionRegistrySnapshot,
)


def detection_registry_snapshot() -> DetectionRegistrySnapshot:
    return DEFAULT_DETECTION_REGISTRY_SNAPSHOT


def detection_registry_value(name: str, default: object = None) -> object:
    return DEFAULT_DETECTION_REGISTRY_SNAPSHOT.value(name, default)


__all__ = (
    "DetectionRegistrySnapshot",
    "detection_registry_snapshot",
    "detection_registry_value",
)
