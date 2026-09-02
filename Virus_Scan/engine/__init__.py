"""Canonical engine identity contract for UMIGE routing audits.

This package owns the stable engine vocabulary used by validation code and
human audit checks. Routing decisions remain implemented in ``Virus_Scan.routing``;
this module provides importable, immutable engine identity values so clean-process
subsystem validation can prove the engine namespace initializes without runtime
state hydration.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Tuple


CANONICAL_ENGINES: Tuple[str, ...] = ("renpy", "rpgm", "unity", "media", "other")
ENGINE_CANONICAL_NAMES: Mapping[str, str] = MappingProxyType({name: name for name in CANONICAL_ENGINES})
UNKNOWN_ENGINE = "other"


@dataclass(frozen=True, slots=True)
class EngineIdentity:
    """Immutable engine identity snapshot used by routing/JSON audits."""

    container_engine: str = UNKNOWN_ENGINE
    artifact_engine: str = UNKNOWN_ENGINE
    detected_engine: str = UNKNOWN_ENGINE

    def normalized(self) -> "EngineIdentity":
        return EngineIdentity(
            container_engine=normalize_engine_name(self.container_engine),
            artifact_engine=normalize_engine_name(self.artifact_engine),
            detected_engine=normalize_engine_name(self.detected_engine),
        )


def normalize_engine_name(value: object) -> str:
    """Return the canonical engine name for an untrusted value."""
    text = str(value or "").strip().lower()
    return text if text in ENGINE_CANONICAL_NAMES else UNKNOWN_ENGINE


def engine_identity_from_record(record: Mapping[str, object] | None) -> EngineIdentity:
    """Build an immutable engine identity snapshot from a scan record."""
    source = record or {}
    return EngineIdentity(
        container_engine=normalize_engine_name(source.get("container_engine")),
        artifact_engine=normalize_engine_name(source.get("artifact_engine")),
        detected_engine=normalize_engine_name(source.get("detected_engine")),
    )


__all__ = (
    "CANONICAL_ENGINES",
    "ENGINE_CANONICAL_NAMES",
    "UNKNOWN_ENGINE",
    "EngineIdentity",
    "engine_identity_from_record",
    "normalize_engine_name",
)
