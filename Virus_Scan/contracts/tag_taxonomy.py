"""Neutral immutable classification contract for canonical local detection tags."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

TAG_TAXONOMY_VERSION = "stage2636_11020_tag_taxonomy_v4"
TAG_CONTEXT_ONLY_MODALITIES = frozenset({"static_string"})
TAG_CLASS_ATOMIC_OBSERVATION = "atomic_observation"
TAG_CLASS_CONTEXT = "context"
TAG_CLASS_BEHAVIOR_DERIVATION = "behavior_derivation"
TAG_CLASS_ANALYTIC_CANDIDATE = "analytic_candidate"
TAG_CLASS_REPORTING_ONLY = "reporting_only"
TAG_CLASS_UNAVAILABLE = "unavailable"
TAG_CLASSES = frozenset({
    TAG_CLASS_ATOMIC_OBSERVATION,
    TAG_CLASS_CONTEXT,
    TAG_CLASS_BEHAVIOR_DERIVATION,
    TAG_CLASS_ANALYTIC_CANDIDATE,
    TAG_CLASS_REPORTING_ONLY,
    TAG_CLASS_UNAVAILABLE,
})


def _exact_text(value: object, reason: str, *, maximum: int = 128) -> str:
    if type(value) is not str:
        raise TypeError(reason)
    if not value or len(value) > maximum:
        raise ValueError(reason)
    return str.__str__(value)


@dataclass(frozen=True, slots=True)
class TagDefinition:
    """One explicit semantic class declaration for one canonical tag ID."""

    tag_id: str
    tag_class: str
    taxonomy_version: str = TAG_TAXONOMY_VERSION

    def __post_init__(self) -> None:
        if type(self) is not TagDefinition:
            raise TypeError("tag_definition_owner_invalid")
        tag_id = _exact_text(self.tag_id, "tag_definition_id_invalid")
        tag_class = _exact_text(self.tag_class, "tag_definition_class_invalid")
        version = _exact_text(
            self.taxonomy_version, "tag_definition_version_invalid",
        )
        if tag_class not in TAG_CLASSES:
            raise ValueError("tag_definition_class_invalid")
        object.__setattr__(self, "tag_id", tag_id)
        object.__setattr__(self, "tag_class", tag_class)
        object.__setattr__(self, "taxonomy_version", version)

    def to_record(self) -> dict[str, str]:
        return {
            "tag_id": self.tag_id,
            "tag_class": self.tag_class,
            "taxonomy_version": self.taxonomy_version,
        }


def tag_definition_digest(definitions: tuple[TagDefinition, ...]) -> str:
    if type(definitions) is not tuple or any(
        type(item) is not TagDefinition for item in definitions
    ):
        raise TypeError("tag_definitions_invalid")
    if len({item.tag_id for item in definitions}) != len(definitions):
        raise ValueError("tag_definition_duplicate")
    payload = tuple(
        item.to_record() for item in sorted(definitions, key=lambda row: row.tag_id)
    )
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = (
    "TAG_CLASSES",
    "TAG_CONTEXT_ONLY_MODALITIES",
    "TAG_CLASS_ANALYTIC_CANDIDATE",
    "TAG_CLASS_ATOMIC_OBSERVATION",
    "TAG_CLASS_BEHAVIOR_DERIVATION",
    "TAG_CLASS_CONTEXT",
    "TAG_CLASS_REPORTING_ONLY",
    "TAG_CLASS_UNAVAILABLE",
    "TAG_TAXONOMY_VERSION",
    "TagDefinition",
    "tag_definition_digest",
)
