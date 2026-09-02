"""Boundary helpers for string-enrichment model inputs."""
from __future__ import annotations

from collections.abc import Iterable

from Virus_Scan.detection.enrichment.text_boundary import detection_enrichment_text_or_empty


def enrichment_text_or_empty(value: object) -> str:
    """Return deterministic text without probing caller-owned truthiness."""
    return detection_enrichment_text_or_empty(value)


def enrichment_sequence(value: object) -> tuple:
    """Freeze helper-returned tag sequences without falsey fallback semantics."""
    if value is None:
        return ()
    if isinstance(value, (str, bytes)):
        return (value,)
    if isinstance(value, Iterable):
        return tuple(value)
    return (value,)


__all__ = (
    "enrichment_sequence",
    "enrichment_text_or_empty",
)
