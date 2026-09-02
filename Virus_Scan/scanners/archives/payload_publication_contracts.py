"""Immutable archive payload publication request contracts."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ArchivePayloadPublicationRequest:
    tags: list[str]
    observed_tags: list[str]
    suspicious_tags: frozenset[str]
    path: str
    finding_tag: str
    failure_tag: str


__all__ = ("ArchivePayloadPublicationRequest",)
