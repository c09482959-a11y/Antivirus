"""Immutable result contract for one in-memory routing triage."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator


@dataclass(frozen=True, slots=True)
class InMemoryTriageResult:
    """Carry exact route provenance while preserving five-field triage unpacking."""

    tags: object
    suspicious: object
    current_stage: object
    terminal_result: object
    tag_evidence: object
    router_identity: object

    def __iter__(self) -> Iterator[object]:
        yield self.tags
        yield self.suspicious
        yield self.current_stage
        yield self.terminal_result
        yield self.tag_evidence


__all__ = ("InMemoryTriageResult",)
