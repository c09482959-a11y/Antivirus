"""Typed no-hook outcomes for in-memory scheduler live state construction."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

LiveStateFieldStatus = Literal["materialized", "defaulted", "rejected"]
LiveStateRejection = dict[str, object]


@dataclass(frozen=True)
class LiveStateFieldOutcome:
    field: str
    status: LiveStateFieldStatus
    reason: str
    rejection_count: int = 0


@dataclass(frozen=True)
class LiveScalarOutcome:
    value: object
    accepted: bool
    reason: str


@dataclass(frozen=True)
class LiveMappingSnapshot:
    value: dict[object, object] = field(default_factory=dict)
    outcome: LiveStateFieldOutcome = field(default_factory=lambda: LiveStateFieldOutcome("", "materialized", ""))
    rejections: tuple[LiveStateRejection, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class LiveSetSnapshot:
    value: set[object] = field(default_factory=set)
    outcome: LiveStateFieldOutcome = field(default_factory=lambda: LiveStateFieldOutcome("", "materialized", ""))
    rejections: tuple[LiveStateRejection, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class LiveProcessSnapshot:
    value: list[object] = field(default_factory=list)
    outcome: LiveStateFieldOutcome = field(default_factory=lambda: LiveStateFieldOutcome("", "materialized", ""))
    rejections: tuple[LiveStateRejection, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class LiveEwmaSnapshot:
    value: dict[str, float] = field(default_factory=dict)
    outcome: LiveStateFieldOutcome = field(default_factory=lambda: LiveStateFieldOutcome("ewma_state", "materialized", ""))
    rejections: tuple[LiveStateRejection, ...] = field(default_factory=tuple)
